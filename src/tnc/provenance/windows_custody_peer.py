"""Pure Windows pipe peer policy and FAKE-API acquisition. No native backend."""
from typing import Annotated, Literal
from pydantic import Field, AfterValidator, model_validator
from tnc.provenance.authorization_models import Model, Identifier, canonical_bytes, decode_canonical
from tnc.provenance.windows_protected_files import parse_security

TOKEN_QUERY = 0x0008
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
CLIENT_RIGHTS = 0x00120083  # data read/write, attributes read, READ_CONTROL, SYNCHRONIZE
SERVICE_RIGHTS = 0x001f01ff
MAX_BUFFER = 65536
U32 = Annotated[int, Field(strict=True, ge=0, le=2**32-1)]
U64 = Annotated[int, Field(strict=True, ge=0, le=2**64-1)]
Tick = Annotated[int, Field(strict=True, ge=0, le=2**63-1)]


def _sid(value):
    parts=value.split('-')
    if (len(parts)<4 or len(parts)>18 or parts[:2]!=['S','1']
            or any(not p.isascii() or not p.isdecimal() or str(int(p))!=p for p in parts[2:])
            or int(parts[2])>=2**48 or any(int(p)>=2**32 for p in parts[3:])):
        raise ValueError('Canonical SID required')
    return value


SID = Annotated[str, Field(strict=True, max_length=184), AfterValidator(_sid)]


class PipeACE(Model):
    sid: SID
    mask: U32


class PipeSecurityObservation(Model):
    owner_sid: SID
    protected_dacl: bool = Field(strict=True)
    aces: tuple[PipeACE,...] = Field(max_length=32)


class PeerProcess(Model):
    pid: int = Field(strict=True, ge=1, le=2**32-1)
    creation_filetime: U64
    session_id: U32
    running: bool = Field(strict=True)


class PipeEndpoint(Model):
    name: str = Field(strict=True,max_length=256)
    server_end: bool = Field(strict=True)
    local: bool = Field(strict=True)


class PeerToken(Model):
    user_sid: SID
    logon_sid: SID
    authentication_id: U64
    session_id: U32
    token_type: Literal['IMPERSONATION','PRIMARY']
    level: Literal['IDENTIFICATION','IMPERSONATION','DELEGATION','ANONYMOUS']
    logon_enabled: bool = Field(strict=True)
    restricted: bool = Field(strict=True)
    app_container: bool = Field(strict=True)


class WindowsPeerPolicy(Model):
    profile: Literal['tnc-windows-peer-test-v1']='tnc-windows-peer-test-v1'
    deployment_id: Identifier
    store_instance_id: Identifier
    pipe_name: str = Field(strict=True,pattern=r'^\\\\\.\\pipe\\TNC-[A-Za-z0-9_-]{1,64}$')
    service_sid: SID
    client_sid: SID
    logon_sid: SID
    authentication_id: U64
    expected_process: PeerProcess
    timestamp: Tick
    expiry: Tick

    @model_validator(mode='after')
    def valid(self):
        if (self.timestamp>=self.expiry or self.service_sid==self.client_sid
                or not self.expected_process.running or not self.logon_sid.startswith('S-1-5-5-')
                or len(self.logon_sid.split('-'))!=6):
            raise ValueError('Explicit distinct principals and lifetime required')
        return self


class WindowsPeerObservation(Model):
    source: Literal['FAKE_WINDOWS_API']='FAKE_WINDOWS_API'
    deployment_id: Identifier
    store_instance_id: Identifier
    pipe_name: str = Field(strict=True,max_length=256)
    process: PeerProcess
    token: PeerToken
    security: PipeSecurityObservation
    observed_at: Tick


class WindowsPeerResult(Model):
    status: Literal['CONFORMS','VIOLATIONS','INDETERMINATE','BROKER_SHUTDOWN_REQUIRED']
    reason: Identifier
    observation: WindowsPeerObservation | None = None
    audit_only: Literal[True]=True
    authorization_granted: Literal[False]=False


def _copy(kind,value):
    if type(value) is not kind:raise ValueError('Exact record required')
    raw=canonical_bytes(value)
    if len(raw)>MAX_BUFFER:raise ValueError('Record bound exceeded')
    return decode_canonical(kind,raw)


def _identity_mismatch(policy, *, scope, observed_at, process, token, security, now):
    """Shared field comparisons on already reconstructed records; no provenance claim."""
    if not policy.timestamp<=observed_at<=now<policy.expiry:return 'TIME_MISMATCH'
    if scope!=(policy.deployment_id,policy.store_instance_id,policy.pipe_name):return 'SCOPE_MISMATCH'
    expected=(PipeACE(sid=policy.service_sid,mask=SERVICE_RIGHTS),PipeACE(sid=policy.client_sid,mask=CLIENT_RIGHTS))
    if security.owner_sid!=policy.service_sid or not security.protected_dacl or security.aces!=expected:
        return 'DESCRIPTOR_MISMATCH'
    if process!=policy.expected_process:return 'PROCESS_LIFETIME_MISMATCH'
    if (token.user_sid!=policy.client_sid or token.logon_sid!=policy.logon_sid
            or token.authentication_id!=policy.authentication_id
            or token.session_id!=policy.expected_process.session_id or not token.logon_enabled):
        return 'TOKEN_IDENTITY_MISMATCH'
    return None


def evaluate_windows_peer(policy,observation,*,now):
    """Audit comparison only. Synthetic observations are not authorization tokens."""
    try:
        policy=_copy(WindowsPeerPolicy,policy);observation=_copy(WindowsPeerObservation,observation)
        if type(now) is not int or not 0<=now<=2**63-1:raise ValueError('Exact time required')
        def deny(reason):return WindowsPeerResult(status='VIOLATIONS',reason=reason)
        reason=_identity_mismatch(policy,scope=(observation.deployment_id,observation.store_instance_id,observation.pipe_name),
            observed_at=observation.observed_at,process=observation.process,token=observation.token,
            security=observation.security,now=now)
        if reason:return deny(reason)
        token=observation.token
        if token.token_type!='IMPERSONATION' or token.level!='IDENTIFICATION' or token.restricted or token.app_container:
            return deny('TOKEN_PROFILE_DENIED')
        return WindowsPeerResult(status='CONFORMS',reason='MATCHED',observation=observation)
    except (ValueError,TypeError,AttributeError):
        return WindowsPeerResult(status='INDETERMINATE',reason='INVALID_RECORD')


def _security(raw):
    if type(raw) is not bytes or not 20<=len(raw)<=MAX_BUFFER:raise ValueError('Descriptor bounds')
    owner,entries=parse_security(raw)
    if len(entries)>32 or any(kind!=0 or flags!=0 for kind,flags,mask,sid in entries):
        raise ValueError('Ordinary explicit allow ACEs required')
    return PipeSecurityObservation(owner_sid=owner,protected_dacl=bool(int.from_bytes(raw[2:4],'little')&0x1000),
        aces=tuple(PipeACE(sid=sid,mask=mask) for kind,flags,mask,sid in entries))


def inspect_windows_peer_for_testing(api,pipe,*,policy,now,deadline,clock):
    """Fake adapter contract; borrowed pipe remains owned by caller.

    API calls are deliberately explicit about rights/bounds. No WinDLL binding,
    real impersonation, endpoint creation or shutdown is performed by this module.
    """
    handles=[];fatal=False;revert_needed=False;observation=None;reason='INSPECTION_FAILED'
    try:
        policy=_copy(WindowsPeerPolicy,policy)
        if type(now) is not int or not 0<=now<=2**63-1:raise ValueError('Invalid epoch')
        if type(deadline) is not int or not 0<deadline<=2**63-1:raise ValueError('Invalid deadline')
        previous=-1
        def check():
            nonlocal previous
            tick=clock()
            if type(tick) is not int or not 0<=tick or not previous<=tick<deadline:raise ValueError('Deadline or clock regression')
            previous=tick
        check()
        initial=api.open_thread_token(TOKEN_QUERY,True)
        if initial is not None:
            handles.append(initial)
            raise ValueError('Preexisting impersonation')
        check()
        endpoint=_copy(PipeEndpoint,api.pipe_information(pipe))
        if endpoint.name!=policy.pipe_name or not endpoint.server_end or not endpoint.local:
            raise ValueError('Local server endpoint required')
        security_raw=api.security_descriptor(pipe,MAX_BUFFER)
        security=_security(security_raw)
        pid=api.client_process_id(pipe)
        if type(pid) is not int or not 0<pid<2**32:raise ValueError('Invalid PID')
        process=api.open_process(pid,PROCESS_QUERY_LIMITED_INFORMATION)
        if process is None or process==0:raise ValueError('Invalid process handle')
        handles.append(process)
        before=_copy(PeerProcess,api.process_information(process))
        if before.pid!=pid or not before.running:raise ValueError('Process mismatch')
        check()
        revert_needed=True
        try:
            if api.impersonate_pipe_client(pipe) is not True:raise ValueError('Impersonation failed')
            token_handle=api.open_thread_token(TOKEN_QUERY,True)
            if token_handle is None or token_handle==0:raise ValueError('Missing effective token')
            handles.append(token_handle)
            token=_copy(PeerToken,api.token_information(token_handle,MAX_BUFFER))
            check()
        finally:
            # Close acquired token before returning to service context; still
            # attempt reversion if token querying or cleanup fails.
            if len(handles)>1:
                handle=handles.pop()
                try:
                    if api.close(handle) is not True:fatal=True
                except Exception:fatal=True
            try:
                if api.revert_to_self() is not True:fatal=True
            except Exception:fatal=True
            revert_needed=False
        if fatal:raise ValueError('Unsafe cleanup')
        check()
        leftover=api.open_thread_token(TOKEN_QUERY,True)
        if leftover is not None:
            handles.append(leftover);fatal=True
            raise ValueError('Unexpected residual impersonation')
        after=_copy(PeerProcess,api.process_information(process))
        if before!=after or api.client_process_id(pipe)!=pid:raise ValueError('Peer changed')
        if api.security_descriptor(pipe,MAX_BUFFER)!=security_raw:raise ValueError('Descriptor changed')
        if _copy(PipeEndpoint,api.pipe_information(pipe))!=endpoint:raise ValueError('Endpoint changed')
        check()
        observation=WindowsPeerObservation(deployment_id=policy.deployment_id,store_instance_id=policy.store_instance_id,
            pipe_name=endpoint.name,process=after,token=token,security=security,observed_at=now)
    except Exception:
        observation=None
    finally:
        if revert_needed:
            try:
                if api.revert_to_self() is not True:fatal=True
            except Exception:fatal=True
        for handle in reversed(handles):
            try:
                if api.close(handle) is not True:fatal=True
            except Exception:fatal=True
    if fatal:return WindowsPeerResult(status='BROKER_SHUTDOWN_REQUIRED',reason='CLEANUP_FAILED')
    if observation is None:return WindowsPeerResult(status='INDETERMINATE',reason=reason)
    try:check()
    except Exception:return WindowsPeerResult(status='INDETERMINATE',reason='DEADLINE_OR_CLOCK_INVALID')
    return evaluate_windows_peer(policy,observation,now=now)
