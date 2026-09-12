"""Pure and fake-only Windows identity checks: no OS impersonation performed."""
import struct
import pytest
from tnc.provenance.windows_custody_peer import *

SERVICE='S-1-5-80-100'
CLIENT='S-1-5-21-200'
LOGON='S-1-5-5-300-400'


def change(value,**updates):return type(value).model_validate({**value.model_dump(),**updates})


@pytest.fixture
def policy():
    return WindowsPeerPolicy(deployment_id='deployment',store_instance_id='store',pipe_name=r'\\.\pipe\TNC-test',
        service_sid=SERVICE,client_sid=CLIENT,logon_sid=LOGON,authentication_id=42,
        expected_process=PeerProcess(pid=123,creation_filetime=1000,session_id=2,running=True),timestamp=100,expiry=200)


def sid_bytes(text):
    parts=[int(p) for p in text.split('-')[1:]]
    return bytes([parts[0],len(parts)-2])+parts[1].to_bytes(6,'big')+b''.join(struct.pack('<I',x) for x in parts[2:])


def descriptor(owner=SERVICE,client=CLIENT,mask=CLIENT_RIGHTS,flags=0,kind=0,protected=True):
    owner_raw=sid_bytes(owner);aces=[]
    for sid,rights in ((SERVICE,SERVICE_RIGHTS),(client,mask)):
        raw=sid_bytes(sid);aces.append(struct.pack('<BBHI',kind,flags,8+len(raw),rights)+raw)
    body=b''.join(aces);acl=struct.pack('<BBHHH',2,0,8+len(body),2,0)+body
    return struct.pack('<BBHIIII',1,0,0x8004|(0x1000 if protected else 0),20,0,0,20+len(owner_raw))+owner_raw+acl


class FakeAPI:
    def __init__(self,policy):
        self.calls=[];self.opened=[];self.closed=[];self.active=False;self.preexisting=False;self.residual=False
        self.fail='';self.close_fail=False;self.revert_fail=False;self.impersonate_fail=False
        self.process=policy.expected_process
        self.endpoint=PipeEndpoint(name=policy.pipe_name,server_end=True,local=True)
        self.token=PeerToken(user_sid=CLIENT,logon_sid=LOGON,authentication_id=42,session_id=2,
            token_type='IMPERSONATION',level='IDENTIFICATION',logon_enabled=True,restricted=False,app_container=False)
        self.security=descriptor();self.pid=123;self.changed=False;self.process_reads=0;self.security_reads=0
    def hit(self,name,*args):
        self.calls.append((name,*args))
        if self.fail==name:raise RuntimeError('Private API error')
    def open_thread_token(self,access,open_as_self):
        self.hit('open_thread_token',access,open_as_self)
        if self.active or self.preexisting or self.residual:
            handle='token-'+str(len(self.opened));self.opened.append(handle);return handle
        return None
    def pipe_information(self,pipe):self.hit('pipe_information');return self.endpoint
    def security_descriptor(self,pipe,limit):
        self.hit('security_descriptor',limit);self.security_reads+=1
        return descriptor(owner=CLIENT) if self.changed and self.security_reads>1 else self.security
    def client_process_id(self,pipe):self.hit('client_process_id');return self.pid
    def open_process(self,pid,access):
        self.hit('open_process',pid,access);self.opened.append('process');return 'process'
    def process_information(self,handle):
        self.hit('process_information');self.process_reads+=1
        return self.process
    def impersonate_pipe_client(self,pipe):
        self.hit('impersonate_pipe_client')
        if self.impersonate_fail:return False
        self.active=True;return True
    def token_information(self,handle,limit):self.hit('token_information',limit);return self.token
    def revert_to_self(self):
        self.hit('revert_to_self')
        if self.revert_fail:return False
        self.active=False;return True
    def close(self,handle):
        self.calls.append(('close',handle));self.closed.append(handle)
        return not self.close_fail


def inspect(api,policy,**kwargs):
    return inspect_windows_peer_for_testing(api,'borrowed-pipe',policy=policy,now=110,deadline=100,
        clock=kwargs.pop('clock',lambda:1),**kwargs)


@pytest.fixture
def observation(policy):return inspect(FakeAPI(policy),policy).observation


def test_fake_acquisition_rights_order_and_cleanup(policy):
    api=FakeAPI(policy);result=inspect(api,policy)
    assert result.status=='CONFORMS' and result.audit_only and not result.authorization_granted
    assert not api.active and set(api.closed)==set(api.opened)
    assert all(call[1:]==(TOKEN_QUERY,True) for call in api.calls if call[0]=='open_thread_token')
    assert ('open_process',123,PROCESS_QUERY_LIMITED_INFORMATION) in api.calls
    assert ('token_information',MAX_BUFFER) in api.calls
    names=[c[0] for c in api.calls]
    assert names.index('token_information')<names.index('revert_to_self')<len(names)-1
    assert 'borrowed-pipe' not in api.closed


@pytest.mark.parametrize('field,value,reason',[
    ('user_sid','S-1-5-21-999','TOKEN_IDENTITY_MISMATCH'),('logon_sid','S-1-5-5-1-2','TOKEN_IDENTITY_MISMATCH'),
    ('authentication_id',43,'TOKEN_IDENTITY_MISMATCH'),('session_id',3,'TOKEN_IDENTITY_MISMATCH'),
    ('logon_enabled',False,'TOKEN_IDENTITY_MISMATCH'),('level','ANONYMOUS','TOKEN_PROFILE_DENIED'),
    ('level','DELEGATION','TOKEN_PROFILE_DENIED'),('level','IMPERSONATION','TOKEN_PROFILE_DENIED'),
    ('token_type','PRIMARY','TOKEN_PROFILE_DENIED'),('restricted',True,'TOKEN_PROFILE_DENIED'),
    ('app_container',True,'TOKEN_PROFILE_DENIED')])
def test_effective_identity_policy(policy,observation,field,value,reason):
    obs=change(observation,token=change(observation.token,**{field:value}))
    assert evaluate_windows_peer(policy,obs,now=110).reason==reason


@pytest.mark.parametrize('field,value',[('pid',124),('creation_filetime',1001),('session_id',3),('running',False)])
def test_process_lifetime_policy(policy,observation,field,value):
    obs=change(observation,process=change(observation.process,**{field:value}))
    assert evaluate_windows_peer(policy,obs,now=110).reason=='PROCESS_LIFETIME_MISMATCH'


@pytest.mark.parametrize('kwargs',[{'owner':CLIENT},{'client':SERVICE},{'mask':0x40000000},{'mask':CLIENT_RIGHTS|4},{'protected':False}])
def test_descriptor_policy_rejects_wrong_owner_and_creation_rights(policy,kwargs):
    api=FakeAPI(policy);api.security=descriptor(**kwargs)
    assert inspect(api,policy).reason=='DESCRIPTOR_MISMATCH'


@pytest.mark.parametrize('kind',['deny','inherited','null','oversize','truncated'])
def test_descriptor_acquisition_bounds(policy,kind):
    api=FakeAPI(policy)
    api.security={'deny':descriptor(kind=1),'inherited':descriptor(flags=16),'null':bytes(20),
        'oversize':bytes(MAX_BUFFER+1),'truncated':descriptor()[:25]}[kind]
    result=inspect(api,policy)
    assert result.status=='INDETERMINATE'
    assert not any(c[0]=='impersonate_pipe_client' for c in api.calls)


@pytest.mark.parametrize('point',['open_thread_token','pipe_information','security_descriptor','client_process_id',
    'open_process','process_information','impersonate_pipe_client','token_information'])
def test_api_failures_release_handles(policy,point):
    api=FakeAPI(policy);api.fail=point;result=inspect(api,policy)
    assert result.status=='INDETERMINATE' and result.observation is None
    assert set(api.closed)==set(api.opened) and not api.active
    if point in ('impersonate_pipe_client','token_information'):
        assert ('revert_to_self',) in api.calls


@pytest.mark.parametrize('failure',['revert_false','revert_exception','close_false','residual'])
def test_cleanup_failure_requires_shutdown(policy,failure):
    api=FakeAPI(policy)
    if failure=='revert_false':api.revert_fail=True
    elif failure=='revert_exception':api.fail='revert_to_self'
    elif failure=='close_false':api.close_fail=True
    else:
        original=api.revert_to_self
        def residual():
            result=original();api.residual=True;return result
        api.revert_to_self=residual
    result=inspect(api,policy)
    assert result.status=='BROKER_SHUTDOWN_REQUIRED' and result.observation is None
    assert set(api.closed)==set(api.opened)


def test_preexisting_impersonation_is_not_reverted_by_inspector(policy):
    api=FakeAPI(policy);api.preexisting=True
    assert inspect(api,policy).status=='INDETERMINATE'
    assert not any(c[0] in ('impersonate_pipe_client','revert_to_self') for c in api.calls)
    assert api.closed==api.opened


def test_false_impersonation_never_queries_broker_token(policy):
    api=FakeAPI(policy);api.impersonate_fail=True
    assert inspect(api,policy).status=='INDETERMINATE'
    assert not any(c[0]=='token_information' for c in api.calls)
    assert ('revert_to_self',) in api.calls


def test_changed_descriptor_rejected(policy):
    api=FakeAPI(policy);api.changed=True
    assert inspect(api,policy).status=='INDETERMINATE'
    assert set(api.closed)==set(api.opened)


@pytest.mark.parametrize('field,value',[('name',r'\\.\pipe\TNC-other'),('server_end',False),('local',False)])
def test_endpoint_scope(policy,field,value):
    api=FakeAPI(policy);api.endpoint=change(api.endpoint,**{field:value})
    assert inspect(api,policy).status=='INDETERMINATE'


@pytest.mark.parametrize('ticks',[[100],[True],[-1],[2,1],[1,2,3,100]])
def test_deadline_regression_cleanup(policy,ticks):
    api=FakeAPI(policy);values=iter(ticks)
    assert inspect(api,policy,clock=lambda:next(values)).status=='INDETERMINATE'
    assert not api.active and set(api.closed)==set(api.opened)


@pytest.mark.parametrize('sid',['S-1-05-21','S-1-5-01','S-1-5-4294967296','S-1-281474976710656-1'])
def test_canonical_sid_rejection(policy,sid):
    with pytest.raises(ValueError):change(policy,client_sid=sid)


def test_pure_scope_time_and_frozen_records(policy,observation):
    assert evaluate_windows_peer(policy,observation,now=200).reason=='TIME_MISMATCH'
    assert evaluate_windows_peer(policy,observation,now=True).reason=='INVALID_RECORD'
    assert evaluate_windows_peer(policy,change(observation,store_instance_id='other'),now=110).reason=='SCOPE_MISMATCH'
    with pytest.raises(ValueError):policy.expiry=300


def test_no_native_or_io_entrypoints(policy,observation,monkeypatch):
    def forbidden(*args,**kw):raise AssertionError('Unexpected side effect')
    for target in ('builtins.open','socket.socket','sqlite3.connect','time.time','time.monotonic','ctypes.WinDLL'):
        monkeypatch.setattr(target,forbidden)
    assert evaluate_windows_peer(policy,observation,now=110).status=='CONFORMS'
    assert inspect(FakeAPI(policy),policy).status=='CONFORMS'


@pytest.mark.parametrize('kind',['creation','pid','exited'])
def test_peer_changes_during_acquisition(policy,kind):
    api=FakeAPI(policy);original=api.revert_to_self
    def changed():
        result=original()
        if kind=='pid':api.pid=124
        elif kind=='creation':api.process=change(api.process,creation_filetime=1001)
        else:api.process=change(api.process,running=False)
        return result
    api.revert_to_self=changed
    assert inspect(api,policy).status=='INDETERMINATE'
    assert set(api.closed)==set(api.opened)


def test_cleanup_time_counts_toward_deadline(policy):
    api=FakeAPI(policy);tick=[1];close=api.close
    def delayed(handle):
        result=close(handle)
        if handle=='process':tick[0]=100
        return result
    api.close=delayed
    result=inspect(api,policy,clock=lambda:tick[0])
    assert result.status=='INDETERMINATE' and result.observation is None
