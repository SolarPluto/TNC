"""Spawned broker and clients; fixture credentials do not attest Windows PIDs."""
import multiprocessing as mp
import secrets
import socket
import struct
from hashlib import sha256
from time import monotonic
from types import SimpleNamespace

import pytest
from test_key_custody_logic import custody,change
from test_key_custody_provider import harness
from tnc.provenance.authorization_models import canonical_bytes,record_digest,decode_canonical
from tnc.provenance.key_custody_logic import (
    KeyHandleRecord,CustodyCapabilities,CustodyTrustAnchor,CustodySignRequest,decode_custody_record)
from tnc.provenance.key_custody_provider import TestCustodyProvider
from tnc.provenance.reconciliation_verifier import ObservationRequest,observation_preimage
from tnc.provenance.key_custody_ipc import (
    CustodyIPCBroker,CustodyIPCClient,IPCRequest,IPCResult,MAX_FRAME,receive_frame,send_frame,
    _Hello,_packet)


def broker_child(pipe, stop, policy, reached, resume, templates, credentials, mode, pause):
    request,handle,caps,anchor,expected,now=templates
    request=decode_custody_record(CustodySignRequest,request)
    handle=decode_custody_record(KeyHandleRecord,handle)
    caps=decode_custody_record(CustodyCapabilities,caps)
    anchor=decode_custody_record(CustodyTrustAnchor,anchor)
    expected=decode_canonical(ObservationRequest,expected)
    provider=TestCustodyProvider(epoch_clock=lambda:now)
    public=provider.public_key_bytes
    handle=change(handle,public_key_hex=public.hex(),key_id=sha256(public).hexdigest())
    anchor=change(anchor,handle_digest=record_digest(handle))
    payload=change(request.payload,signing_key_id=handle.key_id)
    request=change(request,handle_digest=record_digest(handle),payload=payload,preimage_hex=observation_preimage(payload).hex())
    def authorized(principal,action):
        return bool(policy.value & (1 if action=='SIGN' else 2))
    def hook(point):
        if point==pause:
            reached.set()
            if not resume.wait(3):raise TimeoutError('Test barrier')
    broker=CustodyIPCBroker(provider,credentials=credentials,
        custody_inputs=dict(handle=handle,capabilities=caps,trusted_anchor=anchor,expected_request=expected),
        authorization=authorized,epoch_clock=lambda:now,mode=mode,hook=hook)
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(8)
            pipe.send_bytes(str(listener.getsockname()[1]).encode())
            pipe.send_bytes(canonical_bytes(request))
            pipe.send_bytes(public)
            pipe.close()
            broker.serve(listener,stop)
    finally:provider.close()


def client_child(pipe, address, principal, secret, raw):
    client=CustodyIPCClient(address,principal=principal,secret=secret)
    result=client.exchange(decode_canonical(IPCRequest,raw))
    pipe.send_bytes(canonical_bytes(result));pipe.close()


@pytest.fixture
def launch(custody):
    processes=[]
    def start(mode='SUCCESS',pause='',caps_limit=4096):
        ctx=mp.get_context('spawn');parent,child=ctx.Pipe(duplex=False)
        stop=ctx.Event();policy=ctx.Value('i',3);reached=ctx.Event();resume=ctx.Event()
        request,handle,caps,anchor,expected,now=custody
        caps=change(caps,max_message_bytes=caps_limit)
        anchor=change(anchor,capabilities_digest=record_digest(caps))
        templates=tuple(canonical_bytes(v) for v in (request,handle,caps,anchor,expected))+(now,)
        secret=secrets.token_bytes(32);other=secrets.token_bytes(32)
        process=ctx.Process(target=broker_child,args=(child,stop,policy,reached,resume,templates,
            {'host-signer':secret,'other':other},mode,pause))
        process.start();child.close();processes.append((process,stop,resume))
        assert parent.poll(15),'Broker startup timed out'
        port=int(parent.recv_bytes());raw=parent.recv_bytes();public=parent.recv_bytes();parent.close()
        request=decode_custody_record(CustodySignRequest,raw)
        address=('127.0.0.1',port)
        return SimpleNamespace(process=process,stop=stop,policy=policy,reached=reached,resume=resume,ctx=ctx,
            client=CustodyIPCClient(address,principal='host-signer',secret=secret),address=address,secret=secret,
            other=other,request=request,public=public)
    yield start
    for process,stop,resume in processes:
        if process.is_alive():
            resume.set();stop.set()
        process.join(7)
        if process.is_alive():process.terminate();process.join(5)
        assert not process.is_alive()
        process.close()


def issue(h,**kw):
    return h.client.exchange(IPCRequest(action='ISSUE',request=h.request,
        request_digest=record_digest(h.request),**kw))


def command(h,token,action='SIGN',**kw):
    return IPCRequest(action=action,token=token,request_digest=record_digest(h.request),**kw)


def spawned(h,request):
    parent,child=h.ctx.Pipe(duplex=False)
    process=h.ctx.Process(target=client_child,args=(child,h.address,'host-signer',h.secret,canonical_bytes(request)))
    process.start();child.close()
    return process,parent


def finish(process,pipe):
    try:
        assert pipe.poll(10)
        result=decode_canonical(IPCResult,pipe.recv_bytes())
        process.join(5);assert process.exitcode==0
        return result
    finally:
        pipe.close()
        if process.is_alive():process.terminate();process.join(5)
        process.close()


def test_real_broker_and_client_process_roundtrip(launch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    h=launch();issued=issue(h);assert issued.status=='ISSUED'
    result=finish(*spawned(h,command(h,issued.token)))
    assert result.status=='VERIFIED'
    Ed25519PublicKey.from_public_bytes(h.public).verify(bytes.fromhex(result.response.signature_hex),
        observation_preimage(h.request.payload))
    assert h.client.exchange(command(h,issued.token)).status=='TOKEN_ALREADY_CONSUMED'


@pytest.mark.parametrize('kind',['unknown-principal','wrong-secret'])
def test_unauthenticated_connections(launch,kind):
    h=launch()
    client=CustodyIPCClient(h.address,principal='nobody' if kind=='unknown-principal' else 'host-signer',
        secret=h.secret if kind=='unknown-principal' else secrets.token_bytes(32))
    assert client.exchange(IPCRequest(action='ISSUE',request=h.request,request_digest=record_digest(h.request))).status=='OUTCOME_UNKNOWN'
    assert issue(h).status=='ISSUED'


@pytest.mark.parametrize('size',[0,MAX_FRAME+1,2**32-1])
def test_oversized_headers_drop_without_payload(launch,size):
    h=launch()
    with socket.create_connection(h.address,timeout=2) as sock:
        receive_frame(sock,monotonic()+2)
        sock.sendall(struct.pack('!I',size));sock.settimeout(2)
        assert sock.recv(1)==b''
    assert issue(h).status=='ISSUED'


def test_request_packet_replay_rejected_new_connection(launch):
    h=launch();body=canonical_bytes(IPCRequest(action='ISSUE',request=h.request,request_digest=record_digest(h.request)))
    with socket.create_connection(h.address,timeout=2) as sock:
        hello=decode_canonical(_Hello,receive_frame(sock,monotonic()+2))
        packet=_packet('host-signer',body,h.secret,hello.nonce,b'REQUEST')
        send_frame(sock,packet,monotonic()+2);receive_frame(sock,monotonic()+2)
    with socket.create_connection(h.address,timeout=2) as sock:
        receive_frame(sock,monotonic()+2);send_frame(sock,packet,monotonic()+2)
        sock.settimeout(2);assert sock.recv(1)==b''


def test_token_foreign_owner_cannot_consume(launch):
    h=launch();token=issue(h).token
    other=CustodyIPCClient(h.address,principal='other',secret=h.other)
    assert other.exchange(command(h,token)).status=='TOKEN_INVALID'
    assert h.client.exchange(command(h,token)).status=='VERIFIED'


def test_mismatched_digest_burns_owned_token(launch):
    h=launch();token=issue(h).token
    bad=command(h,token).model_copy(update={'request_digest':'f'*64})
    assert h.client.exchange(bad).status=='REQUEST_MISMATCH'
    assert h.client.exchange(command(h,token)).status=='TOKEN_ALREADY_CONSUMED'


def test_revocation_after_issue_burns_without_existence_leak(launch):
    h=launch();token=issue(h).token;h.policy.value=2
    assert h.client.exchange(command(h,token)).status=='ACCESS_DENIED'
    assert h.client.exchange(command(h,'unknown')).status=='ACCESS_DENIED'
    h.policy.value=3
    assert h.client.exchange(command(h,token)).status=='TOKEN_ALREADY_CONSUMED'


@pytest.mark.parametrize('point',['before_dispatch','after_dispatch'])
def test_live_revocation_at_barrier(launch,point):
    h=launch(pause=point);token=issue(h).token
    child,pipe=spawned(h,command(h,token))
    assert h.reached.wait(5);h.policy.value=2;h.resume.set()
    result=finish(child,pipe);assert result.status=='ACCESS_DENIED' and result.response is None


@pytest.mark.parametrize('mode,status',[('WRONG_KEY','SIGNATURE_INVALID'),('AMBIGUOUS_OUTCOME','OUTCOME_UNKNOWN'),
    ('LATE_RESULT_REJECTION','RESULT_DISCARDED'),('PROVIDER_FAILURE','PROVIDER_FAILED')])
def test_faults_and_exact_recovery_without_resigning(launch,mode,status):
    h=launch(mode=mode);token=issue(h).token
    assert h.client.exchange(command(h,token)).status==status
    recovered=h.client.exchange(command(h,token,'RECOVER'))
    assert recovered.status=='RECOVERED' and recovered.outcome==status and recovered.response is None
    assert h.client.exchange(command(h,token)).status=='TOKEN_ALREADY_CONSUMED'


def test_lost_ack_cached_success_recovery(launch):
    h=launch(pause='recorded');token=issue(h).token
    child,pipe=spawned(h,command(h,token))
    assert h.reached.wait(5)
    child.terminate();child.join(5);child.close();pipe.close();h.resume.set()
    recovered=h.client.exchange(command(h,token,'RECOVER'))
    assert recovered.status=='RECOVERED' and recovered.outcome=='VERIFIED' and recovered.response
    assert h.client.exchange(command(h,token,'RECOVER'))==recovered
    assert h.client.exchange(command(h,token)).status=='TOKEN_ALREADY_CONSUMED'


def test_recovery_requires_current_permission(launch):
    h=launch();token=issue(h).token;h.client.exchange(command(h,token));h.policy.value=1
    assert h.client.exchange(command(h,token,'RECOVER')).status=='ACCESS_DENIED'


def test_broker_death_does_not_claim_durable_recovery(launch):
    h=launch(pause='after_dispatch');token=issue(h).token
    child,pipe=spawned(h,command(h,token));assert h.reached.wait(5)
    h.process.terminate();h.process.join(5)
    assert finish(child,pipe).status=='OUTCOME_UNKNOWN'
    new=launch()
    assert new.client.exchange(command(new,token,'RECOVER')).status=='TOKEN_INVALID'


def test_small_provider_limit_rejected_before_token_issue(launch):
    assert issue(launch(caps_limit=1)).status=='REQUEST_DENIED'


def test_duplicate_issue_conflict(launch):
    h=launch();assert issue(h).status=='ISSUED';assert issue(h).status=='OPERATION_CONFLICT'


def test_untrusted_fields_rejected_without_object_loading(launch):
    h=launch()
    with socket.create_connection(h.address,timeout=2) as sock:
        hello=decode_canonical(_Hello,receive_frame(sock,monotonic()+2))
        body=b'{"__reduce__":"not-executable"}'
        send_frame(sock,_packet('host-signer',body,h.secret,hello.nonce,b'REQUEST'),monotonic()+2)
        sock.settimeout(2);assert sock.recv(1)==b''
    assert issue(h).status=='ISSUED'


def test_expired_token_consumed_and_cannot_extend_budget(launch):
    h=launch();token=issue(h,budget_ms=1).token
    h.stop.wait(.02)
    result=h.client.exchange(command(h,token,budget_ms=5000))
    assert result.status=='DEADLINE_EXCEEDED'
    assert h.client.exchange(command(h,token)).status=='TOKEN_ALREADY_CONSUMED'


def test_tampered_token_does_not_consume_original(launch):
    h=launch();token=issue(h).token
    altered=token[:-1]+('0' if token[-1]!='0' else '1')
    assert h.client.exchange(command(h,altered)).status=='TOKEN_INVALID'
    assert h.client.exchange(command(h,token)).status=='VERIFIED'


def test_recovery_digest_must_match(launch):
    h=launch();token=issue(h).token;h.client.exchange(command(h,token))
    bad=command(h,token,'RECOVER').model_copy(update={'request_digest':'f'*64})
    assert h.client.exchange(bad).status=='REQUEST_MISMATCH'


def test_no_automatic_recovery_for_unconsumed_token(launch):
    h=launch();token=issue(h).token
    assert h.client.exchange(command(h,token,'RECOVER')).status=='NO_RECORDED_OUTCOME'
    assert h.client.exchange(command(h,token)).status=='VERIFIED'


def test_registry_capacity_no_eviction(harness,monkeypatch):
    import tnc.provenance.key_custody_ipc as module
    provider,request,kwargs,clock,*_=harness
    monkeypatch.setattr(module,'MAX_TOKENS',2)
    inputs={k:v for k,v in kwargs.items() if k!='signer_id'}
    broker=CustodyIPCBroker(provider,credentials={'host-signer':secrets.token_bytes(32)},
        custody_inputs=inputs,authorization=lambda p,a:True,epoch_clock=lambda:clock[1])
    for index,expected in enumerate(('ISSUED','ISSUED','CAPACITY_EXCEEDED')):
        candidate=change(request,attempt_id=f'capacity-{index}')
        result=broker._execute(IPCRequest(action='ISSUE',request=candidate,
            request_digest=record_digest(candidate)),'host-signer')
        assert result.status==expected
    assert len(broker._entries)==2 and provider.dispatch_count==0


@pytest.mark.parametrize('kind',['tampered','noncanonical'])
def test_authenticated_packet_shape_and_integrity(launch,kind):
    h=launch()
    with socket.create_connection(h.address,timeout=2) as sock:
        hello=decode_canonical(_Hello,receive_frame(sock,monotonic()+2))
        body=canonical_bytes(IPCRequest(action='ISSUE',request=h.request,request_digest=record_digest(h.request)))
        raw=_packet('host-signer',body,h.secret,hello.nonce,b'REQUEST')
        if kind=='tampered':raw=raw.replace(b'host-signer',b'other-owner')
        else:raw=b' '+raw
        send_frame(sock,raw,monotonic()+2);sock.settimeout(2)
        assert sock.recv(1)==b''
    assert issue(h).status=='ISSUED'


def local_broker(harness):
    provider,request,kwargs,clock,*_=harness
    inputs={k:v for k,v in kwargs.items() if k!='signer_id'}
    return CustodyIPCBroker(provider,credentials={'host-signer':secrets.token_bytes(32)},
        custody_inputs=inputs,authorization=lambda p,a:True,epoch_clock=lambda:clock[1])


def test_policy_provider_failure_denies_and_burns_owned_token(harness):
    broker=local_broker(harness);request=harness[1];digest=record_digest(request)
    token=broker._execute(IPCRequest(action='ISSUE',request=request,request_digest=digest),'host-signer').token
    def unavailable(*args):raise RuntimeError('private provider diagnostic')
    broker.authorization=unavailable
    command=IPCRequest(action='SIGN',token=token,request_digest=digest)
    assert broker._execute(command,'host-signer').status=='ACCESS_DENIED'
    broker.authorization=lambda p,a:True
    assert broker._execute(command,'host-signer').status=='TOKEN_ALREADY_CONSUMED'
    assert harness[0].dispatch_count==0


def test_expired_connection_cannot_issue_token(harness):
    broker=local_broker(harness);request=harness[1]
    result=broker._execute(IPCRequest(action='ISSUE',request=request,request_digest=record_digest(request)),
        'host-signer',connection_deadline=monotonic()-1)
    assert result.status=='DEADLINE_EXCEEDED' and not broker._entries


def test_connection_budget_intersects_issued_lease(harness):
    broker=local_broker(harness);request=harness[1];deadline=monotonic()+.5
    token=broker._execute(IPCRequest(action='ISSUE',request=request,request_digest=record_digest(request)),
        'host-signer',connection_deadline=deadline).token
    assert broker._entries[token]['deadline']==deadline


def test_expired_sign_connection_burns_token_without_dispatch(harness):
    broker=local_broker(harness);request=harness[1];digest=record_digest(request)
    token=broker._execute(IPCRequest(action='ISSUE',request=request,request_digest=digest),'host-signer').token
    command=IPCRequest(action='SIGN',token=token,request_digest=digest)
    assert broker._execute(command,'host-signer',connection_deadline=monotonic()-1).status=='DEADLINE_EXCEEDED'
    assert broker._execute(command,'host-signer').status=='TOKEN_ALREADY_CONSUMED'
    assert harness[0].dispatch_count==0
