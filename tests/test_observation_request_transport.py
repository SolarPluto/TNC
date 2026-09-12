"""Real loopback TLS with temporary certificates; no signing or database setup."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
from types import SimpleNamespace
import socket
import pytest

from test_mtls import pki, Reader, server, client
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.reconciliation_verifier import ObservationRequest
from tnc.provenance.observation_request_binding import ObservationGrant, ObservationPolicy, ObservationHostContext
from tnc.provenance.observation_request_transport import ObservationRequestTransport
import tnc.provenance.observation_request_transport as transport
import tnc.provenance.mtls as mtls


@pytest.fixture
def setup(pki):
    now=pki.now
    grant=ObservationGrant(grant_id='observe',principal_id='alice',deployment_id='d',store_instance_id='s',
        valid_from=now-timedelta(seconds=1),valid_until=now+timedelta(seconds=60))
    policy=ObservationPolicy(revision=1,grants=(grant,),valid_from=grant.valid_from,valid_until=grant.valid_until)
    context=ObservationHostContext(deployment_id='d',store_instance_id='s',issuer_id='issuer',registry_revision=1,
        policy_revision=1,policy_digest=record_digest(policy),valid_from=grant.valid_from,valid_until=grant.valid_until)
    request=ObservationRequest(deployment_id='d',store_instance_id='s',issuer_id='issuer',principal_id='alice',
        challenge='a'*64,timestamp=int(now.timestamp()),expiry=int(now.timestamp())+60)
    s=SimpleNamespace(pki=pki,registry=Reader(pki),policy=policy,context=context,request=request)
    s.adapter=ObservationRequestTransport(policy_reader=lambda:s.policy,context_reader=lambda:s.context,clock=lambda:now)
    return s


def frame(data):return len(data).to_bytes(4,'big')+data


def exchange(s, wire=None, *, callback=None, rounds=1, fragment=False, end_stream=False):
    """The worker owns the accepted connection; no sleeps or background services."""
    wire=frame(canonical_bytes(s.request)) if wire is None else wire
    host=server(s.pki,s.registry,clock=lambda:s.pki.now)
    def serve(listener):
        raw,_=listener.accept()
        with host.accept(raw) as conn:
            if callback:callback(conn)
            results=[]
            for _ in range(rounds):
                result=s.adapter.bind(conn);results.append(result)
                if result.status!='BOUND':break
                conn.sendall(b'k')
            return results
    with socket.socket() as listener,ThreadPoolExecutor(max_workers=1) as pool:
        listener.settimeout(5);listener.bind(('127.0.0.1',0));listener.listen(1)
        future=pool.submit(serve,listener)
        with socket.create_connection(listener.getsockname(),timeout=5) as raw:
            with client(s.pki).wrap_socket(raw,server_hostname='localhost') as conn:
                try:
                    if fragment:
                        for byte in wire:conn.sendall(bytes((byte,)))
                    else:conn.sendall(wire)
                    if end_stream:conn.shutdown(socket.SHUT_WR)
                    for _ in range(rounds):
                        if conn.recv(1)!=b'k':break
                except OSError:pass
        return future.result(timeout=7)


def test_real_binding(setup):
    result=exchange(setup)[0]
    assert result.status=='BOUND' and result.binding.audit_only
    assert result.binding.principal_id=='alice'
    assert result.binding.credential_id==setup.registry.state.credentials[0].credential_id
    assert result.binding.request_digest==sha256(canonical_bytes(setup.request)).hexdigest()


def test_fragmented_header_and_payload(setup):
    assert exchange(setup,fragment=True)[0].status=='BOUND'


def test_same_connection_two_frames(setup):
    results=exchange(setup,frame(canonical_bytes(setup.request))*2,rounds=2)
    assert all(r.status=='BOUND' for r in results)
    assert results[0].binding.connection_id==results[1].binding.connection_id
    assert results[0].binding.identity_audit_id!=results[1].binding.identity_audit_id


@pytest.mark.parametrize('field,value',[('principal_id','mallory'),('store_instance_id','other'),('issuer_id','other')])
def test_spoofed_claim(setup,field,value):
    setup.request=setup.request.model_copy(update={field:value})
    result=exchange(setup)[0]
    assert result.status=='DENIED' and result.binding is None and result.reason_code=='ACCESS_DENIED'


@pytest.mark.parametrize('wire',[b'\0\0\0\0',(16385).to_bytes(4,'big'),b'\0\0',b'\0\0\0\5xy',frame(b'{}'),frame(b' ' + b'{}')],
    ids=['zero','oversize','short-header','short-body','bad-shape','noncanonical'])
def test_bad_frames(setup,wire):
    assert exchange(setup,wire,end_stream=True)[0].status=='DENIED'


def test_missing_grant(setup):
    setup.policy=setup.policy.model_copy(update={'grants':()})
    setup.context=setup.context.model_copy(update={'policy_digest':record_digest(setup.policy)})
    assert exchange(setup)[0].status=='DENIED'


@pytest.mark.parametrize('kind',['disabled','unknown','revision'])
def test_enrollment_changed_after_handshake(setup,kind):
    def change(conn):
        state=setup.registry.state
        values={'revision':2}
        if kind=='disabled':values['credentials']=(state.credentials[0].model_copy(update={'enabled':False}),)
        if kind=='unknown':values['credentials']=()
        setup.registry.state=state.model_copy(update=values)
    assert exchange(setup,callback=change)[0].status=='DENIED'


def test_policy_change_on_final_read(setup):
    calls=[]
    def policy():
        calls.append(1)
        return setup.policy if len(calls)==1 else setup.policy.model_copy(update={'grants':()})
    setup.adapter._policy_reader=policy
    assert exchange(setup)[0].status=='DENIED' and len(calls)==2


def test_revocation_during_policy_read(setup):
    def policy():
        state=setup.registry.state
        setup.registry.state=state.model_copy(update={'revision':2,'credentials':()})
        return setup.policy
    setup.adapter._policy_reader=policy
    assert exchange(setup)[0].status=='DENIED'


def test_total_deadline_after_provider(setup,monkeypatch):
    ticks=[0.0]
    monkeypatch.setattr(transport,'monotonic',lambda:ticks[0])
    monkeypatch.setattr(mtls,'monotonic',lambda:ticks[0])
    def policy():ticks[0]=10.0;return setup.policy
    setup.adapter._policy_reader=policy
    assert exchange(setup)[0].status=='DENIED'


def test_deadline_during_fragment_accumulation(setup,monkeypatch):
    ticks=[0.0]
    monkeypatch.setattr(transport,'monotonic',lambda:ticks[0])
    monkeypatch.setattr(mtls,'monotonic',lambda:ticks[0])
    original=mtls.MtlsConnection.recv_before
    def one_byte(conn,size,deadline):
        result=original(conn,1,deadline)
        ticks[0]+=3.0
        return result
    monkeypatch.setattr(mtls.MtlsConnection,'recv_before',one_byte)
    assert exchange(setup)[0].status=='DENIED'


def test_real_socket_timeout_without_frame(setup):
    setup.adapter._timeout=0.05
    assert exchange(setup,b'')[0].status=='DENIED'


def test_socket_timeout_restored(setup):
    original=setup.adapter.bind
    def bind(conn):
        before=conn._socket.gettimeout()
        result=original(conn)
        assert conn._socket.gettimeout()==before
        return result
    setup.adapter.bind=bind
    assert exchange(setup)[0].status=='BOUND'


def test_unverified_object_rejected(setup):
    assert setup.adapter.bind(object()).status=='DENIED'


def test_provider_exception_is_sanitized(setup):
    def fail():raise OSError('private policy path and principal inventory')
    setup.adapter._policy_reader=fail
    result=exchange(setup)[0]
    assert result.reason_code=='ACCESS_DENIED' and result.binding is None
    assert 'private' not in canonical_bytes(result).decode()


@pytest.mark.parametrize('delta',[-1,60])
def test_final_wall_clock_rollback_or_expiry(setup,delta):
    calls=[]
    def clock():
        calls.append(1)
        return setup.pki.now if len(calls)<3 else setup.pki.now+timedelta(seconds=delta)
    setup.adapter._clock=clock
    assert exchange(setup)[0].status=='DENIED'


def test_default_real_wall_clock(setup):
    setup.adapter=ObservationRequestTransport(policy_reader=lambda:setup.policy,context_reader=lambda:setup.context)
    assert exchange(setup)[0].status=='BOUND'


def test_reused_connection_checks_new_policy(setup):
    bind=setup.adapter.bind
    def change_after_first(conn):
        result=bind(conn)
        setup.policy=setup.policy.model_copy(update={'grants':()})
        setup.context=setup.context.model_copy(update={'policy_digest':record_digest(setup.policy)})
        return result
    setup.adapter.bind=change_after_first
    results=exchange(setup,frame(canonical_bytes(setup.request))*2,rounds=2)
    assert [r.status for r in results]==['BOUND','DENIED']


@pytest.mark.parametrize('timeout',[0,-1,31,float('nan'),True])
def test_configuration_bounds(timeout):
    with pytest.raises(ValueError):ObservationRequestTransport(policy_reader=lambda:None,context_reader=lambda:None,timeout=timeout)
