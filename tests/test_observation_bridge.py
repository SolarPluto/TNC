"""Real mTLS -> transient handoff -> separate read-only temporary authority."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
import copy
import json
import pickle
import socket
import sqlite3

import pytest
from test_mtls import pki, Reader, server, client
from test_reconciliation_durable_writer import (
    case, inventory, config, update, signed, host, stored, reconciliation,
    sim, db, writer, NOW, submit, policy,
)
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.observation_request_binding import ObservationGrant, ObservationPolicy, ObservationHostContext
from tnc.provenance.observation_request_transport import ObservationRequestTransport
from tnc.provenance.observation_handoff import ObservationHandoff
from tnc.provenance.observation_bridge import TestObservationBridge
from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore
from tnc.provenance.reconciliation_verifier import ObservationRequest
import tnc.provenance.observation_handoff as handoff_module
import tnc.provenance.observation_request_transport as transport_module


@pytest.fixture
def bridge_case(pki, db, sim):
    # The authority fixtures use fixed time; the actual TLS handshake uses system time.
    pki.client=pki.issue('bridge-client',start=min(NOW,pki.now)-timedelta(days=2),
        end=max(NOW,pki.now)+timedelta(days=2))
    registry=Reader(pki)
    principal=sim[2].principal_id
    credential=registry.state.credentials[0].model_copy(update={'principal_id':principal,
        'valid_from':NOW-timedelta(days=2),'valid_until':NOW+timedelta(days=2)})
    registry.state=registry.state.model_copy(update={'credentials':(credential,)})
    env=sim[4]
    grant=ObservationGrant(grant_id='observe',principal_id=principal,deployment_id=env.deployment_id,
        store_instance_id=env.store_instance_id,valid_from=NOW,valid_until=NOW+timedelta(seconds=60))
    grants=ObservationPolicy(revision=1,grants=(grant,),valid_from=grant.valid_from,valid_until=grant.valid_until)
    context=ObservationHostContext(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id,
        issuer_id='observer',registry_revision=1,policy_revision=1,policy_digest=record_digest(grants),
        valid_from=grant.valid_from,valid_until=grant.valid_until)
    request=ObservationRequest(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id,
        issuer_id='observer',principal_id=principal,challenge='c'*64,timestamp=int(NOW.timestamp()),expiry=int(NOW.timestamp())+60)
    s=SimpleNamespace(pki=pki,registry=registry,policy=grants,context=context,request=request,now=NOW)
    s.transport=ObservationRequestTransport(policy_reader=lambda:s.policy,context_reader=lambda:s.context,clock=lambda:s.now)
    s.reader=ReadOnlyAuthorityAdapter(db.path,trusted_initial_envelope=env)
    s.bridge=TestObservationBridge(s.transport,s.reader)
    return s


def exchange(s, action):
    host=server(s.pki,s.registry,clock=lambda:s.now)
    def serve(listener):
        raw,_=listener.accept()
        with host.accept(raw) as conn:
            return action(conn)
    raw_request=canonical_bytes(s.request)
    with socket.socket() as listener,ThreadPoolExecutor(max_workers=1) as pool:
        listener.settimeout(5);listener.bind(('127.0.0.1',0));listener.listen(1)
        pending=pool.submit(serve,listener)
        with socket.create_connection(listener.getsockname(),timeout=5) as raw:
            with client(s.pki).wrap_socket(raw,server_hostname='localhost') as conn:
                try:
                    conn.sendall(len(raw_request).to_bytes(4,'big')+raw_request)
                    conn.recv(1)
                except OSError:pass
        return pending.result(timeout=7)


def observe(s, conn):return s.bridge.observe(conn,s.transport.receive_handoff(conn))


def test_real_round_trip(bridge_case,sim):
    s=bridge_case; result=exchange(s,lambda c:observe(s,c))
    assert result.status=='CANDIDATE'
    p=result.candidate
    assert p.unsigned and p.source=='SYNTHETIC_TEST_AUTHORITY'
    assert p.request==s.request and p.request_digest==record_digest(s.request)
    assert p.envelope==sim[4] and p.policy_digest==record_digest(sim[0].policy)
    assert p.binding.credential_id==s.registry.state.credentials[0].credential_id


def test_single_use_and_no_second_read(bridge_case,monkeypatch):
    s=bridge_case; reads=[]; original=s.reader.observe_current_snapshot
    def read(*a,**kw):reads.append(1);return original(*a,**kw)
    monkeypatch.setattr(s.reader,'observe_current_snapshot',read)
    def action(conn):
        token=s.transport.receive_handoff(conn)
        return s.bridge.observe(conn,token),s.bridge.observe(conn,token)
    first,second=exchange(s,action)
    assert (first.status,second.status)==('CANDIDATE','DENIED') and len(reads)==1


def test_audit_record_is_not_handoff(bridge_case,monkeypatch):
    s=bridge_case
    monkeypatch.setattr(s.reader,'observe_current_snapshot',lambda *a,**k:pytest.fail('Unexpected read'))
    result=exchange(s,lambda c:s.bridge.observe(c,s.transport.bind(c).binding))
    assert result.status=='DENIED'


@pytest.mark.parametrize('kind',['revoke','grant','expiry','rollback','registry'])
def test_pre_read_change_blocks_storage(bridge_case,monkeypatch,kind):
    s=bridge_case
    def action(conn):
        token=s.transport.receive_handoff(conn)
        if kind=='revoke':s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
        if kind=='registry':s.registry.state=s.registry.state.model_copy(update={'revision':2})
        if kind=='grant':
            s.policy=s.policy.model_copy(update={'grants':()})
            s.context=s.context.model_copy(update={'policy_digest':record_digest(s.policy)})
        if kind=='expiry':s.now+=timedelta(seconds=60)
        if kind=='rollback':s.now-=timedelta(seconds=1)
        with monkeypatch.context() as patch:
            patch.setattr(sqlite3,'connect',lambda *a,**k:pytest.fail('Unauthorized SQLite read'))
            return s.bridge.observe(conn,token)
    assert exchange(s,action).status=='DENIED'


@pytest.mark.parametrize('kind',['thread','owner','connection','expired','process'])
def test_handoff_confinement(bridge_case,monkeypatch,kind):
    s=bridge_case
    monkeypatch.setattr(s.reader,'observe_current_snapshot',lambda *a,**k:pytest.fail('Detached read'))
    def action(conn):
        token=s.transport.receive_handoff(conn)
        if kind=='thread':
            with ThreadPoolExecutor(max_workers=1) as pool:return pool.submit(s.bridge.observe,conn,token).result(timeout=5)
        if kind=='owner':
            other=ObservationRequestTransport(policy_reader=lambda:s.policy,context_reader=lambda:s.context,clock=lambda:s.now)
            return TestObservationBridge(other,s.reader).observe(conn,token)
        if kind=='connection':
            # An actual different accepted TLS connection cannot consume the first token.
            return exchange(s,lambda other:s.bridge.observe(other,token))
        if kind=='expired':monkeypatch.setattr(handoff_module,'monotonic',lambda:token._deadline)
        if kind=='process':monkeypatch.setattr(handoff_module.os,'getpid',lambda:token._pid+1)
        return s.bridge.observe(conn,token)
    assert exchange(s,action).status=='DENIED'


@pytest.mark.parametrize('kind',['pickle','copy','deepcopy','json','mutate'])
def test_handoff_not_exportable(bridge_case,kind):
    s=bridge_case
    def action(conn):
        token=s.transport.receive_handoff(conn)
        with pytest.raises(TypeError):
            if kind=='pickle':pickle.dumps(token)
            elif kind=='copy':copy.copy(token)
            elif kind=='deepcopy':copy.deepcopy(token)
            elif kind=='json':json.dumps(token)
            else:token._raw=b'forged'
        return s.bridge.observe(conn,token)
    assert exchange(s,action).status=='CANDIDATE'


def test_direct_handoff_construction_rejected():
    with pytest.raises(TypeError):ObservationHandoff(object(),None,None,None,None,None)


def test_atomic_policy_snapshot(bridge_case,writer,sim,monkeypatch):
    s=bridge_case; old=writer.load(now=NOW).policy
    original=TestCheckpointAuthorityStore._load; changed=[]
    def load(store,connection,*,now):
        state=original(store,connection,now=now)
        if not changed:
            changed.append(1)
            policy(writer,sim,old.model_copy(update={'revision':2}))
        return state
    with monkeypatch.context() as patch:
        patch.setattr(TestCheckpointAuthorityStore,'_load',load)
        result=exchange(s,lambda c:observe(s,c))
    assert result.status=='CANDIDATE' and result.candidate.policy_revision==1
    assert result.candidate.policy_digest==record_digest(old)
    later=exchange(s,lambda c:observe(s,c))
    assert later.candidate.policy_revision==2 and later.candidate.envelope==result.candidate.envelope


def test_host_revocation_during_read_suppresses_candidate(bridge_case,monkeypatch):
    s=bridge_case; original=s.reader.observe_current_snapshot
    def read(*a,**kw):
        result=original(*a,**kw)
        s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
        return result
    monkeypatch.setattr(s.reader,'observe_current_snapshot',read)
    result=exchange(s,lambda c:observe(s,c))
    assert result.status=='DENIED' and result.candidate is None


def test_authority_permission_independently_required(bridge_case,writer,sim):
    s=bridge_case;policy(writer,sim)
    assert exchange(s,lambda c:observe(s,c)).status=='DENIED'


def test_no_database_mutation(bridge_case,db):
    s=bridge_case
    with sqlite3.connect(db.path) as c:before=list(c.iterdump())
    assert exchange(s,lambda c:observe(s,c)).status=='CANDIDATE'
    with sqlite3.connect(db.path) as c:assert list(c.iterdump())==before


def test_failed_read_consumes_handoff(bridge_case,monkeypatch):
    s=bridge_case; reads=[]
    def fail(*a,**kw):reads.append(1);raise OSError('private database path')
    monkeypatch.setattr(s.reader,'observe_current_snapshot',fail)
    def action(conn):
        token=s.transport.receive_handoff(conn)
        return s.bridge.observe(conn,token),s.bridge.observe(conn,token)
    results=exchange(s,action)
    assert all(r.status=='DENIED' and r.candidate is None for r in results) and len(reads)==1
    assert b'private' not in canonical_bytes(results[0])


def test_closed_connection_blocks_read(bridge_case,monkeypatch):
    s=bridge_case
    monkeypatch.setattr(s.reader,'observe_current_snapshot',lambda *a,**k:pytest.fail('Closed connection read'))
    def action(conn):
        token=s.transport.receive_handoff(conn);conn.close()
        return s.bridge.observe(conn,token)
    assert exchange(s,action).status=='DENIED'


def test_late_snapshot_never_returns_candidate(bridge_case,monkeypatch):
    s=bridge_case; original=s.reader.observe_current_snapshot
    def action(conn):
        token=s.transport.receive_handoff(conn)
        def read(*a,**kw):
            snapshot=original(*a,**kw)
            monkeypatch.setattr(transport_module,'monotonic',lambda:token._deadline)
            return snapshot
        monkeypatch.setattr(s.reader,'observe_current_snapshot',read)
        return s.bridge.observe(conn,token)
    assert exchange(s,action).status=='DENIED'


def test_revalidation_cannot_extend_original_interval(bridge_case):
    s=bridge_case
    state=s.registry.state
    short=state.credentials[0].model_copy(update={'valid_until':NOW+timedelta(seconds=10)})
    s.registry.state=state.model_copy(update={'credentials':(short,)})
    def action(conn):
        token=s.transport.receive_handoff(conn)
        # Even an inconsistent host provider retaining its revision cannot extend the lease.
        s.registry.state=state
        return s.bridge.observe(conn,token)
    result=exchange(s,action)
    assert result.status=='CANDIDATE' and result.candidate.valid_until==NOW+timedelta(seconds=10)


def test_revocation_inside_pre_read_provider_blocks_sqlite(bridge_case,monkeypatch):
    s=bridge_case
    def action(conn):
        token=s.transport.receive_handoff(conn)
        def revoke():
            s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
            return s.policy
        s.transport._policy_reader=revoke
        with monkeypatch.context() as patch:
            patch.setattr(sqlite3,'connect',lambda *a,**k:pytest.fail('Read after revocation'))
            return s.bridge.observe(conn,token)
    assert exchange(s,action).status=='DENIED'
