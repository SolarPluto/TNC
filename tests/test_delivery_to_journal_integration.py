"""Real loopback delivery to three separate temporary stores; no retention files."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
import multiprocessing
import os
import socket
import sqlite3
from time import monotonic
import pytest

from test_response_delivery_harness import (
    pki,case,inventory,config,update,signed,host,stored,reconciliation,sim,db,writer,
    NOW,bridge_case,signing,harness,submit,prepare,sign,
)
from test_mtls import server, client
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.client_request_journal_logic import ClientJournalIntent
from tnc.provenance.client_request_journal_store import TestClientRequestJournalStore,ClientJournalStoreError
from tnc.provenance.client_high_water_store import TestClientHighWaterStore,ClientStoreError
from tnc.provenance.delivery_journal_integration import TestDeliveryJournalIntegration,DeliveryJournalIntegrationError
from tnc.provenance.observation_response_delivery import send_signed_response,encode_signed_response,ResponseDeliveryError
from tnc.provenance.mtls import create_mtls_client_context


def make_intent(h,operation='delivery-journal-1'):
    s=h.upstream
    return ClientJournalIntent(operation_id=operation,client_anchor_digest=record_digest(h.anchor),
        principal_id=h.anchor.principal_id,request=s.request,trust_store=s.trust,trusted_checkpoint=s.checkpoint,
        created_at=h.client.clock(),expires_at=min(s.request.expiry,s.trust.expiry,s.checkpoint.expiry))


@pytest.fixture
def flow(harness,tmp_path):
    h=harness
    h.journal=TestClientRequestJournalStore.create_for_testing(tmp_path/'client_request_journal.db',
        trusted_client_anchor=h.anchor,now=h.t)
    h.journal.clock=lambda:h.client.clock();h.journal.high_water_store=h.client
    h.flow=TestDeliveryJournalIntegration(h.journal)
    h.intent=make_intent(h)
    return h


def kw(h): return dict(caller_principal=h.anchor.principal_id)
def register(h,intent=None): return h.flow.register_intent(intent or h.intent,**kw(h))
def recover(h,op=None): return h.flow.recover(op or h.intent.operation_id,**kw(h))
def apply(h,op=None): return h.flow.apply_retained(op or h.intent.operation_id,**kw(h))
def entry(h,op=None):
    return next(e for e in h.journal.load(now=h.client.clock(),**kw(h)).entries if e.intent.operation_id==(op or h.intent.operation_id))
def high_state(h): return h.client.load(now=h.client.clock())
def dump(path):
    with closing(sqlite3.connect(path)) as c:return tuple(c.iterdump())


def serve(h,listener,mode='normal'):
    s=h.upstream;raw,_=listener.accept()
    with server(s.pki,s.registry,clock=lambda:s.now).accept(raw) as conn:
        response=sign(s,conn,prepare(s,conn))
        if mode=='drop': return response
        if mode=='bad-signature':response=response.model_copy(update={'signature_hex':'0'*128})
        if mode=='short':conn.sendall(encode_signed_response(response)[:-10])
        elif mode=='oversize':conn.sendall((32769).to_bytes(4,'big'))
        else:send_signed_response(conn,response,deadline=monotonic()+5)
        return response


def deliver(h,mode='normal',operation=None):
    op=operation or h.intent.operation_id
    # No socket is created before validated registration lookup.
    framed=h.flow.request_frame(op,**kw(h))
    with socket.socket() as listener,ThreadPoolExecutor(max_workers=1) as pool:
        listener.settimeout(8);listener.bind(('127.0.0.1',0));listener.listen(1)
        future=pool.submit(serve,h,listener,mode)
        context=client(h.upstream.pki)
        result,error=None,None
        with socket.create_connection(listener.getsockname(),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname='localhost') as conn:
                conn.sendall(framed)
                try:result=h.flow.receive_and_retain(op,conn,trusted_context=context,deadline=monotonic()+5,**kw(h))
                except (ResponseDeliveryError,ClientJournalStoreError) as exc:error=exc
        return result,error,future.result(timeout=10)


def offline(h,monkeypatch,*,journal_only=False):
    from tnc.provenance.observation_signer_adapter import TestObservationSignerAdapter
    from tnc.provenance.observation_bridge import TestObservationBridge
    from tnc.provenance.observation_request_transport import ObservationRequestTransport
    from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter
    h.upstream.signer.close()
    def fail(*a,**kw):pytest.fail('Offline recovery touched upstream')
    for obj,name in ((TestObservationSignerAdapter,'sign'),(TestObservationBridge,'prepare_signing'),
                     (ObservationRequestTransport,'receive_handoff'),(ReadOnlyAuthorityAdapter,'observe_current_snapshot'),
                     (h.upstream.registry,'read'),(socket,'create_connection')):
        monkeypatch.setattr(obj,name,fail)
    original=sqlite3.connect
    paths=[h.journal.path] if journal_only else [h.journal.path,h.client.path]
    allowed={':memory:'}
    for p in paths:allowed.update((str(p),p.as_uri()+'?mode=rw',p.as_uri()+'?mode=ro'))
    def connect(path,*a,**kw):
        if str(path) not in allowed:pytest.fail('Unexpected database during offline recovery')
        return original(path,*a,**kw)
    monkeypatch.setattr(sqlite3,'connect',connect)


def reopen(h,now,*,without_high_water=False):
    h.client=TestClientHighWaterStore(h.client.path,trusted_initial_anchor=h.anchor,clock=lambda:now)
    h.journal=TestClientRequestJournalStore(h.journal.path,trusted_client_anchor=h.anchor,
        high_water_store=None if without_high_water else h.client,clock=lambda:now)
    h.flow=TestDeliveryJournalIntegration(h.journal)


def test_full_loopback_lifecycle_preserves_exact_bytes(flow):
    h=flow;submit(h.writer,h.sim);authority=dump(h.authority.path)
    assert register(h).status=='REGISTERED'
    assert h.flow.request_frame(h.intent.operation_id,**kw(h))[4:]==canonical_bytes(h.intent.request)
    result,error,response=deliver(h)
    assert error is None and result.status=='RETAINED'
    assert entry(h).retained_response.response_canonical_json.encode()==canonical_bytes(response)
    assert high_state(h).local_sequence==0
    assert recover(h).status=='READY_TO_APPLY'
    result=apply(h)
    assert result.status=='VALID_ADVANCE' and entry(h).state=='RETAINED_RESPONSE'
    assert high_state(h).authority_revision==2
    assert recover(h).receipt_bytes==result.receipt_bytes
    assert entry(h).state=='COMMITTED_RECEIPT' and dump(h.authority.path)==authority


def test_request_cannot_dispatch_before_registration(flow,monkeypatch):
    def fail(*a,**kw):pytest.fail('Premature network access')
    monkeypatch.setattr(socket,'socket',fail)
    with pytest.raises(DeliveryJournalIntegrationError,match='Access denied'):deliver(flow)


@pytest.mark.parametrize('mode',['drop','short','oversize'])
def test_delivery_failure_leaves_awaiting(flow,mode):
    h=flow;register(h);before=dump(h.journal.path);high_before=dump(h.client.path)
    result,error,_=deliver(h,mode)
    assert result is None and isinstance(error,ResponseDeliveryError)
    assert dump(h.journal.path)==before and dump(h.client.path)==high_before


def test_complete_but_forged_response_not_retained(flow):
    h=flow;register(h);before=dump(h.journal.path)
    result,error,_=deliver(h,'bad-signature')
    assert error is None and result.reason_code=='VERIFICATION_FAILED'
    assert dump(h.journal.path)==before and high_state(h).local_sequence==0


def test_retained_state_refuses_network_redispatch(flow,monkeypatch):
    h=flow;register(h);deliver(h)
    def fail(*a,**kw):pytest.fail('Retained response triggered dispatch')
    monkeypatch.setattr(socket,'socket',fail)
    with pytest.raises(DeliveryJournalIntegrationError,match='Use local recovery'):deliver(h)


def test_response_lost_before_retention_is_not_fabricated(flow):
    h=flow;register(h)
    def hook(where):
        if where=='response_inserted':raise RuntimeError('retention interrupted')
    h.journal._hook=hook
    result,error,_=deliver(h)
    assert result is None and isinstance(error,ClientJournalStoreError)
    assert entry(h).state=='AWAITING_RESPONSE' and high_state(h).local_sequence==0


def test_expired_retained_response_requires_new_intent(flow):
    h=flow;register(h);_,_,old=deliver(h)
    old_entry=entry(h);now=old.payload.expiry
    h.client.clock=lambda:now
    assert recover(h).reason_code=='RESPONSE_EXPIRED'
    assert apply(h).reason_code=='RESPONSE_EXPIRED' and high_state(h).local_sequence==0
    assert entry(h)==old_entry
    h.upstream.now=NOW+timedelta(seconds=now-h.t)
    h.upstream.request=h.upstream.request.model_copy(update={'timestamp':now,'challenge':'d'*64})
    fresh=make_intent(h,'fresh-attempt')
    assert register(h,fresh).status=='REGISTERED'
    result,error,new=deliver(h,operation=fresh.operation_id)
    assert error is None and result.status=='RETAINED'
    assert new.payload.request_digest!=old.payload.request_digest
    assert apply(h,fresh.operation_id).status=='UNCHANGED'
    assert recover(h,fresh.operation_id).status=='COMMITTED'
    assert entry(h)==old_entry


def test_terminal_exact_retry_needs_only_journal(flow,monkeypatch):
    h=flow;register(h);deliver(h);saved=apply(h).receipt_bytes
    assert recover(h).receipt_bytes==saved
    reopen(h,h.t+1000,without_high_water=True);before=dump(h.journal.path)
    offline(h,monkeypatch,journal_only=True)
    assert recover(h).status=='RECOVERED' and apply(h).receipt_bytes==saved
    assert dump(h.journal.path)==before


def test_gap_recovery_does_not_reapply_or_sign(flow,monkeypatch):
    h=flow;register(h);deliver(h);saved=apply(h).receipt_bytes
    reopen(h,h.t+1000);offline(h,monkeypatch)
    def fail(*a,**kw):pytest.fail('Committed high-water request reapplied')
    monkeypatch.setattr(h.client,'apply',fail)
    assert apply(h).status=='COMMITTED' and recover(h).receipt_bytes==saved


def test_invalid_high_water_evidence_stops_application(flow,monkeypatch):
    h=flow;register(h);deliver(h)
    with closing(sqlite3.connect(h.client.path)) as c:c.execute('PRAGMA user_version=99')
    def fail(*a,**kw):pytest.fail('Applied with unavailable evidence')
    monkeypatch.setattr(h.client,'apply',fail)
    before=dump(h.journal.path)
    assert apply(h).status=='INDETERMINATE' and dump(h.journal.path)==before


def test_wrong_principal_cannot_frame_or_recover(flow,monkeypatch):
    h=flow;register(h)
    def fail(*a,**kw):pytest.fail('Opened storage before principal check')
    monkeypatch.setattr(sqlite3,'connect',fail)
    with pytest.raises(ClientJournalStoreError,match='ACCESS_DENIED'):
        h.flow.request_frame(h.intent.operation_id,caller_principal='other')
    with pytest.raises(ClientJournalStoreError,match='ACCESS_DENIED'):
        h.flow.apply_retained(h.intent.operation_id,caller_principal='other')


def child(journal_path,high_path,anchor,intent,now,stage,address=None,certificates=None):
    # No signer or authority state is transferred into the client process.
    high=TestClientHighWaterStore(high_path,trusted_initial_anchor=anchor,clock=lambda:now)
    j=TestClientRequestJournalStore(journal_path,trusted_client_anchor=anchor,high_water_store=high,clock=lambda:now)
    f=TestDeliveryJournalIntegration(j);kw=dict(caller_principal=anchor.principal_id)
    assert f.register_intent(intent,**kw).status=='REGISTERED'
    if stage=='A':os._exit(81)
    if stage=='BEFORE_RETENTION_COMMIT':
        def hook(point):
            if point=='before_commit':os._exit(81)
        j._hook=hook
    if stage=='AFTER_RECEIVE':
        import tnc.provenance.delivery_journal_integration as integration
        original=integration.receive_signed_response
        def received(*a,**kw):
            original(*a,**kw);os._exit(81)
        integration.receive_signed_response=received
    cert,key,ca=certificates
    context=create_mtls_client_context(certificate=cert,private_key=key,trusted_ca=ca)
    with socket.create_connection(address,timeout=5) as raw:
        with context.wrap_socket(raw,server_hostname='localhost') as conn:
            conn.sendall(f.request_frame(intent.operation_id,**kw))
            assert f.receive_and_retain(intent.operation_id,conn,trusted_context=context,deadline=monotonic()+5,**kw).status=='RETAINED'
    if stage=='B':os._exit(81)
    if stage=='BEFORE_HIGH_WATER_COMMIT':
        def hook(point):
            if point=='before_commit':os._exit(81)
        high._hook=hook
    assert f.apply_retained(intent.operation_id,**kw).status in ('UNCHANGED','VALID_ADVANCE')
    if stage=='C':os._exit(81)
    if stage=='BEFORE_JOURNAL_ACK_COMMIT':
        def hook(point):
            if point=='before_commit':os._exit(81)
        j._hook=hook
    assert f.recover(intent.operation_id,**kw).status=='COMMITTED'
    if stage=='D':os._exit(81)
    raise AssertionError('Unexpected crash stage')


def crash(h,stage):
    ctx=multiprocessing.get_context('spawn');p=None
    base=(str(h.journal.path),str(h.client.path),h.anchor,h.intent,h.t,stage)
    try:
        if stage=='A':
            p=ctx.Process(target=child,args=base);p.start();p.join(25)
        else:
            with socket.socket() as listener,ThreadPoolExecutor(max_workers=1) as pool:
                listener.settimeout(10);listener.bind(('127.0.0.1',0));listener.listen(1)
                future=pool.submit(serve,h,listener)
                s=h.upstream;certs=tuple(str(x) for x in (s.pki.client[2],s.pki.client[3],s.pki.ca[2]))
                p=ctx.Process(target=child,args=base+(listener.getsockname(),certs));p.start()
                future.result(timeout=15);p.join(25)
        assert p.exitcode==81
    finally:
        if p is not None:
            p.join(2)
            if p.is_alive():p.terminate();p.join(5)


@pytest.mark.parametrize('stage,journal_state,high_sequence',[
    ('A','AWAITING_RESPONSE',0),('AFTER_RECEIVE','AWAITING_RESPONSE',0),
    ('BEFORE_RETENTION_COMMIT','AWAITING_RESPONSE',0),('B','RETAINED_RESPONSE',0),
    ('BEFORE_HIGH_WATER_COMMIT','RETAINED_RESPONSE',0),('C','RETAINED_RESPONSE',1),
    ('BEFORE_JOURNAL_ACK_COMMIT','RETAINED_RESPONSE',1),('D','COMMITTED_RECEIPT',1),
])
def test_real_client_process_exit_matrix(flow,monkeypatch,stage,journal_state,high_sequence):
    h=flow;submit(h.writer,h.sim);authority=dump(h.authority.path)
    crash(h,stage)
    assert entry(h).state==journal_state and high_state(h).local_sequence==high_sequence
    assert dump(h.authority.path)==authority
    saved=canonical_bytes(high_state(h).history[0].receipt) if high_sequence else None
    reopen(h,h.t+1000 if high_sequence else h.t,without_high_water=journal_state=='COMMITTED_RECEIPT')
    offline(h,monkeypatch,journal_only=journal_state=='COMMITTED_RECEIPT')
    if journal_state=='AWAITING_RESPONSE':assert recover(h).status=='AWAITING_RESPONSE'
    elif high_sequence:
        assert recover(h).receipt_bytes==saved
        assert entry(h).state=='COMMITTED_RECEIPT'
    else:
        assert recover(h).status=='READY_TO_APPLY'
        receipt=apply(h).receipt_bytes
        assert recover(h).receipt_bytes==receipt


def test_process_exit_after_retention_then_expiry_preserves_evidence(flow,monkeypatch):
    h=flow;crash(h,'B');before=dump(h.journal.path)
    reopen(h,h.t+1000);offline(h,monkeypatch)
    assert recover(h).reason_code=='RESPONSE_EXPIRED'
    assert apply(h).reason_code=='RESPONSE_EXPIRED'
    assert dump(h.journal.path)==before and high_state(h).local_sequence==0


def test_lost_journal_completion_ack_is_offline(flow,monkeypatch):
    h=flow;register(h);deliver(h);saved=apply(h).receipt_bytes
    def hook(where):
        if where=='after_commit':raise RuntimeError('lost completion')
    h.journal._hook=hook
    with pytest.raises(ClientJournalStoreError,match='OUTCOME_UNKNOWN'):recover(h)
    reopen(h,h.t+1000,without_high_water=True);offline(h,monkeypatch,journal_only=True)
    assert recover(h).receipt_bytes==saved


def test_apply_rechecks_time_after_ready_proposal(flow):
    h=flow;register(h);_,_,response=deliver(h)
    def hook(where):
        if where=='locked':h.client.clock=lambda:response.payload.expiry
    h.client._hook=hook
    before=dump(h.journal.path)
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'):apply(h)
    assert high_state(h).local_sequence==0 and dump(h.journal.path)==before
