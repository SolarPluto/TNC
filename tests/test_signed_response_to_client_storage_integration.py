"""Real upstream mTLS signing, separate client persistence, offline exact recovery."""
from contextlib import closing
import multiprocessing
import os
import sqlite3
from types import SimpleNamespace

import pytest
from test_observation_signer_adapter import (
    pki, case, inventory, config, update, signed, host, stored, reconciliation,
    sim, db, writer, NOW, bridge_case, signing, prepare, sign, verify, exchange,
)
from test_reconciliation_durable_writer import submit
from test_reconciliation_simulation import auth, next_command
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.client_high_water_logic import ClientAnchor, AdvancementRequest, decode_client_record
from tnc.provenance.client_high_water_store import TestClientHighWaterStore, ClientStoreError
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore
from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter
from tnc.provenance.reconciliation_simulation import _prefix
from tnc.provenance.reconciliation_verifier import verify_observation
from tnc.provenance.observation_signer_adapter import TestObservationSignerAdapter
from tnc.provenance.observation_bridge import TestObservationBridge
from tnc.provenance.observation_request_transport import ObservationRequestTransport


@pytest.fixture
def harness(signing,sim,db,writer,tmp_path):
    s=signing; env=sim[4]; t=int(NOW.timestamp())
    anchor=ClientAnchor(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id,
        principal_id=s.request.principal_id,authority_revision=env.authority_revision,
        envelope_digest=record_digest(env),accepted_timestamp=t)
    client_store=TestClientHighWaterStore.create_for_testing(tmp_path/'client_high_water.db',trusted_initial_anchor=anchor,now=t)
    client_store.clock=lambda:t
    return SimpleNamespace(upstream=s,sim=sim,authority=db,writer=writer,client=client_store,anchor=anchor,t=t)


def observation(h,operation_id='client-1'):
    s=h.upstream
    response=exchange(s,lambda conn:sign(s,conn,prepare(s,conn)))
    assert verify(s,response).status=='VERIFIED'
    return AdvancementRequest(operation_id=operation_id,response=response,retained_request=s.request,
        trust_store=s.trust,trusted_checkpoint=s.checkpoint)


def apply(h,request):return h.client.apply(request,caller_principal=h.anchor.principal_id)
def state(h):return h.client.load(now=h.client.clock())


def dump(path):
    with closing(sqlite3.connect(path)) as c:return tuple(c.iterdump())


def split_advance(h,partial):
    image=h.sim[1].candidate_image
    if partial:image=_prefix(image,len(image.events)-1)
    command=next_command(h.writer.load(now=NOW),image,'first-part' if partial else 'second-part')
    return h.writer.submit(command,caller=h.sim[2],batch_authorization=auth(command.request),now=NOW)


def forbid_upstream(h,monkeypatch):
    h.upstream.signer.close()
    def fail(*a,**kw):pytest.fail('Offline client recovery touched upstream')
    monkeypatch.setattr(TestObservationSignerAdapter,'sign',fail)
    monkeypatch.setattr(TestObservationBridge,'prepare_signing',fail)
    monkeypatch.setattr(ObservationRequestTransport,'receive_handoff',fail)
    monkeypatch.setattr(ReadOnlyAuthorityAdapter,'observe_current_snapshot',fail)
    monkeypatch.setattr(h.upstream.registry,'read',fail)
    original=sqlite3.connect
    def connect(path,*a,**kw):
        # Client schema checks use :memory:. No authority database is permitted.
        if str(path) not in (str(h.client.path),h.client.path.as_uri()+'?mode=rw',h.client.path.as_uri()+'?mode=ro',':memory:'):
            pytest.fail('Recovery opened a non-client database')
        return original(path,*a,**kw)
    monkeypatch.setattr(sqlite3,'connect',connect)


def test_valid_advancement_and_saved_receipt(harness):
    h=harness;submit(h.writer,h.sim);request=observation(h);before=dump(h.authority.path)
    result=apply(h,request);current=state(h)
    assert result.status=='VALID_ADVANCE' and current.authority_revision==2 and current.local_sequence==1
    assert current.envelope_digest==request.response.payload.envelope_digest
    assert result.receipt_bytes==canonical_bytes(current.history[0].receipt)
    with closing(sqlite3.connect(h.client.path)) as c:
        assert c.execute('SELECT canonical FROM client_receipts').fetchall()==[(result.receipt_bytes,)]
    assert dump(h.authority.path)==before


def test_expired_exact_retry_after_key_disposal_is_offline(harness,monkeypatch):
    h=harness;submit(h.writer,h.sim);request=observation(h);saved=apply(h,request).receipt_bytes
    retained=decode_client_record(AdvancementRequest,canonical_bytes(request))
    before=dump(h.client.path)
    h.client=TestClientHighWaterStore(h.client.path,trusted_initial_anchor=h.anchor,clock=lambda:h.t+1000)
    forbid_upstream(h,monkeypatch)
    result=apply(h,retained)
    assert result.status=='RECOVERED' and result.receipt_bytes==saved and dump(h.client.path)==before


def test_lost_acknowledgement_recovers_original_without_signing(harness,monkeypatch):
    h=harness;submit(h.writer,h.sim);request=observation(h)
    def hook(point):
        if point=='after_commit':raise RuntimeError('acknowledgement lost')
    h.client._hook=hook
    with pytest.raises(ClientStoreError,match='OUTCOME_UNKNOWN'):apply(h,request)
    saved=canonical_bytes(state(h).history[0].receipt); before=dump(h.client.path)
    h.client=TestClientHighWaterStore(h.client.path,trusted_initial_anchor=h.anchor,clock=lambda:h.t+1000)
    forbid_upstream(h,monkeypatch)
    result=apply(h,request)
    assert result.status=='RECOVERED' and result.receipt_bytes==saved and dump(h.client.path)==before


def test_old_receipt_retry_does_not_regress_later_head(harness,monkeypatch):
    h=harness;split_advance(h,True);first=observation(h);receipt=apply(h,first).receipt_bytes
    split_advance(h,False);second=observation(h,'client-2');assert apply(h,second).status=='VALID_ADVANCE'
    before=dump(h.client.path);h.client.clock=lambda:h.t+1000
    forbid_upstream(h,monkeypatch)
    assert apply(h,first).receipt_bytes==receipt and state(h).authority_revision==3
    assert dump(h.client.path)==before


@pytest.mark.parametrize('kind',['tampered','expired','trust','request'])
def test_invalid_response_never_changes_storage(harness,kind):
    h=harness;submit(h.writer,h.sim);request=observation(h)
    if kind=='tampered':request=request.model_copy(update={'response':request.response.model_copy(update={'signature_hex':'0'*128})})
    elif kind=='expired':h.client.clock=lambda:request.response.payload.expiry
    elif kind=='trust':request=request.model_copy(update={'trusted_checkpoint':request.trusted_checkpoint.model_copy(update={'trust_store_digest':'f'*64})})
    else:request=request.model_copy(update={'retained_request':request.retained_request.model_copy(update={'challenge':'e'*64})})
    before=(dump(h.client.path),dump(h.authority.path))
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'):apply(h,request)
    assert (dump(h.client.path),dump(h.authority.path))==before


def test_stale_signed_response_is_not_current_acceptance(harness):
    h=harness;old=observation(h,'old-uncommitted');submit(h.writer,h.sim);apply(h,observation(h))
    before=dump(h.client.path)
    assert apply(h,old).status=='STALE' and dump(h.client.path)==before


def test_skipped_signed_revision_is_rejected(harness):
    h=harness;split_advance(h,True);split_advance(h,False)
    request=observation(h);assert request.response.payload.authority_revision==3
    before=dump(h.client.path)
    assert apply(h,request).status=='PREDECESSOR_MISMATCH' and dump(h.client.path)==before


def test_fork_signed_through_alternate_authority_is_rejected(harness,tmp_path):
    h=harness;original=h.sim[0]
    fork_anchor=h.sim[4].model_copy(update={'key_id':'f'*64})
    fork_state=original.model_copy(update={'initial_envelope':fork_anchor,'current_envelope':fork_anchor})
    alternate=TestCheckpointAuthorityStore.create_for_testing(tmp_path/'alternate_authority.db',fork_state,
        trusted_initial_envelope=fork_anchor,now=NOW)
    # A separate, internally valid fixture authority asserts a different same-revision head.
    # No payload tampering or private-key bypass is used to obtain this signature.
    h.upstream.bridge._reader=ReadOnlyAuthorityAdapter(alternate.path,trusted_initial_envelope=fork_anchor)
    request=observation(h,'fork'); before=dump(h.client.path)
    assert request.response.payload.authority_revision==h.anchor.authority_revision
    assert apply(h,request).status=='CONFLICT_FORK' and dump(h.client.path)==before


def child(path,anchor_bytes,request_bytes,now,point):
    """Only public retained records cross the process boundary; no signer is created."""
    anchor=decode_client_record(ClientAnchor,anchor_bytes)
    request=decode_client_record(AdvancementRequest,request_bytes)
    def forbidden(*a,**kw):raise AssertionError('Upstream dependency in client process')
    TestObservationSignerAdapter.sign=forbidden
    TestObservationBridge.prepare_signing=forbidden
    ObservationRequestTransport.receive_handoff=forbidden
    ReadOnlyAuthorityAdapter.observe_current_snapshot=forbidden
    assert verify_observation(request.response,expected_request=request.retained_request,trust_store=request.trust_store,
        trusted_checkpoint=request.trusted_checkpoint,now=now).status=='VERIFIED'
    if point=='after_verification':os._exit(73)
    client=TestClientHighWaterStore(path,trusted_initial_anchor=anchor,clock=lambda:now)
    def hook(where):
        if where==point:os._exit(73)
    client._hook=hook
    client.apply(request,caller_principal=anchor.principal_id)


def crash(h,request,point):
    process=multiprocessing.get_context('spawn').Process(target=child,args=(str(h.client.path),
        canonical_bytes(h.anchor),canonical_bytes(request),h.t,point))
    try:
        process.start();process.join(25);assert process.exitcode==73
    finally:
        if process.is_alive():process.terminate();process.join(5)


@pytest.mark.parametrize('point,committed',[('after_verification',False),('before_commit',False),('after_commit',True)])
def test_process_crash_and_reopen(harness,monkeypatch,point,committed):
    h=harness;submit(h.writer,h.sim);request=observation(h);upstream=dump(h.authority.path)
    h.upstream.signer.close();crash(h,request,point)
    assert dump(h.authority.path)==upstream
    h.client=TestClientHighWaterStore(h.client.path,trusted_initial_anchor=h.anchor,clock=lambda:h.t)
    current=state(h);assert current.local_sequence==int(committed)
    saved=canonical_bytes(current.history[0].receipt) if committed else None
    if committed:h.client.clock=lambda:h.t+1000
    forbid_upstream(h,monkeypatch)
    result=apply(h,request)
    assert result.status==('RECOVERED' if committed else 'VALID_ADVANCE')
    if committed:assert result.receipt_bytes==saved


def test_uncommitted_expired_response_has_no_receipt_to_recover(harness,monkeypatch):
    h=harness;submit(h.writer,h.sim);request=observation(h);crash(h,request,'before_commit')
    before=dump(h.client.path);h.client.clock=lambda:h.t+1000
    forbid_upstream(h,monkeypatch)
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'):apply(h,request)
    assert dump(h.client.path)==before


@pytest.mark.parametrize('kind',['principal','changed-trust'])
def test_recovery_requires_exact_local_identity_and_request(harness,monkeypatch,kind):
    h=harness;submit(h.writer,h.sim);request=observation(h);apply(h,request);before=dump(h.client.path)
    h.client.clock=lambda:h.t+1000;forbid_upstream(h,monkeypatch)
    with pytest.raises(ClientStoreError,match='ACCESS_DENIED' if kind=='principal' else 'OPERATION_CONFLICT'):
        if kind=='principal':h.client.apply(request,caller_principal='other')
        else:apply(h,request.model_copy(update={'trusted_checkpoint':request.trusted_checkpoint.model_copy(update={'revision':2})}))
    assert dump(h.client.path)==before


def test_isolated_databases_and_public_retained_records(harness):
    h=harness;submit(h.writer,h.sim);request=observation(h);apply(h,request)
    ids=[]
    for path in (h.authority.path,h.client.path):
        with closing(sqlite3.connect(path)) as c:
            ids.append(c.execute('PRAGMA application_id').fetchone()[0])
            assert len(c.execute('PRAGMA database_list').fetchall())==1
    assert h.authority.path!=h.client.path and ids[0]!=ids[1]
    restored=decode_client_record(AdvancementRequest,canonical_bytes(request))
    assert restored==request and 'private' not in type(request).model_fields


def test_same_response_with_new_operation_is_not_historical_retry(harness,monkeypatch):
    h=harness;submit(h.writer,h.sim);request=observation(h);apply(h,request)
    before=dump(h.client.path);h.client.clock=lambda:h.t+1000
    forbid_upstream(h,monkeypatch)
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'):
        apply(h,request.model_copy(update={'operation_id':'new-operation'}))
    assert dump(h.client.path)==before
