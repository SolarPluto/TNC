from contextlib import closing
from datetime import timedelta
from types import SimpleNamespace
from copy import deepcopy
import multiprocessing
import os
import sqlite3

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update, locator
from test_update_verification import signed
from test_update_integration import host
from test_update_storage_validation import stored, image_from, checkpoint
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.update_durable_store import UpdateDurableStore, _rows
from tnc.provenance.update_verification import update_signature_preimage
from tnc.provenance.update_durable_writer import (
    TestUpdateStoreWriter as Writer, LocalCheckpointForTesting, UpdateWriteError,
)


class Admin:
    def __init__(self, value): self.value, self.allowed = value, True
    def verify(self): return self.allowed
    def read(self): return self.value


def clock(): return NOW


@pytest.fixture
def setup(tmp_path, stored, host, signed):
    empty = image_from(stored[0], [])
    path = tmp_path / 'writer.sqlite'
    UpdateDurableStore.create_empty_for_testing(path, empty, trusted_checkpoint=checkpoint(empty))
    admin = Admin(stored[1][0])
    writer = Writer(path, identity_provider=host.identity, administration_provider=admin,
        observation_provider=host.observations, checkpoint_provider=LocalCheckpointForTesting(), clock=clock)
    result = writer.record_authority(expected_revision=0)
    return SimpleNamespace(writer=writer, admin=admin, host=host, intent=signed['intent'], signature=signed['envelope'], cp=result.checkpoint)


def read(s):
    with closing(sqlite3.connect(s.writer.path)) as connection:
        cp = LocalCheckpointForTesting().read(connection)
    return UpdateDurableStore(s.writer.path).load(trusted_checkpoint=cp)


def prepare(s):
    s.writer.register(s.intent,s.signature)
    return s.writer.prepare(s.intent,s.signature)


def commit(s):
    prepare(s)
    return s.writer.commit(s.intent,s.signature)


def revoke(s):
    view = s.admin.value
    trust = view.trust_store.model_copy(update={'revision':view.trust_store.revision+1,
        'revoked_key_ids':(s.intent.signer_key_hash,)})
    cp = view.trust_checkpoint.model_copy(update={'revision':trust.revision,'trust_store_hash':record_digest(trust)})
    s.admin.value = view.model_copy(update={'trust_store':trust,'trust_checkpoint':cp})


def test_transaction_lifecycle_and_exact_retries(setup):
    s=setup
    first=s.writer.register(s.intent,s.signature)
    assert s.writer.register(s.intent,s.signature).status=='UNCHANGED'
    assert read(s).events[-1].sequence==2
    s.writer.prepare(s.intent,s.signature)
    assert s.writer.prepare(s.intent,s.signature).status=='UNCHANGED'
    result=s.writer.commit(s.intent,s.signature)
    image=read(s)
    assert len(image.events)==4 and image.head.sequence==image.base_head.sequence+1
    assert result.receipt_bytes==canonical_bytes(image.events[-1].payload.receipt)
    for action in ('commit','register','recover'):
        retry=getattr(s.writer,action)(s.intent,s.signature)
        assert retry.status=='RECOVERED' and retry.receipt_bytes==result.receipt_bytes
        assert read(s)==image


def test_retry_conflicting_signature_and_intent(setup):
    s=setup; commit(s)
    for intent,signature in [(s.intent.model_copy(update={'valid_until':s.intent.valid_until+timedelta(seconds=1)}),s.signature),
            (s.intent,s.signature.model_copy(update={'signature_hex':'f'*128}))]:
        with pytest.raises(UpdateWriteError,match='OPERATION_CONFLICT'): s.writer.commit(intent,signature)


def test_foreign_or_absent_operation_has_generic_denial(setup):
    s=setup; commit(s)
    s.host.identity.value=s.host.identity.value.model_copy(update={'principal_id':'other'})
    for intent in (s.intent,s.intent.model_copy(update={'operation_id':'absent'})):
        with pytest.raises(UpdateWriteError,match='^ACCESS_DENIED$'): s.writer.recover(intent,s.signature)


def test_recovery_needs_current_permission(setup):
    s=setup; commit(s)
    grant=s.admin.value.permissions[0].model_copy(update={'permissions':('UPDATE_EVALUATE',)})
    s.admin.value=s.admin.value.model_copy(update={'permissions':(grant,)})
    s.writer.record_authority(expected_revision=1)
    with pytest.raises(UpdateWriteError,match='ACCESS_DENIED'): s.writer.commit(s.intent,s.signature)


def test_revocation_before_commit_blocks_and_after_preserves(setup):
    s=setup; prepare(s); before=read(s)
    revoke(s); s.writer.record_authority(expected_revision=1)
    with pytest.raises(UpdateWriteError,match='SIGNATURE_REJECTED'): s.writer.commit(s.intent,s.signature)
    assert read(s).head==before.head and len(read(s).events)==4


def test_historical_retry_after_revocation_does_not_observe(setup):
    s=setup; result=commit(s)
    revoke(s); s.writer.record_authority(expected_revision=1)
    def fail(*args): pytest.fail('Historical retry must not acquire observations')
    s.host.observations.observe=fail
    assert s.writer.commit(s.intent,s.signature).receipt_bytes==result.receipt_bytes


def test_fresh_session_recovers_original_actor(setup):
    s=setup; result=commit(s); image=read(s)
    s.host.identity.value=s.host.identity.value.model_copy(update={'connection_id':'new-session','audit_id':'new-audit'})
    assert s.writer.recover(s.intent,s.signature).receipt_bytes==result.receipt_bytes
    assert read(s)==image


@pytest.mark.parametrize('stage',['locked','insert:events','insert:commits','state','before_recheck','before_commit'])
def test_commit_fault_rolls_back_every_record(setup,stage):
    s=setup; prepare(s); before=read(s)
    def hook(point):
        if point==stage: raise RuntimeError('injected')
    s.writer._hook=hook
    with pytest.raises(UpdateWriteError): s.writer.commit(s.intent,s.signature)
    assert read(s)==before
    s.writer._hook=lambda point:None
    assert s.writer.commit(s.intent,s.signature).status=='APPENDED'
    assert [e.sequence for e in read(s).events]==[1,2,3,4]


def test_acknowledgement_failure_recovers(setup):
    s=setup; prepare(s)
    def hook(point):
        if point=='after_commit': raise RuntimeError('lost acknowledgement')
    s.writer._hook=hook
    with pytest.raises(UpdateWriteError,match='OUTCOME_UNKNOWN'): s.writer.commit(s.intent,s.signature)
    expected=canonical_bytes(read(s).events[-1].payload.receipt)
    s.writer._hook=lambda point:None
    assert s.writer.commit(s.intent,s.signature).receipt_bytes==expected


def test_stale_authority_revision_and_exact_view_retry(setup):
    s=setup
    assert s.writer.record_authority(expected_revision=1).status=='UNCHANGED'
    assert s.writer.record_authority(expected_revision=0).status=='UNCHANGED'
    revoke(s)
    with pytest.raises(UpdateWriteError,match='AUTHORITY_CONFLICT'): s.writer.record_authority(expected_revision=0)
    assert len(read(s).events)==1


def test_admin_denial_before_store_open(setup):
    s=setup; s.admin.allowed=False
    with pytest.raises(UpdateWriteError,match='ACCESS_DENIED'): s.writer.record_authority(expected_revision=1)


def test_final_session_check_rolls_back(setup):
    s=setup; prepare(s); before=read(s)
    def hook(point):
        if point=='before_recheck': s.host.identity.value=s.host.identity.value.model_copy(update={'connection_id':'changed'})
    s.writer._hook=hook
    with pytest.raises(UpdateWriteError,match='STALE_CONTEXT'): s.writer.commit(s.intent,s.signature)
    assert read(s)==before


def test_expiry_before_commit_rolls_back(setup):
    s=setup; prepare(s); before=read(s)
    time=[NOW]
    s.writer.clock=lambda:time[0]
    def hook(point):
        if point=='before_recheck': time[0]=NOW+timedelta(days=1)
    s.writer._hook=hook
    with pytest.raises(UpdateWriteError): s.writer.commit(s.intent,s.signature)
    assert read(s)==before


def test_clock_regression(setup):
    s=setup; s.writer.clock=lambda:NOW-timedelta(seconds=1)
    with pytest.raises(UpdateWriteError): s.writer.register(s.intent,s.signature)
    assert len(read(s).events)==1


def test_preparation_cannot_be_swapped_at_commit(setup):
    s=setup; prepare(s)
    s.host.observations.preparation=s.host.observations.preparation.model_copy(update={'valid_until':NOW+timedelta(minutes=3)})
    with pytest.raises(UpdateWriteError,match='PREPARATION_CONFLICT'): s.writer.commit(s.intent,s.signature)


def test_incomplete_drain_blocks(setup):
    s=setup; prepare(s)
    s.host.observations.drain=s.host.observations.drain.model_copy(update={'processes_terminated':False})
    with pytest.raises(UpdateWriteError,match='INVALID_TRANSITION'): s.writer.commit(s.intent,s.signature)


def test_missing_store_not_created(setup,tmp_path):
    s=setup; s.writer.path=tmp_path/'absent.sqlite'
    with pytest.raises(UpdateWriteError,match='STORE_UNAVAILABLE'): s.writer.register(s.intent,s.signature)
    assert not s.writer.path.exists()


def test_lock_contention_is_bounded(setup):
    s=setup; s.writer.timeout=0.05
    with closing(sqlite3.connect(s.writer.path,isolation_level=None)) as connection:
        connection.execute('BEGIN IMMEDIATE')
        with pytest.raises(UpdateWriteError,match='STORE_UNAVAILABLE'): s.writer.register(s.intent,s.signature)
        connection.execute('ROLLBACK')
    assert len(read(s).events)==1


def test_corrupt_projection_blocks_writer(setup):
    s=setup
    with closing(sqlite3.connect(s.writer.path)) as connection:
        connection.execute("UPDATE store_state SET image_hash='bad'"); connection.commit()
    with pytest.raises(UpdateWriteError,match='INVALID_STORE'): s.writer.register(s.intent,s.signature)


def child(path, identity, admin, observations, intent, signature, start, reached, release, results, action='commit', stop=None):
    writer=Writer(path,identity_provider=identity,administration_provider=admin,observation_provider=observations,
        checkpoint_provider=LocalCheckpointForTesting(),clock=clock,busy_timeout=5)
    def hook(point):
        if stop == 'crash:' + point:
            os._exit(73)
        if point==stop:
            reached.set()
            if not release.wait(15): raise RuntimeError('test deadline')
    writer._hook=hook
    start.wait(15)
    try:
        result=writer.record_authority(expected_revision=1) if action=='authority' else writer.commit(intent,signature)
        results.put((result.status,result.receipt_bytes))
    except Exception as exc: results.put(('error',str(exc)))


def launch(s,ctx,start,reached,release,results,action='commit',stop=None):
    p=ctx.Process(target=child,args=(str(s.writer.path),s.host.identity,s.admin,s.host.observations,s.intent,s.signature,
        start,reached,release,results,action,stop))
    p.start(); return p


def cleanup(processes):
    for p in processes:
        p.join(15)
        if p.is_alive(): p.terminate(); p.join(5)


def test_two_process_exact_commits_insert_once(setup):
    s=setup; prepare(s); ctx=multiprocessing.get_context('spawn')
    start,reached,release=ctx.Event(),ctx.Event(),ctx.Event(); q=ctx.Queue()
    processes=[launch(s,ctx,start,reached,release,q) for _ in range(2)]
    try:
        start.set()
        results=[q.get(timeout=20) for _ in processes]
        assert sorted(x[0] for x in results)==['APPENDED','RECOVERED']
        assert results[0][1]==results[1][1] and len(read(s).events)==4
    finally: cleanup(processes)


@pytest.mark.parametrize('point,committed',[('before_commit',False),('after_commit',True)])
def test_process_termination_commit_boundary(setup,point,committed):
    s=setup; prepare(s); ctx=multiprocessing.get_context('spawn')
    start,reached,release=ctx.Event(),ctx.Event(),ctx.Event(); q=ctx.Queue()
    p=launch(s,ctx,start,reached,release,q,stop='crash:' + point)
    try:
        start.set(); p.join(15); assert p.exitcode == 73
        image=read(s)
        assert len(image.events)==(4 if committed else 3)
        result=s.writer.commit(s.intent,s.signature)
        assert result.status==('RECOVERED' if committed else 'APPENDED')
    finally: cleanup([p])


@pytest.mark.parametrize('revocation_first',[True,False])
def test_serialized_revocation_order_across_processes(setup,revocation_first):
    s=setup; prepare(s); revoke(s); ctx=multiprocessing.get_context('spawn')
    start,reached,release=ctx.Event(),ctx.Event(),ctx.Event(); q=ctx.Queue()
    first=launch(s,ctx,start,reached,release,q,action='authority' if revocation_first else 'commit',stop='before_commit')
    processes=[first]
    try:
        start.set(); assert reached.wait(15)
        second=launch(s,ctx,start,ctx.Event(),ctx.Event(),q,action='commit' if revocation_first else 'authority')
        processes.append(second); release.set()
        results=[q.get(timeout=20) for _ in processes]
        image=read(s)
        if revocation_first:
            assert any(r==('error','SIGNATURE_REJECTED') for r in results)
            assert len([e for e in image.events if e.payload.kind=='COMMIT'])==0
        else:
            assert all(r[0]=='APPENDED' for r in results)
            assert s.writer.recover(s.intent,s.signature).receipt_bytes is not None
    finally: release.set(); cleanup(processes)


def test_distinct_process_updates_cannot_both_advance_same_head(setup,signed):
    s=setup; prepare(s)
    other_intent=s.intent.model_copy(update={'operation_id':'other-update'})
    other_signature=s.signature.model_copy(update={'signature_hex':signed['private'].sign(update_signature_preimage(other_intent)).hex()})
    grant=s.admin.value.permissions[0].model_copy(update={'operation_id':other_intent.operation_id})
    s.admin.value=s.admin.value.model_copy(update={'permissions':tuple(sorted(s.admin.value.permissions+(grant,),key=lambda p:(p.principal_id,p.operation_id,p.credential_id)))})
    s.writer.record_authority(expected_revision=1)
    observations=deepcopy(s.host.observations)
    observations.preparation=observations.preparation.model_copy(update={'intent_hash':record_digest(other_intent)})
    observations.drain=observations.drain.model_copy(update={'intent_hash':record_digest(other_intent)})
    second_writer=Writer(s.writer.path,identity_provider=s.host.identity,administration_provider=s.admin,
        observation_provider=observations,checkpoint_provider=LocalCheckpointForTesting(),clock=clock)
    second_writer.register(other_intent,other_signature); second_writer.prepare(other_intent,other_signature)
    other=SimpleNamespace(writer=second_writer,admin=s.admin,intent=other_intent,signature=other_signature,
        host=SimpleNamespace(identity=s.host.identity,observations=observations))
    ctx=multiprocessing.get_context('spawn'); start,reached,release=ctx.Event(),ctx.Event(),ctx.Event(); q=ctx.Queue()
    processes=[launch(v,ctx,start,reached,release,q) for v in (s,other)]
    try:
        start.set(); results=[q.get(timeout=20) for _ in processes]
        assert sorted(r[0] for r in results)==['APPENDED','error']
        assert next(r[1] for r in results if r[0]=='error')=='INVALID_TRANSITION'
        assert len([e for e in read(s).events if e.payload.kind=='COMMIT'])==1
    finally: cleanup(processes)


@pytest.mark.parametrize('action,stage',[('register','insert:registrations'),('prepare','insert:preparations'),('authority','insert:events')])
def test_other_event_projection_failure_is_atomic(setup,action,stage):
    s=setup
    if action=='prepare': s.writer.register(s.intent,s.signature)
    if action=='authority': revoke(s)
    before=read(s)
    def hook(point):
        if point==stage: raise RuntimeError('fault')
    s.writer._hook=hook
    with pytest.raises(UpdateWriteError):
        if action=='authority': s.writer.record_authority(expected_revision=1)
        else: getattr(s.writer,action)(s.intent,s.signature)
    assert read(s)==before


def test_authority_provider_change_during_transaction_rolls_back(setup):
    s=setup; revoke(s); before=read(s)
    def hook(point):
        if point=='before_recheck': s.admin.value=s.admin.value.model_copy(update={'permissions':()})
    s.writer._hook=hook
    with pytest.raises(UpdateWriteError,match='STALE_CONTEXT'): s.writer.record_authority(expected_revision=1)
    assert read(s)==before


def test_expired_signing_key_historical_recovery_uses_original_time(setup):
    s=setup; receipt=commit(s).receipt_bytes
    # Beyond the signing key's 30-minute interval, inside current identity/grant.
    s.writer.clock=lambda:NOW+timedelta(minutes=40)
    assert s.writer.recover(s.intent,s.signature).receipt_bytes==receipt


def test_pending_recover_and_prepare_without_registration(setup):
    s=setup
    with pytest.raises(UpdateWriteError,match='ACCESS_DENIED'): s.writer.prepare(s.intent,s.signature)
    s.writer.register(s.intent,s.signature)
    result=s.writer.recover(s.intent,s.signature)
    assert result.status=='UNCHANGED' and result.receipt_bytes is None
    assert len(read(s).events)==2


def test_removed_permission_blocks_new_commit(setup):
    s=setup; prepare(s)
    s.admin.value=s.admin.value.model_copy(update={'permissions':()})
    s.writer.record_authority(expected_revision=1)
    with pytest.raises(UpdateWriteError,match='ACCESS_DENIED'): s.writer.commit(s.intent,s.signature)


def test_full_image_rejects_new_commit_without_truncation(setup,stored,tmp_path):
    s=setup
    payloads=[stored[1][0]]*254 + stored[1][1:3]
    image=image_from(stored[0],payloads)
    empty=image_from(stored[0],[])
    path=tmp_path/'full.sqlite'
    UpdateDurableStore.create_empty_for_testing(path,empty,trusted_checkpoint=checkpoint(empty))
    with closing(sqlite3.connect(path)) as connection:
        for name,rows in _rows(image,checkpoint(image)).items():
            if name=='store_metadata': continue
            if name=='store_state': connection.execute('DELETE FROM store_state')
            for row in rows: connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})",row)
        connection.commit()
    s.writer.path=path
    assert read(s)==image
    with pytest.raises(UpdateWriteError,match='CAPACITY_EXCEEDED'): s.writer.commit(s.intent,s.signature)
    assert read(s)==image


def test_authority_exact_retry_with_original_expected_revision(setup):
    s=setup; prepare(s); revoke(s)
    first=s.writer.record_authority(expected_revision=1)
    assert s.writer.record_authority(expected_revision=1).status=='UNCHANGED'
    assert checkpoint(read(s))==first.checkpoint
