"""Temporary stores, provider gates, exact retries and real process exits."""
from contextlib import closing
import multiprocessing as mp
import os
import sqlite3
import threading

import pytest
from test_protected_trust_distribution import case, emit, successor, rotated, policy_pin
from tnc.provenance.authorization_models import canonical_bytes, decode_canonical, record_digest
from tnc.provenance.protected_trust_distribution import TrustDistributionBundle
from tnc.provenance.protected_trust_distribution_store import *
import tnc.provenance.protected_trust_distribution_store as module


@pytest.fixture
def setup(tmp_path, case):
    c=case
    inputs=DistributionPolicyInputs(policy=c.policy,checkpoint=c.pin)
    anchor=DistributionStoreAnchor(local_store_id='node-one',initial_inputs=inputs,created_at=c.t)
    store=TestProtectedTrustDistributionStore.create_for_testing(tmp_path/'distribution.db',trusted_anchor=anchor,now=c.t)
    store.clock=lambda:c.t
    provider=TestDistributionPolicyProvider(inputs)
    return store,provider,c


def apply(setup,bundle=None):
    store,provider,c=setup
    return store.apply(bundle or c.bundle,provider=provider)


def audit(setup,now=None):
    return setup[0].load_audit(now=setup[2].t if now is None else now)


def replace_policy(provider,policy):
    before=provider.snapshot_for_testing()
    provider.replace_for_testing(DistributionPolicyInputs(policy=policy,checkpoint=policy_pin(policy)),
        expected_inputs_digest=record_digest(before))


def revoked(c):
    keys=tuple(sorted((c.key.model_copy(update={'status':'revoked'}),c.new_key),key=lambda k:k.key_id))
    return c.policy.model_copy(update={'revision':8,'keys':keys})


def test_initial_apply_and_current_retry_keep_original_receipt(setup):
    store,provider,c=setup
    assert audit(setup).head is None
    first=apply(setup);saved=audit(setup)
    assert first.status=='INITIAL' and first.audit_only and first.verification.signature_verified
    assert len(saved.history)==1 and first.receipt_bytes==canonical_bytes(saved.history[0].receipt)
    store.clock=lambda:c.t+1
    again=apply(setup);current=audit(setup,c.t+1)
    assert again.status=='UNCHANGED' and again.receipt_bytes==first.receipt_bytes
    assert current.history==saved.history and current.head.checked_at==c.t+1
    assert current.head.accepted_at==saved.head.accepted_at
    assert current.head.checkpoint_revision==10 and current.head.trust_store_revision==3


def test_restart_and_expired_audit_is_not_current_acceptance(setup):
    store,provider,c=setup;receipt=apply(setup).receipt_bytes
    reopened=TestProtectedTrustDistributionStore(store.path,trusted_anchor=store.anchor,clock=lambda:c.t+60)
    image=reopened.load_audit(now=c.t+60)
    assert canonical_bytes(image.history[0].receipt)==receipt
    with pytest.raises(DistributionStoreError,match='CHECKPOINT_STALE'):
        reopened.apply(c.bundle,provider=provider)
    assert reopened.load_audit(now=c.t+60)==image


def test_direct_advance_and_old_checkpoint_is_historical_only(setup):
    store,provider,c=setup;first=apply(setup).receipt_bytes
    second=apply(setup,emit(c,successor(c)))
    image=audit(setup)
    assert second.status=='ADVANCE' and image.head.checkpoint_revision==11
    with pytest.raises(DistributionStoreError,match='CHECKPOINT_REGRESSION'):apply(setup)
    assert canonical_bytes(audit(setup).history[0].receipt)==first and audit(setup)==image


def test_root_rotation_persists_public_authority_projection(setup):
    store,provider,c=setup;apply(setup)
    bundle,_=rotated(c)
    assert apply(setup,bundle).status=='ADVANCE'
    image=audit(setup)
    assert image.head.epoch==2 and image.head.signing_key_id==c.new_key.key_id
    with closing(sqlite3.connect(store.path)) as db:
        raw=db.execute('SELECT authority_key FROM distribution_head').fetchone()[0]
    assert raw==canonical_bytes(c.new_key)
    assert all(b'private' not in canonical_bytes(e.request) for e in image.history)


def test_unchanged_checkpoint_records_new_policy_pin_without_new_checkpoint_revision(setup):
    store,provider,c=setup;apply(setup)
    newer=c.policy.model_copy(update={'revision':8,'max_age_seconds':30})
    replace_policy(provider,newer)
    assert apply(setup).status=='UNCHANGED'
    image=audit(setup)
    assert len(image.history)==2 and image.head.checkpoint_revision==10 and image.head.policy_revision==8
    assert len(audit(setup).history)==2
    old=TestDistributionPolicyProvider(store.anchor.initial_inputs)
    with pytest.raises(DistributionStoreError,match='POLICY_REGRESSION'):store.apply(c.bundle,provider=old)


@pytest.mark.parametrize('stage',['locked','receipt_inserted','image_written','before_recheck','before_commit'])
def test_transaction_rollback(setup,stage):
    store,_,_=setup
    def hook(point):
        if point==stage:raise RuntimeError('private diagnostic')
    store._hook=hook
    with pytest.raises(DistributionStoreError) as error:apply(setup)
    assert 'private' not in str(error.value)
    assert audit(setup).history==() and audit(setup).head is None


def test_lost_ack_recovers_original_persisted_receipt(setup):
    store,_,c=setup
    def hook(point):
        if point=='after_commit':raise RuntimeError('lost ack')
    store._hook=hook
    with pytest.raises(DistributionStoreError,match='OUTCOME_UNKNOWN'):apply(setup)
    original=canonical_bytes(audit(setup).history[0].receipt)
    store._hook=lambda point:None;store.clock=lambda:c.t+1
    assert apply(setup).receipt_bytes==original
    assert len(audit(setup,c.t+1).history)==1


@pytest.mark.parametrize('stage',['locked','before_recheck','before_commit','after_commit'])
def test_expiry_at_transaction_boundaries(setup,stage):
    store,_,c=setup
    def hook(point):
        if point==stage:store.clock=lambda:c.t+60
    store._hook=hook
    with pytest.raises(DistributionStoreError,match='OUTCOME_UNKNOWN' if stage=='after_commit' else 'CHECKPOINT_STALE'):
        apply(setup)
    assert bool(audit(setup,c.t+60).history)==(stage=='after_commit')


def test_clock_regression_does_not_change_store(setup):
    store,_,c=setup;apply(setup);before=audit(setup)
    store.clock=lambda:c.t-1
    with pytest.raises(DistributionStoreError):apply(setup)
    assert audit(setup)==before


@pytest.mark.parametrize('stage',['locked','before_recheck','before_commit'])
def test_provider_replacement_seen_after_lock_or_before_commit(setup,stage):
    store,provider,c=setup
    def hook(point):
        if point==stage:replace_policy(provider,revoked(c))
    store._hook=hook
    with pytest.raises(DistributionStoreError,match='KEY_DENIED' if stage=='locked' else 'POLICY_CHANGED'):
        apply(setup)
    assert not audit(setup).history


def test_shared_provider_gate_serializes_replacement_with_commit(setup):
    store,provider,c=setup
    entered,resume,attempted,replaced=(threading.Event() for _ in range(4))
    results=[];errors=[]
    def hook(point):
        if point=='before_commit':entered.set();assert resume.wait(10)
    store._hook=hook
    def write():
        try:results.append(apply(setup))
        except Exception as e:errors.append(e)
    def replace_current():
        attempted.set()
        try:replace_policy(provider,revoked(c));replaced.set()
        except Exception as e:errors.append(e)
    writer=threading.Thread(target=write);writer.start()
    admin=None
    try:
        assert entered.wait(10)
        admin=threading.Thread(target=replace_current);admin.start()
        assert attempted.wait(10) and not replaced.wait(0.05)
    finally:
        resume.set();writer.join(10)
        if admin:admin.join(10)
    assert not errors and results[0].status=='INITIAL' and replaced.is_set()
    store._hook=lambda point:None
    with pytest.raises(DistributionStoreError,match='KEY_DENIED'):apply(setup)


@pytest.mark.parametrize('action',['load','apply'])
def test_missing_store_never_created(setup,tmp_path,action):
    store,provider,c=setup;path=tmp_path/'missing.db'
    missing=TestProtectedTrustDistributionStore(path,trusted_anchor=store.anchor,clock=lambda:c.t)
    with pytest.raises(DistributionStoreError):
        missing.load_audit(now=c.t) if action=='load' else missing.apply(c.bundle,provider=provider)
    assert not path.exists()


@pytest.mark.parametrize('kind',['existing','sidecar','invalid_anchor'])
def test_explicit_creation_rejections(setup,tmp_path,kind):
    store,_,c=setup
    path=store.path if kind=='existing' else tmp_path/'new.db'
    anchor=store.anchor
    if kind=='sidecar':Path(str(path)+'-wal').write_bytes(b'orphan')
    if kind=='invalid_anchor':anchor=anchor.model_copy(update={'created_at':c.t-100})
    with pytest.raises(DistributionStoreError,match='CREATION_FAILED'):
        TestProtectedTrustDistributionStore.create_for_testing(path,trusted_anchor=anchor,now=c.t)
    if kind!='existing':assert not path.exists()


@pytest.mark.parametrize('sql',[
    'PRAGMA application_id=0','PRAGMA user_version=99','CREATE TABLE sqliteExtra(x TEXT)',
    'DROP TRIGGER distribution_receipts_no_update',
    "UPDATE distribution_image SET digest='"+'f'*64+"'",
    'UPDATE distribution_image SET local_sequence=12',
    "UPDATE distribution_head SET authority_key=x'7b7d'",
])
def test_strict_schema_and_projection_corruption(setup,sql):
    store,_,_=setup;apply(setup)
    with closing(sqlite3.connect(store.path)) as db:db.execute(sql);db.commit()
    with pytest.raises(DistributionStoreError):audit(setup)
    with pytest.raises(DistributionStoreError):apply(setup)


def test_wrong_independent_anchor(setup):
    store,_,c=setup
    wrong=TestProtectedTrustDistributionStore(store.path,trusted_anchor=store.anchor.model_copy(update={'local_store_id':'other'}))
    with pytest.raises(DistributionStoreError):wrong.load_audit(now=c.t)


def test_canonical_history_signature_replay_detects_tamper(setup):
    store,_,_=setup;apply(setup);image=audit(setup)
    entry=image.history[0]
    request=entry.request.model_copy(update={'bundle':entry.request.bundle.model_copy(update={'signature_hex':'0'*128})})
    bad=image.model_copy(update={'history':(entry.model_copy(update={'request':request}),)})
    with closing(sqlite3.connect(store.path)) as db:
        db.execute('DROP TRIGGER distribution_receipts_no_update')
        db.execute('UPDATE distribution_receipts SET request=?',(canonical_bytes(request),))
        db.execute(next(sql for sql in module.DDL if sql.startswith('CREATE TRIGGER distribution_receipts_no_update ')))
        db.execute('UPDATE distribution_image SET canonical=?,digest=?',(canonical_bytes(bad),record_digest(bad)))
        db.commit()
    with pytest.raises(DistributionStoreError):audit(setup)


def test_predecode_blob_bounds(setup,monkeypatch):
    store,_,_=setup
    with closing(sqlite3.connect(store.path)) as db:
        db.execute('PRAGMA ignore_check_constraints=ON')
        db.execute('UPDATE distribution_image SET canonical=?',(b'x'*(module.IMAGE_LIMIT+1),));db.commit()
    monkeypatch.setattr(module,'decode_canonical',lambda *a:pytest.fail('Oversize state must fail before decoding'))
    with pytest.raises(DistributionStoreError):audit(setup)


def test_read_snapshot_does_not_take_writer_lock(setup,monkeypatch):
    store,_,_=setup;apply(setup);before=audit(setup)
    statements=[];connect=sqlite3.connect
    def capture(*a,**kw):
        db=connect(*a,**kw);db.set_trace_callback(statements.append);return db
    with closing(connect(store.path,isolation_level=None)) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            monkeypatch.setattr(module.sqlite3,'connect',capture)
            assert audit(setup)==before
        finally:db.execute('ROLLBACK')
    assert 'PRAGMA query_only=ON' in statements and 'BEGIN' in statements
    assert not any(s.startswith('BEGIN IMMEDIATE') for s in statements)


def test_busy_failure_is_bounded_and_readable(setup):
    store,_,_=setup;store.timeout=0
    with closing(sqlite3.connect(store.path,isolation_level=None)) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            with pytest.raises(DistributionStoreError,match='STORE_BUSY'):apply(setup)
            assert not audit(setup).history
        finally:db.execute('ROLLBACK')


def worker(path,anchor_raw,bundle_raw,inputs_raw,now,stage=None,entered=None,resume=None,queue=None,attempted=None):
    anchor=decode_canonical(DistributionStoreAnchor,anchor_raw)
    store=TestProtectedTrustDistributionStore(path,trusted_anchor=anchor,clock=lambda:now,busy_timeout=5)
    provider=TestDistributionPolicyProvider(decode_canonical(DistributionPolicyInputs,inputs_raw))
    def hook(point):
        if point==stage:
            if entered:
                entered.set()
                if not resume.wait(15):os._exit(92)
            else:os._exit(81)
    store._hook=hook
    try:
        if attempted:attempted.set()
        result=store.apply(decode_canonical(TrustDistributionBundle,bundle_raw),provider=provider)
        if queue:queue.put(result.status)
    except DistributionStoreError as e:
        if queue:queue.put(str(e))
        else:raise


@pytest.mark.parametrize('stage',['locked','receipt_inserted','image_written','before_commit','after_commit'])
def test_spawned_process_crash_boundaries(setup,stage):
    store,provider,c=setup
    p=mp.get_context('spawn').Process(target=worker,args=(str(store.path),canonical_bytes(store.anchor),
        canonical_bytes(c.bundle),canonical_bytes(provider.snapshot_for_testing()),c.t,stage))
    p.start();p.join(20)
    if p.is_alive():p.terminate();p.join();pytest.fail('Child timed out')
    assert p.exitcode==81
    image=audit(setup)
    assert bool(image.history)==(stage=='after_commit')
    original=canonical_bytes(image.history[0].receipt) if image.history else None
    result=apply(setup)
    assert result.status==('UNCHANGED' if original else 'INITIAL')
    if original:assert result.receipt_bytes==original


def test_competing_processes_serialize_fork_decision(setup):
    store,provider,c=setup;apply(setup)
    a=emit(c,successor(c));b=emit(c,successor(c,max_age_seconds=59))
    ctx=mp.get_context('spawn');entered,resume,queue=ctx.Event(),ctx.Event(),ctx.Queue()
    attempted=ctx.Event()
    common=(str(store.path),canonical_bytes(store.anchor))
    tail=(canonical_bytes(provider.snapshot_for_testing()),c.t)
    first=ctx.Process(target=worker,args=(*common,canonical_bytes(a),*tail,'image_written',entered,resume,queue))
    second=ctx.Process(target=worker,args=(*common,canonical_bytes(b),*tail,None,None,None,queue,attempted))
    first.start();started=False
    try:
        assert entered.wait(10);second.start();started=True;assert attempted.wait(10)
    finally:
        resume.set();first.join(20)
        if started:second.join(20)
        for child in (first,second) if started else (first,):
            if child.is_alive():child.terminate();child.join()
    assert first.exitcode==second.exitcode==0
    assert sorted((queue.get(timeout=5),queue.get(timeout=5)))==['ADVANCE','CHECKPOINT_FORK']
    queue.close();queue.join_thread()
    assert len(audit(setup).history)==2


@pytest.mark.parametrize('point',['schema_created','creation_before_commit'])
def test_creation_rollback(setup,tmp_path,monkeypatch,point):
    store,_,c=setup;path=tmp_path/'failed.db'
    def hook(self,stage):
        if stage==point:raise RuntimeError('injected')
    monkeypatch.setattr(TestProtectedTrustDistributionStore,'_hook',hook)
    with pytest.raises(DistributionStoreError):TestProtectedTrustDistributionStore.create_for_testing(path,trusted_anchor=store.anchor,now=c.t)
    with closing(sqlite3.connect(path)) as db:assert db.execute('SELECT name FROM sqlite_schema').fetchall()==[]
    with pytest.raises(DistributionStoreError):TestProtectedTrustDistributionStore(path,trusted_anchor=store.anchor).load_audit(now=c.t)


def test_actual_capacity_boundary_and_retry(setup):
    store,provider,c=setup
    original=apply(setup)
    # Populate the bounded archive using the same pure replay contract; the final
    # write API must reject the 65th event while still allowing a current retry.
    image=audit(setup);history=image.history;head=image.head
    for n in range(2,65):
        policy=c.policy.model_copy(update={'revision':6+n})
        inputs=DistributionPolicyInputs(policy=policy,checkpoint=policy_pin(policy))
        request=DistributionIngestion(bundle=c.bundle,inputs=inputs)
        result=module._verify(request,head,c.t)
        receipt=module._receipt(request,result,n,c.t)
        history+=(DistributionHistoryEntry(request=request,receipt=receipt),);head=result.proposed_head
    full=DistributionStoreImage(anchor=store.anchor,history=history,head=head)
    with closing(sqlite3.connect(store.path,isolation_level=None)) as db:
        db.execute('PRAGMA foreign_keys=ON');db.execute('BEGIN IMMEDIATE')
        for e in history[1:]:db.execute('INSERT INTO distribution_receipts VALUES(?,?,?,?)',(
            e.receipt.local_sequence,e.receipt.request_digest,canonical_bytes(e.request),canonical_bytes(e.receipt)))
        store._write_image(db,full);db.execute('COMMIT')
    replace_policy(provider,history[-1].request.inputs.policy)
    assert apply(setup).receipt_bytes==canonical_bytes(history[-1].receipt)
    replace_policy(provider,c.policy.model_copy(update={'revision':71}))
    with pytest.raises(DistributionStoreError,match='CAPACITY_EXCEEDED'):apply(setup)
    assert len(audit(setup).history)==64


def test_whole_store_restore_is_not_independently_detectable(setup,tmp_path):
    store,provider,c=setup;apply(setup)
    backup=tmp_path/'old.db'
    with closing(sqlite3.connect(store.path)) as source, closing(sqlite3.connect(backup)) as target:
        source.backup(target)
    apply(setup,emit(c,successor(c)))
    assert audit(setup).head.checkpoint_revision==11
    # Simulate privileged restore of a complete internally consistent prior image.
    with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(store.path)) as target:
        source.backup(target)
    assert audit(setup).head.checkpoint_revision==10
    assert apply(setup).status=='UNCHANGED'


def test_provider_compare_and_swap_and_immutable_snapshot(setup):
    _,provider,c=setup;before=provider.snapshot_for_testing()
    with pytest.raises(DistributionStoreError,match='POLICY_CONFLICT'):
        provider.replace_for_testing(before,expected_inputs_digest='f'*64)
    replace_policy(provider,revoked(c))
    assert before.policy.revision==7 and provider.snapshot_for_testing().policy.revision==8
    with pytest.raises(ValueError):before.policy.revision=9
    with pytest.raises(DistributionStoreError,match='POLICY_REGRESSION'):
        provider.replace_for_testing(before,expected_inputs_digest=record_digest(provider.snapshot_for_testing()))


def test_raw_policy_inputs_are_not_a_provider(setup,monkeypatch):
    store,provider,c=setup
    monkeypatch.setattr(module.sqlite3,'connect',lambda *a,**k:pytest.fail('Invalid provider must fail before opening SQLite'))
    with pytest.raises(DistributionStoreError,match='INVALID_INPUT'):
        store.apply(c.bundle,provider=provider.snapshot_for_testing())


def test_postcommit_guard_does_not_claim_unpersisted_timestamp(setup):
    store,_,c=setup
    def hook(point):
        if point=='after_commit':store.clock=lambda:c.t+1
    store._hook=hook
    result=apply(setup)
    assert result.verification.proposed_head==audit(setup,c.t+1).head
    assert result.verification.proposed_head.checked_at==c.t


def test_postcommit_policy_change_is_uncertain_with_durable_audit(setup):
    store,provider,c=setup
    def hook(point):
        if point=='after_commit':replace_policy(provider,revoked(c))
    store._hook=hook
    with pytest.raises(DistributionStoreError,match='OUTCOME_UNKNOWN'):apply(setup)
    assert len(audit(setup).history)==1
    store._hook=lambda point:None
    with pytest.raises(DistributionStoreError,match='KEY_DENIED'):apply(setup)
