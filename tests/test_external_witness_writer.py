"""Synthetic-provider transactions and spawned witness process boundaries."""
from contextlib import closing
import multiprocessing as mp
import os
import sqlite3
import threading

import pytest

from test_external_witness_logic import h, change
from test_external_witness_store import store, populate
from tnc.provenance.authorization_models import canonical_bytes, decode_canonical
from tnc.provenance.external_witness_logic import WitnessStateRecord, WitnessAdvanceRequest, SyntheticLineageEvidence, WitnessImage, witness_digest
from tnc.provenance.external_witness_writer import (
    TestExternalWitnessWriter, TestWitnessPolicyProvider, TestWitnessProviderInputs, WitnessWriterError,
)


def inputs(h, request, policy=None):
    policy = policy or h.policy
    return TestWitnessProviderInputs(policy=policy, caller=h.caller(request, policy))


def provider(h, request, policy=None):
    return TestWitnessPolicyProvider(inputs(h, request, policy))


@pytest.fixture
def writer(store, h):
    return TestExternalWitnessWriter(store.path, trusted_initial=h.initial, clock=lambda:20)


def submit(writer, h, request=None, **kw):
    request = request or h.request()
    return writer.submit(request, provider=kw.pop('provider', provider(h, request)),
                         evidence=kw.pop('evidence', h.proof(request)), **kw)


def test_accept_restart_and_exact_receipt(writer, store, h):
    result = submit(writer, h)
    image = store.load_audit(now=20)
    assert result.status == 'SUCCESS' and result.audit_only and not result.signature_verified
    assert result.receipt_bytes == canonical_bytes(image.receipts[0])
    restarted = TestExternalWitnessWriter(store.path, trusted_initial=h.initial, clock=lambda:210)
    retry = submit(restarted, h, evidence=object())
    assert retry.status == 'HISTORICAL_RECEIPT' and retry.receipt_bytes == result.receipt_bytes
    assert store.load_audit(now=210) == image


def test_retry_after_later_advance(writer, store, h):
    first = submit(writer, h)
    submit(writer, h, h.request(store.load_audit(now=20)))
    image = store.load_audit(now=20)
    assert submit(writer, h).receipt_bytes == first.receipt_bytes
    assert store.load_audit(now=20) == image


def test_advance_without_recovery_permission(writer, store, h):
    request = h.request()
    p = provider(h, request, change(h.policy, recovery_principals=()))
    assert submit(writer, h, provider=p).status == 'SUCCESS'
    with pytest.raises(WitnessWriterError, match='^UNAUTHORIZED_CLIENT$'): submit(writer, h, provider=p)
    assert len(store.load_audit(now=20).receipts) == 1


def test_recovery_without_advance_permission(writer, store, h):
    first = submit(writer, h)
    p = provider(h, h.request(), change(h.policy, revision=2, advance_principals=()))
    assert submit(writer, h, provider=p).receipt_bytes == first.receipt_bytes
    request = h.request(store.load_audit(now=20))
    p = provider(h, request, change(h.policy, revision=2, advance_principals=()))
    with pytest.raises(WitnessWriterError, match='^UNAUTHORIZED_CLIENT$'): submit(writer, h, request, provider=p)


@pytest.mark.parametrize('existing', [False, True])
def test_unauthorized_before_image_lookup(writer, h, monkeypatch, existing):
    if existing: submit(writer, h)
    p = provider(h, h.request(), change(h.policy, revision=2, advance_principals=(), recovery_principals=()))
    monkeypatch.setattr(writer._store, '_load', lambda *a, **kw: pytest.fail('Unauthorized image lookup'))
    with pytest.raises(WitnessWriterError, match='^UNAUTHORIZED_CLIENT$'): submit(writer, h, provider=p)


def test_conflict_and_other_owner(writer, h):
    submit(writer, h)
    with pytest.raises(WitnessWriterError, match='^OPERATION_CONFLICT$'):
        submit(writer, h, change(h.request(), expires_at=199))
    req = change(h.request(), principal_id='bob')
    p = provider(h, req, change(h.policy, revision=2, recovery_principals=('alice','bob')))
    with pytest.raises(WitnessWriterError, match='^UNAUTHORIZED_CLIENT$'): submit(writer, h, req, provider=p)


def test_stale_cas_and_equal_sequence_fork(writer, h):
    with pytest.raises(WitnessWriterError, match='^STATE_FORK$'):
        submit(writer, h, change(h.request(), predecessor_state_digest='f'*64))
    submit(writer, h)
    with pytest.raises(WitnessWriterError, match='^CAS_MISMATCH$'):
        submit(writer, h, change(h.request(), request_id='competitor'))


@pytest.mark.parametrize('stage', ['locked','receipt_inserted','image_written','before_recheck','before_commit'])
def test_precommit_fault_rollback_and_resource_cleanup(writer, store, h, stage):
    def hook(point):
        if point == stage: raise RuntimeError('private injected detail')
    writer._hook = hook
    with pytest.raises(WitnessWriterError, match='^INVALID_WITNESS_STORE$'): submit(writer, h)
    assert store.load_audit(now=20).receipts == ()
    writer._hook = lambda _: None
    assert submit(writer, h).status == 'SUCCESS'


@pytest.mark.parametrize('stage', ['before_recheck','before_commit','after_commit'])
def test_request_expiry_and_preappend_guard(writer, store, h, stage):
    def hook(point):
        if point == stage: writer.clock = lambda:200
    writer._hook = hook
    code = 'OUTCOME_UNKNOWN' if stage == 'after_commit' else 'INDETERMINATE'
    with pytest.raises(WitnessWriterError, match=f'^{code}$'): submit(writer, h)
    assert bool(store.load_audit(now=200).receipts) == (stage == 'after_commit')


@pytest.mark.parametrize('which', ['caller','policy','lineage'])
def test_independent_expiry_guards(writer, store, h, which):
    request = h.request()
    policy = change(h.policy, expires_at=30) if which == 'policy' else h.policy
    supplied = inputs(h, request, policy)
    if which == 'caller': supplied = change(supplied, caller=change(supplied.caller, expires_at=30))
    proof = change(h.proof(request), expires_at=30) if which == 'lineage' else h.proof(request)
    def hook(point):
        if point == 'before_commit': writer.clock = lambda:30
    writer._hook = hook
    with pytest.raises(WitnessWriterError): submit(writer, h, provider=TestWitnessPolicyProvider(supplied), evidence=proof)
    assert store.load_audit(now=30).receipts == ()


def test_rechecks_preserve_initial_acceptance_time(writer, store, h):
    def hook(point):
        if point == 'before_commit': writer.clock = lambda:21
        if point == 'after_commit': writer.clock = lambda:22
    writer._hook = hook
    result = submit(writer, h)
    receipt = store.load_audit(now=22).receipts[0]
    assert receipt.accepted_at == receipt.resulting_state.last_updated_at == 20
    assert result.receipt_bytes == canonical_bytes(receipt)


@pytest.mark.parametrize('stage', ['before_commit','after_commit','after_retry'])
def test_provider_reentrant_change(writer, store, h, stage):
    if stage == 'after_retry': submit(writer, h)
    p = provider(h, h.request())
    def hook(point):
        if point == stage:
            replacement = inputs(h, h.request(), change(h.policy, revision=2, advance_principals=(), recovery_principals=()))
            p.replace_for_testing(replacement, expected_inputs_digest=witness_digest(p.snapshot_for_testing()))
    writer._hook = hook
    code = 'OUTCOME_UNKNOWN' if stage == 'after_commit' else 'POLICY_CHANGED'
    with pytest.raises(WitnessWriterError, match=f'^{code}$'): submit(writer, h, provider=p)
    assert bool(store.load_audit(now=20).receipts) == (stage != 'before_commit')


def test_lost_acknowledgement(writer, store, h):
    def hook(point):
        if point == 'after_commit': raise RuntimeError('lost acknowledgement')
    writer._hook = hook
    with pytest.raises(WitnessWriterError, match='^OUTCOME_UNKNOWN$'): submit(writer, h)
    image = store.load_audit(now=20)
    writer._hook = lambda _: None
    assert submit(writer, h).receipt_bytes == canonical_bytes(image.receipts[0])


def test_retry_failure_is_not_unknown_acceptance(writer, h):
    submit(writer, h)
    def hook(point):
        if point == 'after_retry': raise RuntimeError('read return failed')
    writer._hook = hook
    with pytest.raises(WitnessWriterError, match='^INVALID_WITNESS_STORE$'): submit(writer, h)


def test_retry_has_no_sql_writes(writer, h, monkeypatch):
    submit(writer, h)
    trace, original = [], sqlite3.connect
    def connect(*a, **kw):
        db = original(*a, **kw); db.set_trace_callback(trace.append); return db
    monkeypatch.setattr(sqlite3, 'connect', connect)
    submit(writer, h)
    assert not any(s.startswith(('INSERT','UPDATE','DELETE')) for s in trace)
    assert 'BEGIN IMMEDIATE' in trace and 'ROLLBACK' in trace


def test_busy_store_releases_no_state(writer, store, h):
    writer.busy_timeout = 0
    with closing(sqlite3.connect(store.path, isolation_level=None)) as db:
        db.execute('BEGIN IMMEDIATE')
        with pytest.raises(WitnessWriterError, match='^STORE_BUSY$'): submit(writer, h)
        assert store.load_audit(now=20).receipts == ()
        db.execute('ROLLBACK')
    assert submit(writer, h).status == 'SUCCESS'


def test_provider_timeout_releases_sqlite(writer, store, h):
    p = provider(h, h.request())
    entered, resume = threading.Event(), threading.Event()
    def hold():
        with p._lease(1): entered.set(); resume.wait(5)
    thread = threading.Thread(target=hold); thread.start()
    try:
        assert entered.wait(2)
        writer.provider_timeout = 0
        with pytest.raises(WitnessWriterError, match='^POLICY_BUSY$'): submit(writer, h, provider=p)
    finally: resume.set(); thread.join(5)
    assert not thread.is_alive() and store.load_audit(now=20).receipts == ()
    assert submit(writer, h, provider=p).status == 'SUCCESS'


def test_provider_replacement_waits_through_commit(writer, store, h):
    p = provider(h, h.request())
    old = p.snapshot_for_testing()
    entered, resume, attempted, done = (threading.Event() for _ in range(4))
    results = []
    def hook(point):
        if point == 'before_commit':
            entered.set()
            if not resume.wait(5): raise RuntimeError('barrier timeout')
    writer._hook = hook
    def run():
        try: results.append(submit(writer, h, provider=p).status)
        except Exception as error: results.append(str(error))
    def replace():
        attempted.set()
        try:
            p.replace_for_testing(inputs(h, h.request(), change(h.policy, revision=2, recovery_principals=())),
                                  expected_inputs_digest=witness_digest(old), timeout=5)
        finally: done.set()
    worker = threading.Thread(target=run); replacer = threading.Thread(target=replace)
    worker.start()
    try:
        assert entered.wait(3); replacer.start(); assert attempted.wait(2)
        assert not done.wait(.1)
    finally:
        resume.set(); worker.join(5)
        if replacer.ident is not None: replacer.join(5)
    assert results == ['SUCCESS'] and done.is_set()
    writer._hook = lambda _: None
    with pytest.raises(WitnessWriterError, match='^UNAUTHORIZED_CLIENT$'): submit(writer, h, provider=p)


def test_policy_cas_floor_and_immutable_snapshot(h):
    p = provider(h, h.request()); old = p.snapshot_for_testing()
    with pytest.raises(WitnessWriterError, match='POLICY_CONFLICT'):
        p.replace_for_testing(old, expected_inputs_digest='f'*64)
    new = inputs(h, h.request(), change(h.policy, revision=2))
    p.replace_for_testing(new, expected_inputs_digest=witness_digest(old))
    assert old.policy.revision == 1 and p.snapshot_for_testing().policy.revision == 2
    with pytest.raises(WitnessWriterError, match='POLICY_REGRESSION'):
        p.replace_for_testing(old, expected_inputs_digest=witness_digest(new))


@pytest.mark.parametrize('value', [True, -1, 6, float('nan'), float('inf')])
def test_timeout_bounds(store, h, value):
    with pytest.raises(WitnessWriterError): TestExternalWitnessWriter(store.path, trusted_initial=h.initial, busy_timeout=value)


@pytest.mark.parametrize('now,code', [(True,'CLOCK_INVALID'),(-1,'CLOCK_INVALID'),(19,'CLOCK_REGRESSION')])
def test_clock_guards(writer, store, h, now, code):
    def hook(point):
        if point == 'before_commit': writer.clock = lambda:now
    writer._hook = hook
    with pytest.raises(WitnessWriterError, match=code): submit(writer, h)
    assert store.load_audit(now=20).receipts == ()


def test_missing_invalid_provider_and_corruption(tmp_path, writer, store, h, monkeypatch):
    missing = TestExternalWitnessWriter(tmp_path/'absent.db', trusted_initial=h.initial, clock=lambda:20)
    with pytest.raises(WitnessWriterError): submit(missing, h)
    assert not missing.path.exists()
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, 'connect', lambda *a, **kw: pytest.fail('Invalid provider must fail before SQL'))
        with pytest.raises(WitnessWriterError, match='INVALID_INPUT'): submit(writer, h, provider=inputs(h, h.request()))
    with closing(sqlite3.connect(store.path)) as db:
        db.execute("UPDATE witness_head SET epoch_id='corrupt'"); db.commit()
    with pytest.raises(WitnessWriterError, match='INVALID_WITNESS_STORE'): submit(writer, h)


def test_capacity_and_historical_retry(writer, store, h):
    image = WitnessImage(initial=h.initial, receipts=())
    for _ in range(64): image = h.submit(image).proposed_image
    populate(store, image)
    assert submit(writer, h).receipt_bytes == canonical_bytes(image.receipts[0])
    with pytest.raises(WitnessWriterError, match='CAPACITY_EXCEEDED'): submit(writer, h, h.request(image))
    assert store.load_audit(now=20) == image


def child(path, initial_raw, request_raw, input_raw, evidence_raw, stage=None, entered=None, resume=None, queue=None, attempted=None):
    initial = decode_canonical(WitnessStateRecord, initial_raw)
    request = decode_canonical(WitnessAdvanceRequest, request_raw)
    p = TestWitnessPolicyProvider(decode_canonical(TestWitnessProviderInputs, input_raw))
    evidence = decode_canonical(SyntheticLineageEvidence, evidence_raw)
    writer = TestExternalWitnessWriter(path, trusted_initial=initial, clock=lambda:20, busy_timeout=5)
    def hook(point):
        if point == stage:
            if entered is None: os._exit(81)
            entered.set()
            if not resume.wait(15): os._exit(92)
    writer._hook = hook
    try:
        if attempted: attempted.set()
        result = writer.submit(request, provider=p, evidence=evidence)
        if queue: queue.put((result.status, result.receipt_bytes))
    except WitnessWriterError as error:
        if queue: queue.put((str(error), None))
        else: raise


def args(store, h, request):
    return (str(store.path), canonical_bytes(h.initial), canonical_bytes(request),
            canonical_bytes(inputs(h, request)), canonical_bytes(h.proof(request)))


@pytest.mark.parametrize('stage', ['locked','receipt_inserted','image_written','before_commit','after_commit'])
def test_spawned_exit_boundaries(writer, store, h, stage):
    process = mp.get_context('spawn').Process(target=child, args=(*args(store,h,h.request()),stage))
    process.start(); process.join(20)
    if process.is_alive(): process.terminate(); process.join(); pytest.fail('Child timeout')
    assert process.exitcode == 81
    image = store.load_audit(now=20)
    assert bool(image.receipts) == (stage == 'after_commit')
    result = submit(writer,h)
    assert result.status == ('HISTORICAL_RECEIPT' if image.receipts else 'SUCCESS')
    if image.receipts: assert result.receipt_bytes == canonical_bytes(image.receipts[0])


@pytest.mark.parametrize('identical', [False, True])
def test_competing_spawned_writers(store, h, identical):
    request = h.request()
    other = request if identical else change(request, request_id='competing')
    context = mp.get_context('spawn')
    entered, resume, attempted, queue = context.Event(), context.Event(), context.Event(), context.Queue()
    first = context.Process(target=child, args=(*args(store,h,request),'image_written',entered,resume,queue))
    second = context.Process(target=child, args=(*args(store,h,other),None,None,None,queue,attempted))
    first.start(); started = False
    try:
        assert entered.wait(10); second.start(); started = True; assert attempted.wait(10)
    finally:
        resume.set(); first.join(20)
        if started: second.join(20)
        for process in (first, second) if started else (first,):
            if process.is_alive(): process.terminate(); process.join()
    assert first.exitcode == second.exitcode == 0
    results = [queue.get(timeout=5),queue.get(timeout=5)]
    queue.close(); queue.join_thread()
    assert sorted(r[0] for r in results) == sorted(['SUCCESS','HISTORICAL_RECEIPT' if identical else 'CAS_MISMATCH'])
    if identical: assert results[0][1] == results[1][1]
    assert len(store.load_audit(now=20).receipts) == 1


def test_persisted_policy_floor_after_restart(writer, store, h):
    request = h.request()
    p = provider(h, request, change(h.policy, revision=2))
    submit(writer, h, provider=p)
    restarted = TestExternalWitnessWriter(store.path, trusted_initial=h.initial, clock=lambda:20)
    with pytest.raises(WitnessWriterError, match='^INDETERMINATE$'): submit(restarted, h)
    assert submit(restarted, h, provider=p).status == 'HISTORICAL_RECEIPT'


def test_actual_writer_and_readonly_snapshot(writer, store, h):
    seen = []
    def hook(point):
        if point == 'image_written': seen.append(store.load_audit(now=20))
    writer._hook = hook
    submit(writer, h)
    assert len(seen) == 1 and seen[0].receipts == ()
    assert len(store.load_audit(now=20).receipts) == 1


def test_writer_full_sync_and_lock_order(writer, h, monkeypatch):
    trace, original = [], sqlite3.connect
    def connect(*a, **kw):
        db = original(*a, **kw); db.set_trace_callback(trace.append); return db
    p = provider(h, h.request())
    original_lease = p._lease
    def lease(timeout):
        assert 'BEGIN IMMEDIATE' in trace
        assert 'PRAGMA synchronous=FULL' in trace
        assert 'PRAGMA foreign_keys=ON' in trace
        return original_lease(timeout)
    monkeypatch.setattr(sqlite3, 'connect', connect)
    monkeypatch.setattr(p, '_lease', lease)
    submit(writer, h, provider=p)
    assert 'COMMIT' in trace
