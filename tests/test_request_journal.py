"""Synthetic journal operations, principal isolation, fencing and crash recovery."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
import multiprocessing
import sqlite3
from threading import Barrier, Event

import pytest

from test_historical_admission import candidate as candidate_fixture, OBSERVED
from test_historical_replay import ACTOR, engine as make_engine
from tnc.provenance.review_store import ReviewRequest, ReviewVerdict, ReviewIntegrityError, ReviewStoreError
from tnc.provenance.sqlite_review_store import SqliteReviewStore
from tnc.provenance.request_journal import (
    RequestJournalManager, CallerContext, QueryIdentity, BoundIntent,
    JournalAccessError, JournalConflictError, engine_configuration_bytes,
)
import tnc.provenance.historical_replay as replay_module


CALLER = CallerContext(principal_id="alice")
OTHER = CallerContext(principal_id="bob")


def make(path, *, provision=False, approval=True):
    candidate = candidate_fixture.__wrapped__()
    options = dict(path=path, allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: OBSERVED)
    if provision:
        store = SqliteReviewStore.provision(**options)
        store.migrate_to_v2()
        if approval:
            store.append(request=ReviewRequest(review_id="r1", availability=candidate["availability"],
                verdict=ReviewVerdict.APPROVED, reviewed_at=OBSERVED, rationale="Synthetic journal test"),
                actor=ACTOR, expected_head_sequence=None)
    else:
        store = SqliteReviewStore.open_existing(**options)
    engine = make_engine(candidate, store)
    config = engine_configuration_bytes(engine)
    head = store.resolve(document_id="doc", version_id="version").head
    intent = BoundIntent(query=QueryIdentity(document_id="doc", version_id="version", query_time=candidate["query_time"]),
        configuration_bytes=config, configuration_hash=sha256(config).hexdigest(), availability=candidate["availability"],
        expected_review_sequence=head.sequence if head else None,
        expected_review_entry_hash=head.entry_hash if head else None)
    manager = RequestJournalManager(store=store, allowed_principals=frozenset({"alice", "bob"}))
    return store, manager, engine, intent


@pytest.fixture
def context(tmp_path):
    return make(tmp_path/"journal.sqlite", provision=True)


def register(context, operation="op1"):
    _, manager, _, intent = context
    return manager.register(operation_id=operation, caller=CALLER, intent=intent)


def claimed(context):
    _, manager, _, _ = context
    view = register(context)
    return manager.claim(operation_id="op1", caller=CALLER, worker_id="worker1", expected_head_sequence=view.head_sequence)


def prepared(context):
    _, manager, engine, _ = context
    fence = claimed(context)
    assert manager.prepare(fence=fence, engine=engine).state == "PREPARED"
    return fence


def test_register_exact_retry_is_immutable(context):
    store, manager, _, intent = context
    original = register(context)
    assert register(context) == original
    assert original.state == "REGISTERED" and original.receipt is None
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("SELECT count(*) FROM request_intents").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM request_events").fetchone() == (1,)
    changed = intent.model_copy(update={"expected_review_entry_hash": "a"*64})
    with pytest.raises(JournalConflictError):
        manager.register(operation_id="op1", caller=CALLER, intent=changed)


@pytest.mark.parametrize("action", ["register", "recover", "claim"])
def test_cross_principal_access_is_generic(context, action):
    _, manager, _, intent = context
    view = register(context)
    with pytest.raises(JournalAccessError, match="^Operation unavailable$"):
        if action == "register":
            manager.register(operation_id="op1", caller=OTHER, intent=intent)
        elif action == "recover":
            manager.recover(operation_id="op1", caller=OTHER)
        else:
            manager.claim(operation_id="op1", caller=OTHER, worker_id="bobworker", expected_head_sequence=view.head_sequence)
    with pytest.raises(JournalAccessError, match="^Operation unavailable$"):
        manager.recover(operation_id="absent", caller=OTHER)


def test_unlisted_principal_denied(context):
    _, manager, _, intent = context
    with pytest.raises(JournalAccessError):
        manager.register(operation_id="op1", caller=CallerContext(principal_id="unknown"), intent=intent)


def test_missing_approval_records_failure_without_release(tmp_path):
    context = make(tmp_path/"missing.sqlite", provision=True, approval=False)
    store, manager, engine, _ = context
    fence = claimed(context)
    result = manager.prepare(fence=fence, engine=engine)
    assert result.state == "FAILED" and result.reason_codes == ("MISSING_REVIEW",)
    assert store.history() == store.release_history() == ()


def test_prepare_commit_and_receipt_only_recovery(context, monkeypatch):
    store, manager, _, _ = context
    fence = prepared(context)
    assert store.release_history() == ()
    result = manager.commit(fence=fence)
    assert result.state == "COMMITTED" and result.receipt is not None
    assert manager.commit(fence=fence) == result
    def forbidden(**kwargs):
        pytest.fail("Recovery reran parser")
    monkeypatch.setattr(replay_module, "parse_article", forbidden)
    reopened = make(store._path)
    recovered = reopened[1].recover(operation_id="op1", caller=CALLER)
    assert recovered == result
    assert "payload" not in recovered.model_dump() and "payload" not in recovered.receipt.model_dump()
    assert len(reopened[0].release_history()) == 1


def test_takeover_fences_old_worker_on_all_mutators(context):
    _, manager, engine, _ = context
    first = prepared(context)
    head = manager.recover(operation_id="op1", caller=CALLER)
    second = manager.claim(operation_id="op1", caller=CALLER, worker_id="worker2", expected_head_sequence=head.head_sequence)
    assert second.generation == first.generation + 1
    for action in [lambda: manager.prepare(fence=first, engine=engine), lambda: manager.commit(fence=first),
                   lambda: manager.fail(fence=first, reason_codes=("TEST_FAILURE",))]:
        with pytest.raises(JournalConflictError, match="Worker generation changed"):
            action()
    assert manager.commit(fence=second).state == "COMMITTED"


def test_stale_claim_cas_conflicts(context):
    _, manager, _, _ = context
    view = register(context)
    manager.claim(operation_id="op1", caller=CALLER, worker_id="first", expected_head_sequence=view.head_sequence)
    with pytest.raises(JournalConflictError):
        manager.claim(operation_id="op1", caller=CALLER, worker_id="second", expected_head_sequence=view.head_sequence)


def test_concurrent_claims_have_one_winner(context):
    _, manager, _, _ = context
    view = register(context)
    barrier = Barrier(2)
    def claim(worker):
        barrier.wait(timeout=5)
        try:
            return manager.claim(operation_id="op1", caller=CALLER, worker_id=worker, expected_head_sequence=view.head_sequence)
        except JournalConflictError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, ["a", "b"]))
    assert sum(result is not None for result in results) == 1


def revoke(context):
    store, _, _, intent = context
    store.append(request=ReviewRequest(review_id="r2", availability=intent.availability, verdict=ReviewVerdict.REVOKED,
        reviewed_at=OBSERVED, rationale="Synthetic revocation", supersedes_review_id="r1", revokes_review_id="r1"),
        actor=ACTOR, expected_head_sequence=1)


def test_revocation_before_commit_blocks_but_preserves_prepared_candidate(context):
    store, manager, _, _ = context
    fence = prepared(context)
    revoke(context)
    with pytest.raises(ReviewStoreError):
        manager.commit(fence=fence)
    assert manager.recover(operation_id="op1", caller=CALLER).state == "PREPARED"
    assert store.release_history() == ()


def test_revocation_after_commit_keeps_historical_receipt(context):
    _, manager, _, _ = context
    result = manager.commit(fence=prepared(context))
    revoke(context)
    assert manager.recover(operation_id="op1", caller=CALLER) == result


def test_standalone_commit_cannot_use_reserved_release(context):
    store, manager, engine, intent = context
    view = register(context)
    candidate = engine._prepare(**intent.query.model_dump(), release_id=view.release_id)
    with pytest.raises(ReviewStoreError, match="Journal-owned"):
        store.commit_release(request=candidate)
    assert store.release_history() == ()


def test_changed_configuration_cannot_prepare(context):
    _, manager, engine, _ = context
    fence = claimed(context)
    engine._transitions = ()
    with pytest.raises(JournalConflictError, match="configuration"):
        manager.prepare(fence=fence, engine=engine)


def test_prepared_retry_does_not_reparse_or_mutate(context, monkeypatch):
    store, manager, engine, _ = context
    fence = prepared(context)
    with sqlite3.connect(store._path) as connection:
        original = connection.execute("SELECT * FROM prepared_requests").fetchall()
    def forbidden(**kwargs):
        pytest.fail("Prepared retry reran parser")
    monkeypatch.setattr(replay_module, "parse_article", forbidden)
    assert manager.prepare(fence=fence, engine=engine).state == "PREPARED"
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("SELECT * FROM prepared_requests").fetchall() == original


def test_takeover_during_parse_blocks_old_preparation(context, monkeypatch):
    store, manager, engine, _ = context
    first = claimed(context)
    started, resume = Event(), Event()
    parser = replay_module.parse_article
    def paused(**kwargs):
        started.set()
        assert resume.wait(timeout=10)
        return parser(**kwargs)
    monkeypatch.setattr(replay_module, "parse_article", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(manager.prepare, fence=first, engine=engine)
        try:
            assert started.wait(timeout=10)
            head = manager.recover(operation_id="op1", caller=CALLER)
            manager.claim(operation_id="op1", caller=CALLER, worker_id="replacement", expected_head_sequence=head.head_sequence)
        finally:
            resume.set()
        with pytest.raises(JournalConflictError):
            result.result(timeout=10)
    assert manager.recover(operation_id="op1", caller=CALLER).state == "REGISTERED"
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("SELECT count(*) FROM prepared_requests").fetchone() == (0,)


def test_terminal_failure_is_idempotent_and_cannot_commit(context):
    _, manager, _, _ = context
    fence = claimed(context)
    result = manager.fail(fence=fence, reason_codes=("TEST_FAILURE",))
    assert manager.fail(fence=fence, reason_codes=("TEST_FAILURE",)) == result
    for action in [lambda: manager.commit(fence=fence),
                   lambda: manager.fail(fence=fence, reason_codes=("DIFFERENT_FAILURE",)),
                   lambda: manager.claim(operation_id="op1", caller=CALLER, worker_id="x", expected_head_sequence=result.head_sequence)]:
        with pytest.raises(JournalConflictError):
            action()


def test_cannot_fail_committed_operation(context):
    _, manager, _, _ = context
    fence = prepared(context)
    manager.commit(fence=fence)
    with pytest.raises(JournalConflictError):
        manager.fail(fence=fence, reason_codes=("TEST_FAILURE",))


def test_finalization_failure_rolls_back_both_tables(context, monkeypatch):
    store, manager, _, _ = context
    fence = prepared(context)
    original = manager._event
    def fail_event(*args, **kwargs):
        if args[3] == "COMMITTED":
            raise RuntimeError("Failure after outbox insert")
        return original(*args, **kwargs)
    monkeypatch.setattr(manager, "_event", fail_event)
    with pytest.raises(RuntimeError):
        manager.commit(fence=fence)
    assert store.release_history() == ()
    assert manager.recover(operation_id="op1", caller=CALLER).state == "PREPARED"


@pytest.mark.parametrize("kind", ["intent", "candidate", "event", "checkpoint"])
def test_corruption_blocks_recovery_and_finalization(context, kind):
    store, manager, _, _ = context
    fence = prepared(context)
    with sqlite3.connect(store._path) as connection:
        if kind == "checkpoint":
            connection.execute("UPDATE journal_state SET sequence=0")
        else:
            table, column = {"intent": ("request_intents", "intent_bytes"),
                             "candidate": ("prepared_requests", "request_bytes"),
                             "event": ("request_events", "event_bytes")}[kind]
            trigger = table + "_no_update"
            sql = connection.execute("SELECT sql FROM sqlite_schema WHERE name=?", (trigger,)).fetchone()[0]
            connection.execute("DROP TRIGGER " + trigger)
            connection.execute(f"UPDATE {table} SET {column}=?", (b"{}",))
            connection.execute(sql)
    for action in [lambda: manager.recover(operation_id="op1", caller=CALLER), lambda: manager.commit(fence=fence)]:
        with pytest.raises(ReviewIntegrityError):
            action()


def _crash_worker(path, action, phase, ready, hold):
    store, manager, engine, intent = make(path)
    if action == "register":
        operation = lambda: manager.register(operation_id="op1", caller=CALLER, intent=intent)
    else:
        from tnc.provenance.request_journal import WorkerFence
        fence = WorkerFence(operation_id="op1", principal_id="alice", worker_id="worker1", generation=1)
        operation = (lambda: manager.prepare(fence=fence, engine=engine)) if action == "prepare" else (lambda: manager.commit(fence=fence))
    original = store._transaction
    @contextmanager
    def pause(**kwargs):
        with original(**kwargs) as values:
            yield values
            if kwargs.get("write") and phase == "before":
                ready.set()
                hold.wait(timeout=60)
        if kwargs.get("write") and phase == "after":
            ready.set()
            hold.wait(timeout=60)
    store._transaction = pause
    operation()


@pytest.mark.parametrize("action", ["register", "prepare", "commit"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_process_death_has_no_partial_journal_outbox_state(context, action, phase):
    store, manager, engine, intent = context
    if action == "prepare":
        claimed(context)
    elif action == "commit":
        prepared(context)
    ctx = multiprocessing.get_context("spawn")
    ready, hold = ctx.Event(), ctx.Event()
    worker = ctx.Process(target=_crash_worker, args=(store._path, action, phase, ready, hold))
    try:
        worker.start()
        assert ready.wait(timeout=20)
        worker.terminate()
        worker.join(timeout=10)
        assert not worker.is_alive()
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
    store, manager, engine, intent = make(store._path)
    if action == "register" and phase == "before":
        with pytest.raises(JournalAccessError):
            manager.recover(operation_id="op1", caller=CALLER)
        assert manager.register(operation_id="op1", caller=CALLER, intent=intent).state == "REGISTERED"
    else:
        expected = {("register", "after"): "REGISTERED", ("prepare", "before"): "REGISTERED",
                    ("prepare", "after"): "PREPARED", ("commit", "before"): "PREPARED",
                    ("commit", "after"): "COMMITTED"}[action, phase]
        result = manager.recover(operation_id="op1", caller=CALLER)
        assert result.state == expected
        assert len(store.release_history()) == (1 if expected == "COMMITTED" else 0)


def test_expected_query_cannot_change_on_recovery(context):
    _, manager, _, intent = context
    register(context)
    different = intent.query.model_copy(update={"document_id": "other"})
    with pytest.raises(JournalConflictError):
        manager.recover(operation_id="op1", caller=CALLER, expected_query=different)


def test_v1_requires_explicit_migration(tmp_path):
    store = SqliteReviewStore.provision(path=tmp_path/"old.sqlite", allowed_reviewers=frozenset())
    manager = RequestJournalManager(store=store, allowed_principals=frozenset({"alice"}))
    with pytest.raises(ReviewStoreError, match="migration required"):
        manager.recover(operation_id="op1", caller=CALLER)


def test_preparation_store_failure_is_not_terminal(context, monkeypatch):
    store, manager, engine, _ = context
    fence = claimed(context)
    def unavailable(**kwargs):
        raise OSError("temporarily unavailable")
    monkeypatch.setattr(store, "resolve", unavailable)
    with pytest.raises(ReviewStoreError):
        manager.prepare(fence=fence, engine=engine)
    assert manager.recover(operation_id="op1", caller=CALLER).state == "REGISTERED"


def test_changed_approval_is_not_silently_adopted(context):
    store, manager, engine, intent = context
    fence = claimed(context)
    store.append(request=ReviewRequest(review_id="new", availability=intent.availability, verdict=ReviewVerdict.APPROVED,
        reviewed_at=OBSERVED, rationale="Synthetic replacement", supersedes_review_id="r1"),
        actor=ACTOR, expected_head_sequence=1)
    with pytest.raises(JournalConflictError):
        manager.prepare(fence=fence, engine=engine)
    assert manager.recover(operation_id="op1", caller=CALLER).state == "REGISTERED"


def test_journal_outbox_corruption_still_allows_ledger_revocation(context):
    store, manager, _, _ = context
    manager.commit(fence=prepared(context))
    with sqlite3.connect(store._path) as connection:
        sql = connection.execute("SELECT sql FROM sqlite_schema WHERE name='outbox_no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER outbox_no_update")
        connection.execute("UPDATE outbox SET payload=?", (b"corrupt",))
        connection.execute(sql)
    with pytest.raises(ReviewIntegrityError):
        manager.recover(operation_id="op1", caller=CALLER)
    revoke(context)
    assert len(store.history()) == 2


def test_two_exact_commit_attempts_create_one_result(context):
    store, manager, _, _ = context
    fence = prepared(context)
    barrier = Barrier(2)
    def commit(_):
        barrier.wait(timeout=5)
        return manager.commit(fence=fence)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(commit, range(2)))
    assert results[0] == results[1]
    assert len(store.release_history()) == 1


def _claim_worker(path, expected, barrier, results, worker_id):
    _, manager, _, _ = make(path)
    barrier.wait(timeout=15)
    try:
        manager.claim(operation_id="op1", caller=CALLER, worker_id=worker_id, expected_head_sequence=expected)
        results.put("claimed")
    except JournalConflictError:
        results.put("conflict")


def test_separate_process_claims_fence_one_worker(context):
    store, _, _, _ = context
    registered = register(context)
    ctx = multiprocessing.get_context("spawn")
    barrier, results = ctx.Barrier(2), ctx.Queue()
    workers = [ctx.Process(target=_claim_worker, args=(store._path, registered.head_sequence, barrier, results, worker))
               for worker in ("process1", "process2")]
    try:
        for worker in workers:
            worker.start()
        assert sorted(results.get(timeout=20) for _ in workers) == ["claimed", "conflict"]
        for worker in workers:
            worker.join(timeout=10)
            assert worker.exitcode == 0
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
        results.close()


@pytest.mark.parametrize("capture_index", [0, 1, 2])
def test_real_abc_journal_operations_never_create_approvals(tmp_path, capture_index):
    from tnc.historical_cli import load_host, _CAPTURES
    from tnc.provenance.historical_replay import HistoricalReplayEngine
    archived_engine, _ = load_host()
    document_id, version_id, _ = _CAPTURES[capture_index]
    availability = next(a for a in archived_engine._availability if a.version_id == version_id)
    store = SqliteReviewStore.provision(path=tmp_path/"abc.sqlite", allowed_reviewers=frozenset())
    store.migrate_to_v2()
    engine = HistoricalReplayEngine(corpus=archived_engine._corpus, availability=archived_engine._availability,
                                    transitions=(), review_store=store)
    config = engine_configuration_bytes(engine)
    intent = BoundIntent(query=QueryIdentity(document_id=document_id, version_id=version_id, query_time=availability.capture_at),
        configuration_bytes=config, configuration_hash=sha256(config).hexdigest(), availability=availability)
    manager = RequestJournalManager(store=store, allowed_principals=frozenset({"alice"}))
    view = manager.register(operation_id="abc", caller=CALLER, intent=intent)
    fence = manager.claim(operation_id="abc", caller=CALLER, worker_id="test", expected_head_sequence=view.head_sequence)
    result = manager.prepare(fence=fence, engine=engine)
    assert result.state == "FAILED" and result.reason_codes == ("MISSING_REVIEW",)
    assert store.history() == store.release_history() == ()
