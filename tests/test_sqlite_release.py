"""Durable release contract, restart and transaction crash-boundary checks."""
from contextlib import contextmanager
import multiprocessing
import sqlite3

import pytest

from tnc.provenance.sqlite_review_store import SqliteReviewStore
from tnc.provenance.review_store import ReviewIntegrityError, ReviewStoreError
import test_review_release as memory_tests
from test_review_release import (
    NOW, ACTOR, replace,
    test_release_records_exact_payload_and_review_checkpoint,
    test_replacement_blocks_old_candidate_without_outbox_entry,
    test_wrong_review_preconditions_block_release,
    test_full_evidence_binding_required,
    test_query_before_capture_blocks_release,
    test_retry_after_revocation_acknowledges_only_prior_release,
    test_duplicate_id_with_different_candidate_conflicts,
    test_unrelated_review_does_not_invalidate_target_approval,
    test_equivalent_timezone_retry_is_idempotent,
    test_invalid_constructed_request_is_revalidated,
    test_release_does_not_call_injected_clock,
    test_concurrent_exact_retries_insert_once,
    test_revocation_commits_while_candidate_preparation_is_paused,
)

@pytest.fixture
def setup(tmp_path):
    memory, candidate = memory_tests.setup.__wrapped__()
    store = SqliteReviewStore.provision(path=tmp_path/"release.sqlite", allowed_reviewers=frozenset({ACTOR.reviewer_id}),
                                       clock=lambda: NOW)
    first, = memory.history()
    store.append(request=first.request, actor=ACTOR, expected_head_sequence=None)
    return store, candidate


def reopen(store):
    return SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset({ACTOR.reviewer_id}),
                                          clock=lambda: NOW)


def test_restart_retry_after_revocation_preserves_bytes(setup):
    store, candidate = setup
    receipt = store.commit_release(request=candidate)
    original, = store.release_history()
    replace(store, candidate)
    new = reopen(store)
    assert new.commit_release(request=candidate) == receipt
    assert new.release_history() == (original,)


def test_failure_after_insert_rolls_back_row_and_checkpoint(setup, monkeypatch):
    store, candidate = setup
    original = store._transaction
    @contextmanager
    def fail_before_commit(**kwargs):
        with original(**kwargs) as values:
            yield values
            raise RuntimeError("simulated pre-commit failure")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_transaction", fail_before_commit)
        with pytest.raises(RuntimeError):
            store.commit_release(request=candidate)
    assert reopen(store).release_history() == ()
    assert store.commit_release(request=candidate).release_sequence == 1


@pytest.mark.parametrize("mutation", ["payload", "receipt", "checkpoint"])
def test_outbox_corruption_blocks_release_but_allows_revocation(setup, mutation):
    store, candidate = setup
    store.commit_release(request=candidate)
    with sqlite3.connect(store._path) as conn:
        if mutation == "checkpoint":
            conn.execute("UPDATE store_state SET release_sequence=0")
        else:
            trigger = conn.execute("SELECT sql FROM sqlite_schema WHERE name='outbox_no_update'").fetchone()[0]
            conn.execute("DROP TRIGGER outbox_no_update")
            if mutation == "payload":
                conn.execute("UPDATE outbox SET payload=?", (b"tampered",))
            else:
                conn.execute("UPDATE outbox SET receipt_bytes=?", (b"{}",))
            conn.execute(trigger)
    for operation in [store.release_history, lambda: store.commit_release(request=candidate)]:
        with pytest.raises(ReviewIntegrityError):
            operation()
    assert replace(reopen(store), candidate).sequence == 2


def _crash_worker(path, serialized, phase, ready, hold):
    from tnc.provenance.review_store import ReleaseRequest
    store = SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: NOW)
    original = store._transaction
    @contextmanager
    def pause(**kwargs):
        with original(**kwargs) as values:
            yield values
            if phase == "before":
                ready.set()
                hold.wait(timeout=60)
        if phase == "after":
            ready.set()
            hold.wait(timeout=60)
    store._transaction = pause
    store.commit_release(request=ReleaseRequest.model_validate_json(serialized))


@pytest.mark.parametrize("phase,expected_count", [("before", 0), ("after", 1)])
def test_process_death_before_or_after_commit_recovers_exactly(setup, phase, expected_count):
    store, candidate = setup
    ctx = multiprocessing.get_context("spawn")
    ready, hold = ctx.Event(), ctx.Event()
    worker = ctx.Process(target=_crash_worker, args=(store._path, candidate.model_dump_json(), phase, ready, hold))
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
    new = reopen(store)
    assert len(new.release_history()) == expected_count
    prior = new.release_history()[0].receipt if expected_count else None
    receipt = new.commit_release(request=candidate)
    if prior is not None:
        assert receipt == prior
    assert receipt.release_sequence == 1 and len(new.release_history()) == 1


def _revoke_worker(path, serialized):
    from tnc.provenance.review_store import ReleaseRequest
    store = SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: NOW)
    replace(store, ReleaseRequest.model_validate_json(serialized))


@pytest.mark.parametrize("release_first", [False, True])
def test_cross_process_revocation_order(setup, release_first):
    from tnc.provenance.review_store import ReviewConflictError
    store, candidate = setup
    if release_first:
        receipt = store.commit_release(request=candidate)
    ctx = multiprocessing.get_context("spawn")
    worker = ctx.Process(target=_revoke_worker, args=(store._path, candidate.model_dump_json()))
    try:
        worker.start()
        worker.join(timeout=15)
        assert worker.exitcode == 0
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
    if release_first:
        assert reopen(store).commit_release(request=candidate) == receipt
        assert len(store.release_history()) == 1
    else:
        with pytest.raises(ReviewConflictError):
            store.commit_release(request=candidate)
        assert store.release_history() == ()


def test_release_busy_is_blocked_without_outbox_entry(setup):
    store, candidate = setup
    other = SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset(), timeout=0.01)
    connection = store._connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(ReviewStoreError):
            other.commit_release(request=candidate)
    finally:
        connection.execute("ROLLBACK")
        connection.close()
    assert store.release_history() == ()
