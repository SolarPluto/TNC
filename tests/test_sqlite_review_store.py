"""Existing governance rules against a fresh disk-backed SQLite store."""
import multiprocessing
import sqlite3

import pytest

from tnc.provenance.sqlite_review_store import SqliteReviewStore
from tnc.provenance.review_store import ReviewConflictError, ReviewIntegrityError, ReviewStoreError
from test_historical_admission import candidate
from test_review_store import (
    availability, NOW, ACTOR, request, append, head,
    test_empty_store_is_missing_not_approved,
    test_approval_has_store_assigned_sequence_and_immutable_audit,
    test_blocking_head_never_falls_back_to_approval,
    test_explicit_reapproval_preserves_revocation_history,
    test_new_binding_head_is_returned_without_searching_for_old_match,
    test_equal_timestamps_use_sequence_and_concurrency_head,
    test_stale_head_and_bad_links_leave_ledger_unchanged,
    test_invalid_revocation_links,
    test_revocation_requires_active_approval_and_exact_binding,
    test_cross_version_revocation_and_self_link_rejected,
    test_exact_retry_returns_original_without_resurrecting_old_head,
    test_duplicate_id_with_different_content_or_expected_head_fails,
    test_version_identity_cannot_be_rebound,
    test_global_sequence_and_independent_version_heads,
    test_review_time_outside_supported_interval,
    test_backdated_review_is_rejected,
    test_writer_allowlist_and_request_injection,
    test_invalid_model_copy_is_revalidated_on_append,
    test_concurrent_writers_cannot_both_replace_same_head,
    test_retry_with_equivalent_timezones_is_same_write,
    test_all_real_abc_reviews_remain_missing_and_pending,
    test_concurrent_exact_retries_produce_one_record,
    test_invalid_expected_sequence_rejected_without_mutation,
)


@pytest.fixture
def store(tmp_path):
    return SqliteReviewStore.provision(path=tmp_path/"reviews.sqlite", allowed_reviewers=frozenset({ACTOR.reviewer_id}),
                                       clock=lambda: NOW)


def reopen(store, **options):
    return SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset({ACTOR.reviewer_id}),
                                           clock=lambda: NOW, **options)


def test_reopen_preserves_receipt_and_chain(store, availability):
    original = append(store, request(availability))
    reopened = reopen(store)
    assert reopened.history() == (original,)
    assert append(reopened, request(availability)) == original


def test_missing_file_never_created(tmp_path):
    path = tmp_path/"absent.sqlite"
    with pytest.raises(ReviewStoreError):
        SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset())
    assert not path.exists()


def test_provision_never_overwrites(store):
    with pytest.raises(FileExistsError):
        SqliteReviewStore.provision(path=store._path, allowed_reviewers=frozenset())
    assert store.history() == ()


def test_connection_configuration(store):
    conn = store._connect()
    try:
        assert conn.isolation_level is None
        for pragma, expected in [("foreign_keys", 1), ("recursive_triggers", 1), ("synchronous", 2), ("journal_mode", "wal")]:
            assert conn.execute("PRAGMA " + pragma).fetchone() == (expected,)
    finally:
        conn.close()


@pytest.mark.parametrize("mutation", ["version", "trigger", "checkpoint", "blob", "projection", "truncate"])
def test_corruption_blocks_ledger_operations(store, availability, mutation):
    append(store, request(availability))
    with sqlite3.connect(store._path) as conn:
        if mutation == "version":
            conn.execute("PRAGMA user_version=99")
        elif mutation == "trigger":
            conn.execute("DROP TRIGGER reviews_no_update")
        elif mutation == "checkpoint":
            conn.execute("UPDATE store_state SET review_sequence=0")
        else:
            name = "reviews_no_delete" if mutation == "truncate" else "reviews_no_update"
            sql = conn.execute("SELECT sql FROM sqlite_schema WHERE name=?", (name,)).fetchone()[0]
            conn.execute("DROP TRIGGER " + name)
            if mutation == "blob":
                conn.execute("UPDATE reviews SET record_bytes=?", (b"{}",))
            elif mutation == "projection":
                conn.execute("UPDATE reviews SET document_id='wrong'")
            else:
                conn.execute("DELETE FROM reviews")
            conn.execute(sql)
    for operation in [store.history, lambda: head(store), lambda: append(store, request(availability))]:
        with pytest.raises(ReviewIntegrityError):
            operation()


def test_sql_guards_reject_updates_deletes(store, availability):
    append(store, request(availability))
    with sqlite3.connect(store._path) as conn:
        for statement in ["UPDATE reviews SET verdict='rejected'", "DELETE FROM reviews", "DELETE FROM store_state"]:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(statement)
    assert len(store.history()) == 1


def test_busy_failure_never_appends(store, availability):
    second = reopen(store, timeout=0.01)
    conn = store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ReviewStoreError):
            append(second, request(availability))
    finally:
        conn.execute("ROLLBACK")
        conn.close()
    assert store.history() == ()


def _writer(path, serialized, barrier, results):
    from tnc.provenance.review_store import ReviewRequest
    store = SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: NOW)
    barrier.wait(timeout=15)
    try:
        append(store, ReviewRequest.model_validate_json(serialized), 1)
        results.put("appended")
    except ReviewConflictError:
        results.put("conflict")


def test_separate_processes_cannot_replace_same_head(store, availability):
    append(store, request(availability))
    ctx = multiprocessing.get_context("spawn")
    barrier, results = ctx.Barrier(2), ctx.Queue()
    workers = [ctx.Process(target=_writer, args=(store._path,
        request(availability, name, supersedes_review_id="r1").model_dump_json(), barrier, results))
        for name in ("r2", "r3")]
    try:
        for worker in workers:
            worker.start()
        assert sorted(results.get(timeout=20) for _ in workers) == ["appended", "conflict"]
        for worker in workers:
            worker.join(timeout=10)
            assert worker.exitcode == 0
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
        results.close()
    assert len(reopen(store).history()) == 2


def test_invalid_database_is_integrity_failure(tmp_path):
    path = tmp_path/"invalid.sqlite"
    path.write_bytes(b"not a database")
    with pytest.raises(ReviewIntegrityError):
        SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset())


def test_read_snapshot_is_consistent_during_other_writer(store, availability):
    original = append(store, request(availability))
    with store._transaction() as (connection, snapshot, _):
        append(reopen(store), request(availability, "r2", supersedes_review_id="r1"), 1)
        assert snapshot.history() == (original,)
        assert connection.execute("SELECT count(*) FROM reviews").fetchone() == (1,)
    assert len(store.history()) == 2


def test_replay_wrapper_releases_through_durable_adapter(store, candidate):
    from test_historical_replay import engine, execute
    append(store, request(candidate["availability"]))
    outcome = execute(engine(candidate, store))
    assert outcome.status == "released"
    assert reopen(store).release_history()[0].receipt == outcome.receipt
