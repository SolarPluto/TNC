"""Explicit layout migration; the journal manager is not enabled yet."""
from contextlib import contextmanager
import multiprocessing
import sqlite3

import pytest

import tnc.provenance.sqlite_review_store as module
from tnc.provenance.review_store import ReviewIntegrityError, ReviewStoreError, ReviewConflictError
from test_sqlite_release import setup, reopen
from test_review_release import ACTOR, NOW, replace


def rows(store):
    with sqlite3.connect(store._path) as connection:
        return tuple(connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                     for table in ("reviews", "outbox", "store_state"))


def version(store):
    with sqlite3.connect(store._path) as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0]


def test_migration_preserves_bytes_receipts_and_revocation(setup):
    store, candidate = setup
    receipt = store.commit_release(request=candidate)
    replace(store, candidate)
    before = rows(store)
    store.migrate_to_v2()
    assert version(store) == 2 and rows(store) == before
    migrated = reopen(store)
    assert migrated.commit_release(request=candidate) == receipt
    with pytest.raises(ReviewConflictError):
        migrated.commit_release(request=candidate.model_copy(update={"release_id": "new"}))
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_open_never_migrates_implicitly(setup):
    store, _ = setup
    reopen(store)
    assert version(store) == 1
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("SELECT name FROM sqlite_schema WHERE name='request_intents'").fetchone() is None


def test_empty_database_migrates(tmp_path):
    store = module.SqliteReviewStore.provision(path=tmp_path/"empty.sqlite", allowed_reviewers=frozenset())
    store.migrate_to_v2()
    assert version(store) == 2
    assert store.history() == store.release_history() == ()


def test_idempotent_migration_retry_validates_target(setup):
    store, _ = setup
    store.migrate_to_v2()
    before = rows(store)
    reopen(store).migrate_to_v2()
    assert rows(store) == before
    with sqlite3.connect(store._path) as connection:
        connection.execute("UPDATE journal_state SET sequence=1")
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v2()


@pytest.mark.parametrize("kind", ["unknown_version", "broken_outbox", "unexpected_table"])
def test_invalid_source_not_migrated(setup, kind):
    store, candidate = setup
    store.commit_release(request=candidate)
    with sqlite3.connect(store._path) as connection:
        if kind == "unknown_version":
            connection.execute("PRAGMA user_version=99")
        elif kind == "broken_outbox":
            connection.execute("UPDATE store_state SET release_sequence=0")
        else:
            connection.execute("CREATE TABLE unexpected(x TEXT)")
    before = rows(store)
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v2()
    assert rows(store) == before
    assert version(store) == (99 if kind == "unknown_version" else 1)
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("SELECT name FROM sqlite_schema WHERE name='request_intents'").fetchone() is None


def test_partial_ddl_failure_rolls_back(setup, monkeypatch):
    store, _ = setup
    before = rows(store)
    def interrupted(connection):
        connection.execute("CREATE TABLE partial_journal(x INTEGER)")
        connection.execute("PRAGMA user_version=2")
        raise RuntimeError("synthetic interruption")
    monkeypatch.setattr(module, "_apply_v2", interrupted)
    with pytest.raises(RuntimeError):
        store.migrate_to_v2()
    assert version(store) == 1 and rows(store) == before
    with sqlite3.connect(store._path) as connection:
        assert connection.execute("SELECT name FROM sqlite_schema WHERE name='partial_journal'").fetchone() is None


def test_validation_failure_after_ddl_rolls_back(setup, monkeypatch):
    store, _ = setup
    module._expected_schema(2)
    original = module._apply_v2
    def incomplete(connection):
        original(connection)
        connection.execute("UPDATE journal_state SET head_hash=?", ("a" * 64,))
    monkeypatch.setattr(module, "_apply_v2", incomplete)
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v2()
    assert version(store) == 1
    assert len(store.history()) == 1


def test_v2_accepts_new_reviews_and_releases_with_contiguous_sequences(setup):
    store, candidate = setup
    store.migrate_to_v2()
    receipt = store.commit_release(request=candidate)
    assert receipt.release_sequence == 1
    assert replace(store, candidate).sequence == 2
    assert len(reopen(store).history()) == 2


def test_unmanaged_journal_intent_cannot_bypass_future_fencing(setup):
    store, candidate = setup
    store.migrate_to_v2()
    with sqlite3.connect(store._path) as connection:
        connection.execute("INSERT INTO request_intents VALUES (?, ?, ?, ?, ?)",
                           ("op", "principal", candidate.release_id, "a"*64, b"{}"))
    for action in (store.history, store.release_history, lambda: store.commit_release(request=candidate)):
        with pytest.raises(ReviewIntegrityError):
            action()


def test_migration_obeys_bounded_writer_lock(setup):
    store, _ = setup
    other = module.SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset(), timeout=0.01)
    connection = store._connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(ReviewStoreError):
            other.migrate_to_v2()
    finally:
        connection.execute("ROLLBACK")
        connection.close()
    assert version(store) == 1


def _migration_worker(path, phase, ready, hold):
    store = module.SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset({ACTOR.reviewer_id}),
                                                  clock=lambda: NOW)
    original = store._transaction
    @contextmanager
    def paused(**kwargs):
        with original(**kwargs) as values:
            yield values
            if phase == "before":
                ready.set()
                hold.wait(timeout=60)
        if phase == "after":
            ready.set()
            hold.wait(timeout=60)
    store._transaction = paused
    store.migrate_to_v2()


@pytest.mark.parametrize("phase,expected_version", [("before", 1), ("after", 2)])
def test_process_death_at_migration_commit_boundary(setup, phase, expected_version):
    store, candidate = setup
    receipt = store.commit_release(request=candidate)
    before = rows(store)
    ctx = multiprocessing.get_context("spawn")
    ready, hold = ctx.Event(), ctx.Event()
    worker = ctx.Process(target=_migration_worker, args=(store._path, phase, ready, hold))
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
    assert version(store) == expected_version and rows(store) == before
    reopened = reopen(store)
    reopened.migrate_to_v2()
    assert version(store) == 2
    assert reopened.commit_release(request=candidate) == receipt
