"""Real adapter migration: preserve history and keep all new authority closed."""
from contextlib import contextmanager
import multiprocessing
import sqlite3

import pytest

import tnc.provenance.sqlite_review_store as module
from tnc.provenance.review_store import ReviewIntegrityError, ReviewStoreError
from test_request_journal import context, make, register, claimed, prepared, CALLER
from test_request_journal import revoke
from test_sqlite_release import setup as release_setup


LEGACY = ('reviews', 'outbox', 'store_state', 'request_intents', 'prepared_requests',
          'request_events', 'journal_state')


def rows(store):
    with sqlite3.connect(store._path) as db:
        return tuple(db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall() for table in LEGACY)


def version(store):
    with sqlite3.connect(store._path) as db:
        return db.execute('PRAGMA user_version').fetchone()[0]


@pytest.mark.parametrize('state', ['REGISTERED', 'PREPARED', 'COMMITTED', 'FAILED'])
def test_populated_history_and_recovery_preserved(context, state):
    store, manager, engine, _ = context
    if state == 'REGISTERED':
        view = register(context)
    else:
        fence = prepared(context)
        if state == 'COMMITTED':
            view = manager.commit(fence=fence)
        elif state == 'FAILED':
            view = manager.fail(fence=fence, reason_codes=('TEST_FAILED',))
        else:
            view = manager.recover(operation_id='op1', caller=CALLER)
    before = rows(store)
    store.migrate_to_v3()
    assert version(store) == 3 and rows(store) == before
    reopened, recovered, _, _ = make(store._path)
    assert recovered.recover(operation_id='op1', caller=CALLER) == view
    reopened.migrate_to_v3()
    assert rows(store) == before
    with sqlite3.connect(store._path) as db:
        assert db.execute('PRAGMA foreign_key_check').fetchall() == []
        assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)


def test_v1_requires_explicit_v2_and_open_never_migrates(tmp_path):
    store = module.SqliteReviewStore.provision(path=tmp_path/'empty.db', allowed_reviewers=frozenset())
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v3()
    assert version(store) == 1
    store.migrate_to_v2()
    module.SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset())
    assert version(store) == 2
    store.migrate_to_v3()
    assert store.history() == store.release_history() == ()
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v2()
    assert version(store) == 3


@pytest.mark.parametrize('table', [
    'request_intents', 'prepared_requests', 'request_events', 'outbox',
    'authorization_events', 'execution_authorizations', 'execution_assignments', 'release_authorizations',
])
def test_database_guards_block_direct_inserts(context, table):
    store = context[0]
    store.migrate_to_v3()
    with sqlite3.connect(store._path) as db:
        with pytest.raises(sqlite3.IntegrityError, match='not enabled'):
            db.execute(f'INSERT INTO {table} DEFAULT VALUES')


@pytest.mark.parametrize('method', ['register', 'claim', 'prepare', 'commit', 'fail', 'release'])
def test_legacy_write_apis_block_even_exact_retries(context, method, monkeypatch):
    store, manager, engine, intent = context
    fence = prepared(context)
    committed = manager.commit(fence=fence)
    candidate = store.release_history()[0].request
    before = rows(store)
    store.migrate_to_v3()
    def no_parse(**kwargs):
        raise AssertionError('must not parse')
    monkeypatch.setattr(engine, '_prepare', no_parse)
    actions = {
        'register': lambda: manager.register(operation_id='op1', caller=CALLER, intent=intent),
        'claim': lambda: manager.claim(operation_id='op1', caller=CALLER, worker_id='worker1',
                                       expected_head_sequence=committed.head_sequence),
        'prepare': lambda: manager.prepare(fence=fence, engine=engine),
        'commit': lambda: manager.commit(fence=fence),
        'fail': lambda: manager.fail(fence=fence, reason_codes=('TEST_FAILED',)),
        'release': lambda: store.commit_release(request=candidate),
    }
    with pytest.raises(ReviewStoreError):
        actions[method]()
    assert rows(store) == before
    assert manager.recover(operation_id='op1', caller=CALLER) == committed


@pytest.mark.parametrize('fault', ['version', 'extra_table', 'journal_checkpoint'])
def test_invalid_source_rejected_unchanged(context, fault):
    store = context[0]
    with sqlite3.connect(store._path) as db:
        if fault == 'version':
            db.execute('PRAGMA user_version=999')
        elif fault == 'extra_table':
            db.execute('CREATE TABLE unexpected(x)')
        else:
            db.execute('UPDATE journal_state SET sequence=1')
    before = rows(store)
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v3()
    assert rows(store) == before
    assert version(store) == (999 if fault == 'version' else 2)


@pytest.mark.parametrize('fault', ['checkpoint', 'boundary', 'guard', 'premature_event'])
def test_invalid_target_rejected_on_read_and_retry(context, fault):
    store = context[0]
    store.migrate_to_v3()
    with sqlite3.connect(store._path) as db:
        if fault == 'checkpoint':
            db.execute('UPDATE authorization_state SET sequence=1')
        elif fault == 'boundary':
            trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='authorization_boundary_no_update'").fetchone()[0]
            db.execute('DROP TRIGGER authorization_boundary_no_update')
            db.execute('UPDATE authorization_migration_boundary SET legacy_journal_sequence=1')
            db.execute(trigger)
        elif fault == 'guard':
            db.execute('DROP TRIGGER v3_events_closed')
        else:
            trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='v3_authorization_events_closed'").fetchone()[0]
            db.execute('DROP TRIGGER v3_authorization_events_closed')
            db.execute('INSERT INTO authorization_events VALUES (?,?,?,?,?,?,?,?)',
                       (1, 'fake', 'CREDENTIAL_ENROLLED', 'alice', 'admin', '0'*64, 'a'*64, b'{}'))
            db.execute(trigger)
    for action in (store.history, store.migrate_to_v3):
        with pytest.raises(ReviewIntegrityError):
            action()


def test_failure_after_every_ddl_statement_restores_source(context, monkeypatch):
    store = context[0]
    module._expected_schema(3)
    statements, buffer = [], ''
    for line in module._MIGRATION_V3.read_text().splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer)
            buffer = ''
    before = rows(store)
    with sqlite3.connect(store._path) as db:
        schema = module._schema_rows(db)
    for count in range(1, len(statements) + 1):
        def interrupted(db):
            for statement in statements[:count]:
                db.execute(statement)
            raise RuntimeError('injected DDL interruption')
        monkeypatch.setattr(module, '_apply_v3', interrupted)
        with pytest.raises(RuntimeError):
            store.migrate_to_v3()
        assert version(store) == 2 and rows(store) == before
        with sqlite3.connect(store._path) as db:
            assert module._schema_rows(db) == schema


def test_target_validation_failure_rolls_back(context, monkeypatch):
    store = context[0]
    module._expected_schema(3)
    original = module._apply_v3
    def invalid(db):
        original(db)
        db.execute("UPDATE release_authorization_state SET head_hash=?", ('b'*64,))
    monkeypatch.setattr(module, '_apply_v3', invalid)
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v3()
    assert version(store) == 2
    assert len(store.history()) == 1


def test_bounded_lock_contention(context):
    store = context[0]
    other = module.SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset(), timeout=0.01)
    with store._transaction(write=True):
        with pytest.raises(ReviewStoreError):
            other.migrate_to_v3()
    assert version(store) == 2


def migration_worker(path, phase, ready, hold):
    store = module.SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset())
    original = store._transaction
    @contextmanager
    def paused(**kwargs):
        with original(**kwargs) as values:
            yield values
            if phase == 'before':
                ready.set()
                hold.wait(30)
        if phase == 'after':
            ready.set()
            hold.wait(30)
    store._transaction = paused
    store.migrate_to_v3()


@pytest.mark.parametrize('phase,expected', [('before', 2), ('after', 3)])
def test_process_death_at_commit(context, phase, expected):
    store, manager, _, _ = context
    receipt = manager.commit(fence=prepared(context))
    before = rows(store)
    ctx = multiprocessing.get_context('spawn')
    ready, hold = ctx.Event(), ctx.Event()
    process = ctx.Process(target=migration_worker, args=(store._path, phase, ready, hold))
    try:
        process.start()
        assert ready.wait(20)
        process.terminate()
        process.join(5)
        assert not process.is_alive()
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
    assert version(store) == expected and rows(store) == before
    store.migrate_to_v3()
    assert manager.recover(operation_id='op1', caller=CALLER) == receipt


def test_standalone_historical_receipt_preserved(release_setup):
    store, candidate = release_setup
    receipt = store.commit_release(request=candidate)
    store.migrate_to_v2()
    before = rows(store)
    store.migrate_to_v3()
    assert rows(store) == before
    assert store.release_history()[0].receipt == receipt
    with pytest.raises(ReviewStoreError):
        store.commit_release(request=candidate)


def test_review_revocation_survives_migration_and_corrupt_outbox(context):
    store, manager, _, _ = context
    view = manager.commit(fence=prepared(context))
    store.migrate_to_v3()
    with sqlite3.connect(store._path) as db:
        trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='outbox_no_update'").fetchone()[0]
        db.execute('DROP TRIGGER outbox_no_update')
        db.execute('UPDATE outbox SET payload=?', (b'corrupt',))
        db.execute(trigger)
    with pytest.raises(ReviewIntegrityError):
        manager.recover(operation_id='op1', caller=CALLER)
    revoke(context)
    assert len(store.history()) == 2
    with pytest.raises(ReviewIntegrityError):
        store.migrate_to_v3()


def test_existing_review_revocation_does_not_rewrite_receipt(context):
    store, manager, _, _ = context
    view = manager.commit(fence=prepared(context))
    revoke(context)
    before = rows(store)
    store.migrate_to_v3()
    assert rows(store) == before
    assert manager.recover(operation_id='op1', caller=CALLER) == view


def concurrent_worker(path, ready, start, result):
    try:
        store = module.SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset())
        ready.set()
        if not start.wait(20):
            raise RuntimeError('start timeout')
        store.migrate_to_v3()
        result.put('ok')
    except Exception as exc:
        result.put(type(exc).__name__)


def test_two_processes_migrate_once_and_validate_retry(context):
    store = context[0]
    before = rows(store)
    ctx = multiprocessing.get_context('spawn')
    start, result = ctx.Event(), ctx.Queue()
    ready = [ctx.Event(), ctx.Event()]
    workers = [ctx.Process(target=concurrent_worker, args=(store._path, item, start, result)) for item in ready]
    try:
        for worker in workers:
            worker.start()
        assert all(item.wait(20) for item in ready)
        start.set()
        assert [result.get(timeout=20) for _ in workers] == ['ok', 'ok']
        for worker in workers:
            worker.join(5)
            assert worker.exitcode == 0
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
        result.close()
    assert version(store) == 3 and rows(store) == before
