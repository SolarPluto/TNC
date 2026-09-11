"""Host-only v4 transactions with explicitly synthetic identity adapters."""
from contextlib import contextmanager
from datetime import timedelta
import multiprocessing
import sqlite3

import pytest

from test_authorization_validation import Chain, NOW, END, ROOT, OTHER, enrollment, grant
from tnc.provenance.authorization_models import (
    BootstrapManifest, BootstrapTrustAnchor, CredentialDisabled, PermissionRevoked,
    record_digest,
)
from tnc.provenance.authorization_writer import (
    AdministrationWriter, AdministrativeAppendRequest, ProvisioningAuthorization,
)
from tnc.provenance.host_auth import (
    RegistryCredentialVerifier, TrustedTransportEvidence, AuthenticationError, AuthorizationError,
)
from tnc.provenance.sqlite_review_store import SqliteReviewStore
from tnc.provenance.review_store import ReviewStoreError, ReviewIntegrityError, ReviewConflictError
import tnc.provenance.authorization_writer as writer_module
import tnc.provenance.sqlite_review_store as store_module


class TestProvisioningSession:
    __test__ = False
    def __init__(self, anchor, **changes):
        self.anchor, self.changes = anchor, changes

    def verify_activation(self, manifest):
        return ProvisioningAuthorization(**(dict(operator_id=self.anchor.operator_id,
            session_id=self.anchor.provisioning_session_id, manifest_hash=record_digest(manifest),
            deployment_id=manifest.deployment_id, valid_from=NOW, valid_until=END) | self.changes))

    def verify_commit(self, proof, *, database_path):
        """Synthetic fixture; real monotonic checks are tested by provisioning_session."""
        return None


class TestSession:
    __test__ = False
    def __init__(self, writer, fingerprint=ROOT):
        self.writer, self.fingerprint = writer, fingerprint

    def verify_identity(self):
        return RegistryCredentialVerifier(self.writer, clock=lambda: NOW).verify(
            TrustedTransportEvidence(credential_id=self.fingerprint, connection_id='test-connection',
                verified_at=NOW, credential_valid_from=NOW-timedelta(days=1), credential_valid_until=END))


def open_writer(path, anchor):
    store = SqliteReviewStore.open_existing(path=path, allowed_reviewers=frozenset(), bootstrap_anchor=anchor)
    return AdministrationWriter(store=store, clock=lambda: NOW)


@pytest.fixture
def pending(tmp_path):
    chain = Chain()
    path = tmp_path/'administration.sqlite'
    store = SqliteReviewStore.provision(path=path, allowed_reviewers=frozenset())
    store.migrate_to_v2()
    store.migrate_to_v3()
    return open_writer(path, chain.anchor), chain.manifest, chain.anchor


@pytest.fixture
def active(pending):
    writer, manifest, anchor = pending
    writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
    return pending


def request(writer, payload=None, event_id='new'):
    head = writer.history()[-1]
    return AdministrativeAppendRequest(event_id=event_id, expected_head_sequence=head.sequence,
        expected_head_hash=head.entry_hash, payload=payload or enrollment(OTHER, 'bob'))


def snapshot(writer):
    with sqlite3.connect(writer._store._path) as db:
        return db.execute('PRAGMA user_version').fetchone(), tuple(
            (table, db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall())
            for table, in db.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall())


def test_bootstrap_and_fresh_provisioning_retry(pending):
    writer, manifest, anchor = pending
    receipt = writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
    before = snapshot(writer)
    reopened = open_writer(writer._store._path, anchor)
    assert reopened.migrate_to_v4(provisioning=TestProvisioningSession(anchor, session_id='fresh'), manifest=manifest) == receipt
    assert snapshot(writer) == before
    assert len(writer.history()) == 2
    with pytest.raises(ReviewIntegrityError):
        SqliteReviewStore.open_existing(path=writer._store._path, allowed_reviewers=frozenset())


@pytest.mark.parametrize('change', [dict(operator_id='attacker'), dict(valid_until=NOW),
    dict(manifest_hash='0'*64), dict(deployment_id='wrong'), dict(session_id='wrong')])
def test_bootstrap_rejects_false_provisioning_without_mutation(pending, change):
    writer, manifest, anchor = pending
    before = snapshot(writer)
    with pytest.raises(AuthorizationError):
        writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor, **change), manifest=manifest)
    assert snapshot(writer) == before


def test_provisioning_callback_failure_has_no_mutation(pending):
    writer, manifest, _ = pending
    before = snapshot(writer)
    class Denied:
        def verify_activation(self, manifest):
            raise AuthorizationError('No verified OS operator')
    with pytest.raises(AuthorizationError):
        writer.migrate_to_v4(provisioning=Denied(), manifest=manifest)
    assert snapshot(writer) == before


def test_exact_append_retry_with_new_session_and_changed_head(active):
    writer, _, anchor = active
    original = request(writer)
    receipt = writer.append(session=TestSession(writer), request=original)
    writer.append(session=TestSession(writer), request=request(writer, grant('second'), 'second'))
    before = snapshot(writer)
    reopened = open_writer(writer._store._path, anchor)
    assert reopened.append(session=TestSession(reopened), request=original) == receipt
    assert snapshot(writer) == before


@pytest.mark.parametrize('change', ['payload', 'head', 'credential'])
def test_append_retry_conflicts(active, change):
    writer, _, _ = active
    original = request(writer, enrollment(OTHER))
    writer.append(session=TestSession(writer), request=original)
    before = snapshot(writer)
    altered = original
    session = TestSession(writer)
    if change == 'payload':
        altered = original.model_copy(update={'payload': grant('different')})
    elif change == 'head':
        altered = original.model_copy(update={'expected_head_sequence': 0})
    else:
        session = TestSession(writer, OTHER)
    with pytest.raises(ReviewConflictError):
        writer.append(session=session, request=altered)
    assert snapshot(writer) == before


def test_stale_new_request_and_disabled_actor(active):
    writer, _, _ = active
    stale = request(writer)
    writer.append(session=TestSession(writer), request=request(writer, grant('second'), 'second'))
    with pytest.raises(ReviewConflictError):
        writer.append(session=TestSession(writer), request=stale)
    writer.append(session=TestSession(writer), request=request(writer,
        CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='disable'), 'disable'))
    before = snapshot(writer)
    with pytest.raises(AuthenticationError):
        writer.append(session=TestSession(writer), request=stale)
    assert snapshot(writer) == before


@pytest.mark.parametrize('table', ['request_intents', 'prepared_requests', 'request_events', 'outbox',
    'execution_authorizations', 'execution_assignments', 'release_authorizations'])
def test_seven_execution_guards_remain(active, table):
    writer = active[0]
    with sqlite3.connect(writer._store._path) as db:
        with pytest.raises(sqlite3.IntegrityError, match='not enabled'):
            db.execute(f'INSERT INTO {table} DEFAULT VALUES')


def test_execution_event_kind_denied(active):
    writer = active[0]
    with sqlite3.connect(writer._store._path) as db:
        with pytest.raises(sqlite3.IntegrityError, match='not enabled'):
            db.execute('INSERT INTO authorization_events VALUES (?,?,?,?,?,?,?,?)',
                (3, 'fake', 'WORKER_ASSIGNED', 'bob', 'root', '0'*64, 'a'*64, b'{}'))


@pytest.mark.parametrize('kind', ['projection', 'checkpoint', 'bootstrap', 'guard'])
def test_corruption_blocks_authority(active, kind):
    writer = active[0]
    with sqlite3.connect(writer._store._path) as db:
        if kind == 'checkpoint':
            db.execute('UPDATE authorization_state SET sequence=99')
        elif kind == 'guard':
            db.execute('DROP TRIGGER v4_administrative_kinds_only')
        else:
            table = 'authorization_events' if kind == 'projection' else 'administration_bootstrap'
            trigger_name = table+'_no_update'
            sql = db.execute('SELECT sql FROM sqlite_schema WHERE name=?', (trigger_name,)).fetchone()[0]
            db.execute(f'DROP TRIGGER {trigger_name}')
            if kind == 'projection':
                db.execute("UPDATE authorization_events SET principal_id='wrong'")
            else:
                db.execute('UPDATE administration_bootstrap SET receipt_hash=?', ('0'*64,))
            db.execute(sql)
    with pytest.raises(ReviewIntegrityError):
        writer.read()


def test_failure_after_every_ddl_statement_rolls_back(pending, monkeypatch):
    writer, manifest, anchor = pending
    store_module._expected_schema(4)
    statements, buffer = [], ''
    for line in store_module._MIGRATION_V4.read_text().splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer)
            buffer = ''
    before = snapshot(writer)
    for count in range(1, len(statements)+1):
        def interrupt(db):
            for statement in statements[:count]:
                db.execute(statement)
            raise RuntimeError('injected failure')
        monkeypatch.setattr(writer_module, '_apply_v4', interrupt)
        with pytest.raises(RuntimeError):
            writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
        assert snapshot(writer) == before


def test_target_failure_rolls_back_seed_events(pending, monkeypatch):
    writer, manifest, anchor = pending
    before = snapshot(writer)
    original = writer._store._load
    def fail_target(connection, **kwargs):
        result = original(connection, **kwargs)
        if connection.execute('PRAGMA user_version').fetchone() == (4,):
            raise ReviewIntegrityError('injected target failure')
        return result
    monkeypatch.setattr(writer._store, '_load', fail_target)
    with pytest.raises(ReviewIntegrityError):
        writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
    assert snapshot(writer) == before


def process_worker(path, anchor_json, manifest_json, phase, ready, hold, operation):
    anchor = BootstrapTrustAnchor.model_validate_json(anchor_json)
    manifest = BootstrapManifest.model_validate_json(manifest_json)
    writer = open_writer(path, anchor)
    original = writer._store._transaction
    @contextmanager
    def paused(**kwargs):
        with original(**kwargs) as result:
            yield result
            if kwargs.get('write') and phase == 'before':
                ready.set()
                hold.wait(30)
        if kwargs.get('write') and phase == 'after':
            ready.set()
            hold.wait(30)
    writer._store._transaction = paused
    if operation == 'bootstrap':
        writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
    else:
        writer.append(session=TestSession(writer), request=request(writer))


@pytest.mark.parametrize('operation', ['bootstrap', 'append'])
@pytest.mark.parametrize('phase', ['before', 'after'])
def test_process_death_at_commit(pending, operation, phase):
    writer, manifest, anchor = pending
    if operation == 'append':
        writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
        original_request = request(writer)
    ctx = multiprocessing.get_context('spawn')
    ready, hold = ctx.Event(), ctx.Event()
    process = ctx.Process(target=process_worker, args=(writer._store._path, anchor.model_dump_json(),
        manifest.model_dump_json(), phase, ready, hold, operation))
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
    reopened = open_writer(writer._store._path, anchor)
    if operation == 'bootstrap':
        assert snapshot(reopened)[0] == ((3,) if phase == 'before' else (4,))
        reopened.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
        assert len(reopened.history()) == 2
    else:
        assert len(reopened.history()) == (2 if phase == 'before' else 3)
        receipt = reopened.append(session=TestSession(reopened), request=original_request)
        assert receipt.event_sequence == 3 and len(reopened.history()) == 3


def populated(tmp_path):
    from test_request_journal import make, prepared
    context = make(tmp_path/'populated.sqlite', provision=True)
    store, manager, _, _ = context
    manager.commit(fence=prepared(context))
    store.migrate_to_v3()
    with sqlite3.connect(store._path) as db:
        boundary = db.execute('SELECT * FROM authorization_migration_boundary').fetchone()
    chain = Chain()
    manifest = chain.manifest.model_copy(update=dict(legacy_journal_sequence=boundary[1],
        legacy_journal_hash=boundary[2], legacy_release_sequence=boundary[3], legacy_release_hash=boundary[4]))
    anchor = chain.anchor.model_copy(update={'manifest_hash': record_digest(manifest)})
    return open_writer(store._path, anchor), manifest, anchor


def test_populated_legacy_bytes_preserved_and_journal_recovery_available(tmp_path):
    from tnc.provenance.request_journal import RequestJournalManager, CallerContext
    writer, manifest, anchor = populated(tmp_path)
    legacy_before = dict(snapshot(writer)[1])
    writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
    after = dict(snapshot(writer)[1])
    for table in ('reviews', 'outbox', 'store_state', 'request_intents', 'prepared_requests',
                  'request_events', 'journal_state', 'authorization_migration_boundary'):
        assert after[table] == legacy_before[table]
    journal = RequestJournalManager(store=writer._store, allowed_principals=frozenset({'alice'}))
    assert journal.recover(operation_id='op1', caller=CallerContext(principal_id='alice')).state == 'COMMITTED'
    candidate = writer._store.release_history()[0].request
    with pytest.raises(ReviewStoreError):
        writer._store.commit_release(request=candidate)


def test_outbox_fault_does_not_block_credential_disablement(tmp_path):
    writer, manifest, anchor = populated(tmp_path)
    writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
    with sqlite3.connect(writer._store._path) as db:
        trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='outbox_no_update'").fetchone()[0]
        db.execute('DROP TRIGGER outbox_no_update')
        db.execute('UPDATE outbox SET payload=?', (b'corrupted',))
        db.execute(trigger)
    with pytest.raises(ReviewIntegrityError):
        writer._store.release_history()
    writer.append(session=TestSession(writer), request=request(writer,
        CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='containment'), 'disable'))
    assert writer.read().credentials[0].enabled is False


def test_exact_retry_uses_current_independent_grant(active):
    writer = active[0]
    original = request(writer)
    receipt = writer.append(session=TestSession(writer), request=original)
    writer.append(session=TestSession(writer), request=request(writer, grant('second'), 'second'))
    writer.append(session=TestSession(writer), request=request(writer,
        PermissionRevoked(grant_id='admin', expected_grant_sequence=2, rationale='retire'), 'revoke'))
    assert writer.append(session=TestSession(writer), request=original) == receipt
    assert writer.history()[2].actor.permission_grant_id == 'admin'


def revocation_worker(path, anchor_json, ready, proceed, result):
    writer = open_writer(path, BootstrapTrustAnchor.model_validate_json(anchor_json))
    candidate = request(writer, enrollment('f'*64, 'third'), 'competing')
    class PausedSession:
        def verify_identity(self):
            identity = TestSession(writer, OTHER).verify_identity()
            ready.set()
            if not proceed.wait(20):
                raise RuntimeError('timeout')
            return identity
    try:
        writer.append(session=PausedSession(), request=candidate)
        result.put('appended')
    except AuthorizationError:
        result.put('denied')


@pytest.mark.parametrize('revocation_first', [True, False])
def test_multi_actor_revocation_order(active, revocation_first):
    writer, _, anchor = active
    writer.append(session=TestSession(writer), request=request(writer))  # enroll bob
    writer.append(session=TestSession(writer), request=request(writer, grant('bob-admin', 'bob'), 'bob-admin'))
    ctx = multiprocessing.get_context('spawn')
    ready, proceed, result = ctx.Event(), ctx.Event(), ctx.Queue()
    process = ctx.Process(target=revocation_worker, args=(writer._store._path, anchor.model_dump_json(), ready, proceed, result))
    def revoke_bob():
        writer.append(session=TestSession(writer), request=request(writer,
            PermissionRevoked(grant_id='bob-admin', expected_grant_sequence=4, rationale='revoke'), 'revoke'))
    try:
        process.start()
        assert ready.wait(20)
        if revocation_first:
            revoke_bob()
        proceed.set()
        assert result.get(timeout=20) == ('denied' if revocation_first else 'appended')
        process.join(5)
        assert process.exitcode == 0
        if not revocation_first:
            revoke_bob()
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        result.close()
    assert len(writer.history()) == (5 if revocation_first else 6)


@pytest.mark.parametrize('operation,fragment,occurrence', [
    ('bootstrap', 'INSERT INTO authorization_events', 1),
    ('bootstrap', 'INSERT INTO authorization_events', 2),
    ('bootstrap', 'INSERT INTO administration_bootstrap', 1),
    ('bootstrap', 'UPDATE authorization_state', 1),
    ('append', 'INSERT INTO authorization_events', 1),
    ('append', 'UPDATE authorization_state', 1),
])
def test_partial_write_failure_is_atomic(pending, monkeypatch, operation, fragment, occurrence):
    writer, manifest, anchor = pending
    if operation == 'append':
        writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
        candidate = request(writer)
    before = snapshot(writer)
    original = writer._store._connect
    counter = [0]
    class FaultConnection:
        def __init__(self, connection):
            self.connection = connection
        def __getattr__(self, name):
            return getattr(self.connection, name)
        def execute(self, sql, *args):
            result = self.connection.execute(sql, *args)
            if sql.startswith(fragment):
                counter[0] += 1
                if counter[0] == occurrence:
                    raise RuntimeError('after-write failure')
            return result
    monkeypatch.setattr(writer._store, '_connect', lambda: FaultConnection(original()))
    with pytest.raises(RuntimeError):
        if operation == 'bootstrap':
            writer.migrate_to_v4(provisioning=TestProvisioningSession(anchor), manifest=manifest)
        else:
            writer.append(session=TestSession(writer), request=candidate)
    assert counter[0] == occurrence and snapshot(writer) == before


def test_manifest_boundary_mismatch_rolls_back(pending):
    writer, manifest, anchor = pending
    before = snapshot(writer)
    changed = manifest.model_copy(update={'legacy_journal_sequence': 1, 'legacy_journal_hash': 'a'*64})
    changed_anchor = anchor.model_copy(update={'manifest_hash': record_digest(changed)})
    other = open_writer(writer._store._path, changed_anchor)
    with pytest.raises(ReviewIntegrityError):
        other.migrate_to_v4(provisioning=TestProvisioningSession(changed_anchor), manifest=changed)
    assert snapshot(writer) == before
