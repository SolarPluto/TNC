"""Phase 1 temporary-store tests; direct SQL population is test scaffolding."""
from contextlib import closing
import sqlite3

import pytest

from test_external_witness_logic import h, change
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.external_witness_logic import WitnessImage, witness_digest
from tnc.provenance import external_witness_store as storage
from tnc.provenance.external_witness_store import TestExternalWitnessStore, WitnessStoreError


@pytest.fixture
def store(tmp_path, h):
    return TestExternalWitnessStore.create_for_testing(tmp_path/'witness.db', trusted_initial=h.initial, now=20)


def populate(store, image):
    """No writer API is implemented; materialize a pure image in a temp fixture."""
    with closing(sqlite3.connect(store.path)) as db:
        for name, rows in storage._rows(image).items():
            if name == 'witness_anchor': continue
            if name == 'witness_receipts':
                for row in rows: db.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
            else:
                columns = [r[1] for r in db.execute(f'PRAGMA table_info({name})')]
                db.execute(f"UPDATE {name} SET {','.join(c+'=?' for c in columns[1:])} WHERE id=1", rows[0][1:])
        db.commit()


def mutate(store, sql):
    with closing(sqlite3.connect(store.path)) as db:
        db.executescript(sql)


def test_explicit_creation_and_restart(store, h):
    image = store.load_audit(now=20)
    assert image == WitnessImage(initial=h.initial, receipts=())
    assert TestExternalWitnessStore(store.path, trusted_initial=h.initial).load_audit(now=300) == image
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        assert db.execute('PRAGMA application_id').fetchone() == (storage.APPLICATION_ID,)
        assert db.execute('PRAGMA user_version').fetchone() == (1,)
        assert all(r[-1] == 1 for r in db.execute('PRAGMA table_list') if r[1] in storage.TABLES)


def test_full_history_original_receipt_bytes_after_expiry(store, h):
    first = h.submit()
    second = h.submit(first.proposed_image, now=21)
    populate(store, second.proposed_image)
    image = store.load_audit(now=1000)
    assert image == second.proposed_image
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute('SELECT receipt FROM witness_receipts WHERE witness_sequence=1').fetchone()[0] == canonical_bytes(first.receipt)


def test_missing_never_creates(tmp_path, h):
    path = tmp_path/'absent.db'
    with pytest.raises(WitnessStoreError, match='^INVALID_WITNESS_STORE$'):
        TestExternalWitnessStore(path, trusted_initial=h.initial).load_audit(now=20)
    assert not path.exists()


def test_existing_creation_refused_without_changes(store, h):
    before = store.path.read_bytes()
    with pytest.raises(WitnessStoreError, match='CREATION_FAILED'):
        TestExternalWitnessStore.create_for_testing(store.path, trusted_initial=h.initial, now=20)
    assert store.path.read_bytes() == before


@pytest.mark.parametrize('suffix', ['-wal', '-shm', '-journal'])
def test_orphan_sidecar_rejected(tmp_path, h, suffix):
    path = tmp_path/'witness.db'
    sidecar = tmp_path/('witness.db'+suffix)
    sidecar.write_bytes(b'keep')
    with pytest.raises(WitnessStoreError):
        TestExternalWitnessStore.create_for_testing(path, trusted_initial=h.initial, now=20)
    assert not path.exists() and sidecar.read_bytes() == b'keep'


def test_missing_parent_not_created(tmp_path, h):
    path = tmp_path/'missing'/'witness.db'
    with pytest.raises(WitnessStoreError):
        TestExternalWitnessStore.create_for_testing(path, trusted_initial=h.initial, now=20)
    assert not path.parent.exists()


@pytest.mark.parametrize('now', [True, -1, '20', 20.5, 2**63, 9])
def test_invalid_creation_time_before_file_creation(tmp_path, h, now):
    path = tmp_path/'new.db'
    with pytest.raises(WitnessStoreError):
        TestExternalWitnessStore.create_for_testing(path, trusted_initial=h.initial, now=now)
    assert not path.exists()


@pytest.mark.parametrize('point', ['ddl_statement', 'initial_rows', 'before_commit'])
def test_creation_transaction_rollback(tmp_path, h, monkeypatch, point):
    path = tmp_path/'new.db'
    def fault(self, current):
        if current == point: raise RuntimeError('injected')
    monkeypatch.setattr(TestExternalWitnessStore, '_hook', fault)
    with pytest.raises(WitnessStoreError):
        TestExternalWitnessStore.create_for_testing(path, trusted_initial=h.initial, now=20)
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT count(*) FROM sqlite_schema WHERE name LIKE 'witness_%'").fetchone() == (0,)
        assert db.execute('PRAGMA user_version').fetchone() == (0,)
    with pytest.raises(WitnessStoreError): TestExternalWitnessStore(path, trusted_initial=h.initial).load_audit(now=20)


def test_creation_commit_return_gap(tmp_path, h, monkeypatch):
    path = tmp_path/'new.db'
    def fault(self, point):
        if point == 'after_commit': raise RuntimeError('lost return')
    monkeypatch.setattr(TestExternalWitnessStore, '_hook', fault)
    with pytest.raises(WitnessStoreError):
        TestExternalWitnessStore.create_for_testing(path, trusted_initial=h.initial, now=20)
    assert TestExternalWitnessStore(path, trusted_initial=h.initial).load_audit(now=20).initial == h.initial


@pytest.mark.parametrize('sql', [
    'PRAGMA application_id=3;', 'PRAGMA user_version=9;',
    'CREATE TABLE extra(x TEXT) STRICT;',
    'DROP TRIGGER witness_receipts_no_update;',
    "UPDATE witness_image SET digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';",
    'UPDATE witness_image SET receipt_count=1;',
    'UPDATE witness_head SET witness_sequence=1;',
    "UPDATE witness_head SET epoch_id='wrong';",
    'DROP TRIGGER witness_head_no_delete; DELETE FROM witness_head;',
    "UPDATE witness_image SET canonical=CAST('{}' AS BLOB);",
    "UPDATE witness_image SET canonical=CAST(CAST(canonical AS TEXT)||' ' AS BLOB);",
])
def test_schema_and_projection_corruption(store, sql):
    mutate(store, sql)
    with pytest.raises(WitnessStoreError, match='^INVALID_WITNESS_STORE$'): store.load_audit(now=20)


@pytest.mark.parametrize('field,value', [('deployment_id','other'), ('store_instance_id','other'),
    ('local_store_id','other'), ('bootstrap_anchor_digest','f'*64)])
def test_independent_anchor_binding(store, h, field, value):
    anchor = change(h.initial, context=change(h.initial.context, **{field:value}))
    with pytest.raises(WitnessStoreError): TestExternalWitnessStore(store.path, trusted_initial=anchor).load_audit(now=20)


def test_future_history_rejected(store, h):
    populate(store, h.submit(now=30).proposed_image)
    with pytest.raises(WitnessStoreError): store.load_audit(now=29)


@pytest.mark.parametrize('table', ['witness_anchor', 'witness_receipts'])
@pytest.mark.parametrize('action', ['UPDATE', 'DELETE'])
def test_immutable_guards(store, h, table, action):
    populate(store, h.submit().proposed_image)
    sql = f'DELETE FROM {table}' if action == 'DELETE' else f'UPDATE {table} SET '+('id=id' if table=='witness_anchor' else 'request_id=request_id')
    with closing(sqlite3.connect(store.path)) as db:
        with pytest.raises(sqlite3.IntegrityError): db.execute(sql)


@pytest.mark.parametrize('column,value', [('witness_sequence',1), ('request_id','request-1')])
def test_sequence_and_operation_uniqueness(store, h, column, value):
    image = h.submit().proposed_image
    populate(store, image)
    row = list(storage._rows(image)['witness_receipts'][0])
    row[0], row[1], row[3] = 2, 'different', 'f'*64
    row[0 if column == 'witness_sequence' else 1] = value
    with closing(sqlite3.connect(store.path)) as db:
        with pytest.raises(sqlite3.IntegrityError): db.execute('INSERT INTO witness_receipts VALUES (?,?,?,?,?,?,?,?)', row)


def test_oversize_before_decode(store, monkeypatch):
    with closing(sqlite3.connect(store.path)) as db:
        db.execute('PRAGMA ignore_check_constraints=ON')
        db.execute('UPDATE witness_image SET canonical=?', (b'x'*(storage.IMAGE_LIMIT+1),))
        db.commit()
    def forbidden(*args): raise AssertionError('Must bound before decoding')
    monkeypatch.setattr(storage, 'decode_canonical', forbidden)
    with pytest.raises(WitnessStoreError): store.load_audit(now=20)


def test_missing_receipt_projection(store, h):
    populate(store, h.submit().proposed_image)
    with closing(sqlite3.connect(store.path)) as db:
        db.execute('DROP TRIGGER witness_receipts_no_delete')
        db.execute('DELETE FROM witness_receipts')
        db.execute(next(s for s in storage.DDL if s.startswith('CREATE TRIGGER witness_receipts_no_delete ')))
        db.commit()
    with pytest.raises(WitnessStoreError): store.load_audit(now=20)


def test_consistent_projection_tampering_still_replays_pure_rules(store, h):
    image = h.submit().proposed_image
    populate(store, image)
    bad = change(image.receipts[0], caller=change(image.receipts[0].caller, request_digest='f'*64))
    forged = change(image, receipts=(bad,))
    with closing(sqlite3.connect(store.path)) as db:
        db.execute('UPDATE witness_image SET canonical=?,digest=?', (canonical_bytes(forged), witness_digest(forged)))
        db.execute('DROP TRIGGER witness_receipts_no_update')
        db.execute('UPDATE witness_receipts SET receipt=?,receipt_digest=?', (canonical_bytes(bad), witness_digest(bad)))
        db.execute(next(s for s in storage.DDL if s.startswith('CREATE TRIGGER witness_receipts_no_update ')))
        db.commit()
    with pytest.raises(WitnessStoreError): store.load_audit(now=20)


def test_ro_snapshot_alongside_writer(store, monkeypatch):
    statements, original = [], sqlite3.connect
    def connect(*args, **kwargs):
        db = original(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db
    with closing(original(store.path, isolation_level=None)) as writer:
        writer.execute('BEGIN IMMEDIATE')
        writer.execute('UPDATE witness_head SET witness_sequence=99')
        monkeypatch.setattr(storage.sqlite3, 'connect', connect)
        before = writer.execute('SELECT canonical FROM witness_image').fetchone()
        assert store.load_audit(now=20).initial.witness_sequence == 0
        assert writer.execute('SELECT witness_sequence FROM witness_head').fetchone() == (99,)
        assert writer.execute('SELECT canonical FROM witness_image').fetchone() == before
        writer.execute('ROLLBACK')
    assert 'PRAGMA query_only=ON' in statements and 'BEGIN' in statements
    assert 'BEGIN IMMEDIATE' not in statements
    assert not any(s.startswith(('INSERT','UPDATE','DELETE')) for s in statements)


def test_capacity_image_loads(store, h):
    image = WitnessImage(initial=h.initial, receipts=())
    for _ in range(64): image = h.submit(image).proposed_image
    populate(store, image)
    assert len(store.load_audit(now=200).receipts) == 64


def test_no_mutation_api_or_signature_columns(store):
    assert not any(hasattr(store, name) for name in ('submit','apply','observe_current','replace_policy'))
    assert 'signature' not in ' '.join(storage.DDL)


def test_entire_old_restore_not_self_detectable(store, h, tmp_path):
    backup = tmp_path/'backup.db'
    with closing(sqlite3.connect(store.path)) as source, closing(sqlite3.connect(backup)) as dest:
        source.backup(dest)
    populate(store, h.submit().proposed_image)
    assert len(store.load_audit(now=20).receipts) == 1
    with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(store.path)) as dest:
        source.backup(dest)
    assert store.load_audit(now=20).receipts == ()
