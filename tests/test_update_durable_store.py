from contextlib import closing
import sqlite3

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update, locator
from test_update_verification import signed
from test_update_integration import host
from test_update_storage_validation import stored, image_from, checkpoint
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.update_storage_models import StoredLocatorPublication
from tnc.provenance.update_durable_store import UpdateDurableStore, UpdateStoreError, DDL, _rows


@pytest.fixture
def database(tmp_path, stored):
    image = image_from(*stored)
    empty = image_from(stored[0], [])
    path = tmp_path / 'update.sqlite'
    store = UpdateDurableStore.create_empty_for_testing(path, empty, trusted_checkpoint=checkpoint(empty))
    # Test-only materialization, deliberately no production import/write API.
    with closing(sqlite3.connect(path)) as connection:
        connection.execute('PRAGMA foreign_keys=ON')
        for name, rows in _rows(image, checkpoint(image)).items():
            if name == 'store_metadata': continue
            if name == 'store_state':
                connection.execute('DELETE FROM store_state')
            for row in rows:
                connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
        connection.commit()
    return store, image


def mutate(store, sql, args=()):
    with closing(sqlite3.connect(store.path)) as connection:
        # Restore original guards afterward so these cases test data validation.
        for statement in DDL:
            if statement.startswith('CREATE TRIGGER'):
                connection.execute('DROP TRIGGER ' + statement.split()[2])
        connection.execute(sql, args)
        for statement in DDL:
            if statement.startswith('CREATE TRIGGER'): connection.execute(statement)
        connection.commit()


def test_roundtrip_and_no_database_change(database):
    store, image = database
    before = store.path.read_bytes()
    assert canonical_bytes(store.load(trusted_checkpoint=checkpoint(image))) == canonical_bytes(image)
    assert store.path.read_bytes() == before


def test_missing_store_not_created(tmp_path, stored):
    path = tmp_path / 'absent.sqlite'
    with pytest.raises(UpdateStoreError):
        UpdateDurableStore(path).load(trusted_checkpoint=checkpoint(image_from(*stored)))
    assert not path.exists()


def test_creation_never_overwrites(database):
    store, image = database
    before = store.path.read_bytes()
    empty = image_from(image.base_head, [])
    with pytest.raises(UpdateStoreError):
        store.create_empty_for_testing(store.path, empty, trusted_checkpoint=checkpoint(empty))
    assert store.path.read_bytes() == before


def test_nonempty_creation_rejected_before_io(tmp_path, stored):
    image = image_from(*stored)
    path = tmp_path / 'no.sqlite'
    with pytest.raises(UpdateStoreError):
        UpdateDurableStore.create_empty_for_testing(path, image, trusted_checkpoint=checkpoint(image))
    assert not path.exists()


def test_empty_roundtrip(tmp_path, stored):
    image = image_from(stored[0], [])
    store = UpdateDurableStore.create_empty_for_testing(tmp_path / 'empty.sqlite', image, trusted_checkpoint=checkpoint(image))
    assert store.load(trusted_checkpoint=checkpoint(image)) == image


@pytest.mark.parametrize('sql', [
    'PRAGMA user_version=99', 'PRAGMA application_id=0',
    'CREATE TABLE extra (id INTEGER)', 'CREATE INDEX extra ON events(kind)',
    'DROP TRIGGER events_no_delete',
    'CREATE VIEW extra AS SELECT * FROM events',
])
def test_schema_changes_fail(database, sql):
    store, image = database
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute(sql)
        connection.commit()
    with pytest.raises(UpdateStoreError, match='^INVALID_STORE$'):
        store.load(trusted_checkpoint=checkpoint(image))


@pytest.mark.parametrize('sql', [
    'DELETE FROM registrations', 'DELETE FROM preparations', 'DELETE FROM commits',
    'DELETE FROM store_metadata', 'DELETE FROM store_state', 'DELETE FROM events WHERE sequence=2',
    "UPDATE registrations SET owner='other'", "UPDATE registrations SET intent_hash='wrong'",
    'UPDATE preparations SET event_sequence=1', "UPDATE commits SET archive_hash='wrong'",
    'UPDATE commits SET authority_sequence=99', "UPDATE store_metadata SET base_hash='wrong'",
    "UPDATE store_metadata SET deployment='other'", 'UPDATE store_state SET authority_revision=4',
    'UPDATE store_state SET event_count=0', "UPDATE store_state SET image_hash='wrong'",
    "UPDATE events SET kind='PUBLISH' WHERE sequence=1", "UPDATE events SET recorded_at='wrong' WHERE sequence=1",
    "UPDATE events SET entry_hash='wrong' WHERE sequence=1",
    "INSERT INTO publications VALUES (1, (SELECT operation_id FROM commits))",
    "UPDATE events SET canonical=x'7b7d' WHERE sequence=1",
    "UPDATE store_state SET checkpoint=x'7b7d'",
])
def test_corrupt_projections_and_records_fail(database, sql):
    store, image = database
    mutate(store, sql)
    with pytest.raises(UpdateStoreError, match='^INVALID_STORE$'):
        store.load(trusted_checkpoint=checkpoint(image))


def test_untrusted_checkpoint_cannot_be_replaced_by_local(database):
    store, image = database
    bad = checkpoint(image).model_copy(update={'image_hash': 'f'*64})
    with pytest.raises(UpdateStoreError): store.load(trusted_checkpoint=bad)


def test_oversized_projection_rejected_before_decode(database, monkeypatch):
    store, image = database
    mutate(store, 'UPDATE registrations SET owner=?', ('x' * (4194304 + 1),))
    def forbidden(*args, **kwargs): pytest.fail('Decoded oversized store')
    monkeypatch.setattr('tnc.provenance.update_durable_store.decode_canonical', forbidden)
    with pytest.raises(UpdateStoreError): store.load(trusted_checkpoint=checkpoint(image))


@pytest.mark.parametrize('table', ['events', 'registrations', 'preparations', 'commits', 'store_metadata'])
def test_append_only_guards(database, table):
    store, image = database
    with closing(sqlite3.connect(store.path)) as connection:
        with pytest.raises(sqlite3.IntegrityError): connection.execute(f'DELETE FROM {table}')
    assert store.load(trusted_checkpoint=checkpoint(image)) == image


def test_uncommitted_change_not_visible(database):
    store, image = database
    with closing(sqlite3.connect(store.path, isolation_level=None)) as writer:
        writer.execute('BEGIN IMMEDIATE')
        writer.execute("UPDATE store_state SET image_hash='wrong'")
        assert store.load(trusted_checkpoint=checkpoint(image)) == image
        writer.execute('ROLLBACK')


def test_multiple_publication_observations(database):
    store, image = database
    commit = image.events[-1].payload
    publication = StoredLocatorPublication(operation_id=commit.operation_id, credential_id='9'*64, locator=locator(commit.head))
    new = image_from(image.base_head, [e.payload for e in image.events] + [publication, publication])
    with closing(sqlite3.connect(store.path)) as connection:
        expected = _rows(new, checkpoint(new))
        for name in ('events', 'publications'):
            for row in expected[name]:
                if row[0] <= 4: continue
                connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
        connection.execute('DELETE FROM store_state')
        row = expected['store_state'][0]
        connection.execute(f"INSERT INTO store_state VALUES ({','.join('?' for _ in row)})", row)
        connection.commit()
    assert store.load(trusted_checkpoint=checkpoint(new)) == new


def test_initialization_failure_rolls_back_schema(tmp_path, stored, monkeypatch):
    image = image_from(stored[0], [])
    path = tmp_path / 'failed.sqlite'
    def fail(*args): raise RuntimeError('Injected before commit')
    monkeypatch.setattr(UpdateDurableStore, '_load', staticmethod(fail))
    with pytest.raises(UpdateStoreError):
        UpdateDurableStore.create_empty_for_testing(path, image, trusted_checkpoint=checkpoint(image))
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT name FROM sqlite_schema').fetchall() == []
        assert connection.execute('PRAGMA user_version').fetchone() == (0,)


def test_invalid_creation_checkpoint_leaves_no_file(tmp_path, stored):
    image = image_from(stored[0], [])
    path = tmp_path / 'invalid.sqlite'
    with pytest.raises(UpdateStoreError):
        UpdateDurableStore.create_empty_for_testing(path, image,
            trusted_checkpoint=checkpoint(image).model_copy(update={'image_hash':'f'*64}))
    assert not path.exists()


def test_noncanonical_event_rejected(database):
    store, image = database
    mutate(store, 'UPDATE events SET canonical=? WHERE sequence=1',
        (canonical_bytes(image.events[0]) + b'\n',))
    with pytest.raises(UpdateStoreError): store.load(trusted_checkpoint=checkpoint(image))


def test_event_capacity_sql_guard(database):
    store, image = database
    row = list(_rows(image, checkpoint(image))['events'][0])
    row[0], row[4] = 257, 'f'*64
    with closing(sqlite3.connect(store.path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute('INSERT INTO events VALUES (?,?,?,?,?,?)', row)


def test_invalid_file_safe_error(tmp_path, stored):
    path = tmp_path / 'not-sqlite'
    path.write_bytes(b'not a database')
    with pytest.raises(UpdateStoreError, match='^INVALID_STORE$'):
        UpdateDurableStore(path).load(trusted_checkpoint=checkpoint(image_from(*stored)))
