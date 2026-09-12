from contextlib import closing
from datetime import timedelta
import sqlite3

import pytest

from test_reconciliation_simulation import (
    case, inventory, config, update, signed, host, stored, reconciliation, sim,
    NOW, accepted,
)
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.reconciliation_simulation import validate_simulation_state
from tnc.provenance import reconciliation_durable_store as module
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore, AuthorityStoreError


@pytest.fixture
def db(tmp_path, sim):
    state, _, _, _, anchor = sim
    return TestCheckpointAuthorityStore.create_for_testing(tmp_path / 'authority.db', state,
        trusted_initial_envelope=anchor, now=NOW)


def execute(db, sql, args=()):
    with closing(sqlite3.connect(db.path)) as connection:
        connection.execute(sql, args)
        connection.commit()


def install_history(db, state):
    # Fixture-only insertion; no acceptance/submission adapter exists yet.
    with closing(sqlite3.connect(db.path)) as connection:
        rows = module._rows(state)
        connection.execute('DELETE FROM authority_state')
        for name in ('authority_state', 'authority_acceptances'):
            for row in rows[name]:
                connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
        connection.commit()


def test_initial_roundtrip(db, sim):
    assert canonical_bytes(db.load(now=NOW)) == canonical_bytes(sim[0])
    assert db.load(now=NOW) is not sim[0]


def test_history_reconstruction_and_original_bytes(db, sim):
    result = accepted(sim)
    install_history(db, result.proposed_state)
    assert db.load(now=NOW) == result.proposed_state
    with closing(sqlite3.connect(db.path)) as connection:
        assert connection.execute('SELECT acceptance FROM authority_acceptances').fetchone()[0] == canonical_bytes(result.acceptance)


def test_read_does_not_change_tables(db):
    with closing(sqlite3.connect(db.path)) as connection:
        before = list(connection.iterdump())
    db.load(now=NOW)
    with closing(sqlite3.connect(db.path)) as connection:
        assert list(connection.iterdump()) == before


def test_existing_file_not_overwritten(db, sim):
    before = db.path.read_bytes()
    with pytest.raises(AuthorityStoreError):
        TestCheckpointAuthorityStore.create_for_testing(db.path, sim[0], trusted_initial_envelope=sim[4], now=NOW)
    assert db.path.read_bytes() == before
    assert db.load(now=NOW) == sim[0]


def test_missing_file_not_created(tmp_path, sim):
    path = tmp_path / 'missing.db'
    with pytest.raises(AuthorityStoreError):
        TestCheckpointAuthorityStore(path, trusted_initial_envelope=sim[4]).load(now=NOW)
    assert not path.exists()


def test_initial_creation_rejects_history(tmp_path, sim):
    path = tmp_path / 'new.db'
    with pytest.raises(AuthorityStoreError):
        TestCheckpointAuthorityStore.create_for_testing(path, accepted(sim).proposed_state,
            trusted_initial_envelope=sim[4], now=NOW)
    assert not path.exists()


@pytest.mark.parametrize('change', [dict(store_instance_id='wrong'), dict(issuer_id='wrong')])
def test_independent_anchor(db, sim, change):
    other = TestCheckpointAuthorityStore(db.path, trusted_initial_envelope=sim[4].model_copy(update=change))
    with pytest.raises(AuthorityStoreError):
        other.load(now=NOW)


@pytest.mark.parametrize('sql', [
    'PRAGMA user_version=2', 'PRAGMA application_id=0',
    'CREATE TABLE unexpected (x INTEGER)',
    'CREATE INDEX extra ON authority_state(revision)',
    'DROP TRIGGER authority_metadata_no_update',
    'DELETE FROM authority_state',
    "UPDATE authority_state SET digest='" + '0'*64 + "'",
    'UPDATE authority_state SET revision=2',
    'UPDATE authority_state SET policy_revision=2',
    "UPDATE authority_state SET envelope_digest='" + '0'*64 + "'",
    "UPDATE authority_state SET policy_digest='" + '0'*64 + "'",
    "UPDATE authority_state SET canonical=CAST('{}' AS BLOB)",
])
def test_corruption_rejected(db, sql):
    execute(db, sql)
    with pytest.raises(AuthorityStoreError, match='^INVALID_AUTHORITY_STORE$'):
        db.load(now=NOW)


@pytest.mark.parametrize('field,value', [('owner','other'), ('acceptance',b'{}'), ('entry',b'{}'), ('request',b'{}')])
def test_history_projection_mismatch(db, sim, field, value):
    install_history(db, accepted(sim).proposed_state)
    # Restore the exact trigger so schema verification passes, leaving bad rows.
    execute(db, 'DROP TRIGGER authority_acceptances_no_update')
    execute(db, f'UPDATE authority_acceptances SET {field}=?', (value,))
    execute(db, next(s for s in module.DDL if s.startswith('CREATE TRIGGER authority_acceptances_no_update ')))
    with pytest.raises(AuthorityStoreError):
        db.load(now=NOW)


def test_missing_history_projection(db, sim):
    install_history(db, accepted(sim).proposed_state)
    execute(db, 'DROP TRIGGER authority_acceptances_no_delete')
    execute(db, 'DELETE FROM authority_acceptances')
    execute(db, next(s for s in module.DDL if s.startswith('CREATE TRIGGER authority_acceptances_no_delete ')))
    with pytest.raises(AuthorityStoreError):
        db.load(now=NOW)


def test_forged_canonical_history_with_matching_projections(db, sim):
    state = accepted(sim).proposed_state
    entry = state.history[0]
    entry = entry.model_copy(update={'authorization': entry.authorization.model_copy(update={'approved': False})})
    install_history(db, state.model_copy(update={'history': (entry,)}))
    with pytest.raises(AuthorityStoreError):
        db.load(now=NOW)


def test_noncanonical_state(db, sim):
    execute(db, 'UPDATE authority_state SET canonical=?', (b' ' + canonical_bytes(sim[0]),))
    with pytest.raises(AuthorityStoreError):
        db.load(now=NOW)


@pytest.mark.parametrize('limit', ['STATE_LIMIT', 'STORED_LIMIT', 'RECONCILIATION_LIMIT'])
def test_lengths_checked_before_decode(db, monkeypatch, limit):
    monkeypatch.setattr(module, limit, 1)
    monkeypatch.setattr(module, 'decode_simulation_record', lambda *args: pytest.fail('Decoded oversized data'))
    with pytest.raises(AuthorityStoreError):
        db.load(now=NOW)


@pytest.mark.parametrize('now', [NOW.replace(tzinfo=None), NOW-timedelta(days=1), 'not-a-time'])
def test_invalid_clock(db, now):
    with pytest.raises(AuthorityStoreError):
        db.load(now=now)


def test_creation_ddl_rollback(tmp_path, sim, monkeypatch):
    path = tmp_path / 'interrupted.db'
    monkeypatch.setattr(module, 'DDL', module.DDL[:1] + ('INVALID SQL',))
    with pytest.raises(AuthorityStoreError):
        TestCheckpointAuthorityStore.create_for_testing(path, sim[0], trusted_initial_envelope=sim[4], now=NOW)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT name FROM sqlite_schema').fetchall() == []
        assert connection.execute('PRAGMA user_version').fetchone() == (0,)


def test_creation_validation_rollback(tmp_path, sim, monkeypatch):
    path = tmp_path / 'interrupted.db'
    def fail(*args, **kwargs):
        raise ValueError('failure')
    monkeypatch.setattr(TestCheckpointAuthorityStore, '_load', fail)
    with pytest.raises(AuthorityStoreError):
        TestCheckpointAuthorityStore.create_for_testing(path, sim[0], trusted_initial_envelope=sim[4], now=NOW)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT name FROM sqlite_schema').fetchall() == []


@pytest.mark.parametrize('table', ['authority_metadata', 'authority_acceptances'])
@pytest.mark.parametrize('action', ['UPDATE', 'DELETE'])
def test_immutable_projection_guards(db, sim, table, action):
    install_history(db, accepted(sim).proposed_state)
    sql = f'DELETE FROM {table}' if action == 'DELETE' else f'UPDATE {table} SET ' + ('id=id' if table == 'authority_metadata' else 'owner=owner')
    with pytest.raises(sqlite3.IntegrityError):
        execute(db, sql)


def test_no_write_or_submission_routes(db):
    for name in ('submit','recover','observe_current','replace_policy_for_testing','commit'):
        assert not hasattr(db, name)


def test_shared_validator_rejects_untyped_state(sim):
    with pytest.raises(ValueError, match='INVALID_SIMULATION_STATE'):
        validate_simulation_state(sim[0].model_dump(), trusted_initial_envelope=sim[4], now=NOW)
