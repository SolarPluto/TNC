"""Isolated temporary authority storage inspection; no acceptance writer or signing."""
from contextlib import closing
from datetime import datetime
from pathlib import Path
import sqlite3

from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.reconciliation_models import RECONCILIATION_LIMIT
from tnc.provenance.reconciliation_simulation import (
    STATE_LIMIT, AuthoritySimulationState, decode_simulation_record,
    validate_simulation_state,
)

APPLICATION_ID = 0x544E4341
SCHEMA_VERSION = 1
STORED_LIMIT = 64 * 1024 * 1024
TABLES = {
    'authority_metadata': 'id INTEGER PRIMARY KEY CHECK(id=1), profile TEXT NOT NULL, deployment TEXT NOT NULL, store_instance TEXT NOT NULL, initial_envelope BLOB NOT NULL CHECK(length(initial_envelope) BETWEEN 1 AND 65536), initial_digest TEXT NOT NULL',
    'authority_state': 'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 33554432), digest TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 65), envelope_digest TEXT NOT NULL, policy_revision INTEGER NOT NULL CHECK(policy_revision>0), policy_digest TEXT NOT NULL',
    'authority_acceptances': 'request_id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL UNIQUE CHECK(revision BETWEEN 2 AND 65), acceptance_id TEXT NOT NULL UNIQUE, request BLOB NOT NULL CHECK(length(request) BETWEEN 1 AND 65536), acceptance BLOB NOT NULL CHECK(length(acceptance) BETWEEN 1 AND 65536), entry BLOB NOT NULL CHECK(length(entry) BETWEEN 1 AND 65536)',
}
DDL = tuple(f'CREATE TABLE {name} ({columns}) STRICT' for name, columns in TABLES.items()) + tuple(
    f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT, 'Append only'); END"
    for name in TABLES if name != 'authority_state' for action in ('UPDATE', 'DELETE')
)


class AuthorityStoreError(ValueError):
    """Fixed diagnostics without paths or stored evidence."""


def _require(condition):
    if not condition:
        raise AuthorityStoreError('INVALID_AUTHORITY_STORE')


def _schema(connection):
    return connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()


def _expected_schema():
    with closing(sqlite3.connect(':memory:')) as connection:
        for statement in DDL:
            connection.execute(statement)
        return _schema(connection)


def _rows(state):
    anchor = state.initial_envelope
    return {
        'authority_metadata': [(1, 'SYNTHETIC_TEST_ONLY_V1', anchor.deployment_id,
            anchor.store_instance_id, canonical_bytes(anchor), record_digest(anchor))],
        'authority_state': [(1, canonical_bytes(state), record_digest(state),
            state.current_envelope.authority_revision, record_digest(state.current_envelope),
            state.policy.revision, record_digest(state.policy))],
        'authority_acceptances': [(e.request.request_id, e.request.principal_id,
            e.acceptance.successor.authority_revision, e.acceptance.acceptance_id,
            canonical_bytes(e.request), canonical_bytes(e.acceptance), canonical_bytes(e))
            for e in state.history],
    }


class TestCheckpointAuthorityStore:
    """Host-only inspection with a pinned synthetic anchor; not rollback protection."""
    __test__ = False

    def __init__(self, path, *, trusted_initial_envelope):
        self.path = Path(path).absolute()
        self._anchor = trusted_initial_envelope

    @classmethod
    def create_for_testing(cls, path, initial_state, *, trusted_initial_envelope, now):
        """Exclusive initial creation only. Failure may leave an invalid empty file."""
        try:
            state = validate_simulation_state(initial_state,
                trusted_initial_envelope=trusted_initial_envelope, now=now)
            _require(not state.history)
            store = cls(path, trusted_initial_envelope=trusted_initial_envelope)
            with store.path.open('xb'):
                pass
            with closing(sqlite3.connect(store.path, isolation_level=None, timeout=1)) as connection:
                connection.execute('PRAGMA foreign_keys=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                _require(connection.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',))
                connection.execute('PRAGMA synchronous=FULL')
                _require(connection.execute('PRAGMA synchronous').fetchone() == (2,))
                connection.execute('BEGIN IMMEDIATE')
                try:
                    for statement in DDL:
                        connection.execute(statement)
                    connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                    for name, rows in _rows(state).items():
                        for row in rows:
                            connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
                    store._load(connection, now=now)
                    connection.execute('COMMIT')
                except Exception:
                    connection.execute('ROLLBACK')
                    raise
            return store
        except Exception:
            raise AuthorityStoreError('AUTHORITY_STORE_CREATION_FAILED') from None

    def load(self, *, now):
        """Read a bounded consistent snapshot. No repair or request-facing recovery."""
        try:
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True,
                    isolation_level=None, timeout=1)) as connection:
                connection.execute('PRAGMA query_only=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.execute('PRAGMA foreign_keys=ON')
                connection.execute('BEGIN')
                try:
                    return self._load(connection, now=now)
                finally:
                    connection.execute('ROLLBACK')
        except Exception:
            raise AuthorityStoreError('INVALID_AUTHORITY_STORE') from None

    def _load(self, connection, *, now):
        _require(type(now) is datetime and now.utcoffset() is not None)
        _require(connection.execute('PRAGMA application_id').fetchone() == (APPLICATION_ID,))
        _require(connection.execute('PRAGMA user_version').fetchone() == (SCHEMA_VERSION,))
        _require(connection.execute('PRAGMA foreign_keys').fetchone() == (1,))
        _require(connection.execute('PRAGMA journal_mode').fetchone() == ('wal',))
        size, count = connection.execute('SELECT coalesce(sum(length(CAST(sql AS BLOB))),0),count(*) FROM sqlite_schema').fetchone()
        _require(size <= 65536 and count <= 64)
        _require(_schema(connection) == _expected_schema())
        total = 0
        for name in TABLES:
            count = connection.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
            _require(count <= 64 if name == 'authority_acceptances' else count == 1)
            for column in (row[1] for row in connection.execute(f'PRAGMA table_info({name})')):
                maximum, amount = connection.execute(f'SELECT coalesce(max(length(CAST({column} AS BLOB))),0),coalesce(sum(length(CAST({column} AS BLOB))),0) FROM {name}').fetchone()
                limit = STATE_LIMIT if (name, column) == ('authority_state', 'canonical') else RECONCILIATION_LIMIT
                _require(maximum <= limit)
                total += amount
                _require(total <= STORED_LIMIT)
        raw = connection.execute('SELECT canonical FROM authority_state').fetchone()[0]
        state = decode_simulation_record(AuthoritySimulationState, raw)
        state = validate_simulation_state(state, trusted_initial_envelope=self._anchor, now=now)
        for name, expected in _rows(state).items():
            _require(sorted(connection.execute(f'SELECT * FROM {name}').fetchall()) == sorted(expected))
        _require(connection.execute('PRAGMA foreign_key_check').fetchone() is None)
        _require(connection.execute('PRAGMA quick_check(1)').fetchone() == ('ok',))
        return state
