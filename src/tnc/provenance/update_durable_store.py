"""Bounded SQLite inspection and explicit empty test-store creation.

Not a production authority provider, update writer, or filesystem publisher.
"""
from contextlib import closing
from pathlib import Path
import sqlite3

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical, record_digest
from tnc.provenance.update_models import UpdateAuthorityHead
from tnc.provenance.update_storage_models import (
    EVENT_LIMIT, IMAGE_LIMIT, UpdateStorageImage, UpdateStorageCheckpoint, StoredUpdateEvent,
)
from tnc.provenance.update_storage_validation import decode_update_storage_record, validate_update_storage_image

APPLICATION_ID = 0x544E4355
SCHEMA_VERSION = 1
TABLES = {
    'store_metadata': 'id INTEGER PRIMARY KEY CHECK(id=1), deployment TEXT NOT NULL, base BLOB NOT NULL, base_hash TEXT NOT NULL',
    'events': "sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 256), kind TEXT NOT NULL CHECK(kind IN ('AUTHORITY','REGISTER','PREPARE','COMMIT','PUBLISH')), recorded_at TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE, canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 4194304)",
    'registrations': 'operation_id TEXT PRIMARY KEY, event_sequence INTEGER NOT NULL UNIQUE REFERENCES events(sequence), owner TEXT NOT NULL, intent_hash TEXT NOT NULL',
    'preparations': 'event_sequence INTEGER PRIMARY KEY REFERENCES events(sequence), operation_id TEXT NOT NULL REFERENCES registrations(operation_id)',
    'commits': 'operation_id TEXT PRIMARY KEY REFERENCES registrations(operation_id), event_sequence INTEGER NOT NULL UNIQUE REFERENCES events(sequence), authority_sequence INTEGER NOT NULL UNIQUE, receipt_hash TEXT NOT NULL, head_hash TEXT NOT NULL, archive_hash TEXT NOT NULL',
    'publications': 'event_sequence INTEGER PRIMARY KEY REFERENCES events(sequence), operation_id TEXT NOT NULL REFERENCES commits(operation_id)',
    'store_state': 'id INTEGER PRIMARY KEY CHECK(id=1), event_count INTEGER NOT NULL CHECK(event_count BETWEEN 0 AND 256), event_hash TEXT NOT NULL, authority_revision INTEGER NOT NULL, head BLOB NOT NULL, image_hash TEXT NOT NULL, checkpoint BLOB NOT NULL',
}
DDL = tuple(f'CREATE TABLE {name} ({columns}) STRICT' for name, columns in TABLES.items()) + tuple(
    f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT, 'Append only'); END"
    for name in TABLES if name != 'store_state' for action in ('UPDATE', 'DELETE')
)


class UpdateStoreError(ValueError):
    """Bounded diagnostic; never includes stored payloads or filesystem paths."""


def _require(condition):
    if not condition:
        raise UpdateStoreError('INVALID_STORE')


def _schema(connection):
    return connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()


def _expected_schema():
    with closing(sqlite3.connect(':memory:')) as connection:
        for statement in DDL:
            connection.execute(statement)
        return _schema(connection)


def _rows(image, checkpoint):
    """Deterministic expected projections, also used to check complete bijections."""
    rows = {name: [] for name in TABLES}
    rows['store_metadata'] = [(1, image.deployment_id, canonical_bytes(image.base_head), record_digest(image.base_head))]
    authority_revision = 0
    for event in image.events:
        p, seq = event.payload, event.sequence
        at = event.model_dump(mode='json')['recorded_at']
        rows['events'].append((seq, p.kind, at, event.previous_hash, event.entry_hash, canonical_bytes(event)))
        if p.kind == 'AUTHORITY':
            authority_revision = seq
        elif p.kind == 'REGISTER':
            rows['registrations'].append((p.intent.operation_id, seq, p.intent.publisher_id, record_digest(p.intent)))
        elif p.kind == 'PREPARE':
            rows['preparations'].append((seq, p.operation_id))
        elif p.kind == 'COMMIT':
            rows['commits'].append((p.operation_id, seq, p.receipt.authority_sequence,
                record_digest(p.receipt), record_digest(p.head), record_digest(p.archive)))
        else:
            rows['publications'].append((seq, p.operation_id))
    rows['store_state'] = [(1, len(image.events), checkpoint.event_head_hash, authority_revision,
        canonical_bytes(image.head), record_digest(image), canonical_bytes(checkpoint))]
    return rows


class UpdateDurableStore:
    """Read-only loader. Trusted checkpoint is always supplied independently."""

    def __init__(self, path):
        self.path = Path(path).absolute()

    @classmethod
    def create_empty_for_testing(cls, path, image, *, trusted_checkpoint):
        """Explicit exclusive creation, empty image only; no authentication implied.

        Failed initialization may leave an unusable file for explicit test cleanup.
        Never opens, replaces, or repairs an existing file.
        """
        try:
            _require(type(image) is UpdateStorageImage and not image.events)
            _require(validate_update_storage_image(image, trusted_checkpoint=trusted_checkpoint).status == 'CONSISTENT')
            path = Path(path).absolute()
            with path.open('xb'):
                pass
            with closing(sqlite3.connect(path, isolation_level=None, timeout=1)) as connection:
                connection.execute('PRAGMA foreign_keys=ON')
                _require(connection.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal')
                connection.execute('PRAGMA synchronous=FULL')
                connection.execute('BEGIN IMMEDIATE')
                try:
                    for statement in DDL:
                        connection.execute(statement)
                    connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                    for name, rows in _rows(image, trusted_checkpoint).items():
                        for row in rows:
                            connection.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
                    cls._load(connection, trusted_checkpoint)
                    connection.execute('COMMIT')
                except Exception:
                    connection.execute('ROLLBACK')
                    raise
            return cls(path)
        except Exception:
            raise UpdateStoreError('STORE_CREATION_FAILED') from None

    def load(self, *, trusted_checkpoint):
        try:
            # mode=ro cannot silently create a missing file. Do not use immutable=1:
            # it would ignore live locking/WAL semantics.
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True,
                                        isolation_level=None, timeout=1)) as connection:
                connection.execute('PRAGMA query_only=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.execute('PRAGMA foreign_keys=ON')
                connection.execute('BEGIN')
                try:
                    return self._load(connection, trusted_checkpoint)
                finally:
                    connection.execute('ROLLBACK')
        except Exception:
            raise UpdateStoreError('INVALID_STORE') from None

    @staticmethod
    def _load(connection, checkpoint):
        _require(type(checkpoint) is UpdateStorageCheckpoint)
        checkpoint = decode_update_storage_record(UpdateStorageCheckpoint, canonical_bytes(checkpoint))
        _require(connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID)
        _require(connection.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION)
        _require(connection.execute('PRAGMA foreign_keys').fetchone()[0] == 1)
        _require(connection.execute('PRAGMA journal_mode').fetchone()[0] == 'wal')
        # Bound schema text before retrieving it; reject extra objects as well.
        size, count = connection.execute('SELECT coalesce(sum(length(CAST(sql AS BLOB))),0),count(*) FROM sqlite_schema').fetchone()
        _require(size <= 65536 and count <= 64)
        _require(_schema(connection) == _expected_schema())
        # Inspect lengths before fetching any stored value. This also bounds
        # malformed text projections, not just the canonical event blobs.
        total = 0
        for name in TABLES:
            _require(connection.execute(f'SELECT count(*) FROM {name}').fetchone()[0] <= (1 if name.startswith('store_') else 256))
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info({name})')]
            for column in columns:
                maximum, amount = connection.execute(f'SELECT coalesce(max(length(CAST({column} AS BLOB))),0), coalesce(sum(length(CAST({column} AS BLOB))),0) FROM {name}').fetchone()
                _require(maximum <= EVENT_LIMIT)
                total += amount
        _require(total <= IMAGE_LIMIT * 2)
        _require(connection.execute('SELECT coalesce(sum(length(canonical)),0) FROM events').fetchone()[0] <= IMAGE_LIMIT)
        raw_events = connection.execute('SELECT canonical FROM events ORDER BY sequence').fetchall()
        _require(sum(len(row[0]) for row in raw_events) <= IMAGE_LIMIT)
        meta = connection.execute('SELECT * FROM store_metadata').fetchall()
        state = connection.execute('SELECT * FROM store_state').fetchall()
        _require(len(meta) == len(state) == 1)
        events = tuple(decode_update_storage_record(StoredUpdateEvent, row[0]) for row in raw_events)
        image = UpdateStorageImage(deployment_id=meta[0][1], base_head=decode_canonical(UpdateAuthorityHead, meta[0][2]),
            events=events, head=decode_canonical(UpdateAuthorityHead, state[0][4]))
        _require(len(canonical_bytes(image)) <= IMAGE_LIMIT)
        _require(validate_update_storage_image(image, trusted_checkpoint=checkpoint).status == 'CONSISTENT')
        for name, expected in _rows(image, checkpoint).items():
            actual = connection.execute(f'SELECT * FROM {name}').fetchall()
            _require(sorted(actual) == sorted(expected))
        _require(connection.execute('PRAGMA foreign_key_check').fetchone() is None)
        _require(connection.execute('PRAGMA quick_check(1)').fetchone() == ('ok',))
        return image
