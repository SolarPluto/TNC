"""Phase 1 isolated test witness store: explicit genesis and read-only audit.

No submission API, current authorization provider, signing or observation service.
Synthetic historical evidence remains synthetic even when persisted in SQLite.
"""
from contextlib import closing
from pathlib import Path
import sqlite3

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical
from tnc.provenance.external_witness_logic import (
    HISTORY_LIMIT, IMAGE_LIMIT, RECORD_LIMIT, WitnessImage, checked, valid_time,
    validate_witness_image, witness_digest,
)

APPLICATION_ID = 0x544E4357
SCHEMA_VERSION = 1
STORED_LIMIT = 4 * IMAGE_LIMIT
TABLES = {
    'witness_anchor': '''id INTEGER PRIMARY KEY CHECK(id=1),
        canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 262144),
        digest TEXT NOT NULL CHECK(length(digest)=64)''',
    'witness_image': '''id INTEGER PRIMARY KEY CHECK(id=1),
        canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 1048576),
        digest TEXT NOT NULL CHECK(length(digest)=64),
        receipt_count INTEGER NOT NULL CHECK(receipt_count BETWEEN 0 AND 64)''',
    'witness_receipts': '''witness_sequence INTEGER PRIMARY KEY CHECK(witness_sequence>0),
        request_id TEXT NOT NULL UNIQUE CHECK(length(request_id) BETWEEN 1 AND 128),
        principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 128),
        request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64),
        request BLOB NOT NULL CHECK(length(request) BETWEEN 1 AND 262144),
        receipt BLOB NOT NULL CHECK(length(receipt) BETWEEN 1 AND 262144),
        receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64),
        state_digest TEXT NOT NULL CHECK(length(state_digest)=64)''',
    'witness_head': '''id INTEGER PRIMARY KEY CHECK(id=1),
        canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 262144),
        digest TEXT NOT NULL CHECK(length(digest)=64),
        witness_sequence INTEGER NOT NULL CHECK(witness_sequence>=0),
        local_sequence INTEGER NOT NULL CHECK(local_sequence>=0),
        checkpoint_revision INTEGER NOT NULL CHECK(checkpoint_revision>0),
        epoch_id TEXT NOT NULL CHECK(length(epoch_id) BETWEEN 1 AND 128)''',
}
DDL = tuple(f'CREATE TABLE {name} ({columns}) STRICT' for name, columns in TABLES.items()) + tuple(
    f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT, 'Immutable witness evidence'); END"
    for name in TABLES for action in (('UPDATE', 'DELETE') if name in ('witness_anchor', 'witness_receipts') else ('DELETE',))
)


class WitnessStoreError(ValueError):
    """Fixed diagnostics with no stored payloads or filesystem paths."""


def _require(condition):
    if not condition: raise WitnessStoreError('INVALID_WITNESS_STORE')


def _schema(db):
    return db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()


def _expected_schema():
    with closing(sqlite3.connect(':memory:')) as db:
        for statement in DDL: db.execute(statement)
        return _schema(db)


def _rows(image):
    head = validate_witness_image(image, trusted_initial=image.initial)
    return {
        'witness_anchor': [(1, canonical_bytes(image.initial), witness_digest(image.initial))],
        'witness_image': [(1, canonical_bytes(image), witness_digest(image), len(image.receipts))],
        'witness_receipts': [(r.resulting_state.witness_sequence, r.request.request_id, r.request.principal_id,
            witness_digest(r.request), canonical_bytes(r.request), canonical_bytes(r), witness_digest(r),
            witness_digest(r.resulting_state)) for r in image.receipts],
        'witness_head': [(1, canonical_bytes(head), witness_digest(head), head.witness_sequence,
            head.head.local_sequence, head.head.checkpoint_revision, head.head.epoch_id)],
    }


class TestExternalWitnessStore:
    """One explicitly pinned context per file; audit loading never authorizes use."""
    __test__ = False

    def __init__(self, path, *, trusted_initial):
        self.path = Path(path).absolute()
        self._initial = checked(trusted_initial)
        validate_witness_image(WitnessImage(initial=self._initial, receipts=()), trusted_initial=self._initial)

    def _hook(self, point):
        """Private deterministic creation fault-injection seam."""

    @classmethod
    def create_for_testing(cls, path, *, trusted_initial, now):
        """Exclusive genesis creation. Failure can leave an invalid empty file."""
        try:
            valid_time(now)
            store = cls(path, trusted_initial=trusted_initial)
            _require(store._initial.last_updated_at <= now)
            for suffix in ('-wal', '-shm', '-journal'):
                _require(not Path(str(store.path) + suffix).exists())
            with store.path.open('xb'): pass
            with closing(sqlite3.connect(store.path, isolation_level=None, timeout=1)) as db:
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('PRAGMA trusted_schema=OFF')
                _require(db.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',))
                db.execute('PRAGMA synchronous=FULL')
                _require(db.execute('PRAGMA synchronous').fetchone() == (2,))
                db.execute('BEGIN IMMEDIATE')
                try:
                    for statement in DDL:
                        db.execute(statement)
                        store._hook('ddl_statement')
                    db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                    image = WitnessImage(initial=store._initial, receipts=())
                    for name, rows in _rows(image).items():
                        for row in rows:
                            db.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})", row)
                    store._hook('initial_rows')
                    store._load(db, now=now)
                    store._hook('before_commit')
                    db.execute('COMMIT')
                    store._hook('after_commit')
                except BaseException:
                    if db.in_transaction: db.execute('ROLLBACK')
                    raise
            return store
        except Exception:
            # A commit/return gap may leave a valid store. Never claim rollback.
            raise WitnessStoreError('WITNESS_STORE_CREATION_FAILED') from None

    def load_audit(self, *, now):
        """Bounded mode=ro transaction snapshot; no repair or receipt endpoint."""
        try:
            valid_time(now)
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True,
                                         isolation_level=None, timeout=1)) as db:
                db.execute('PRAGMA query_only=ON')
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('BEGIN')
                try: return self._load(db, now=now)
                finally: db.execute('ROLLBACK')
        except Exception:
            raise WitnessStoreError('INVALID_WITNESS_STORE') from None

    def _load(self, db, *, now):
        valid_time(now)
        _require(db.execute('PRAGMA application_id').fetchone() == (APPLICATION_ID,))
        _require(db.execute('PRAGMA user_version').fetchone() == (SCHEMA_VERSION,))
        _require(db.execute('PRAGMA journal_mode').fetchone() == ('wal',))
        _require(db.execute('PRAGMA foreign_keys').fetchone() == (1,))
        size, count = db.execute('SELECT coalesce(sum(length(CAST(sql AS BLOB))),0),count(*) FROM sqlite_schema').fetchone()
        _require(size <= 65536 and count <= 64)
        _require(_schema(db) == _expected_schema())
        total = 0
        for name in TABLES:
            count = db.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
            _require(count <= HISTORY_LIMIT if name == 'witness_receipts' else count == 1)
            for column in (row[1] for row in db.execute(f'PRAGMA table_info({name})')):
                maximum, amount = db.execute(f'SELECT coalesce(max(length(CAST({column} AS BLOB))),0), coalesce(sum(length(CAST({column} AS BLOB))),0) FROM {name}').fetchone()
                limit = IMAGE_LIMIT if (name, column) == ('witness_image', 'canonical') else RECORD_LIMIT
                _require(maximum <= limit)
                total += amount
                _require(total <= STORED_LIMIT)
        raw = db.execute('SELECT canonical FROM witness_image').fetchone()[0]
        image = decode_canonical(WitnessImage, raw)
        head = validate_witness_image(image, trusted_initial=self._initial)
        _require(head.last_updated_at <= now)
        for name, expected in _rows(image).items():
            _require(sorted(db.execute(f'SELECT * FROM {name}').fetchall()) == sorted(expected))
        _require(db.execute('PRAGMA foreign_key_check').fetchone() is None)
        _require(db.execute('PRAGMA quick_check(1)').fetchone() == ('ok',))
        return image
