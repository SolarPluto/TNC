"""Local SQLite adapter; host-only paths/actors, no CLI approval loading."""
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
import json
import math
from pathlib import Path
import sqlite3

from tnc.provenance.review_store import (
    InMemoryReviewStore, ReleaseReceipt, ReleaseRequest, ReviewIntegrityError,
    ReviewRequest, ReviewResolution, ReviewerContext, ReviewStoreError,
    StoredRelease, StoredReviewRecord,
)


_SCHEMA = Path(__file__).with_name("sqlite_schema.sql")
_MIGRATION_V2 = Path(__file__).with_name("sqlite_migration_v2.sql")


def _require(condition):
    if not condition:
        raise ReviewIntegrityError("SQLite store validation failed")


def _encode(model) -> bytes:
    def canonical(value):
        if isinstance(value, datetime):
            if value.utcoffset() is None:
                raise ValueError("Naive timestamp")
            return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, dict):
            return {k: canonical(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [canonical(v) for v in value]
        return value
    return json.dumps(canonical(model.model_dump()), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _decode(kind, value):
    _require(type(value) is bytes)
    model = kind.model_validate_json(value)
    _require(_encode(model) == value)
    return model


def _schema_rows(connection):
    return connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name").fetchall()


def _apply_v2(connection):
    """Execute trusted DDL without executescript's implicit pre-commit behavior."""
    statement = ""
    for line in _MIGRATION_V2.read_text(encoding="utf-8").splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    _require(not statement.strip())


@lru_cache(maxsize=2)
def _expected_schema(version=1):
    _require(version in (1, 2))
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.executescript(_SCHEMA.read_text(encoding="utf-8"))
        if version == 2:
            connection.execute("BEGIN IMMEDIATE")
            _apply_v2(connection)
            connection.execute("COMMIT")
        return _schema_rows(connection)
    finally:
        connection.close()


def _review_values(record):
    req = record.request
    return (record.sequence, req.review_id, req.availability.document_id, req.availability.version_id,
            req.verdict.value, record.availability_fingerprint, record.expected_head_sequence,
            req.supersedes_review_id, req.revokes_review_id, record.previous_entry_hash,
            record.entry_hash, _encode(record))


def _release_values(record):
    receipt = record.receipt
    return (receipt.release_sequence, receipt.release_id, receipt.review_sequence, receipt.store_revision,
            receipt.candidate_hash, receipt.payload_hash, receipt.previous_release_hash, receipt.entry_hash,
            _encode(record.request), _encode(receipt), record.request.payload)


class SqliteReviewStore:
    """Each operation opens an existing file and owns one explicit transaction.

    The transient InMemoryReviewStore below is the shared semantic validator,
    reconstructed from this transaction's rows. It is never a cached authority.
    SQLite, not its local RLock, serializes independent processes.
    """
    def __init__(self, *, path: Path, allowed_reviewers: frozenset[str],
                 clock: Callable[[], datetime] | None = None, timeout: float = 5.0):
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 <= timeout <= 60:
            raise ValueError("Timeout must be finite and between 0 and 60 seconds")
        self._path = Path(path).absolute()
        self._allowed_reviewers = frozenset(allowed_reviewers)
        self._clock = clock
        self._timeout = timeout

    @classmethod
    def provision(cls, *, path: Path, allowed_reviewers: frozenset[str], clock=None, timeout=5.0):
        store = cls(path=path, allowed_reviewers=allowed_reviewers, clock=clock, timeout=timeout)
        # Exclusive file creation prevents accidental overwrite, including empty files.
        # Directory creation and ACL provisioning are the host's responsibility.
        with store._path.open("xb"):
            pass
        connection = None
        try:
            connection = sqlite3.connect(store._path.as_uri() + "?mode=rw", uri=True,
                isolation_level=None, autocommit=sqlite3.LEGACY_TRANSACTION_CONTROL, timeout=timeout)
            _require(connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",))
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(_SCHEMA.read_text(encoding="utf-8"))
        except sqlite3.Error as exc:
            raise ReviewStoreError("Database provisioning failed; no automatic overwrite") from exc
        finally:
            if connection is not None:
                connection.close()
        store.history()
        return store

    @classmethod
    def open_existing(cls, *, path: Path, allowed_reviewers: frozenset[str], clock=None, timeout=5.0):
        store = cls(path=path, allowed_reviewers=allowed_reviewers, clock=clock, timeout=timeout)
        store.history()  # Validate ledger; outbox faults must not prevent revocation.
        return store

    def migrate_to_v2(self) -> None:
        """Explicit, atomic layout upgrade; preserve all old ledger/outbox bytes.

        Already-v2 retries validate before succeeding. No auto-migration on open.
        Journal tables remain empty until journal-aware operations are implemented.
        """
        with self._transaction(write=True, outbox=True) as (connection, _, _state):
            if connection.execute("PRAGMA user_version").fetchone() == (1,):
                _apply_v2(connection)
                # Validate the target layout/data before the enclosing COMMIT.
                self._load(connection, outbox=True)

    def _connect(self):
        connection = sqlite3.connect(self._path.as_uri() + "?mode=rw", uri=True,
            isolation_level=None, autocommit=sqlite3.LEGACY_TRANSACTION_CONTROL, timeout=self._timeout)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA recursive_triggers=ON")
            connection.execute("PRAGMA synchronous=FULL")
            _require(connection.execute("PRAGMA foreign_keys").fetchone() == (1,))
            _require(connection.execute("PRAGMA recursive_triggers").fetchone() == (1,))
            _require(connection.execute("PRAGMA synchronous").fetchone() == (2,))
            _require(connection.execute("PRAGMA journal_mode").fetchone() == ("wal",))
            return connection
        except BaseException:
            connection.close()
            raise

    def _load(self, connection, *, outbox):
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            _require(version in (1, 2))
            _require(_schema_rows(connection) == _expected_schema(version))
            if version == 2:
                # Until the manager is implemented, legacy operations must not
                # bypass ownership/fencing on externally inserted journal rows.
                for table in ("request_intents", "prepared_requests", "request_events"):
                    _require(connection.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,))
                _require(connection.execute("SELECT * FROM journal_state").fetchall()
                         == [(1, 1, 0, "0" * 64)])
            checkpoints = connection.execute("SELECT * FROM store_state").fetchall()
            _require(len(checkpoints) == 1)
            state = checkpoints[0]
            _require(state[:2] == (1, 1))
            records = []
            for row in connection.execute("SELECT * FROM reviews ORDER BY sequence"):
                record = _decode(StoredReviewRecord, row[-1])
                _require(row == _review_values(record))
                records.append(record)
            snapshot = InMemoryReviewStore(allowed_reviewers=self._allowed_reviewers, clock=self._clock)
            snapshot._records = tuple(records)
            snapshot._revision, snapshot._head_hash = state[2:4]
            snapshot._validate()
            if outbox:
                releases = []
                for row in connection.execute("SELECT * FROM outbox ORDER BY release_sequence"):
                    record = StoredRelease(request=_decode(ReleaseRequest, row[8]),
                                           receipt=_decode(ReleaseReceipt, row[9]))
                    _require(row == _release_values(record))
                    releases.append(record)
                _require(len(releases) == state[4])
                snapshot._release_state = (tuple(releases), state[5])
                snapshot._validate_releases()
            return snapshot, state
        except (ValueError, TypeError, AttributeError) as exc:
            raise ReviewIntegrityError("SQLite history or schema is invalid") from exc

    @contextmanager
    def _transaction(self, *, write=False, outbox=False):
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            snapshot, state = self._load(connection, outbox=outbox)
            yield connection, snapshot, state
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            raise ReviewIntegrityError("SQLite constraint failure; no retry inferred") from exc
        except sqlite3.DatabaseError as exc:
            if getattr(exc, "sqlite_errorcode", 0) & 255 in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB):
                raise ReviewIntegrityError("SQLite database is corrupt or invalid") from exc
            raise ReviewStoreError("SQLite operation unavailable or commit uncertain") from exc
        finally:
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                finally:
                    connection.close()

    def resolve(self, *, document_id: str, version_id: str) -> ReviewResolution:
        with self._transaction() as (_, snapshot, _state):
            result = snapshot.resolve(document_id=document_id, version_id=version_id)
        return result

    def history(self) -> tuple[StoredReviewRecord, ...]:
        with self._transaction() as (_, snapshot, _state):
            result = snapshot.history()
        return result

    def release_history(self) -> tuple[StoredRelease, ...]:
        with self._transaction(outbox=True) as (_, snapshot, _state):
            result = snapshot.release_history()
        return result

    def append(self, *, request: ReviewRequest, actor: ReviewerContext,
               expected_head_sequence: int | None) -> StoredReviewRecord:
        with self._transaction(write=True) as (connection, snapshot, state):
            result = snapshot.append(request=request, actor=actor, expected_head_sequence=expected_head_sequence)
            if snapshot._revision != state[2]:
                connection.execute("INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   _review_values(result))
                updated = connection.execute("UPDATE store_state SET review_sequence=?, review_head_hash=? "
                    "WHERE singleton=1 AND review_sequence=? AND review_head_hash=?",
                    (result.sequence, result.entry_hash, state[2], state[3]))
                _require(updated.rowcount == 1)
        return result

    def commit_release(self, *, request: ReleaseRequest) -> ReleaseReceipt:
        with self._transaction(write=True, outbox=True) as (connection, snapshot, state):
            result = snapshot.commit_release(request=request)
            if len(snapshot._release_state[0]) != state[4]:
                record = snapshot._release_state[0][-1]
                connection.execute("INSERT INTO outbox VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   _release_values(record))
                updated = connection.execute("UPDATE store_state SET release_sequence=?, release_head_hash=? "
                    "WHERE singleton=1 AND release_sequence=? AND release_head_hash=?",
                    (result.release_sequence, result.entry_hash, state[4], state[5]))
                _require(updated.rowcount == 1)
        return result
