"""Host-only durable request journal. Caller contexts are not authentication."""
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tnc.provenance.admission import ArchiveAvailabilityRecord
from tnc.provenance.historical_replay import HistoricalReplayEngine
from tnc.provenance.review_store import (
    ReleaseRequest, ReleaseReceipt, ReviewConflictError, ReviewIntegrityError,
    ReviewStoreError, availability_fingerprint, _candidate_digest,
)
from tnc.provenance.sqlite_review_store import SqliteReviewStore, _encode, _decode


ZERO = "0" * 64


class JournalAccessError(ReviewStoreError):
    pass


class JournalConflictError(ReviewConflictError):
    pass


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", ser_json_bytes="hex", val_json_bytes="hex")


class CallerContext(Model):
    principal_id: str = Field(min_length=1, pattern=r"\S")


class QueryIdentity(Model):
    document_id: str = Field(min_length=1, pattern=r"\S")
    version_id: str = Field(min_length=1, pattern=r"\S")
    query_time: datetime

    @field_validator("query_time")
    @classmethod
    def aware(cls, value):
        if value.utcoffset() is None:
            raise ValueError("Query time must be aware")
        return value.astimezone(timezone.utc)


class BoundIntent(Model):
    query: QueryIdentity
    parser_version: Literal["tnc-parser-1"] = "tnc-parser-1"
    policy_version: Literal["single-version-replay-1"] = "single-version-replay-1"
    configuration_bytes: bytes = Field(strict=True, min_length=1)
    configuration_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    availability: ArchiveAvailabilityRecord | None
    expected_review_sequence: int | None = Field(default=None, strict=True, gt=0)
    expected_review_entry_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def binding(self):
        if sha256(self.configuration_bytes).hexdigest() != self.configuration_hash:
            raise ValueError("Configuration hash mismatch")
        if (self.expected_review_sequence is None) != (self.expected_review_entry_hash is None):
            raise ValueError("Incomplete review binding")
        if self.availability is not None:
            availability_fingerprint(self.availability)
            if (self.availability.document_id, self.availability.version_id) != (
                    self.query.document_id, self.query.version_id):
                raise ValueError("Availability identity mismatch")
        return self


class IntentRecord(Model):
    operation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    principal_id: str = Field(min_length=1, pattern=r"\S")
    release_id: str = Field(min_length=1, pattern=r"\S")
    intent: BoundIntent


class WorkerFence(Model):
    operation_id: str
    principal_id: str
    worker_id: str = Field(min_length=1, pattern=r"\S")
    generation: int = Field(strict=True, gt=0)


class JournalView(Model):
    operation_id: str
    release_id: str
    state: Literal["REGISTERED", "PREPARED", "COMMITTED", "FAILED"]
    head_sequence: int
    receipt: ReleaseReceipt | None = None
    reason_codes: tuple[str, ...] = ()


class Event(Model):
    sequence: int = Field(strict=True, gt=0)
    operation_id: str
    kind: Literal["REGISTERED", "CLAIMED", "PREPARED", "COMMITTED", "FAILED"]
    worker_generation: int = Field(strict=True, ge=0)
    worker_id: str | None = None
    previous_operation_sequence: int | None = None
    intent_hash: str
    candidate_hash: str | None = None
    receipt_release_id: str | None = None
    receipt_hash: str | None = None
    reason_codes: tuple[str, ...] = ()
    previous_entry_hash: str
    entry_hash: str


def _digest(record):
    return sha256(_encode(record)).hexdigest()


def _event_digest(event):
    return _digest(event.model_copy(update={"entry_hash": ZERO}))


def _check(value):
    if not value:
        raise ReviewIntegrityError("Invalid journal history or binding")


def _candidate_matches(record, candidate):
    intent = record.intent
    return (candidate.release_id == record.release_id
        and intent.availability is not None and candidate.availability == intent.availability
        and candidate.expected_availability_fingerprint == availability_fingerprint(intent.availability)
        and candidate.expected_review_sequence == intent.expected_review_sequence
        and candidate.expected_review_entry_hash == intent.expected_review_entry_hash
        and candidate.query_time == intent.query.query_time
        and candidate.parser_version == intent.parser_version and candidate.policy_version == intent.policy_version)


def _event_values(event):
    return (event.sequence, event.operation_id, event.kind, event.worker_generation,
            event.receipt_release_id, event.previous_entry_hash, event.entry_hash, _encode(event))


def validate_journal(connection, snapshot, *, outbox):
    """Validate structural history always; cross-check outbox only on release/read.

    Ledger-only operations retain the ability to revoke despite outbox corruption.
    Returns transaction-local records, candidates, heads, states and checkpoint.
    """
    try:
        intents, prepared, heads, states = {}, {}, {}, {}
        for row in connection.execute("SELECT * FROM request_intents"):
            record = _decode(IntentRecord, row[4])
            _check(row == (record.operation_id, record.principal_id, record.release_id, _digest(record), _encode(record)))
            intents[record.operation_id] = record
        for row in connection.execute("SELECT * FROM prepared_requests"):
            candidate = _decode(ReleaseRequest, row[3])
            _check(row[0] in intents and _candidate_matches(intents[row[0]], candidate))
            _check(row == (row[0], candidate.release_id, _candidate_digest(candidate), _encode(candidate)))
            prepared[row[0]] = candidate
        previous, count, prepared_seen = ZERO, 0, set()
        releases = {r.receipt.release_id: r for r in snapshot._release_state[0]} if outbox else {}
        for row in connection.execute("SELECT * FROM request_events ORDER BY sequence"):
            event = _decode(Event, row[7])
            count += 1
            _check(row == _event_values(event) and event.sequence == count)
            _check(event.previous_entry_hash == previous and event.entry_hash == _event_digest(event))
            _check(event.operation_id in intents)
            record = intents[event.operation_id]
            _check(event.intent_hash == _digest(record))
            head = heads.get(event.operation_id)
            _check(event.previous_operation_sequence == (head.sequence if head else None))
            state = states.get(event.operation_id)
            _check(state not in ("COMMITTED", "FAILED"))
            if event.kind == "REGISTERED":
                _check(head is None and event.worker_generation == 0 and event.worker_id is None)
                state = "REGISTERED"
            elif event.kind == "CLAIMED":
                _check(head is not None and bool(event.worker_id and event.worker_id.strip()))
                _check(event.worker_generation == head.worker_generation + 1)
            else:
                _check(head is not None and event.worker_generation > 0)
                _check((event.worker_generation, event.worker_id) == (head.worker_generation, head.worker_id))
                if event.kind == "PREPARED":
                    _check(state == "REGISTERED" and event.operation_id in prepared)
                    _check(event.candidate_hash == _candidate_digest(prepared[event.operation_id]))
                    prepared_seen.add(event.operation_id)
                    state = "PREPARED"
                elif event.kind == "COMMITTED":
                    _check(state == "PREPARED" and event.receipt_release_id == record.release_id)
                    _check(event.candidate_hash == _candidate_digest(prepared[event.operation_id]))
                    _check(event.receipt_hash is not None and len(event.receipt_hash) == 64)
                    if outbox:
                        release = releases.get(record.release_id)
                        _check(release is not None and release.request == prepared[event.operation_id])
                        _check(event.receipt_hash == _digest(release.receipt))
                    state = "COMMITTED"
                else:
                    _check(bool(event.reason_codes) and all(code.strip() for code in event.reason_codes))
                    state = "FAILED"
            if event.kind != "COMMITTED":
                _check(event.receipt_release_id is None and event.receipt_hash is None)
            if event.kind not in ("PREPARED", "COMMITTED"):
                _check(event.candidate_hash is None)
            if event.kind != "FAILED":
                _check(not event.reason_codes)
            heads[event.operation_id], states[event.operation_id] = event, state
            previous = event.entry_hash
        _check(set(heads) == set(intents) and prepared_seen == set(prepared))
        checkpoint = connection.execute("SELECT * FROM journal_state").fetchall()
        _check(checkpoint == [(1, 1, count, previous)])
        if outbox:
            for operation_id, record in intents.items():
                _check((record.release_id in releases) == (states[operation_id] == "COMMITTED"))
        return intents, prepared, heads, states, (count, previous)
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise ReviewIntegrityError("Journal validation failed") from exc


def engine_configuration_bytes(engine: HistoricalReplayEngine) -> bytes:
    """Canonical exact host snapshot, including frozen bytes and transitions."""
    class Configuration(Model):
        corpus: object
        availability: tuple
        transitions: tuple
        parser_version: str = "tnc-parser-1"
        policy_version: str = "single-version-replay-1"
    return _encode(Configuration(corpus=engine._corpus, availability=engine._availability,
                                 transitions=engine._transitions))


class RequestJournalManager:
    """Internal host orchestration. Allowlisted principal/worker strings are not credentials."""
    def __init__(self, *, store: SqliteReviewStore, allowed_principals: frozenset[str]):
        self._store = store
        self._principals = frozenset(allowed_principals)

    def _caller(self, caller):
        caller = CallerContext.model_validate(caller.model_dump())
        if caller.principal_id not in self._principals:
            raise JournalAccessError("Operation unavailable")
        return caller

    def _read(self, connection, snapshot, *, write=True):
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (2, 3):
            raise ReviewStoreError("Explicit schema-v2 migration required")
        if version == 3 and write:
            raise ReviewStoreError("Authenticated journal writes not enabled")
        return validate_journal(connection, snapshot, outbox=True)

    def _owned(self, data, operation_id, caller):
        record = data[0].get(operation_id)
        if record is None or record.principal_id != caller.principal_id:
            raise JournalAccessError("Operation unavailable")
        return record

    def _fenced(self, data, fence):
        fence = WorkerFence.model_validate(fence.model_dump())
        caller = self._caller(CallerContext(principal_id=fence.principal_id))
        record = self._owned(data, fence.operation_id, caller)
        head = data[2][fence.operation_id]
        if (fence.generation, fence.worker_id) != (head.worker_generation, head.worker_id):
            raise JournalConflictError("Worker generation changed")
        return record

    def _view(self, data, operation_id, snapshot):
        record, head = data[0][operation_id], data[2][operation_id]
        receipt = None
        if data[3][operation_id] == "COMMITTED":
            receipt = next(r.receipt for r in snapshot._release_state[0] if r.receipt.release_id == record.release_id)
        return JournalView(operation_id=operation_id, release_id=record.release_id, state=data[3][operation_id],
                           head_sequence=head.sequence, receipt=receipt, reason_codes=head.reason_codes)

    def _event(self, connection, data, record, kind, *, worker=None, generation=None, candidate=None, receipt=None, reasons=()):
        head = data[2].get(record.operation_id)
        sequence, previous = data[4]
        event = Event(sequence=sequence+1, operation_id=record.operation_id, kind=kind,
            worker_generation=generation if generation is not None else (head.worker_generation if head else 0),
            worker_id=worker if worker is not None else (head.worker_id if head else None),
            previous_operation_sequence=head.sequence if head else None, intent_hash=_digest(record),
            candidate_hash=_candidate_digest(candidate) if candidate is not None else None,
            receipt_release_id=receipt.release_id if receipt is not None else None,
            receipt_hash=_digest(receipt) if receipt is not None else None, reason_codes=reasons,
            previous_entry_hash=previous, entry_hash=ZERO)
        event = event.model_copy(update={"entry_hash": _event_digest(event)})
        connection.execute("INSERT INTO request_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", _event_values(event))
        updated = connection.execute("UPDATE journal_state SET sequence=?, head_hash=? WHERE singleton=1 AND sequence=? AND head_hash=?",
                                     (event.sequence, event.entry_hash, sequence, previous))
        _check(updated.rowcount == 1)

    def _result(self, connection, operation_id):
        snapshot, _ = self._store._load(connection, outbox=True)
        return self._view(self._read(connection, snapshot), operation_id, snapshot)

    def register(self, *, operation_id: str, caller: CallerContext, intent: BoundIntent) -> JournalView:
        caller = self._caller(caller)
        intent = BoundIntent.model_validate(intent.model_dump())
        with self._store._transaction(write=True, outbox=True) as (connection, snapshot, _):
            data = self._read(connection, snapshot)
            if operation_id in data[0]:
                record = self._owned(data, operation_id, caller)
                if record.intent != intent:
                    raise JournalConflictError("Operation ID is bound to another intent")
            else:
                current = snapshot.resolve(document_id=intent.query.document_id, version_id=intent.query.version_id).head
                if (intent.expected_review_sequence, intent.expected_review_entry_hash) != (
                        current.sequence if current else None, current.entry_hash if current else None):
                    raise JournalConflictError("Review changed before registration")
                if current and current.request.availability != intent.availability:
                    raise JournalConflictError("Intent evidence does not match review")
                record = IntentRecord(operation_id=operation_id, principal_id=caller.principal_id,
                                      release_id=str(uuid4()), intent=intent)
                if any(r.receipt.release_id == record.release_id for r in snapshot._release_state[0]):
                    raise JournalConflictError("Release ID collision")
                connection.execute("INSERT INTO request_intents VALUES (?, ?, ?, ?, ?)",
                    (operation_id, caller.principal_id, record.release_id, _digest(record), _encode(record)))
                self._event(connection, data, record, "REGISTERED")
            result = self._result(connection, operation_id)
        return result

    def recover(self, *, operation_id: str, caller: CallerContext, expected_query: QueryIdentity | None = None) -> JournalView:
        caller = self._caller(caller)
        if expected_query is not None:
            expected_query = QueryIdentity.model_validate(expected_query.model_dump())
        with self._store._transaction(outbox=True) as (connection, snapshot, _):
            data = self._read(connection, snapshot, write=False)
            record = self._owned(data, operation_id, caller)
            if expected_query is not None and record.intent.query != expected_query:
                raise JournalConflictError("Recovery query mismatch")
            result = self._view(data, operation_id, snapshot)
        return result

    def claim(self, *, operation_id: str, caller: CallerContext, worker_id: str, expected_head_sequence: int) -> WorkerFence:
        caller = self._caller(caller)
        if type(expected_head_sequence) is not int or expected_head_sequence <= 0:
            raise JournalConflictError("Invalid expected operation head")
        with self._store._transaction(write=True, outbox=True) as (connection, snapshot, _):
            data = self._read(connection, snapshot)
            record = self._owned(data, operation_id, caller)
            head = data[2][operation_id]
            if head.sequence != expected_head_sequence or data[3][operation_id] in ("COMMITTED", "FAILED"):
                raise JournalConflictError("Operation head changed or is terminal")
            fence = WorkerFence(operation_id=operation_id, principal_id=caller.principal_id,
                                worker_id=worker_id, generation=head.worker_generation+1)
            self._event(connection, data, record, "CLAIMED", worker=worker_id, generation=fence.generation)
            self._result(connection, operation_id)
        return fence

    def prepare(self, *, fence: WorkerFence, engine: HistoricalReplayEngine) -> JournalView:
        # Read/check before expensive work; write transaction rechecks after parsing.
        with self._store._transaction(outbox=True) as (connection, snapshot, _):
            data = self._read(connection, snapshot)
            record = self._fenced(data, fence)
            if data[3][record.operation_id] != "REGISTERED":
                return self._view(data, record.operation_id, snapshot)
            if engine_configuration_bytes(engine) != record.intent.configuration_bytes or engine._store is not self._store:
                raise JournalConflictError("Pipeline configuration/store mismatch")
        query = record.intent.query
        candidate = engine._prepare(document_id=query.document_id, version_id=query.version_id,
                                     query_time=query.query_time, release_id=record.release_id)
        if not isinstance(candidate, ReleaseRequest):
            if any(code.startswith("REVIEW_STORE_") for code in candidate.reason_codes):
                raise ReviewStoreError("Preparation unavailable; operation remains recoverable")
            return self.fail(fence=fence, reason_codes=candidate.reason_codes)
        candidate = ReleaseRequest.model_validate(candidate.model_dump())
        if not _candidate_matches(record, candidate):
            raise JournalConflictError("Prepared candidate differs from bound intent")
        with self._store._transaction(write=True, outbox=True) as (connection, snapshot, _):
            data = self._read(connection, snapshot)
            record = self._fenced(data, fence)
            state = data[3][record.operation_id]
            if state == "REGISTERED":
                connection.execute("INSERT INTO prepared_requests VALUES (?, ?, ?, ?)",
                    (record.operation_id, candidate.release_id, _candidate_digest(candidate), _encode(candidate)))
                self._event(connection, data, record, "PREPARED", candidate=candidate)
            elif state != "PREPARED" or data[1][record.operation_id] != candidate:
                raise JournalConflictError("Operation no longer accepts preparation")
            result = self._result(connection, record.operation_id)
        return result

    def commit(self, *, fence: WorkerFence) -> JournalView:
        with self._store._transaction(write=True, outbox=True) as (connection, snapshot, state):
            data = self._read(connection, snapshot)
            record = self._fenced(data, fence)
            if data[3][record.operation_id] == "COMMITTED":
                result = self._view(data, record.operation_id, snapshot)
            else:
                if data[3][record.operation_id] != "PREPARED":
                    raise JournalConflictError("Operation is not prepared")
                candidate = data[1][record.operation_id]
                receipt = self._store._commit_release_in_transaction(connection, snapshot, state, candidate)
                self._event(connection, data, record, "COMMITTED", candidate=candidate, receipt=receipt)
                result = self._result(connection, record.operation_id)
        return result

    def fail(self, *, fence: WorkerFence, reason_codes: tuple[str, ...]) -> JournalView:
        if not isinstance(reason_codes, tuple) or not reason_codes or any(
                not isinstance(code, str) or not code or not all(c.isupper() or c.isdigit() or c == "_" for c in code)
                for code in reason_codes):
            raise ValueError("Failure reasons must be nonempty structured codes")
        with self._store._transaction(write=True, outbox=True) as (connection, snapshot, _):
            data = self._read(connection, snapshot)
            record = self._fenced(data, fence)
            current = data[3][record.operation_id]
            if current == "FAILED" and data[2][record.operation_id].reason_codes == reason_codes:
                result = self._view(data, record.operation_id, snapshot)
            else:
                if current in ("FAILED", "COMMITTED"):
                    raise JournalConflictError("Operation is terminal")
                self._event(connection, data, record, "FAILED", reasons=reason_codes)
                result = self._result(connection, record.operation_id)
        return result
