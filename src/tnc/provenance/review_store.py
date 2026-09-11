"""In-memory review ledger for testing. Not a durable or authenticated service."""
from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
import json
from threading import RLock
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tnc.provenance.admission import ArchiveAvailabilityRecord


class ReviewStoreError(ValueError):
    """A blocked ledger operation; callers must not fall back to old approval."""


class ReviewAuthorizationError(ReviewStoreError):
    pass


class ReviewConflictError(ReviewStoreError):
    pass


class ReviewIntegrityError(ReviewStoreError):
    pass


class ReviewVerdict(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


class ReviewModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _utc(value: datetime) -> datetime:
    if value.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_availability_bytes(availability: ArchiveAvailabilityRecord) -> bytes:
    """Version 1: exact strings, sorted UTF-8 JSON, capture time in fixed UTC form."""
    # Revalidate even model_copy/model_construct inputs at this trust boundary.
    record = ArchiveAvailabilityRecord.model_validate(availability.model_dump())
    if record.capture_at.microsecond:
        raise ValueError("CDX capture timestamp must have whole-second precision")
    data = record.model_dump(mode="json")
    data["capture_at"] = _timestamp_text(record.capture_at)
    return _json_bytes({"canonicalization_version": 1, "availability": data})


def availability_fingerprint(availability: ArchiveAvailabilityRecord) -> str:
    return sha256(canonical_availability_bytes(availability)).hexdigest()


class ReviewerContext(ReviewModel):
    """Host-asserted identity. The in-memory store does not authenticate it."""
    reviewer_id: str = Field(min_length=1, pattern=r"\S")


class ReviewRequest(ReviewModel):
    review_id: str = Field(min_length=1, pattern=r"\S")
    availability: ArchiveAvailabilityRecord
    verdict: ReviewVerdict
    reviewed_at: datetime
    rationale: str = Field(min_length=1, pattern=r"\S")
    supersedes_review_id: str | None = Field(default=None, min_length=1, pattern=r"\S")
    revokes_review_id: str | None = Field(default=None, min_length=1, pattern=r"\S")

    @field_validator("reviewed_at")
    @classmethod
    def normalize_review_time(cls, value):
        return _utc(value)

    @field_validator("availability", mode="before")
    @classmethod
    def validate_availability(cls, value):
        if isinstance(value, ArchiveAvailabilityRecord):
            value = value.model_dump()
        record = ArchiveAvailabilityRecord.model_validate(value)
        canonical_availability_bytes(record)
        return record.model_copy(update={"capture_at": _utc(record.capture_at)})


class StoredReviewRecord(ReviewModel):
    schema_version: Literal[1] = 1
    canonicalization_version: Literal[1] = 1
    sequence: int = Field(gt=0, strict=True)
    request: ReviewRequest
    availability_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewer: str = Field(min_length=1, pattern=r"\S")
    recorded_at: datetime
    expected_head_sequence: int | None = Field(default=None, gt=0, strict=True)
    previous_entry_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    entry_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("recorded_at")
    @classmethod
    def normalize_receipt_time(cls, value):
        return _utc(value)


class ReviewResolution(ReviewModel):
    status: Literal["missing", "found"]
    head: StoredReviewRecord | None
    store_revision: int
    store_head_hash: str


class ReviewReader(Protocol):
    def resolve(self, *, document_id: str, version_id: str) -> ReviewResolution: ...


class ReleaseRequest(ReviewModel):
    """Host-internal candidate, not public query input or proof of admission."""
    model_config = ConfigDict(frozen=True, extra="forbid", ser_json_bytes="hex",
                              val_json_bytes="hex")
    release_id: str = Field(min_length=1, pattern=r"\S")
    availability: ArchiveAvailabilityRecord
    expected_review_sequence: int = Field(gt=0, strict=True)
    expected_review_entry_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_availability_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    query_time: datetime
    parser_version: str = Field(min_length=1, pattern=r"\S")
    policy_version: str = Field(min_length=1, pattern=r"\S")
    payload: bytes = Field(strict=True)

    @field_validator("query_time")
    @classmethod
    def normalize_query_time(cls, value):
        return _utc(value)

    @field_validator("availability", mode="before")
    @classmethod
    def validate_availability(cls, value):
        return ReviewRequest.validate_availability(value)


class ReleaseReceipt(ReviewModel):
    release_id: str
    release_sequence: int = Field(gt=0, strict=True)
    review_sequence: int = Field(gt=0, strict=True)
    review_entry_hash: str
    store_revision: int = Field(gt=0, strict=True)
    store_head_hash: str
    candidate_hash: str
    payload_hash: str
    previous_release_hash: str
    entry_hash: str


class StoredRelease(ReviewModel):
    request: ReleaseRequest
    receipt: ReleaseReceipt


class ReleaseCommitter(Protocol):
    def commit_release(self, *, request: ReleaseRequest) -> ReleaseReceipt: ...


class ReviewWriter(Protocol):
    def append(self, *, request: ReviewRequest, actor: ReviewerContext,
               expected_head_sequence: int | None) -> StoredReviewRecord: ...


_GENESIS = "0" * 64


def _entry_digest(record: StoredReviewRecord) -> str:
    data = record.model_dump(mode="json", exclude={"entry_hash"})
    data["recorded_at"] = _timestamp_text(record.recorded_at)
    data["request"]["reviewed_at"] = _timestamp_text(record.request.reviewed_at)
    data["request"]["availability"] = json.loads(
        canonical_availability_bytes(record.request.availability)
    )["availability"]
    return sha256(_json_bytes(data)).hexdigest()


def _candidate_digest(request: ReleaseRequest) -> str:
    return sha256(_json_bytes(request.model_dump(mode="json"))).hexdigest()


def _release_digest(receipt: ReleaseReceipt) -> str:
    return sha256(_json_bytes(receipt.model_dump(mode="json", exclude={"entry_hash"}))).hexdigest()


def _require(condition: bool) -> None:
    if not condition:
        raise ReviewIntegrityError("Invalid ledger record")


def _key(request: ReviewRequest) -> tuple[str, str]:
    return request.availability.document_id, request.availability.version_id


def _check_transition(request: ReviewRequest, head: StoredReviewRecord | None,
                      recorded_at: datetime, expected: int | None) -> None:
    if expected != (head.sequence if head else None):
        raise ReviewConflictError("Head sequence changed")
    if request.supersedes_review_id != (head.request.review_id if head else None):
        raise ReviewConflictError("Supersedes must name the current version head")
    if request.reviewed_at > recorded_at:
        raise ReviewStoreError("Review time is after receipt time")
    if request.reviewed_at < request.availability.capture_at:
        raise ReviewStoreError("Review time is before the archive capture")
    if head and request.reviewed_at < head.request.reviewed_at:
        raise ReviewStoreError("Backdated review")
    if request.verdict == ReviewVerdict.REVOKED:
        if (head is None or head.request.verdict != ReviewVerdict.APPROVED
                or request.revokes_review_id != head.request.review_id
                or request.availability != head.request.availability):
            raise ReviewStoreError("Revocation must target the active approval and exact evidence")
    elif request.revokes_review_id is not None:
        raise ReviewStoreError("Only a revocation may name revokes_review_id")


class InMemoryReviewStore:
    """Locked, append-only test ledger; no persistence or in-process attacker isolation.

    allowed_reviewers is a host-configured allowlist, not authentication. Do not
    expose this writer or its actor parameter directly to public query clients.
    """
    def __init__(self, *, allowed_reviewers: frozenset[str],
                 clock: Callable[[], datetime] | None = None):
        self._allowed_reviewers = frozenset(allowed_reviewers)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._records: tuple[StoredReviewRecord, ...] = ()
        self._revision = 0
        self._head_hash = _GENESIS
        self._lock = RLock()
        # One assignment commits both immutable outbox contents and checkpoint.
        self._release_state: tuple[tuple[StoredRelease, ...], str] = ((), _GENESIS)

    def _validate_releases(self) -> None:
        """Caller holds the ledger lock and has validated the review history."""
        try:
            releases, checkpoint = self._release_state
            previous, ids, previous_revision = _GENESIS, set(), 0
            for sequence, original in enumerate(releases, start=1):
                request = ReleaseRequest.model_validate(original.request.model_dump())
                receipt = ReleaseReceipt.model_validate(original.receipt.model_dump())
                _require(receipt.release_sequence == sequence)
                _require(receipt.release_id == request.release_id and request.release_id not in ids)
                _require(receipt.previous_release_hash == previous)
                _require(receipt.entry_hash == _release_digest(receipt))
                _require(receipt.candidate_hash == _candidate_digest(request))
                _require(receipt.payload_hash == sha256(request.payload).hexdigest())
                _require(previous_revision <= receipt.store_revision <= self._revision)
                prefix = self._records[:receipt.store_revision]
                _require(bool(prefix) and prefix[-1].entry_hash == receipt.store_head_hash)
                matching = [r for r in prefix if _key(r.request) == (
                    request.availability.document_id, request.availability.version_id)]
                _require(bool(matching))
                head = matching[-1]
                self._check_release_head(request, head)
                _require(receipt.review_sequence == head.sequence)
                _require(receipt.review_entry_hash == head.entry_hash)
                previous, previous_revision = receipt.entry_hash, receipt.store_revision
                ids.add(request.release_id)
            _require(previous == checkpoint)
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ReviewIntegrityError("Outbox validation failed; no release permitted") from exc

    @staticmethod
    def _check_release_head(request: ReleaseRequest, head: StoredReviewRecord | None) -> None:
        if head is None or head.request.verdict != ReviewVerdict.APPROVED:
            raise ReviewConflictError("Current review is not approved")
        if (head.sequence != request.expected_review_sequence
                or head.entry_hash != request.expected_review_entry_hash):
            raise ReviewConflictError("Review changed before release")
        if (head.request.availability != request.availability
                or head.availability_fingerprint != request.expected_availability_fingerprint
                or availability_fingerprint(request.availability) != request.expected_availability_fingerprint):
            raise ReviewConflictError("Release evidence does not match approval")
        if request.query_time < request.availability.capture_at:
            raise ReviewStoreError("Query precedes archive capture")

    def commit_release(self, *, request: ReleaseRequest) -> ReleaseReceipt:
        """Atomically check current approval and insert a private outbox result.

        Host-only: this does not validate archive bytes, spans, or claim semantics.
        Exact retries acknowledge a prior release even after revocation, without
        publishing again. Outbox insertion, not later transport, is release.
        """
        request = ReleaseRequest.model_validate(request.model_dump(warnings=False))
        with self._lock:
            heads = self._validate()
            self._validate_releases()
            releases, previous_hash = self._release_state
            for stored in releases:
                if stored.request.release_id == request.release_id:
                    if stored.request == request:
                        return stored.receipt
                    raise ReviewConflictError("Release ID already exists with different content")
            head = heads.get((request.availability.document_id, request.availability.version_id))
            self._check_release_head(request, head)
            receipt = ReleaseReceipt(
                release_id=request.release_id, release_sequence=len(releases) + 1,
                review_sequence=head.sequence, review_entry_hash=head.entry_hash,
                store_revision=self._revision, store_head_hash=self._head_hash,
                candidate_hash=_candidate_digest(request), payload_hash=sha256(request.payload).hexdigest(),
                previous_release_hash=previous_hash, entry_hash=_GENESIS,
            )
            receipt = receipt.model_copy(update={"entry_hash": _release_digest(receipt)})
            record = StoredRelease(request=request, receipt=receipt)
            next_state = ((*releases, record), receipt.entry_hash)
            # Linearization point, under the same lock used by review append.
            # No injected callbacks, clock calls, or I/O occur in this operation.
            self._release_state = next_state
            return receipt

    def release_history(self) -> tuple[StoredRelease, ...]:
        """Host-only audit of already released results, not fresh authorization."""
        with self._lock:
            self._validate()
            self._validate_releases()
            return self._release_state[0]

    def _validate(self) -> dict[tuple[str, str], StoredReviewRecord]:
        """Validate the whole ledger; corruption anywhere blocks all reads/writes."""
        try:
            heads, identities, ids = {}, {}, set()
            previous_hash, previous_time = _GENESIS, None
            for sequence, original in enumerate(self._records, start=1):
                record = StoredReviewRecord.model_validate_json(original.model_dump_json())
                request = record.request
                _require(record.sequence == sequence)
                _require(record.previous_entry_hash == previous_hash)
                _require(record.entry_hash == _entry_digest(record))
                _require(record.availability_fingerprint == availability_fingerprint(request.availability))
                _require(request.review_id not in ids)
                _require(previous_time is None or record.recorded_at >= previous_time)
                identity = (request.availability.document_id, request.availability.body_hash,
                            request.availability.original_url)
                version_id = request.availability.version_id
                _require(identities.get(version_id, identity) == identity)
                _check_transition(request, heads.get(_key(request)), record.recorded_at,
                                  record.expected_head_sequence)
                heads[_key(request)] = record
                identities[version_id] = identity
                ids.add(request.review_id)
                previous_hash, previous_time = record.entry_hash, record.recorded_at
            _require(self._revision == len(self._records))
            _require(self._head_hash == previous_hash)
            return heads
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ReviewIntegrityError("Ledger validation failed; no fallback permitted") from exc

    def resolve(self, *, document_id: str, version_id: str) -> ReviewResolution:
        with self._lock:
            heads = self._validate()
            head = heads.get((document_id, version_id))
            return ReviewResolution(status="found" if head else "missing", head=head,
                                    store_revision=self._revision, store_head_hash=self._head_hash)

    def history(self) -> tuple[StoredReviewRecord, ...]:
        """Immutable validated snapshot, not a mutable list or historical approval API."""
        with self._lock:
            self._validate()
            return self._records

    def append(self, *, request: ReviewRequest, actor: ReviewerContext,
               expected_head_sequence: int | None) -> StoredReviewRecord:
        actor = ReviewerContext.model_validate(actor.model_dump())
        if actor.reviewer_id not in self._allowed_reviewers:
            raise ReviewAuthorizationError("Reviewer is not allowed to write")
        request = ReviewRequest.model_validate_json(request.model_dump_json(warnings=False))
        if (expected_head_sequence is not None and
                (type(expected_head_sequence) is not int or expected_head_sequence <= 0)):
            raise ReviewStoreError("Invalid expected head sequence")
        with self._lock:
            heads = self._validate()
            for existing in self._records:
                if existing.request.review_id == request.review_id:
                    if (existing.request == request and existing.reviewer == actor.reviewer_id
                            and existing.expected_head_sequence == expected_head_sequence):
                        # A retry acknowledges the old write; it does not change the head.
                        return existing
                    raise ReviewConflictError("Review ID already exists with different content")
            try:
                now = _utc(self._clock())
            except (ValueError, TypeError, AttributeError) as exc:
                raise ReviewStoreError("Invalid store clock") from exc
            if self._records and now < self._records[-1].recorded_at:
                raise ReviewStoreError("Store clock moved backwards")
            head = heads.get(_key(request))
            _check_transition(request, head, now, expected_head_sequence)
            for existing in self._records:
                known = existing.request.availability
                if known.version_id == request.availability.version_id:
                    if (known.document_id, known.body_hash, known.original_url) != (
                        request.availability.document_id, request.availability.body_hash,
                        request.availability.original_url,
                    ):
                        raise ReviewStoreError("Version identity cannot be rebound")
            record = StoredReviewRecord(
                sequence=self._revision + 1, request=request,
                availability_fingerprint=availability_fingerprint(request.availability),
                reviewer=actor.reviewer_id, recorded_at=now,
                expected_head_sequence=expected_head_sequence,
                previous_entry_hash=self._head_hash, entry_hash=_GENESIS,
            )
            record = record.model_copy(update={"entry_hash": _entry_digest(record)})
            self._records = (*self._records, record)
            self._revision = record.sequence
            self._head_hash = record.entry_hash
            return record
