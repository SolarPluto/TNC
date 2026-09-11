"""Host-configured single-version replay; no public evidence or review overrides."""
from datetime import datetime, timezone
import json
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tnc.ingestion.parser import hash_text, normalize_text, parse_article
from tnc.provenance.admission import (
    ArchiveAvailabilityRecord, FrozenCorpus, HistoricalAdmissionDecision,
    HistoricalAdmissionReview, HistoricalAdmissionStatus, HistoricalReviewStatus,
    evaluate_historical_admission,
)
from tnc.provenance.review_store import (
    ReleaseCommitter, ReleaseReceipt, ReleaseRequest, ReviewReader, ReviewResolution,
    ReviewConflictError, ReviewIntegrityError, ReviewStoreError, ReviewVerdict,
    availability_fingerprint,
)
from tnc.spans.models import SourceSpan
from tnc.spans.replay import evidence_availability_from_spans, replay_snapshots
from tnc.spans.state import ClaimStateTransition


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TransitionInventory(Model):
    document_id: str = Field(min_length=1, pattern=r"\S")
    version_id: str = Field(min_length=1, pattern=r"\S")
    event_id: str = Field(min_length=1, pattern=r"\S")
    transitions: tuple[ClaimStateTransition, ...]


class ReplayOutcome(Model):
    status: Literal["released", "rejected", "unverified"]
    reason_codes: tuple[str, ...]
    admission: HistoricalAdmissionDecision | None = None
    receipt: ReleaseReceipt | None = None


class CoordinatedReviewStore(ReviewReader, ReleaseCommitter, Protocol):
    """Both operations must use the same authoritative ledger."""


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid replay evidence")


def _validate_spans(raw, version_id, cutoff, query_time):
    spans = [SourceSpan.model_validate(s.model_dump()) for s in raw]
    _require(bool(spans))
    ids = {s.span_id for s in spans}
    _require(len(ids) == len(spans))
    for ordinal, span in enumerate(spans):
        _require(span.ordinal == ordinal and span.span_id == f"{version_id}:span:{ordinal}")
        _require(span.document_version_id == version_id)
        _require(bool(span.normalized_text) and span.normalized_text == normalize_text(span.raw_text))
        _require(span.content_hash == hash_text(span.normalized_text))
        _require(span.available_from.utcoffset() is not None and span.available_from == cutoff <= query_time)
        # This parser produces no offsets, links, or expiry. Reject unexpected
        # coordinates until a parser contract defines their meaning.
        _require(all(getattr(span, name) is None for name in (
            "char_start", "char_end", "parent_span_id", "previous_span_id", "next_span_id", "available_until")))
    return spans


def _select_transitions(inventory, spans, query_time):
    ids, eligible = set(), []
    for transition in inventory.transitions:
        _require(bool(transition.transition_id.strip()) and bool(transition.assertion_id.strip()))
        _require(transition.transition_id not in ids and transition.occurred_at.utcoffset() is not None)
        ids.add(transition.transition_id)
        if transition.occurred_at <= query_time:
            eligible.append(transition)
    coordinates = {s.span_id: s for s in spans}
    states, times = {}, {}
    for transition in sorted(eligible, key=lambda t: (t.occurred_at, t.transition_id)):
        _require(bool(transition.evidence_span_ids))
        _require(len(set(transition.evidence_span_ids)) == len(transition.evidence_span_ids))
        for coordinate in transition.evidence_span_ids:
            _require(coordinate in coordinates)
            _require(coordinates[coordinate].available_from <= transition.occurred_at)
        # No implicit history or ambiguous simultaneous states for one assertion.
        key = transition.assertion_id
        _require(key not in times or times[key] < transition.occurred_at)
        _require(transition.from_state == states.get(key))
        states[key], times[key] = transition.to_state, transition.occurred_at
    return sorted(eligible, key=lambda t: (t.occurred_at, t.transition_id))


class HistoricalReplayEngine:
    """Single-version integration, not authentication or a durable service.

    Construct only in trusted host code. The store must implement coordinated
    release, not two unrelated reader/writer services. Existing low-level APIs
    remain callable; production entry-point enforcement is separate work.
    """
    def __init__(self, *, corpus: FrozenCorpus,
                 availability: tuple[ArchiveAvailabilityRecord, ...],
                 transitions: tuple[TransitionInventory, ...],
                 review_store: CoordinatedReviewStore):
        # Reconstruct nested records as well as outer frozen models.
        self._corpus = FrozenCorpus.model_validate(corpus.model_dump())
        self._availability = tuple(ArchiveAvailabilityRecord.model_validate(a.model_dump()) for a in availability)
        self._transitions = tuple(TransitionInventory.model_validate(t.model_dump()) for t in transitions)
        self._store = review_store

    def execute(self, *, document_id: str, version_id: str, query_time: datetime) -> ReplayOutcome:
        return self._run(document_id=document_id, version_id=version_id, query_time=query_time)

    def _prepare(self, *, document_id: str, version_id: str, query_time: datetime, release_id: str):
        """Host-only journal preparation: return a private candidate, never publish."""
        return self._run(document_id=document_id, version_id=version_id, query_time=query_time,
                         preparation_release_id=release_id)

    def _run(self, *, document_id, version_id, query_time, preparation_release_id=None):
        admission = None

        def blocked(reason, status="rejected"):
            return ReplayOutcome(status=status, reason_codes=(reason,), admission=admission)

        if (not isinstance(document_id, str) or not document_id.strip()
                or not isinstance(version_id, str) or not version_id.strip()
                or not isinstance(query_time, datetime) or query_time.utcoffset() is None):
            return blocked("INVALID_REQUEST")
        query_time = query_time.astimezone(timezone.utc)
        matches = [a for a in self._availability if (a.document_id, a.version_id) == (document_id, version_id)]
        if len(matches) > 1:
            return blocked("AMBIGUOUS_AVAILABILITY")
        availability = matches[0] if matches else None
        try:
            resolution = self._store.resolve(document_id=document_id, version_id=version_id)
            resolution = ReviewResolution.model_validate(resolution.model_dump())
            if (resolution.status == "found") != (resolution.head is not None):
                return blocked("REVIEW_STORE_INVALID")
        except (ReviewIntegrityError, ValidationError):
            return blocked("REVIEW_STORE_INVALID")
        except (ReviewStoreError, OSError):
            return blocked("REVIEW_STORE_UNAVAILABLE")
        head, review = resolution.head, None
        if head is not None:
            if (head.request.availability.document_id, head.request.availability.version_id) != (document_id, version_id):
                return blocked("REVIEW_STORE_INVALID")
            if head.request.verdict == ReviewVerdict.REVOKED:
                return blocked("REVIEW_REVOKED")
            if availability is not None:
                try:
                    fingerprint = availability_fingerprint(availability)
                except ValueError:
                    return blocked("INVALID_HOST_CONFIGURATION")
                if head.request.availability != availability or head.availability_fingerprint != fingerprint:
                    return blocked("REVIEW_EVIDENCE_MISMATCH")
            review = HistoricalAdmissionReview(
                review_id=head.request.review_id, availability=head.request.availability,
                status=HistoricalReviewStatus(head.request.verdict.value), reviewer=head.reviewer,
                reviewed_at=head.request.reviewed_at, rationale=head.request.rationale,
            )
        admission = evaluate_historical_admission(
            document_id=document_id, version_id=version_id, query_time=query_time,
            corpus=self._corpus, availability=availability, review=review,
        )
        if admission.status != HistoricalAdmissionStatus.ADMITTED:
            return blocked(admission.reason_codes[0].value, admission.status.value)
        version = next(v for v in self._corpus.versions if v.version_id == version_id)
        try:
            html = version.body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return blocked("BODY_DECODE_FAILED")
        try:
            raw = parse_article(html=html, document_version_id=version_id,
                                available_from=admission.verified_available_from)
        except ValueError:
            return blocked("PARSE_FAILED")
        try:
            spans = _validate_spans(raw, version_id, admission.verified_available_from, query_time)
        except (ValueError, AttributeError, TypeError):
            return blocked("INVALID_SPANS")
        inventories = [t for t in self._transitions if (t.document_id, t.version_id) == (document_id, version_id)]
        if not inventories:
            return blocked("MISSING_TRANSITION_CONFIGURATION")
        if len(inventories) != 1:
            return blocked("INVALID_HOST_CONFIGURATION")
        inventory = inventories[0]
        try:
            transitions = _select_transitions(inventory, spans, query_time)
            snapshots = replay_snapshots(
                event_id=inventory.event_id, timestamps=[query_time], transitions=transitions,
                evidence_availability=evidence_availability_from_spans(spans),
            )
        except ValueError:
            return blocked("INVALID_TRANSITION_EVIDENCE")
        # Payload is serialized privately before commit; no text escapes on failure.
        payload = json.dumps({
            "schema_version": 1, "admission": admission.model_dump(mode="json"),
            "spans": [s.model_dump(mode="json") for s in spans],
            "transitions": [t.model_dump(mode="json") for t in transitions],
            "snapshots": [s.model_dump(mode="json") for s in snapshots],
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        candidate = ReleaseRequest(
            release_id=preparation_release_id or str(uuid4()), availability=availability,
            expected_review_sequence=head.sequence, expected_review_entry_hash=head.entry_hash,
            expected_availability_fingerprint=head.availability_fingerprint,
            query_time=query_time, parser_version="tnc-parser-1", policy_version="single-version-replay-1",
            payload=payload,
        )
        if preparation_release_id is not None:
            return candidate
        try:
            receipt = self._store.commit_release(request=candidate)
        except ReviewIntegrityError:
            return blocked("REVIEW_STORE_INVALID")
        except ReviewConflictError:
            return blocked("REVIEW_CHANGED_BEFORE_RELEASE")
        except (ReviewStoreError, OSError):
            return blocked("RELEASE_COMMIT_FAILED")
        return ReplayOutcome(status="released", reason_codes=("RELEASE_COMMITTED",),
                             admission=admission, receipt=receipt)
