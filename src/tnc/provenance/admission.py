"""Read-only admission of exact archived versions, separate from claim replay."""
import base64
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha1, sha256
import json

from pydantic import BaseModel, ConfigDict, Field


class HistoricalAdmissionStatus(StrEnum):
    ADMITTED = "admitted"
    REJECTED = "rejected"
    UNVERIFIED = "unverified"


class AdmissionReason(StrEnum):
    INVALID_QUERY_TIME = "INVALID_QUERY_TIME"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    AMBIGUOUS_VERSION = "AMBIGUOUS_VERSION"
    DOCUMENT_IDENTITY_MISMATCH = "DOCUMENT_IDENTITY_MISMATCH"
    MISSING_BODY = "MISSING_BODY"
    BODY_HASH_MISMATCH = "BODY_HASH_MISMATCH"
    INVALID_RETRIEVAL_TIME = "INVALID_RETRIEVAL_TIME"
    MISSING_AVAILABILITY = "MISSING_AVAILABILITY"
    AVAILABILITY_BINDING_MISMATCH = "AVAILABILITY_BINDING_MISMATCH"
    INVALID_CAPTURE_TIME = "INVALID_CAPTURE_TIME"
    MISSING_ARCHIVE_INDEX = "MISSING_ARCHIVE_INDEX"
    ARCHIVE_INDEX_HASH_MISMATCH = "ARCHIVE_INDEX_HASH_MISMATCH"
    INVALID_ARCHIVE_INDEX = "INVALID_ARCHIVE_INDEX"
    ARCHIVE_CAPTURE_MISMATCH = "ARCHIVE_CAPTURE_MISMATCH"
    ARCHIVE_PAYLOAD_MISMATCH = "ARCHIVE_PAYLOAD_MISMATCH"
    CAPTURE_TIME_AFTER_QUERY = "CAPTURE_TIME_AFTER_QUERY"
    MISSING_REVIEW = "MISSING_REVIEW"
    REVIEW_BINDING_MISMATCH = "REVIEW_BINDING_MISMATCH"
    REVIEW_PENDING = "REVIEW_PENDING"
    REVIEW_REJECTED = "REVIEW_REJECTED"
    MISSING_REVIEW_PROVENANCE = "MISSING_REVIEW_PROVENANCE"
    ADMISSION_REQUIREMENTS_MET = "ADMISSION_REQUIREMENTS_MET"


class AdmissionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FrozenVersion(AdmissionRecord):
    document_id: str = Field(min_length=1, pattern=r"\S")
    version_id: str = Field(min_length=1, pattern=r"\S")
    original_url: str = Field(min_length=1, pattern=r"\S")
    body_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime
    body: bytes | None


class FrozenObject(AdmissionRecord):
    body_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    body: bytes


class FrozenCorpus(AdmissionRecord):
    versions: tuple[FrozenVersion, ...]
    archive_indexes: tuple[FrozenObject, ...] = ()


class ArchiveAvailabilityRecord(AdmissionRecord):
    evidence_record_id: str = Field(min_length=1, pattern=r"\S")
    document_id: str = Field(min_length=1, pattern=r"\S")
    version_id: str = Field(min_length=1, pattern=r"\S")
    original_url: str = Field(min_length=1, pattern=r"\S")
    body_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    capture_at: datetime
    index_body_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    archive_payload_digest: str = Field(min_length=1, pattern=r"\S")


class HistoricalReviewStatus(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    PENDING = "pending"


class HistoricalAdmissionReview(AdmissionRecord):
    review_id: str = Field(min_length=1, pattern=r"\S")
    # Bind the complete evidence record, not merely a mutable evidence ID.
    availability: ArchiveAvailabilityRecord
    status: HistoricalReviewStatus
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    rationale: str | None = None


class HistoricalAdmissionDecision(AdmissionRecord):
    status: HistoricalAdmissionStatus
    document_id: str
    version_id: str
    query_time: datetime
    verified_available_from: datetime | None
    body_hash: str | None
    reason_codes: tuple[AdmissionReason, ...]
    evidence_record_ids: tuple[str, ...]
    review_id: str | None


def _aware(value: datetime | None) -> bool:
    return value is not None and value.utcoffset() is not None


def _capture_row(index: bytes, availability: ArchiveAvailabilityRecord) -> dict:
    """Read the saved CDX JSON table; reject malformed or ambiguous matches."""
    rows = json.loads(index)
    required = {"timestamp", "original", "statuscode", "mimetype", "digest"}
    if (not isinstance(rows, list) or not rows or not isinstance(rows[0], list)
            or not all(isinstance(x, str) for x in rows[0])
            or len(set(rows[0])) != len(rows[0]) or not required.issubset(rows[0])):
        raise ValueError("Invalid CDX header")
    header = rows[0]
    parsed = []
    for row in rows[1:]:
        if (not isinstance(row, list) or len(row) != len(header)
                or not all(isinstance(x, str) for x in row)):
            raise ValueError("Invalid CDX row")
        parsed.append(dict(zip(header, row)))
    capture_key = availability.capture_at.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S")
    matches = [r for r in parsed if r["timestamp"] == capture_key
               and r["original"] == availability.original_url]
    if len(matches) != 1:
        return {}
    return matches[0]


def evaluate_historical_admission(
    *,
    document_id: str,
    version_id: str,
    query_time: datetime,
    corpus: FrozenCorpus,
    availability: ArchiveAvailabilityRecord | None,
    review: HistoricalAdmissionReview | None,
) -> HistoricalAdmissionDecision:
    """Evaluate one query without parsing articles, writing records, or admitting claims.

    Only ADMITTED permits downstream processing. Inputs must be validated models;
    malformed input records raise Pydantic validation errors before evaluation.
    The caller supplies reviews from a trusted review store: this function checks
    binding and provenance fields, not reviewer authentication or authorization.
    """
    verified_at = None
    body_hash = None

    def decision(reason, status=HistoricalAdmissionStatus.REJECTED):
        return HistoricalAdmissionDecision(
            status=status, document_id=document_id, version_id=version_id,
            query_time=query_time, verified_available_from=verified_at,
            body_hash=body_hash, reason_codes=(reason,),
            # These identify supplied records, including rejected ones; their
            # presence is not a claim that the records passed verification.
            evidence_record_ids=(availability.evidence_record_id,) if availability else (),
            review_id=review.review_id if review else None,
        )

    if not _aware(query_time):
        return decision(AdmissionReason.INVALID_QUERY_TIME)
    matches = [v for v in corpus.versions if v.version_id == version_id]
    if not matches:
        return decision(AdmissionReason.UNKNOWN_VERSION)
    if len(matches) != 1:
        return decision(AdmissionReason.AMBIGUOUS_VERSION)
    version = matches[0]
    body_hash = version.body_hash
    if version.document_id != document_id:
        return decision(AdmissionReason.DOCUMENT_IDENTITY_MISMATCH)
    if version.body is None:
        return decision(AdmissionReason.MISSING_BODY)
    if sha256(version.body).hexdigest() != version.body_hash:
        return decision(AdmissionReason.BODY_HASH_MISMATCH)
    if not _aware(version.observed_at):
        return decision(AdmissionReason.INVALID_RETRIEVAL_TIME)
    if availability is None:
        return decision(AdmissionReason.MISSING_AVAILABILITY)
    if (availability.document_id != document_id or availability.version_id != version_id
            or availability.body_hash != version.body_hash
            or availability.original_url != version.original_url):
        return decision(AdmissionReason.AVAILABILITY_BINDING_MISMATCH)
    if (not _aware(availability.capture_at) or availability.capture_at.microsecond
            or availability.capture_at > version.observed_at):
        return decision(AdmissionReason.INVALID_CAPTURE_TIME)
    indexes = [x for x in corpus.archive_indexes if x.body_hash == availability.index_body_hash]
    if not indexes:
        return decision(AdmissionReason.MISSING_ARCHIVE_INDEX)
    if len(indexes) != 1:
        return decision(AdmissionReason.INVALID_ARCHIVE_INDEX)
    index = indexes[0]
    if sha256(index.body).hexdigest() != index.body_hash:
        return decision(AdmissionReason.ARCHIVE_INDEX_HASH_MISMATCH)
    try:
        row = _capture_row(index.body, availability)
    except (ValueError, UnicodeDecodeError):
        return decision(AdmissionReason.INVALID_ARCHIVE_INDEX)
    if not row or row["statuscode"] != "200" or row["mimetype"] != "text/html":
        return decision(AdmissionReason.ARCHIVE_CAPTURE_MISMATCH)
    digest = base64.b32encode(sha1(version.body).digest()).decode("ascii")
    if digest != row["digest"] or digest != availability.archive_payload_digest:
        return decision(AdmissionReason.ARCHIVE_PAYLOAD_MISMATCH)
    verified_at = availability.capture_at
    if verified_at > query_time:
        return decision(AdmissionReason.CAPTURE_TIME_AFTER_QUERY)
    if review is None:
        return decision(AdmissionReason.MISSING_REVIEW, HistoricalAdmissionStatus.UNVERIFIED)
    if review.availability != availability:
        return decision(AdmissionReason.REVIEW_BINDING_MISMATCH)
    if review.status == HistoricalReviewStatus.PENDING:
        return decision(AdmissionReason.REVIEW_PENDING, HistoricalAdmissionStatus.UNVERIFIED)
    if review.status == HistoricalReviewStatus.REJECTED:
        return decision(AdmissionReason.REVIEW_REJECTED)
    if (not review.reviewer or not review.reviewer.strip()
            or not review.rationale or not review.rationale.strip()
            or not _aware(review.reviewed_at)
            or review.reviewed_at < version.observed_at):
        return decision(AdmissionReason.MISSING_REVIEW_PROVENANCE)
    return decision(AdmissionReason.ADMISSION_REQUIREMENTS_MET, HistoricalAdmissionStatus.ADMITTED)
