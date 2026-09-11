"""Admission decisions are separate from parsing and historical claim promotion."""
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha1, sha256
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tnc.provenance.admission import (
    AdmissionReason as R,
    ArchiveAvailabilityRecord,
    FrozenCorpus,
    FrozenObject,
    FrozenVersion,
    HistoricalAdmissionReview,
    HistoricalAdmissionStatus as S,
    HistoricalReviewStatus as ReviewStatus,
    evaluate_historical_admission,
)

AT = datetime(2013, 5, 21, 12, 0, 16, tzinfo=timezone.utc)
OBSERVED = datetime(2026, 9, 11, tzinfo=timezone.utc)


@pytest.fixture
def candidate():
    body = b"<article><p>Archive admission test body.</p></article>"
    digest = base64.b32encode(sha1(body).digest()).decode()
    original = "https://example.test/article"
    index = json.dumps([
        ["timestamp", "original", "statuscode", "mimetype", "digest"],
        ["20130521120016", original, "200", "text/html", digest],
    ]).encode()
    version = FrozenVersion(
        document_id="doc", version_id="version", original_url=original,
        body_hash=sha256(body).hexdigest(), body=body, observed_at=OBSERVED,
    )
    obj = FrozenObject(body_hash=sha256(index).hexdigest(), body=index)
    availability = ArchiveAvailabilityRecord(
        evidence_record_id="archive-001", document_id="doc", version_id="version",
        original_url=original, body_hash=version.body_hash, capture_at=AT,
        index_body_hash=obj.body_hash, archive_payload_digest=digest,
    )
    review = HistoricalAdmissionReview(
        review_id="synthetic-approved-review", availability=availability,
        status=ReviewStatus.APPROVED, reviewer="test reviewer",
        reviewed_at=OBSERVED, rationale="Synthetic approval for unit tests only.",
    )
    return dict(document_id="doc", version_id="version", query_time=AT,
                corpus=FrozenCorpus(versions=(version,), archive_indexes=(obj,)),
                availability=availability, review=review)


def evaluate(candidate, **changes):
    return evaluate_historical_admission(**(candidate | changes))


def assert_decision(result, status, reason):
    assert result.status == status
    assert result.reason_codes == (reason,)


@pytest.mark.parametrize("offset,status,reason", [
    (-1, S.REJECTED, R.CAPTURE_TIME_AFTER_QUERY),
    (0, S.ADMITTED, R.ADMISSION_REQUIREMENTS_MET),
    (1, S.ADMITTED, R.ADMISSION_REQUIREMENTS_MET),
])
def test_inclusive_capture_boundary(candidate, offset, status, reason):
    result = evaluate(candidate, query_time=AT + timedelta(microseconds=offset))
    assert_decision(result, status, reason)
    assert result.verified_available_from == AT
    assert result.body_hash == candidate["availability"].body_hash
    assert result.evidence_record_ids == ("archive-001",)
    assert result.review_id == "synthetic-approved-review"


@pytest.mark.parametrize("review_status,status,reason", [
    (None, S.UNVERIFIED, R.MISSING_REVIEW),
    (ReviewStatus.PENDING, S.UNVERIFIED, R.REVIEW_PENDING),
    (ReviewStatus.REJECTED, S.REJECTED, R.REVIEW_REJECTED),
])
def test_review_is_separate_from_verified_availability(candidate, review_status, status, reason):
    review = None if review_status is None else candidate["review"].model_copy(update={"status": review_status})
    result = evaluate(candidate, review=review)
    assert_decision(result, status, reason)
    assert result.verified_available_from == AT


def test_future_capture_rejected_even_when_review_missing(candidate):
    assert_decision(evaluate(candidate, query_time=AT-timedelta(seconds=1), review=None),
                    S.REJECTED, R.CAPTURE_TIME_AFTER_QUERY)


@pytest.mark.parametrize("changes,reason", [
    ({"query_time": AT.replace(tzinfo=None)}, R.INVALID_QUERY_TIME),
    ({"version_id": "unknown"}, R.UNKNOWN_VERSION),
    ({"document_id": "another-document"}, R.DOCUMENT_IDENTITY_MISMATCH),
    ({"availability": None}, R.MISSING_AVAILABILITY),
])
def test_missing_or_invalid_query_coordinates(candidate, changes, reason):
    result = evaluate(candidate, **changes)
    assert_decision(result, S.REJECTED, reason)
    assert result.verified_available_from is None


@pytest.mark.parametrize("field,value,reason", [
    ("body", None, R.MISSING_BODY),
    ("body", b"changed live article", R.BODY_HASH_MISMATCH),
    ("observed_at", OBSERVED.replace(tzinfo=None), R.INVALID_RETRIEVAL_TIME),
])
def test_corpus_body_and_observation_integrity(candidate, field, value, reason):
    corpus = candidate["corpus"]
    version = corpus.versions[0].model_copy(update={field: value})
    result = evaluate(candidate, corpus=corpus.model_copy(update={"versions": (version,)}))
    assert_decision(result, S.REJECTED, reason)


def test_ambiguous_version_is_not_selected_arbitrarily(candidate):
    corpus = candidate["corpus"]
    assert_decision(evaluate(candidate, corpus=corpus.model_copy(update={"versions": corpus.versions*2})),
                    S.REJECTED, R.AMBIGUOUS_VERSION)


@pytest.mark.parametrize("field,value", [
    ("document_id", "other-doc"), ("version_id", "other-version"),
    ("body_hash", "0"*64), ("original_url", "https://example.test/other"),
])
def test_availability_must_bind_exact_identity(candidate, field, value):
    availability = candidate["availability"].model_copy(update={field: value})
    assert_decision(evaluate(candidate, availability=availability),
                    S.REJECTED, R.AVAILABILITY_BINDING_MISMATCH)


@pytest.mark.parametrize("at", [AT.replace(tzinfo=None), AT+timedelta(microseconds=1),
                                 OBSERVED+timedelta(days=1)])
def test_invalid_capture_times_rejected(candidate, at):
    assert_decision(evaluate(candidate, availability=candidate["availability"].model_copy(update={"capture_at": at})),
                    S.REJECTED, R.INVALID_CAPTURE_TIME)


def test_missing_or_tampered_index(candidate):
    corpus = candidate["corpus"]
    assert_decision(evaluate(candidate, corpus=corpus.model_copy(update={"archive_indexes": ()})),
                    S.REJECTED, R.MISSING_ARCHIVE_INDEX)
    index = corpus.archive_indexes[0].model_copy(update={"body": b"tampered"})
    assert_decision(evaluate(candidate, corpus=corpus.model_copy(update={"archive_indexes": (index,)})),
                    S.REJECTED, R.ARCHIVE_INDEX_HASH_MISMATCH)


@pytest.mark.parametrize("mutation,reason", [
    ("malformed", R.INVALID_ARCHIVE_INDEX),
    ("header", R.INVALID_ARCHIVE_INDEX),
    ("row_type", R.INVALID_ARCHIVE_INDEX),
    ("url", R.ARCHIVE_CAPTURE_MISMATCH),
    ("timestamp", R.ARCHIVE_CAPTURE_MISMATCH),
    ("status", R.ARCHIVE_CAPTURE_MISMATCH),
    ("mime", R.ARCHIVE_CAPTURE_MISMATCH),
    ("duplicate", R.ARCHIVE_CAPTURE_MISMATCH),
    ("digest", R.ARCHIVE_PAYLOAD_MISMATCH),
])
def test_index_contents_are_checked_not_just_its_hash(candidate, mutation, reason):
    corpus = candidate["corpus"]
    rows = json.loads(corpus.archive_indexes[0].body)
    if mutation == "header": rows[0][0] = "wrong"
    elif mutation == "row_type": rows[1] = {}
    elif mutation == "url": rows[1][1] = "https://example.test/other"
    elif mutation == "timestamp": rows[1][0] = "20130521120017"
    elif mutation == "status": rows[1][2] = "404"
    elif mutation == "mime": rows[1][3] = "application/json"
    elif mutation == "duplicate": rows.append(rows[1])
    elif mutation == "digest": rows[1][4] = "WRONG"
    body = b"{" if mutation == "malformed" else json.dumps(rows).encode()
    index = FrozenObject(body_hash=sha256(body).hexdigest(), body=body)
    availability = candidate["availability"].model_copy(update={"index_body_hash": index.body_hash})
    result = evaluate(candidate, corpus=corpus.model_copy(update={"archive_indexes": (index,)}),
                      availability=availability)
    assert_decision(result, S.REJECTED, reason)
    assert result.verified_available_from is None


def test_availability_payload_digest_is_checked(candidate):
    availability = candidate["availability"].model_copy(update={"archive_payload_digest": "WRONG"})
    assert_decision(evaluate(candidate, availability=availability), S.REJECTED, R.ARCHIVE_PAYLOAD_MISMATCH)


@pytest.mark.parametrize("field,value", [
    ("evidence_record_id", "other-evidence"), ("version_id", "other-version"),
    ("body_hash", "0"*64), ("index_body_hash", "0"*64),
    ("capture_at", AT+timedelta(seconds=1)),
])
def test_review_cannot_be_reused_for_different_evidence(candidate, field, value):
    stale = candidate["availability"].model_copy(update={field: value})
    review = candidate["review"].model_copy(update={"availability": stale})
    assert_decision(evaluate(candidate, review=review), S.REJECTED, R.REVIEW_BINDING_MISMATCH)


@pytest.mark.parametrize("field,value", [
    ("reviewer", None), ("reviewer", " "), ("rationale", None), ("rationale", " "),
    ("reviewed_at", None), ("reviewed_at", OBSERVED.replace(tzinfo=None)),
    ("reviewed_at", OBSERVED-timedelta(seconds=1)),
])
def test_approval_requires_review_provenance(candidate, field, value):
    review = candidate["review"].model_copy(update={field: value})
    assert_decision(evaluate(candidate, review=review), S.REJECTED, R.MISSING_REVIEW_PROVENANCE)


def test_equivalent_offsets_and_deterministic_immutable_results(candidate):
    before = {k:v.model_dump_json() for k,v in candidate.items() if hasattr(v,"model_dump_json")}
    expected = evaluate(candidate)
    assert evaluate(candidate, query_time=AT.astimezone(timezone(timedelta(hours=-5)))) == expected
    assert evaluate(candidate) == expected
    assert {k:v.model_dump_json() for k,v in candidate.items() if hasattr(v,"model_dump_json")} == before
    with pytest.raises(ValidationError):
        expected.status = S.REJECTED
    assert type(expected).model_validate_json(expected.model_dump_json()) == expected


def test_malformed_models_fail_before_evaluation(candidate):
    raw = candidate["availability"].model_dump()
    del raw["capture_at"]
    with pytest.raises(ValidationError):
        ArchiveAvailabilityRecord.model_validate(raw)
    with pytest.raises(ValidationError):
        HistoricalAdmissionReview.model_validate(candidate["review"].model_dump() | {"status": "admit-anyway"})


@pytest.mark.parametrize("index", range(3))
def test_real_abc_candidates_remain_unverified_without_promoting_records(index):
    root = Path(__file__).resolve().parents[1]
    corpus_dir = root / "corpus/tib_run_a"
    timeline = json.loads((root / "tests/fixtures/temporal/abc_capture_timeline.json").read_text())
    item = timeline["versions"][index]
    path = root / item["evidence_file"]
    original = path.read_bytes()
    evidence = json.loads(original)
    assert evidence["replay_admission_status"] == "pending"
    version = FrozenVersion(
        document_id=item["document_id"], version_id=item["version_id"],
        original_url=item["original_url"], body_hash=item["html_body_hash"],
        observed_at=datetime.fromisoformat(item["retrieved_at"].replace("Z", "+00:00")),
        body=(corpus_dir / "objects" / item["html_body_hash"]).read_bytes(),
    )
    obj = FrozenObject(body_hash=item["index_body_hash"],
                       body=(corpus_dir / "objects" / item["index_body_hash"]).read_bytes())
    availability = ArchiveAvailabilityRecord(
        evidence_record_id=item["evidence_file"], document_id=version.document_id,
        version_id=version.version_id, original_url=version.original_url,
        body_hash=version.body_hash, capture_at=datetime.fromisoformat(item["capture_at"].replace("Z", "+00:00")),
        index_body_hash=obj.body_hash, archive_payload_digest=evidence["archive_payload_digest"],
    )
    corpus = FrozenCorpus(versions=(version,), archive_indexes=(obj,))
    for review, reason in [(None, R.MISSING_REVIEW), (HistoricalAdmissionReview(
        review_id="test-adapter:pending", availability=availability, status=ReviewStatus.PENDING,
    ), R.REVIEW_PENDING)]:
        result = evaluate_historical_admission(document_id=version.document_id,
            version_id=version.version_id, query_time=availability.capture_at,
            corpus=corpus, availability=availability, review=review)
        assert_decision(result, S.UNVERIFIED, reason)
        assert result.verified_available_from == availability.capture_at
    assert path.read_bytes() == original


def test_live_body_without_archive_binding_is_rejected():
    root = Path(__file__).resolve().parents[1] / "corpus/tib_run_a"
    inventory = json.loads((root / "sources.json").read_text())
    source = next(s for s in inventory["sources"] if s["source_id"] == "cbs-ap-correction")
    assert source["historical_available_from"] is None
    version = FrozenVersion(document_id=source["source_id"], version_id="live-cbs-correction",
        original_url=source["url"], body_hash=source["body_hash"], observed_at=OBSERVED,
        body=(root / "objects" / source["body_hash"]).read_bytes())
    result = evaluate_historical_admission(document_id=version.document_id,
        version_id=version.version_id, query_time=AT, corpus=FrozenCorpus(versions=(version,)),
        availability=None, review=None)
    assert_decision(result, S.REJECTED, R.MISSING_AVAILABILITY)
