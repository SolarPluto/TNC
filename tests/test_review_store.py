"""Synthetic review ledger rules, not authentication or persistent-storage tests."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import ValidationError

from tnc.provenance.admission import ArchiveAvailabilityRecord
from tnc.provenance.review_store import (
    InMemoryReviewStore, ReviewAuthorizationError, ReviewConflictError,
    ReviewIntegrityError, ReviewRequest, ReviewerContext, ReviewStoreError,
    ReviewVerdict as V, availability_fingerprint, canonical_availability_bytes,
)

AT = datetime(2013, 5, 21, 12, 0, 16, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 11, 12, tzinfo=timezone.utc)
ACTOR = ReviewerContext(reviewer_id="test-reviewer")


@pytest.fixture
def availability():
    return ArchiveAvailabilityRecord(
        evidence_record_id="synthetic-evidence", document_id="doc", version_id="v1",
        original_url="https://example.test/article", body_hash="a"*64,
        capture_at=AT, index_body_hash="b"*64, archive_payload_digest="SYNTHETIC",
    )


@pytest.fixture
def store():
    return InMemoryReviewStore(allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: NOW)


def request(availability, review_id="r1", verdict=V.APPROVED, **changes):
    return ReviewRequest(review_id=review_id, availability=availability, verdict=verdict,
                         reviewed_at=changes.pop("reviewed_at", NOW),
                         rationale="Synthetic unit test review.", **changes)


def append(store, req, expected=None, actor=ACTOR):
    return store.append(request=req, actor=actor, expected_head_sequence=expected)


def head(store):
    return store.resolve(document_id="doc", version_id="v1")


def test_empty_store_is_missing_not_approved(store):
    result = head(store)
    assert result.status == "missing" and result.head is None
    assert result.store_revision == 0
    assert store.history() == ()


def test_approval_has_store_assigned_sequence_and_immutable_audit(store, availability):
    req = request(availability)
    before = req.model_dump_json()
    record = append(store, req)
    assert record.sequence == 1 and record.recorded_at == NOW
    assert record.reviewer == ACTOR.reviewer_id
    assert record.availability_fingerprint == availability_fingerprint(availability)
    assert head(store).head == record
    assert head(store).store_head_hash == record.entry_hash
    assert req.model_dump_json() == before
    with pytest.raises(ValidationError):
        record.sequence = 2
    assert isinstance(store.history(), tuple)
    assert not hasattr(head(store), "append")


@pytest.mark.parametrize("verdict", [V.REJECTED, V.REVOKED])
def test_blocking_head_never_falls_back_to_approval(store, availability, verdict):
    first = append(store, request(availability))
    second = append(store, request(availability, "r2", verdict, supersedes_review_id="r1",
                                  revokes_review_id="r1" if verdict == V.REVOKED else None), 1)
    assert second.sequence == 2
    assert second.previous_entry_hash == first.entry_hash
    assert head(store).status == "found"
    assert head(store).head.request.verdict == verdict
    assert store.history() == (first, second)


def test_explicit_reapproval_preserves_revocation_history(store, availability):
    append(store, request(availability))
    revoked = append(store, request(availability, "r2", V.REVOKED,
                     supersedes_review_id="r1", revokes_review_id="r1"), 1)
    approved = append(store, request(availability, "r3", supersedes_review_id="r2"), 2)
    assert head(store).head == approved
    assert store.history()[1] == revoked
    assert len(store.history()) == 3


def test_new_binding_head_is_returned_without_searching_for_old_match(store, availability):
    append(store, request(availability))
    new = availability.model_copy(update={"index_body_hash": "c"*64,
                                          "evidence_record_id": "new-index"})
    latest = append(store, request(new, "r2", V.REJECTED, supersedes_review_id="r1"), 1)
    assert head(store).head == latest
    assert head(store).head.request.availability != availability
    # API deliberately has no body/index filter that could hide the blocking head.
    with pytest.raises(TypeError):
        store.resolve(document_id="doc", version_id="v1", body_hash=availability.body_hash)


def test_equal_timestamps_use_sequence_and_concurrency_head(store, availability):
    first = append(store, request(availability))
    second = append(store, request(availability, "r2", V.REJECTED, supersedes_review_id="r1"), 1)
    assert first.request.reviewed_at == second.request.reviewed_at
    assert first.sequence < second.sequence
    assert head(store).head == second


@pytest.mark.parametrize("expected,supersedes", [(None, "r1"), (999, "r1"), (1, None), (1, "wrong")])
def test_stale_head_and_bad_links_leave_ledger_unchanged(store, availability, expected, supersedes):
    append(store, request(availability))
    before = store.history()
    with pytest.raises(ReviewConflictError):
        append(store, request(availability, "r2", supersedes_review_id=supersedes), expected)
    assert store.history() == before


@pytest.mark.parametrize("verdict,target", [(V.REVOKED, None), (V.REVOKED, "unknown"),
                                             (V.APPROVED, "r1"), (V.REJECTED, "r1")])
def test_invalid_revocation_links(store, availability, verdict, target):
    append(store, request(availability))
    with pytest.raises(ReviewStoreError):
        append(store, request(availability, "r2", verdict, supersedes_review_id="r1",
                              revokes_review_id=target), 1)
    assert head(store).head.request.review_id == "r1"


def test_revocation_requires_active_approval_and_exact_binding(store, availability):
    with pytest.raises(ReviewStoreError):
        append(store, request(availability, "r0", V.REVOKED, revokes_review_id="missing"))
    append(store, request(availability, verdict=V.REJECTED))
    with pytest.raises(ReviewStoreError):
        append(store, request(availability, "r2", V.REVOKED,
                              supersedes_review_id="r1", revokes_review_id="r1"), 1)
    append(store, request(availability, "r3", supersedes_review_id="r1"), 1)
    different = availability.model_copy(update={"evidence_record_id": "different"})
    with pytest.raises(ReviewStoreError):
        append(store, request(different, "r4", V.REVOKED,
                              supersedes_review_id="r3", revokes_review_id="r3"), 2)


def test_cross_version_revocation_and_self_link_rejected(store, availability):
    append(store, request(availability))
    other = availability.model_copy(update={"version_id": "v2"})
    with pytest.raises(ReviewStoreError):
        append(store, request(other, "r2", V.REVOKED, revokes_review_id="r1"))
    with pytest.raises(ReviewConflictError):
        append(store, request(other, "r2", supersedes_review_id="r2"))


def test_exact_retry_returns_original_without_resurrecting_old_head(store, availability):
    req = request(availability)
    first = append(store, req)
    append(store, request(availability, "r2", V.REVOKED,
                         supersedes_review_id="r1", revokes_review_id="r1"), 1)
    assert append(store, req) == first
    assert head(store).head.request.verdict == V.REVOKED
    assert head(store).store_revision == 2


def test_duplicate_id_with_different_content_or_expected_head_fails(store, availability):
    req = request(availability)
    append(store, req)
    with pytest.raises(ReviewConflictError):
        append(store, req.model_copy(update={"rationale": "changed"}))
    with pytest.raises(ReviewConflictError):
        append(store, req, 1)
    assert len(store.history()) == 1


@pytest.mark.parametrize("change", [{"document_id": "other"}, {"body_hash": "c"*64},
                                    {"original_url": "https://example.test/other"}])
def test_version_identity_cannot_be_rebound(store, availability, change):
    append(store, request(availability))
    modified = availability.model_copy(update=change)
    same_document = modified.document_id == availability.document_id
    with pytest.raises(ReviewStoreError):
        append(store, request(modified, "r2", supersedes_review_id="r1" if same_document else None),
               1 if same_document else None)
    assert len(store.history()) == 1


def test_global_sequence_and_independent_version_heads(store, availability):
    first = append(store, request(availability))
    other = availability.model_copy(update={"version_id": "v2"})
    second = append(store, request(other, "r2"))
    assert (first.sequence, second.sequence) == (1, 2)
    assert head(store).head == first
    assert store.resolve(document_id="doc", version_id="v2").head == second


@pytest.mark.parametrize("review_time", [NOW+timedelta(seconds=1), AT-timedelta(seconds=1)])
def test_review_time_outside_supported_interval(store, availability, review_time):
    with pytest.raises(ReviewStoreError):
        append(store, request(availability, reviewed_at=review_time))
    assert store.history() == ()


def test_backdated_review_is_rejected(store, availability):
    append(store, request(availability))
    with pytest.raises(ReviewStoreError, match="Backdated"):
        append(store, request(availability, "r2", supersedes_review_id="r1",
                              reviewed_at=NOW-timedelta(seconds=1)), 1)


def test_naive_timestamps_and_blank_rationale_fail_validation(availability):
    with pytest.raises(ValidationError):
        request(availability, reviewed_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValidationError):
        request(availability.model_copy(update={"capture_at": AT.replace(tzinfo=None)}))
    raw = request(availability).model_dump() | {"rationale": " "}
    with pytest.raises(ValidationError):
        ReviewRequest.model_validate(raw)


def test_writer_allowlist_and_request_injection(store, availability):
    req = request(availability)
    with pytest.raises(ReviewAuthorizationError):
        append(store, req, actor=ReviewerContext(reviewer_id="unlisted"))
    for field, value in [("reviewer", "test-reviewer"), ("sequence", 1), ("recorded_at", NOW)]:
        with pytest.raises(ValidationError):
            ReviewRequest.model_validate(req.model_dump() | {field: value})
    assert store.history() == ()


def test_invalid_model_copy_is_revalidated_on_append(store, availability):
    bad = request(availability).model_copy(update={"verdict": "admit-anything"})
    with pytest.raises(ValidationError):
        append(store, bad)
    assert store.history() == ()


def test_invalid_or_reversed_store_clock_does_not_append(availability):
    values = iter([NOW, NOW-timedelta(seconds=1), NOW.replace(tzinfo=None)])
    store = InMemoryReviewStore(allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: next(values))
    append(store, request(availability))
    req = request(availability, "r2", supersedes_review_id="r1")
    for _ in range(2):
        with pytest.raises(ReviewStoreError):
            append(store, req, 1)
    assert len(store.history()) == 1


def test_concurrent_writers_cannot_both_replace_same_head(store, availability):
    append(store, request(availability))
    barrier = Barrier(2)
    def write(name):
        barrier.wait()
        try:
            return append(store, request(availability, name, V.REJECTED, supersedes_review_id="r1"), 1)
        except ReviewConflictError:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(write, ["r2", "r3"]))
    assert sum(result is not None for result in results) == 1
    assert head(store).store_revision == 2
    assert len(store.history()) == 2


def test_canonical_bytes_are_fixed_and_offsets_equivalent(availability):
    offset = availability.model_copy(update={"capture_at": AT.astimezone(timezone(timedelta(hours=-5)))})
    expected = ('{"availability":{"archive_payload_digest":"SYNTHETIC","body_hash":"' + 'a'*64 +
        '","capture_at":"2013-05-21T12:00:16.000000Z","document_id":"doc",'
        '"evidence_record_id":"synthetic-evidence","index_body_hash":"' + 'b'*64 +
        '","original_url":"https://example.test/article","version_id":"v1"},"canonicalization_version":1}').encode()
    assert canonical_availability_bytes(availability) == expected
    assert canonical_availability_bytes(offset) == expected
    assert availability_fingerprint(offset) == availability_fingerprint(availability)


@pytest.mark.parametrize("field,value", [
    ("document_id", "other"), ("version_id", "v2"), ("body_hash", "c"*64),
    ("index_body_hash", "c"*64), ("original_url", "https://example.test/other"),
    ("capture_at", AT+timedelta(seconds=1)), ("archive_payload_digest", "OTHER"),
    ("evidence_record_id", "other-record"),
])
def test_every_availability_field_affects_fingerprint(availability, field, value):
    assert availability_fingerprint(availability.model_copy(update={field: value})) != availability_fingerprint(availability)


@pytest.mark.parametrize("mutation", ["content", "fingerprint", "sequence", "truncate", "reorder", "link"])
def test_corruption_blocks_read_and_write_without_fallback(store, availability, mutation):
    append(store, request(availability))
    append(store, request(availability, "r2", V.REJECTED, supersedes_review_id="r1"), 1)
    a, b = store.history()
    # Deliberate internal corruption tests; private access is not a supported API.
    if mutation == "content": b = b.model_copy(update={"request": b.request.model_copy(update={"rationale": "tampered"})})
    elif mutation == "fingerprint": b = b.model_copy(update={"availability_fingerprint": "0"*64})
    elif mutation == "sequence": b = b.model_copy(update={"sequence": 7})
    elif mutation == "link": b = b.model_copy(update={"previous_entry_hash": "0"*64})
    store._records = (a,) if mutation == "truncate" else (b, a) if mutation == "reorder" else (a, b)
    for operation in [lambda: head(store), lambda: store.history(),
                      lambda: append(store, request(availability, "r3", supersedes_review_id="r2"), 2)]:
        with pytest.raises(ReviewIntegrityError):
            operation()


def test_retry_with_equivalent_timezones_is_same_write(store, availability):
    req = request(availability)
    first = append(store, req)
    zone = timezone(timedelta(hours=-5))
    equivalent = request(availability.model_copy(update={"capture_at": AT.astimezone(zone)}),
                         reviewed_at=NOW.astimezone(zone))
    assert append(store, equivalent) == first
    assert len(store.history()) == 1


def test_all_real_abc_reviews_remain_missing_and_pending(store):
    root = Path(__file__).resolve().parents[1]
    path = root / "corpus/tib_run_a/sources.json"
    before = path.read_bytes()
    inventory = json.loads(before)
    for version in inventory["archive_versions"]:
        assert version["replay_admission_status"] == "pending"
        result = store.resolve(document_id=version["source_id"], version_id=version["version_id"])
        assert result.status == "missing" and result.head is None
        evidence = json.loads((root/version["evidence_file"]).read_text())
        assert evidence["replay_admission_status"] == "pending"
    assert path.read_bytes() == before
    assert store.history() == ()


def test_duplicate_review_id_cannot_be_retried_by_different_actor(availability):
    store = InMemoryReviewStore(allowed_reviewers=frozenset({"alice", "bob"}), clock=lambda: NOW)
    req = request(availability)
    append(store, req, actor=ReviewerContext(reviewer_id="alice"))
    with pytest.raises(ReviewConflictError):
        append(store, req, actor=ReviewerContext(reviewer_id="bob"))
    assert len(store.history()) == 1


def test_concurrent_exact_retries_produce_one_record(store, availability):
    barrier = Barrier(2)
    req = request(availability)
    def write(_):
        barrier.wait()
        return append(store, req)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(write, range(2)))
    assert results[0] == results[1]
    assert len(store.history()) == 1


@pytest.mark.parametrize("expected", [0, -1, True, "1"])
def test_invalid_expected_sequence_rejected_without_mutation(store, availability, expected):
    with pytest.raises(ReviewStoreError):
        append(store, request(availability), expected)
    assert store.history() == ()


def test_fractional_capture_precision_is_not_silently_rounded(availability):
    bad = availability.model_copy(update={"capture_at": AT+timedelta(microseconds=1)})
    with pytest.raises(ValueError, match="whole-second"):
        availability_fingerprint(bad)


@pytest.mark.parametrize("mutation", ["link", "backdate", "identity", "duplicate_id"])
def test_semantically_invalid_history_rejected_even_with_recomputed_hashes(store, availability, mutation):
    from tnc.provenance.review_store import _entry_digest
    append(store, request(availability))
    b = append(store, request(availability, "r2", V.REJECTED, supersedes_review_id="r1"), 1)
    req = b.request
    if mutation == "link": req = req.model_copy(update={"supersedes_review_id": "unknown"})
    elif mutation == "backdate": req = req.model_copy(update={"reviewed_at": NOW-timedelta(seconds=1)})
    elif mutation == "identity": req = req.model_copy(update={"availability": availability.model_copy(update={"body_hash": "c"*64})})
    else: req = req.model_copy(update={"review_id": "r1"})
    b = b.model_copy(update={"request": req, "availability_fingerprint": availability_fingerprint(req.availability)})
    b = b.model_copy(update={"entry_hash": _entry_digest(b)})
    store._records = (store._records[0], b)
    store._head_hash = b.entry_hash
    with pytest.raises(ReviewIntegrityError):
        head(store)
