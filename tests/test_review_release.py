"""Coordinated in-memory release tests; all approvals and payloads are synthetic."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import Barrier, Event

import pytest
from pydantic import ValidationError

from tnc.provenance.admission import ArchiveAvailabilityRecord
from tnc.provenance.review_store import (
    InMemoryReviewStore, ReleaseRequest, ReviewConflictError, ReviewIntegrityError,
    ReviewRequest, ReviewerContext, ReviewStoreError, ReviewVerdict,
)

AT = datetime(2013, 5, 21, 12, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 11, tzinfo=timezone.utc)
ACTOR = ReviewerContext(reviewer_id="synthetic-reviewer")


@pytest.fixture
def setup():
    store = InMemoryReviewStore(allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: NOW)
    availability = ArchiveAvailabilityRecord(
        evidence_record_id="synthetic", document_id="doc", version_id="v1",
        original_url="https://example.test/story", body_hash="a" * 64,
        capture_at=AT, index_body_hash="b" * 64, archive_payload_digest="SYNTHETIC",
    )
    review = store.append(request=ReviewRequest(
        review_id="r1", availability=availability, verdict=ReviewVerdict.APPROVED,
        reviewed_at=NOW, rationale="Synthetic release test",
    ), actor=ACTOR, expected_head_sequence=None)
    candidate = ReleaseRequest(
        release_id="release-1", availability=availability,
        expected_review_sequence=review.sequence, expected_review_entry_hash=review.entry_hash,
        expected_availability_fingerprint=review.availability_fingerprint, query_time=AT,
        parser_version="test-parser-1", policy_version="test-policy-1", payload=b'\x00\xffsynthetic',
    )
    return store, candidate


def replace(store, candidate, verdict=ReviewVerdict.REVOKED):
    return store.append(request=ReviewRequest(
        review_id="r2", availability=candidate.availability, verdict=verdict,
        reviewed_at=NOW, rationale="Synthetic replacement", supersedes_review_id="r1",
        revokes_review_id="r1" if verdict == ReviewVerdict.REVOKED else None,
    ), actor=ACTOR, expected_head_sequence=1)


def test_release_records_exact_payload_and_review_checkpoint(setup):
    store, candidate = setup
    receipt = store.commit_release(request=candidate)
    stored, = store.release_history()
    assert stored.request == candidate and stored.receipt == receipt
    assert receipt.payload_hash == sha256(candidate.payload).hexdigest()
    assert receipt.review_sequence == receipt.store_revision == receipt.release_sequence == 1
    assert receipt.review_entry_hash == candidate.expected_review_entry_hash
    assert receipt.store_head_hash == store.history()[-1].entry_hash
    assert not hasattr(receipt, "payload")
    with pytest.raises(ValidationError):
        stored.request.payload = b"changed"


@pytest.mark.parametrize("verdict", list(ReviewVerdict))
def test_replacement_blocks_old_candidate_without_outbox_entry(setup, verdict):
    store, candidate = setup
    replace(store, candidate, verdict)
    with pytest.raises(ReviewConflictError):
        store.commit_release(request=candidate)
    assert store.release_history() == ()


def test_missing_review_blocks_release(setup):
    _, candidate = setup
    empty = InMemoryReviewStore(allowed_reviewers=frozenset())
    with pytest.raises(ReviewConflictError):
        empty.commit_release(request=candidate)
    assert empty.release_history() == ()


@pytest.mark.parametrize("field,value", [
    ("expected_review_sequence", 2), ("expected_review_entry_hash", "c" * 64),
    ("expected_availability_fingerprint", "d" * 64),
])
def test_wrong_review_preconditions_block_release(setup, field, value):
    store, candidate = setup
    with pytest.raises(ReviewConflictError):
        store.commit_release(request=candidate.model_copy(update={field: value}))
    assert store.release_history() == ()


@pytest.mark.parametrize("field,value", [
    ("document_id", "other"), ("version_id", "other"), ("evidence_record_id", "other"),
    ("body_hash", "c" * 64), ("index_body_hash", "c" * 64),
    ("original_url", "https://example.test/other"), ("archive_payload_digest", "OTHER"),
    ("capture_at", AT - timedelta(seconds=1)),
])
def test_full_evidence_binding_required(setup, field, value):
    store, candidate = setup
    candidate = candidate.model_copy(update={"availability": candidate.availability.model_copy(update={field: value})})
    with pytest.raises(ReviewConflictError):
        store.commit_release(request=candidate)
    assert store.release_history() == ()


def test_query_before_capture_blocks_release(setup):
    store, candidate = setup
    with pytest.raises(ReviewStoreError):
        store.commit_release(request=candidate.model_copy(update={"query_time": AT - timedelta(microseconds=1)}))
    assert store.release_history() == ()


def test_retry_after_revocation_acknowledges_only_prior_release(setup):
    store, candidate = setup
    receipt = store.commit_release(request=candidate)
    replace(store, candidate)
    assert store.commit_release(request=candidate) == receipt
    assert len(store.release_history()) == 1
    with pytest.raises(ReviewConflictError):
        store.commit_release(request=candidate.model_copy(update={"release_id": "new-release"}))
    assert store.resolve(document_id="doc", version_id="v1").head.request.verdict == ReviewVerdict.REVOKED


@pytest.mark.parametrize("field,value", [("payload", b"different"), ("policy_version", "v2"),
                                       ("parser_version", "v2"), ("query_time", NOW)])
def test_duplicate_id_with_different_candidate_conflicts(setup, field, value):
    store, candidate = setup
    store.commit_release(request=candidate)
    with pytest.raises(ReviewConflictError):
        store.commit_release(request=candidate.model_copy(update={field: value}))
    assert len(store.release_history()) == 1


def test_unrelated_review_does_not_invalidate_target_approval(setup):
    store, candidate = setup
    original = store.history()[0].request
    store.append(request=original.model_copy(update={"review_id": "other",
        "availability": original.availability.model_copy(update={"version_id": "v2"})}),
        actor=ACTOR, expected_head_sequence=None)
    receipt = store.commit_release(request=candidate)
    assert receipt.review_sequence == 1 and receipt.store_revision == 2
    assert len(store.release_history()) == 1


def test_equivalent_timezone_retry_is_idempotent(setup):
    store, candidate = setup
    first = store.commit_release(request=candidate)
    other = candidate.model_copy(update={"query_time": AT.astimezone(timezone(timedelta(hours=2)))})
    assert store.commit_release(request=other) == first


@pytest.mark.parametrize("field,value", [("expected_review_sequence", True), ("query_time", AT.replace(tzinfo=None)),
                                       ("policy_version", " "), ("payload", "abcd")])
def test_invalid_constructed_request_is_revalidated(setup, field, value):
    store, candidate = setup
    with pytest.raises(ValidationError):
        store.commit_release(request=candidate.model_copy(update={field: value}))
    assert store.release_history() == ()


def test_ledger_corruption_blocks_new_release_and_retry(setup):
    store, candidate = setup
    store.commit_release(request=candidate)
    before = store._release_state
    store._head_hash = "0" * 64
    for req in [candidate, candidate.model_copy(update={"release_id": "new"})]:
        with pytest.raises(ReviewIntegrityError):
            store.commit_release(request=req)
    assert store._release_state == before


@pytest.mark.parametrize("mutation", ["payload", "receipt", "truncate"])
def test_corrupted_outbox_blocks_read_and_commit(setup, mutation):
    store, candidate = setup
    store.commit_release(request=candidate)
    records, checkpoint = store._release_state
    record, = records
    if mutation == "payload":
        record = record.model_copy(update={"request": candidate.model_copy(update={"payload": b"tampered"})})
    elif mutation == "receipt":
        record = record.model_copy(update={"receipt": record.receipt.model_copy(update={"store_revision": 999})})
    store._release_state = (() if mutation == "truncate" else (record,), checkpoint)
    for operation in [store.release_history, lambda: store.commit_release(request=candidate)]:
        with pytest.raises(ReviewIntegrityError):
            operation()


def test_failure_before_atomic_assignment_leaves_outbox_unchanged(setup, monkeypatch):
    import tnc.provenance.review_store as module
    store, candidate = setup
    before = store._release_state
    with monkeypatch.context() as patch:
        def fail(_):
            raise RuntimeError("synthetic construction failure")
        patch.setattr(module, "_release_digest", fail)
        with pytest.raises(RuntimeError):
            store.commit_release(request=candidate)
    assert store._release_state == before
    assert store.commit_release(request=candidate).release_sequence == 1


def test_release_does_not_call_injected_clock(setup):
    store, candidate = setup
    def forbidden():
        raise AssertionError("Release must not invoke host callbacks")
    store._clock = forbidden
    store.commit_release(request=candidate)
    assert len(store.release_history()) == 1


def test_concurrent_exact_retries_insert_once(setup):
    store, candidate = setup
    barrier = Barrier(2)
    def release():
        barrier.wait(timeout=5)
        return store.commit_release(request=candidate)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(release), pool.submit(release)
        assert a.result(timeout=5) == b.result(timeout=5)
    assert len(store.release_history()) == 1


def test_revocation_commits_while_candidate_preparation_is_paused(setup):
    store, candidate = setup
    prepared, resume = Event(), Event()
    def execute():
        prepared.set()
        assert resume.wait(timeout=5)
        with pytest.raises(ReviewConflictError):
            store.commit_release(request=candidate)
    with ThreadPoolExecutor(max_workers=1) as pool:
        execution = pool.submit(execute)
        try:
            assert prepared.wait(timeout=5)
            replace(store, candidate)
        finally:
            resume.set()
        execution.result(timeout=5)
    assert store.release_history() == ()


def test_release_commit_and_revocation_serialize_on_same_lock(setup, monkeypatch):
    import tnc.provenance.review_store as module
    store, candidate = setup
    at_commit, continue_commit, writer_started = Event(), Event(), Event()
    real_digest = module._release_digest
    def paused_digest(receipt):
        at_commit.set()
        assert continue_commit.wait(timeout=5)
        return real_digest(receipt)
    def revoke():
        writer_started.set()
        return replace(store, candidate)
    with monkeypatch.context() as patch:
        patch.setattr(module, "_release_digest", paused_digest)
        with ThreadPoolExecutor(max_workers=2) as pool:
            release = pool.submit(store.commit_release, request=candidate)
            try:
                assert at_commit.wait(timeout=5)
                revocation = pool.submit(revoke)
                assert writer_started.wait(timeout=5)
                assert not revocation.done()
            finally:
                continue_commit.set()
            receipt = release.result(timeout=5)
            assert revocation.result(timeout=5).sequence == 2
    assert receipt.store_revision == 1
    assert len(store.release_history()) == 1
