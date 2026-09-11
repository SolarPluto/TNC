"""Single-version integration with synthetic approvals and real pending captures."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, timezone
from hashlib import sha1, sha256
import json
from pathlib import Path
from threading import Event

import pytest

from test_historical_admission import candidate, AT, OBSERVED
import tnc.provenance.historical_replay as module
from tnc.provenance.admission import ArchiveAvailabilityRecord, FrozenCorpus, FrozenObject, FrozenVersion
from tnc.provenance.historical_replay import HistoricalReplayEngine, TransitionInventory
from tnc.provenance.review_store import InMemoryReviewStore, ReviewerContext, ReviewRequest, ReviewVerdict
from tnc.spans.state import ClaimState, ClaimStateTransition

ACTOR = ReviewerContext(reviewer_id="integration-test")


def store_for(candidate, verdict=ReviewVerdict.APPROVED):
    store = InMemoryReviewStore(allowed_reviewers=frozenset({ACTOR.reviewer_id}), clock=lambda: OBSERVED)
    if verdict is not None:
        store.append(request=ReviewRequest(review_id="r1", availability=candidate["availability"],
            verdict=verdict, reviewed_at=OBSERVED, rationale="Synthetic test approval"),
            actor=ACTOR, expected_head_sequence=None)
    return store


def mapping(**changes):
    transition = ClaimStateTransition(transition_id="t1", assertion_id="claim1", from_state=None,
        to_state=ClaimState.FIRST_REPORTED, occurred_at=AT, evidence_span_ids=("version:span:0",))
    return TransitionInventory(document_id="doc", version_id="version", event_id="synthetic-event",
                               transitions=(transition.model_copy(update=changes),))


def engine(candidate, store, **changes):
    return HistoricalReplayEngine(**(dict(corpus=candidate["corpus"], availability=(candidate["availability"],),
        transitions=(mapping(),), review_store=store) | changes))


def execute(engine, **changes):
    return engine.execute(**(dict(document_id="doc", version_id="version", query_time=AT) | changes))


def no_parse(monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Blocked input reached parser")
    monkeypatch.setattr(module, "parse_article", forbidden)


def test_admitted_pipeline_releases_auditable_snapshot(candidate):
    store = store_for(candidate)
    result = execute(engine(candidate, store))
    assert result.status == "released" and result.receipt is not None
    record, = store.release_history()
    data = json.loads(record.request.payload)
    assert data["snapshots"][0]["claims"][0]["state"] == "first_reported"
    assert data["snapshots"][0]["event_id"] == "synthetic-event"
    assert data["spans"][0]["available_from"].startswith("2013-05-21T12:00:16")
    assert data["admission"]["body_hash"] == candidate["availability"].body_hash
    assert "spans" not in result.model_dump()


@pytest.mark.parametrize("verdict,reason,status", [(None, "MISSING_REVIEW", "unverified"),
    (ReviewVerdict.REJECTED, "REVIEW_REJECTED", "rejected")])
def test_unapproved_never_parses(candidate, monkeypatch, verdict, reason, status):
    no_parse(monkeypatch)
    store = store_for(candidate, verdict)
    result = execute(engine(candidate, store))
    assert result.status == status and result.reason_codes == (reason,)
    assert store.release_history() == ()


@pytest.mark.parametrize("changes,reason", [
    ({"query_time": AT-timedelta(microseconds=1)}, "CAPTURE_TIME_AFTER_QUERY"),
    ({"query_time": AT.replace(tzinfo=None)}, "INVALID_REQUEST"),
    ({"document_id": " "}, "INVALID_REQUEST"),
    ({"version_id": "unknown"}, "UNKNOWN_VERSION"),
    ({"document_id": "wrong"}, "DOCUMENT_IDENTITY_MISMATCH"),
])
def test_invalid_and_future_requests_never_parse(candidate, monkeypatch, changes, reason):
    no_parse(monkeypatch)
    store = store_for(candidate)
    assert execute(engine(candidate, store), **changes).reason_codes == (reason,)
    assert store.release_history() == ()


def test_query_offset_normalized(candidate):
    store = store_for(candidate)
    result = execute(engine(candidate, store), query_time=AT.astimezone(timezone(timedelta(hours=-4))))
    assert result.status == "released"
    assert result.admission.query_time.tzinfo == timezone.utc


@pytest.mark.parametrize("field", ["review", "availability", "transitions", "corpus", "release_id"])
def test_public_override_rejected(candidate, field):
    store = store_for(candidate)
    with pytest.raises(TypeError):
        execute(engine(candidate, store), **{field: None})
    assert store.release_history() == ()


@pytest.mark.parametrize("kind,reason", [("body", "BODY_HASH_MISMATCH"), ("index", "ARCHIVE_INDEX_HASH_MISMATCH"),
    ("availability", "REVIEW_EVIDENCE_MISMATCH"), ("duplicate", "AMBIGUOUS_AVAILABILITY")])
def test_technical_binding_errors_prevent_parse(candidate, monkeypatch, kind, reason):
    store = store_for(candidate)
    no_parse(monkeypatch)
    corpus = candidate["corpus"]
    records = (candidate["availability"],)
    if kind == "body":
        corpus = corpus.model_copy(update={"versions": (corpus.versions[0].model_copy(update={"body": b"altered"}),)})
    elif kind == "index":
        corpus = corpus.model_copy(update={"archive_indexes": (corpus.archive_indexes[0].model_copy(update={"body": b"altered"}),)})
    elif kind == "availability":
        records = (records[0].model_copy(update={"evidence_record_id": "different"}),)
    else:
        records = records * 2
    assert execute(engine(candidate, store, corpus=corpus, availability=records)).reason_codes == (reason,)
    assert store.release_history() == ()


@pytest.mark.parametrize("changes", [{"span_id": "wrong"}, {"ordinal": 2}, {"document_version_id": "other"},
    {"content_hash": "bad"}, {"normalized_text": "wrong"}, {"char_start": 0},
    {"parent_span_id": "dangling"}, {"available_from": AT-timedelta(seconds=1)},
    {"available_until": AT}])
def test_invalid_parser_coordinates_block_release(candidate, monkeypatch, changes):
    store = store_for(candidate)
    parser = module.parse_article
    def altered(**kwargs):
        return [s.model_copy(update=changes) for s in parser(**kwargs)]
    monkeypatch.setattr(module, "parse_article", altered)
    assert execute(engine(candidate, store)).reason_codes == ("INVALID_SPANS",)
    assert store.release_history() == ()


@pytest.mark.parametrize("changes", [{"evidence_span_ids": ()}, {"evidence_span_ids": ("other:span:0",)},
    {"occurred_at": AT-timedelta(microseconds=1)}, {"occurred_at": AT.replace(tzinfo=None)},
    {"from_state": ClaimState.REPEATED}])
def test_invalid_transition_evidence_blocks_release(candidate, changes):
    store = store_for(candidate)
    assert execute(engine(candidate, store, transitions=(mapping(**changes),))).reason_codes == ("INVALID_TRANSITION_EVIDENCE",)
    assert store.release_history() == ()


def test_future_transition_excluded_and_empty_history_explicit(candidate):
    for transitions in [(), mapping(occurred_at=AT+timedelta(seconds=1)).transitions]:
        store = store_for(candidate)
        inventory = mapping().model_copy(update={"transitions": transitions})
        assert execute(engine(candidate, store, transitions=(inventory,))).status == "released"
        data = json.loads(store.release_history()[0].request.payload)
        assert data["snapshots"][0]["claims"] == [] and data["transitions"] == []
    store = store_for(candidate)
    assert execute(engine(candidate, store, transitions=())).reason_codes == ("MISSING_TRANSITION_CONFIGURATION",)
    assert store.release_history() == ()


def revoke(store, candidate):
    store.append(request=ReviewRequest(review_id="r2", availability=candidate["availability"],
        verdict=ReviewVerdict.REVOKED, reviewed_at=OBSERVED, rationale="Synthetic revocation",
        supersedes_review_id="r1", revokes_review_id="r1"), actor=ACTOR, expected_head_sequence=1)


def test_revocation_during_parse_blocks_atomic_release(candidate, monkeypatch):
    store = store_for(candidate)
    parser = module.parse_article
    entered, resume = Event(), Event()
    def paused(**kwargs):
        entered.set()
        assert resume.wait(timeout=5)
        return parser(**kwargs)
    monkeypatch.setattr(module, "parse_article", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(execute, engine(candidate, store))
        try:
            assert entered.wait(timeout=5)
            revoke(store, candidate)
        finally:
            resume.set()
        result = future.result(timeout=5)
    assert result.reason_codes == ("REVIEW_CHANGED_BEFORE_RELEASE",)
    assert result.receipt is None and store.release_history() == ()


def test_revoked_before_query_never_parses(candidate, monkeypatch):
    store = store_for(candidate)
    revoke(store, candidate)
    no_parse(monkeypatch)
    assert execute(engine(candidate, store)).reason_codes == ("REVIEW_REVOKED",)


@pytest.mark.parametrize("failure,reason", [("corrupt", "REVIEW_STORE_INVALID"), ("offline", "REVIEW_STORE_UNAVAILABLE")])
def test_store_failure_blocks(candidate, monkeypatch, failure, reason):
    store = store_for(candidate)
    if failure == "corrupt":
        store._head_hash = "0"*64
    else:
        def offline(**kwargs):
            raise OSError("offline")
        monkeypatch.setattr(store, "resolve", offline)
    no_parse(monkeypatch)
    assert execute(engine(candidate, store)).reason_codes == (reason,)
    assert store._release_state[0] == ()


def test_exact_retained_html_passed_to_parser(candidate, monkeypatch):
    store = store_for(candidate)
    wrapper = engine(candidate, store)
    expected = candidate["corpus"].versions[0].body.decode("utf-8")
    candidate["corpus"] = FrozenCorpus(versions=())
    parser = module.parse_article
    def checked(**kwargs):
        assert kwargs["html"] == expected
        return parser(**kwargs)
    monkeypatch.setattr(module, "parse_article", checked)
    assert execute(wrapper).status == "released"


def test_valid_hashes_do_not_permit_invalid_utf8(candidate, monkeypatch):
    body = b"<article><p>\xff</p></article>"
    digest = base64.b32encode(sha1(body).digest()).decode()
    rows = json.loads(candidate["corpus"].archive_indexes[0].body)
    rows[1][-1] = digest
    index = json.dumps(rows).encode()
    version = candidate["corpus"].versions[0].model_copy(update={"body": body, "body_hash": sha256(body).hexdigest()})
    obj = FrozenObject(body=index, body_hash=sha256(index).hexdigest())
    candidate["corpus"] = FrozenCorpus(versions=(version,), archive_indexes=(obj,))
    candidate["availability"] = candidate["availability"].model_copy(update={"body_hash": version.body_hash,
        "index_body_hash": obj.body_hash, "archive_payload_digest": digest})
    store = store_for(candidate)
    no_parse(monkeypatch)
    assert execute(engine(candidate, store)).reason_codes == ("BODY_DECODE_FAILED",)
    assert store.release_history() == ()


def test_real_abc_captures_remain_unverified(monkeypatch):
    from datetime import datetime
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root/"tests/fixtures/temporal/abc_capture_timeline.json").read_text())
    objects = root/"corpus/tib_run_a/objects"
    no_parse(monkeypatch)
    for item in fixture["versions"]:
        evidence = json.loads((root/item["evidence_file"]).read_text())
        assert evidence["replay_admission_status"] == "pending"
        at = datetime.fromisoformat(item["capture_at"])
        version = FrozenVersion(document_id=item["document_id"], version_id=item["version_id"],
            original_url=item["original_url"], body_hash=item["html_body_hash"],
            body=(objects/item["html_body_hash"]).read_bytes(), observed_at=datetime.fromisoformat(item["retrieved_at"]))
        availability = ArchiveAvailabilityRecord(evidence_record_id=item["evidence_file"],
            document_id=version.document_id, version_id=version.version_id, original_url=version.original_url,
            body_hash=version.body_hash, capture_at=at, index_body_hash=item["index_body_hash"],
            archive_payload_digest=evidence["archive_payload_digest"])
        corpus = FrozenCorpus(versions=(version,), archive_indexes=(FrozenObject(
            body_hash=item["index_body_hash"], body=(objects/item["index_body_hash"]).read_bytes()),))
        store = InMemoryReviewStore(allowed_reviewers=frozenset())
        wrapper = HistoricalReplayEngine(corpus=corpus, availability=(availability,), transitions=(), review_store=store)
        result = wrapper.execute(document_id=version.document_id, version_id=version.version_id, query_time=at)
        assert result.status == "unverified" and result.reason_codes == ("MISSING_REVIEW",)
        assert store.history() == store.release_history() == ()


@pytest.mark.parametrize("mode,reason", [("failure", "PARSE_FAILED"), ("empty", "INVALID_SPANS"),
                                       ("duplicate", "INVALID_SPANS")])
def test_parser_failure_releases_no_partial_result(candidate, monkeypatch, mode, reason):
    store = store_for(candidate)
    parser = module.parse_article
    def broken(**kwargs):
        if mode == "failure":
            raise ValueError("Unsupported content")
        if mode == "empty":
            return []
        spans = parser(**kwargs)
        return spans + spans
    monkeypatch.setattr(module, "parse_article", broken)
    result = execute(engine(candidate, store))
    assert result.reason_codes == (reason,) and result.receipt is None
    assert store.release_history() == ()


@pytest.mark.parametrize("mode", ["offline", "corrupt"])
def test_final_commit_failure_does_not_return_candidate(candidate, monkeypatch, mode):
    store = store_for(candidate)
    if mode == "offline":
        def unavailable(**kwargs):
            raise OSError("outbox unavailable")
        monkeypatch.setattr(store, "commit_release", unavailable)
        expected = "RELEASE_COMMIT_FAILED"
    else:
        parser = module.parse_article
        def corrupt(**kwargs):
            spans = parser(**kwargs)
            store._head_hash = "0" * 64
            return spans
        monkeypatch.setattr(module, "parse_article", corrupt)
        expected = "REVIEW_STORE_INVALID"
    result = execute(engine(candidate, store))
    assert result.reason_codes == (expected,) and result.receipt is None
    assert store._release_state[0] == ()


@pytest.mark.parametrize("mode", ["duplicate_id", "simultaneous_state", "duplicate_mapping"])
def test_ambiguous_transition_configuration_blocks(candidate, mode):
    store = store_for(candidate)
    inventory = mapping()
    transition = inventory.transitions[0]
    if mode == "duplicate_mapping":
        inventories = (inventory, inventory)
        expected = "INVALID_HOST_CONFIGURATION"
    else:
        other = transition if mode == "duplicate_id" else transition.model_copy(update={"transition_id": "t2"})
        inventories = (inventory.model_copy(update={"transitions": (transition, other)}),)
        expected = "INVALID_TRANSITION_EVIDENCE"
    assert execute(engine(candidate, store, transitions=inventories)).reason_codes == (expected,)
    assert store.release_history() == ()
