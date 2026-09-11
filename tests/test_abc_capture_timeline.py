"""Archive-observation boundary tests, not admission of historical claims."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from tnc.ingestion.parser import parse_article
from tnc.spans.models import DocumentVersion
from tnc.spans.replay import (
    TemporalIntegrityError,
    evidence_availability_from_spans,
    replay_snapshots,
)
from tnc.spans.state import ClaimState, ClaimStateTransition
from tnc.spans.temporal import select_document_version_at, select_spans_at

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus" / "tib_run_a"
FIXTURE = json.loads(
    (ROOT / "tests/fixtures/temporal/abc_capture_timeline.json").read_text(encoding="utf-8")
)


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert result.tzinfo is not None
    return result


@pytest.fixture(scope="module")
def archive():
    inventory = json.loads((CORPUS / "sources.json").read_text(encoding="utf-8"))
    records = [json.loads(line) for line in
               (CORPUS / "archive_manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    versions, spans_by_version = [], {}
    for item in FIXTURE["versions"]:
        stored = next(v for v in inventory["archive_versions"]
                      if v["version_id"] == item["version_id"])
        evidence = json.loads((ROOT / item["evidence_file"]).read_text(encoding="utf-8"))
        assert stored["replay_admission_status"] == evidence["replay_admission_status"] == "pending"
        for field in ("html_body_hash", "index_body_hash", "evidence_file"):
            assert item[field] == stored[field]
        assert item["capture_at"] == stored["archive_capture_at"] == evidence["archive_capture_at"]
        assert item["document_id"] == stored["source_id"]
        body = (CORPUS / "objects" / item["html_body_hash"]).read_bytes()
        index = (CORPUS / "objects" / item["index_body_hash"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == item["html_body_hash"] == evidence["html_body_hash"]
        assert hashlib.sha256(index).hexdigest() == item["index_body_hash"] == evidence["index_body_hash"]
        rows = json.loads(index)
        matches = [dict(zip(rows[0], row)) for row in rows[1:]
                   if row[0] == timestamp(item["capture_at"]).strftime("%Y%m%d%H%M%S")]
        assert len(matches) == 1
        capture = matches[0]
        assert capture["original"] == item["original_url"]
        assert capture["statuscode"] == "200"
        assert capture["mimetype"] == "text/html"
        assert base64.b32encode(hashlib.sha1(body).digest()).decode() == capture["digest"] == evidence["archive_payload_digest"]
        assert evidence["payload_digest_matches"] is True
        assert any(r["body_hash"] == item["html_body_hash"]
                   and r["retrieved_at"] == item["retrieved_at"]
                   and r["requested_url"].endswith("id_/" + item["original_url"])
                   for r in records)
        assert item["first_published_at"] is item["exact_edit_at"] is None
        cutoff = timestamp(item["capture_at"])
        # Explicit test-only effective availability; real corpus stays pending.
        versions.append(DocumentVersion(
            version_id=item["version_id"], document_id=item["document_id"],
            observed_at=timestamp(item["retrieved_at"]), effective_from=cutoff,
            body_hash=item["html_body_hash"], content_hash=item["html_body_hash"],
        ))
        spans_by_version[item["version_id"]] = parse_article(
            html=body.decode("utf-8"), document_version_id=item["version_id"],
            available_from=cutoff,
        )
    return versions, spans_by_version


def selected_at(versions, spans_by_version, at):
    selected = []
    for document_id in sorted({v.document_id for v in versions}):
        version = select_document_version_at(
            [v for v in versions if v.document_id == document_id], at,
        )
        if version is not None:
            selected.append(version)
    spans = select_spans_at(
        [s for v in selected for s in spans_by_version[v.version_id]], at,
    )
    return selected, spans


@pytest.mark.parametrize("case", FIXTURE["checkpoints"], ids=lambda c: c["case_id"])
def test_archive_visibility_boundaries(archive, case):
    versions, spans_by_version = archive
    at = timestamp(case["query_at"])
    selected, visible = selected_at(versions, spans_by_version, at)
    expected = set(case["expected_selected_versions"])
    assert {v.version_id for v in selected} == expected
    assert {s.document_version_id for s in visible} == expected
    # No spans disappear within the selected version, including its headline.
    assert len(visible) == sum(len(spans_by_version[v]) for v in expected)
    assert all(s.available_from <= at for s in visible)


def observation_probe(version, spans):
    # Synthetic FIRST_REPORTED marker tests replay mechanics only. It is not an
    # extracted casualty assertion or a claim of first historical publication.
    return ClaimStateTransition(
        transition_id="probe:" + version.version_id,
        assertion_id="test-observation:" + version.version_id,
        from_state=None, to_state=ClaimState.FIRST_REPORTED,
        occurred_at=version.effective_from,
        evidence_span_ids=(spans[0].span_id,),
        rationale="Synthetic test-only observation marker; no factual admission.",
    )


@pytest.mark.parametrize("index", range(3))
def test_replay_probe_respects_capture_boundary(archive, index):
    versions, spans_by_version = archive
    version = versions[index]
    spans = spans_by_version[version.version_id]
    availability = evidence_availability_from_spans(spans)
    probe = observation_probe(version, spans)
    snapshots = replay_snapshots(
        event_id=FIXTURE["fixture_id"],
        timestamps=[version.effective_from + timedelta(microseconds=offset)
                    for offset in (-1, 0, 1)],
        transitions=[probe], evidence_availability=availability,
    )
    assert snapshots[0].claims == ()
    for snapshot in snapshots[1:]:
        assert len(snapshot.claims) == 1
        assert snapshot.claims[0].evidence_span_ids == (spans[0].span_id,)
        assert snapshot.claims[0].state == ClaimState.FIRST_REPORTED
    with pytest.raises(TemporalIntegrityError, match="not yet available"):
        replay_snapshots(
            event_id=FIXTURE["fixture_id"], timestamps=[version.effective_from],
            transitions=[probe.model_copy(update={
                "occurred_at": version.effective_from - timedelta(microseconds=1),
            })], evidence_availability=availability,
        )
    with pytest.raises(TemporalIntegrityError, match="no availability record"):
        replay_snapshots(
            event_id=FIXTURE["fixture_id"], timestamps=[version.effective_from],
            transitions=[probe], evidence_availability={},
        )


def test_revision_preserves_separate_early_article_and_discrepancy(archive):
    versions, spans = archive
    early, correction, later = versions
    assert early.document_id != correction.document_id == later.document_id
    before = selected_at(versions, spans, later.effective_from - timedelta(microseconds=1))[1]
    after = selected_at(versions, spans, later.effective_from)[1]
    first = spans[correction.version_id]
    second = spans[later.version_id]
    assert "7 Children" in first[0].normalized_text
    assert "nine children" in first[1].normalized_text
    assert "9 Children" in second[0].normalized_text
    assert [(s.ordinal, s.span_type, s.normalized_text) for s in first[1:]] == [
        (s.ordinal, s.span_type, s.normalized_text) for s in second[1:]
    ]
    assert first[0] in before and second[0] not in before
    assert second[0] in after and first[0] not in after
    assert spans[early.version_id][1] in before
    assert spans[early.version_id][1] in after
    assert "51" in spans[early.version_id][1].normalized_text


def test_retrieval_is_not_backdated_without_test_effective_cutoff(archive):
    versions, _ = archive
    for version in versions:
        assert version.observed_at.year == 2026
        unadmitted = version.model_copy(update={"effective_from": None})
        assert select_document_version_at([unadmitted], version.effective_from) is None
        assert select_document_version_at([unadmitted], version.observed_at) == unadmitted


def test_equivalent_timezones_and_repeat_selection(archive):
    versions, spans = archive
    at = versions[-1].effective_from
    expected = selected_at(versions, spans, at)
    assert selected_at(versions, spans, at.astimezone(timezone(timedelta(hours=-5)))) == expected
    assert selected_at(list(reversed(versions)), spans, at) == expected
    assert selected_at(versions, spans, at) == expected
