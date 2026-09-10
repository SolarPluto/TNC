import json
from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import parse_article


CORPUS_DIR = Path(r"corpus\tib_run_a")
OBJECTS_DIR = CORPUS_DIR / "objects"
GOLDEN_DIR = Path(r"tests\golden")

SYNTHETIC_TEST_TIME = datetime(2013, 5, 20, tzinfo=timezone.utc)


def load_manifest() -> dict:
    return json.loads(
        (CORPUS_DIR / "sources.json").read_text(encoding="utf-8")
    )


def serialize_spans(spans) -> list[dict]:
    return [
        {
            "ordinal": span.ordinal,
            "span_type": span.span_type.value,
            "raw_text": span.raw_text,
            "normalized_text": span.normalized_text,
            "content_hash": span.content_hash,
        }
        for span in spans
    ]


def test_tib_run_a_parser_matches_golden_ast() -> None:
    manifest = load_manifest()

    for source in manifest["sources"]:
        source_id = source["source_id"]
        body_hash = source["body_hash"]

        golden_path = GOLDEN_DIR / f"{source_id}.json"
        golden = json.loads(golden_path.read_text(encoding="utf-8"))

        html = (OBJECTS_DIR / body_hash).read_text(encoding="utf-8")

        spans = parse_article(
            html=html,
            document_version_id=f"{source_id}-golden-test",
            available_from=SYNTHETIC_TEST_TIME,
        )

        actual_spans = serialize_spans(spans)

        assert golden["format_version"] == 1
        assert golden["source_id"] == source_id
        assert golden["body_hash"] == body_hash
        assert golden["span_count"] == len(actual_spans)
        assert golden["spans"] == actual_spans


def test_archived_abc_matches_golden_ast():
    import hashlib

    source_id = "abc-archive-20130521155330"
    body_hash = "39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704"
    golden = json.loads(
        (GOLDEN_DIR / f"{source_id}.json").read_text(encoding="utf-8")
    )
    body = (OBJECTS_DIR / body_hash).read_bytes()

    assert hashlib.sha256(body).hexdigest() == body_hash

    spans = parse_article(
        html=body.decode("utf-8"),
        document_version_id=f"{source_id}-golden-test",
        available_from=datetime(2026, 9, 10, tzinfo=timezone.utc),
    )

    assert golden["format_version"] == 1
    assert golden["source_id"] == source_id
    assert golden["body_hash"] == body_hash
    assert golden["span_count"] == len(spans) == 22
    assert golden["spans"] == serialize_spans(spans)


def test_archived_abc_evidence_matches_saved_capture():
    import base64
    import hashlib

    evidence = json.loads(
        (CORPUS_DIR / "abc_archive_20130521155330_evidence.json")
        .read_text(encoding="utf-8")
    )

    html_hash = evidence["html_body_hash"]
    index_hash = evidence["index_body_hash"]
    body = (OBJECTS_DIR / html_hash).read_bytes()
    index_body = (OBJECTS_DIR / index_hash).read_bytes()

    assert hashlib.sha256(body).hexdigest() == html_hash
    assert hashlib.sha256(index_body).hexdigest() == index_hash

    rows = json.loads(index_body)
    assert len(rows) == 2
    capture = dict(zip(rows[0], rows[1]))

    assert capture["original"] == (
        "http://abcnews.go.com/US/"
        "oklahoma-tornado-deaths-revised-24-including-children/"
        "story?id=19222656"
    )
    assert capture["statuscode"] == "200"
    assert capture["mimetype"] == "text/html"

    captured_at = datetime.strptime(
        capture["timestamp"], "%Y%m%d%H%M%S"
    ).replace(tzinfo=timezone.utc)
    recorded_at = datetime.fromisoformat(
        evidence["archive_capture_at"].replace("Z", "+00:00")
    )
    assert captured_at == recorded_at

    digest = base64.b32encode(hashlib.sha1(body).digest()).decode("ascii")
    assert digest == capture["digest"] == evidence["archive_payload_digest"]
    assert evidence["payload_digest_matches"] is True
