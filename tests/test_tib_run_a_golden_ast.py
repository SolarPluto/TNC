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
