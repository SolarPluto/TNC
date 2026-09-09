from datetime import datetime, timezone
import json
from pathlib import Path

from tnc.ingestion.parser import parse_article


CORPUS_DIR = Path(__file__).parent.parent / "corpus" / "tib_run_a"
OBJECTS_DIR = CORPUS_DIR / "objects"

EXPECTED_SPAN_COUNTS = {
    "mpr-ap-early": 45,
    "cbs-ap-early": 34,
    "cbs-ap-correction": 67,
    "abc-correction": 33,
    "cbs-ap-status": 63,
    "nws-retrospective": 517,
}


def test_tib_run_a_frozen_corpus_parser_counts():
    manifest = json.loads(
        (CORPUS_DIR / "sources.json").read_text(encoding="utf-8")
    )

    synthetic_test_time = datetime(
        2013, 5, 20, tzinfo=timezone.utc
    )

    actual_counts = {}

    for source in manifest["sources"]:
        source_id = source["source_id"]
        html = (
            OBJECTS_DIR / source["body_hash"]
        ).read_text(encoding="utf-8")

        spans = parse_article(
            html=html,
            document_version_id=f"{source_id}-parser-test",
            available_from=synthetic_test_time,
        )

        actual_counts[source_id] = len(spans)

    assert actual_counts == EXPECTED_SPAN_COUNTS
