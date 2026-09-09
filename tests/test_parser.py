from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import parse_article
from tnc.spans.models import SpanType


FIXTURE = Path(__file__).parent / "fixtures" / "article_v1.html"


def test_parser_preserves_article_structure():
    html = FIXTURE.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="version-001",
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert len(spans) == 8

    assert [span.span_type for span in spans] == [
        SpanType.HEADING,
        SpanType.PARAGRAPH,
        SpanType.PARAGRAPH,
        SpanType.QUOTE,
        SpanType.HEADING,
        SpanType.PARAGRAPH,
        SpanType.UPDATE_NOTICE,
        SpanType.CORRECTION,
    ]


def test_parser_preserves_document_order():
    html = FIXTURE.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="version-001",
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert [span.ordinal for span in spans] == list(range(8))


def test_parser_preserves_update_and_correction_text():
    html = FIXTURE.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="version-001",
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert spans[6].normalized_text == (
        "Update: Officials later said five people were injured."
    )

    assert spans[7].normalized_text == (
        "Correction: An earlier version of this article misstated "
        "the time of the incident."
    )

def test_parser_handles_frozen_abc_article():
    abc_fixture = (
        Path(__file__).parent.parent
        / "corpus"
        / "tib_run_a"
        / "objects"
        / "a4c4100c7c2af0e994b1bcea7e234615c19d845dfaaf7df5b9dd193dc89e9f00"
    )

    html = abc_fixture.read_text(encoding="utf-8")

    spans = parse_article(
        html=html,
        document_version_id="abc-test",
        available_from=datetime(2013, 5, 21, tzinfo=timezone.utc),
    )

    assert len(spans) == 33
    assert spans[0].span_type == SpanType.HEADING
    assert spans[0].normalized_text == (
        "Oklahoma Tornado Deaths Revised Down to 24, Including 9 Children"
    )
    assert spans[1].span_type == SpanType.PARAGRAPH
    assert spans[1].normalized_text == (
        "The tornado destroyed homes and businesses in a 12-mile path."
    )
