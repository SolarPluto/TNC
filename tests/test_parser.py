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