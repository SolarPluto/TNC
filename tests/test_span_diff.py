from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import parse_article
from tnc.spans.diff import SpanChangeType, diff_spans
from tnc.spans.models import SpanType


FIXTURES = Path(__file__).parent / "fixtures"


def load_spans(filename: str, version_id: str):
    html = (FIXTURES / filename).read_text(encoding="utf-8")

    return parse_article(
        html=html,
        document_version_id=version_id,
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_diff_detects_version_changes():
    old_spans = load_spans("article_v1.html", "version-001")
    new_spans = load_spans("article_v2.html", "version-002")

    changes = diff_spans(old_spans, new_spans)

    assert changes[0].change_type == SpanChangeType.MODIFIED
    assert changes[1].change_type == SpanChangeType.UNCHANGED
    assert changes[2].change_type == SpanChangeType.MODIFIED
    assert changes[3].change_type == SpanChangeType.UNCHANGED
    assert changes[4].change_type == SpanChangeType.UNCHANGED
    assert changes[5].change_type == SpanChangeType.UNCHANGED


def test_diff_identifies_inserted_span_without_corrupting_later_matches():
    old_spans = load_spans("article_v1.html", "version-001")
    new_spans = load_spans("article_v2.html", "version-002")

    changes = diff_spans(old_spans, new_spans)

    inserted = [
        change
        for change in changes
        if change.change_type == SpanChangeType.INSERTED
    ]

    assert len(inserted) == 1
    assert inserted[0].new_span is not None
    assert inserted[0].new_span.normalized_text == (
        "The bridge will remain closed while inspectors assess the damage."
    )


def test_diff_keeps_later_correction_aligned_after_insertion():
    old_spans = load_spans("article_v1.html", "version-001")
    new_spans = load_spans("article_v2.html", "version-002")

    changes = diff_spans(old_spans, new_spans)

    correction_changes = [
        change
        for change in changes
        if (
            change.old_span is not None
            and change.new_span is not None
            and change.old_span.span_type == SpanType.CORRECTION
            and change.new_span.span_type == SpanType.CORRECTION
        )
    ]

    assert len(correction_changes) == 1
    assert correction_changes[0].change_type == SpanChangeType.UNCHANGED
