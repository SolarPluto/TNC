from datetime import datetime, timezone

from tnc.provenance.signals import paragraph_similarity
from tnc.spans.models import SourceSpan, SpanType


def make_span(
    span_id: str,
    text: str,
    span_type: SpanType = SpanType.PARAGRAPH,
) -> SourceSpan:
    return SourceSpan(
        span_id=span_id,
        document_version_id="version-001",
        ordinal=0,
        span_type=span_type,
        raw_text=text,
        normalized_text=text,
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        content_hash=f"hash-{span_id}",
    )


def test_identical_paragraphs_have_full_similarity():
    source = [
        make_span(
            "source-001",
            "Officials said five people were injured.",
        )
    ]

    target = [
        make_span(
            "target-001",
            "Officials said five people were injured.",
        )
    ]

    score = paragraph_similarity(source, target)

    assert score == 1.0


def test_different_paragraphs_have_lower_similarity():
    source = [
        make_span(
            "source-001",
            "Officials said five people were injured.",
        )
    ]

    target = [
        make_span(
            "target-001",
            "The bridge will remain closed during the inspection.",
        )
    ]

    score = paragraph_similarity(source, target)

    assert 0.0 <= score < 1.0


def test_best_matching_target_paragraph_is_used():
    source = [
        make_span(
            "source-001",
            "Emergency crews responded shortly after 7 a.m.",
        )
    ]

    target = [
        make_span(
            "target-001",
            "Investigators examined the damaged structure.",
        ),
        make_span(
            "target-002",
            "Emergency crews responded shortly after 7 a.m.",
        ),
    ]

    score = paragraph_similarity(source, target)

    assert score == 1.0


def test_non_paragraph_spans_are_ignored():
    source = [
        make_span(
            "source-heading",
            "Bridge failure",
            SpanType.HEADING,
        )
    ]

    target = [
        make_span(
            "target-heading",
            "Bridge failure",
            SpanType.HEADING,
        )
    ]

    score = paragraph_similarity(source, target)

    assert score == 0.0


def test_empty_paragraph_set_returns_zero():
    score = paragraph_similarity([], [])

    assert score == 0.0