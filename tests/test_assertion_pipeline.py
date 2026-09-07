from datetime import datetime, timezone

from tnc.spans.assertions import EpistemicOperator
from tnc.spans.models import SourceSpan, SpanType
from tnc.spans.pipeline import process_assertion_spans


def make_span(
    span_id: str,
    text: str,
) -> SourceSpan:
    return SourceSpan(
        span_id=span_id,
        document_version_id="version-001",
        ordinal=0,
        span_type=SpanType.PARAGRAPH,
        raw_text=text,
        normalized_text=text,
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        content_hash=f"hash-{span_id}",
    )


def test_pipeline_admits_valid_extracted_assertion():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported five people were injured.",
        )
    ]

    result = process_assertion_spans(spans)

    assert len(result.admitted) == 1
    assert result.rejected == ()

    assertion = result.admitted[0]

    assert assertion.span_ids == ("version-001:span:1",)
    assert assertion.subject == "Officials"
    assert assertion.predicate == "reported"
    assert assertion.object == "five people were injured."
    assert assertion.epistemic_operator == EpistemicOperator.REPORTED


def test_pipeline_ignores_text_the_extractor_does_not_support():
    spans = [
        make_span(
            "version-001:span:1",
            "The bridge remained closed throughout the afternoon.",
        )
    ]

    result = process_assertion_spans(spans)

    assert result.admitted == ()
    assert result.rejected == ()


def test_pipeline_admits_multiple_independent_assertions():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported five people were injured.",
        ),
        make_span(
            "version-001:span:2",
            "Engineers confirmed inspections were underway.",
        ),
    ]

    result = process_assertion_spans(spans)

    assert len(result.admitted) == 2
    assert result.rejected == ()

    assert result.admitted[0].span_ids == (
        "version-001:span:1",
    )
    assert result.admitted[1].span_ids == (
        "version-001:span:2",
    )


def test_pipeline_canonical_assertions_do_not_keep_extraction_confidence():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported five people were injured.",
        )
    ]

    result = process_assertion_spans(spans)

    assert len(result.admitted) == 1
    assert not hasattr(
        result.admitted[0],
        "extraction_confidence",
    )