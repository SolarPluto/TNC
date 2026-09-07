from datetime import datetime, timezone

from tnc.provenance.signals import (
    extract_explicit_citations,
    extract_named_sources,
    has_explicit_citation,
    measure_provenance_signals,
    named_source_overlap,
    paragraph_similarity,
    quote_overlap,
)
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

    assert paragraph_similarity(source, target) == 1.0


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

    assert paragraph_similarity(source, target) == 1.0


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

    assert paragraph_similarity(source, target) == 0.0


def test_empty_paragraph_set_returns_zero():
    assert paragraph_similarity([], []) == 0.0


def test_identical_quotes_have_full_overlap():
    source = [
        make_span(
            "source-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        )
    ]
    target = [
        make_span(
            "target-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        )
    ]

    assert quote_overlap(source, target) == 1.0


def test_different_quotes_have_lower_overlap():
    source = [
        make_span(
            "source-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        )
    ]
    target = [
        make_span(
            "target-quote",
            "The bridge will reopen after inspectors finish their work.",
            SpanType.QUOTE,
        )
    ]

    score = quote_overlap(source, target)

    assert 0.0 <= score < 1.0


def test_quote_overlap_is_symmetric():
    source = [
        make_span(
            "source-quote-1",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        ),
        make_span(
            "source-quote-2",
            "Crews will remain on scene throughout the day.",
            SpanType.QUOTE,
        ),
    ]
    target = [
        make_span(
            "target-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        )
    ]

    forward = quote_overlap(source, target)
    reverse = quote_overlap(target, source)

    assert forward == reverse
    assert 0.0 < forward < 1.0


def test_non_quote_spans_are_ignored_for_quote_overlap():
    source = [
        make_span(
            "source-paragraph",
            "We are still assessing the situation.",
            SpanType.PARAGRAPH,
        )
    ]
    target = [
        make_span(
            "target-paragraph",
            "We are still assessing the situation.",
            SpanType.PARAGRAPH,
        )
    ]

    assert quote_overlap(source, target) == 0.0


def test_empty_quote_set_returns_zero():
    assert quote_overlap([], []) == 0.0


def test_extract_named_source_before_attribution_verb():
    spans = [
        make_span(
            "source-001",
            "Fire Chief Maria Lopez said crews were still assessing the damage.",
        )
    ]

    names = extract_named_sources(spans)

    assert "fire chief maria lopez" in names


def test_extract_multiple_named_sources():
    spans = [
        make_span(
            "source-001",
            "Maria Lopez said the bridge would remain closed.",
        ),
        make_span(
            "source-002",
            "Daniel Reed confirmed inspectors had arrived.",
        ),
    ]

    names = extract_named_sources(spans)

    assert names == {"maria lopez", "daniel reed"}


def test_named_source_extraction_ignores_text_without_attribution():
    spans = [
        make_span(
            "source-001",
            "Maria Lopez arrived at the scene shortly after noon.",
        )
    ]

    assert extract_named_sources(spans) == set()


def test_identical_named_source_sets_have_full_overlap():
    source = [
        make_span(
            "source-001",
            "Maria Lopez said crews were still assessing the damage.",
        )
    ]
    target = [
        make_span(
            "target-001",
            "Maria Lopez said the bridge would remain closed.",
        )
    ]

    assert named_source_overlap(source, target) == 1.0


def test_partial_named_source_overlap_uses_jaccard_similarity():
    source = [
        make_span(
            "source-001",
            "Maria Lopez said crews were still assessing the damage.",
        ),
        make_span(
            "source-002",
            "Daniel Reed confirmed inspectors had arrived.",
        ),
    ]
    target = [
        make_span(
            "target-001",
            "Maria Lopez said the bridge would remain closed.",
        ),
        make_span(
            "target-002",
            "Priya Shah reported traffic was being diverted.",
        ),
    ]

    assert named_source_overlap(source, target) == 1 / 3


def test_named_source_overlap_is_symmetric():
    source = [
        make_span(
            "source-001",
            "Maria Lopez said crews were still assessing the damage.",
        ),
        make_span(
            "source-002",
            "Daniel Reed confirmed inspectors had arrived.",
        ),
    ]
    target = [
        make_span(
            "target-001",
            "Maria Lopez said the bridge would remain closed.",
        )
    ]

    assert named_source_overlap(source, target) == named_source_overlap(
        target,
        source,
    )


def test_named_source_overlap_returns_zero_without_sources():
    source = [
        make_span(
            "source-001",
            "The bridge remained closed throughout the afternoon.",
        )
    ]
    target = [
        make_span(
            "target-001",
            "Inspectors examined the damaged structure.",
        )
    ]

    assert named_source_overlap(source, target) == 0.0


def test_extract_explicit_citation_from_according_to():
    spans = [
        make_span(
            "target-001",
            "According to Reuters, five people were injured.",
        )
    ]

    citations = extract_explicit_citations(spans)

    assert "reuters" in citations


def test_extract_explicit_citation_from_reported_phrase():
    spans = [
        make_span(
            "target-001",
            "The Associated Press reported five people were injured.",
        )
    ]

    citations = extract_explicit_citations(spans)

    assert "the associated press" in citations


def test_has_explicit_citation_matches_case_insensitively():
    spans = [
        make_span(
            "target-001",
            "According to Reuters, officials closed the bridge.",
        )
    ]

    assert has_explicit_citation(spans, "REUTERS") is True


def test_has_explicit_citation_returns_false_without_citation():
    spans = [
        make_span(
            "target-001",
            "Officials closed the bridge shortly after 7 a.m.",
        )
    ]

    assert has_explicit_citation(spans, "Reuters") is False


def test_measure_provenance_signals_builds_signal_model():
    source = [
        make_span(
            "source-paragraph",
            "Maria Lopez said five people were injured.",
        ),
        make_span(
            "source-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        ),
    ]

    target = [
        make_span(
            "target-paragraph",
            "Maria Lopez said five people were injured.",
        ),
        make_span(
            "target-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        ),
    ]

    signals = measure_provenance_signals(
        source_spans=source,
        target_spans=target,
        source_name="Reuters",
        source_published_before_target=True,
    )

    assert signals.paragraph_similarity == 1.0
    assert signals.quote_overlap == 1.0
    assert signals.named_source_overlap == 1.0
    assert signals.explicit_citation is False
    assert signals.source_published_before_target is True


def test_measure_provenance_signals_detects_explicit_citation():
    source = [
        make_span(
            "source-paragraph",
            "Officials closed the bridge.",
        )
    ]

    target = [
        make_span(
            "target-paragraph",
            "According to Reuters, officials closed the bridge.",
        )
    ]

    signals = measure_provenance_signals(
        source_spans=source,
        target_spans=target,
        source_name="Reuters",
        source_published_before_target=True,
    )

    assert signals.explicit_citation is True


def test_measure_provenance_signals_preserves_unknown_time_order():
    signals = measure_provenance_signals(
        source_spans=[],
        target_spans=[],
        source_name="Reuters",
        source_published_before_target=None,
    )

    assert signals.paragraph_similarity == 0.0
    assert signals.quote_overlap == 0.0
    assert signals.named_source_overlap == 0.0
    assert signals.explicit_citation is False
    assert signals.source_published_before_target is None