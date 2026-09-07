from difflib import SequenceMatcher

from tnc.spans.models import SourceSpan, SpanType


def _text_similarity(source_text: str, target_text: str) -> float:
    return SequenceMatcher(
        None,
        source_text,
        target_text,
        autojunk=False,
    ).ratio()


def _directional_best_match_similarity(
    source_texts: list[str],
    target_texts: list[str],
) -> float:
    if not source_texts or not target_texts:
        return 0.0

    best_matches = []

    for source_text in source_texts:
        best_score = max(
            _text_similarity(source_text, target_text)
            for target_text in target_texts
        )
        best_matches.append(best_score)

    return sum(best_matches) / len(best_matches)


def paragraph_similarity(
    source_spans: list[SourceSpan],
    target_spans: list[SourceSpan],
) -> float:
    """
    Measure deterministic paragraph-level similarity between two documents.

    Only paragraph spans are compared.

    For each source paragraph, find the most similar target paragraph.
    Return the average of those best-match scores.

    Returns 0.0 if either document has no paragraph spans.
    """

    source_paragraphs = [
        span.normalized_text
        for span in source_spans
        if span.span_type == SpanType.PARAGRAPH
    ]

    target_paragraphs = [
        span.normalized_text
        for span in target_spans
        if span.span_type == SpanType.PARAGRAPH
    ]

    return _directional_best_match_similarity(
        source_paragraphs,
        target_paragraphs,
    )


def quote_overlap(
    source_spans: list[SourceSpan],
    target_spans: list[SourceSpan],
) -> float:
    """
    Measure deterministic quote overlap between two documents.

    Only quote spans are compared.

    The score is symmetric: source-to-target and target-to-source
    best-match similarities are averaged. This prevents a document
    containing one copied quote from receiving a perfect overlap score
    against a document containing many additional quotes.

    Returns 0.0 if either document has no quote spans.
    """

    source_quotes = [
        span.normalized_text
        for span in source_spans
        if span.span_type == SpanType.QUOTE
    ]

    target_quotes = [
        span.normalized_text
        for span in target_spans
        if span.span_type == SpanType.QUOTE
    ]

    if not source_quotes or not target_quotes:
        return 0.0

    source_to_target = _directional_best_match_similarity(
        source_quotes,
        target_quotes,
    )

    target_to_source = _directional_best_match_similarity(
        target_quotes,
        source_quotes,
    )

    return (source_to_target + target_to_source) / 2