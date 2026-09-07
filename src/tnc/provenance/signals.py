from difflib import SequenceMatcher

from tnc.spans.models import SourceSpan


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
        if span.span_type.value == "paragraph"
    ]

    target_paragraphs = [
        span.normalized_text
        for span in target_spans
        if span.span_type.value == "paragraph"
    ]

    if not source_paragraphs or not target_paragraphs:
        return 0.0

    best_matches: list[float] = []

    for source_text in source_paragraphs:
        best_score = max(
            SequenceMatcher(
                None,
                source_text,
                target_text,
                autojunk=False,
            ).ratio()
            for target_text in target_paragraphs
        )

        best_matches.append(best_score)

    return sum(best_matches) / len(best_matches)