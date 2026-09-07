import re
from difflib import SequenceMatcher

from tnc.spans.models import SourceSpan, SpanType


ATTRIBUTION_PATTERN = re.compile(
    r"\b(?:said|says|told|according to|reported|stated|announced|"
    r"confirmed|wrote|added|warned|explained)\b",
    re.IGNORECASE,
)


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
    best-match similarities are averaged.

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


def extract_named_sources(spans: list[SourceSpan]) -> set[str]:
    """
    Extract conservative named-source candidates from attribution language.

    This v0.1 heuristic looks for capitalized names immediately before
    attribution verbs such as "said", "reported", or "confirmed".

    It is intentionally narrow. Missing a source is preferable to
    inventing one.
    """

    named_sources: set[str] = set()

    for span in spans:
        text = span.normalized_text

        for match in ATTRIBUTION_PATTERN.finditer(text):
            prefix = text[:match.start()].strip()

            candidate_match = re.search(
                r"([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,4})"
                r"(?:\s*,[^,]{1,80},)?\s*$",
                prefix,
            )

            if candidate_match is None:
                continue

            candidate = candidate_match.group(1).strip()

            if candidate:
                named_sources.add(candidate.casefold())

    return named_sources


def named_source_overlap(
    source_spans: list[SourceSpan],
    target_spans: list[SourceSpan],
) -> float:
    """
    Measure overlap between deterministically extracted named sources.

    Uses Jaccard similarity:

        intersection / union

    A score of 1.0 means both documents contain the same extracted
    named-source set. A score of 0.0 means no extracted sources overlap.

    Returns 0.0 when either document has no extracted named sources.
    """

    source_names = extract_named_sources(source_spans)
    target_names = extract_named_sources(target_spans)

    if not source_names or not target_names:
        return 0.0

    intersection = source_names & target_names
    union = source_names | target_names

    return len(intersection) / len(union)