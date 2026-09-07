import re
from difflib import SequenceMatcher

from tnc.provenance.models import ProvenanceSignals
from tnc.spans.models import SourceSpan, SpanType


ATTRIBUTION_PATTERN = re.compile(
    r"\b(?:said|says|told|according to|reported|stated|announced|"
    r"confirmed|wrote|added|warned|explained)\b",
    re.IGNORECASE,
)

EXPLICIT_CITATION_PATTERNS = (
    re.compile(
        r"\baccording to\s+(?P<source>[A-Z][A-Za-z0-9&.' -]{1,80})",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<source>[A-Z][A-Za-z0-9&.' -]{1,80})\s+reported\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\breported by\s+(?P<source>[A-Z][A-Za-z0-9&.' -]{1,80})",
        re.IGNORECASE,
    ),
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

    The score is symmetric.
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
    Measure Jaccard overlap between extracted named sources.
    """

    source_names = extract_named_sources(source_spans)
    target_names = extract_named_sources(target_spans)

    if not source_names or not target_names:
        return 0.0

    intersection = source_names & target_names
    union = source_names | target_names

    return len(intersection) / len(union)


def extract_explicit_citations(spans: list[SourceSpan]) -> set[str]:
    """
    Extract explicitly named cited sources from article text.

    This deliberately recognizes only direct textual attribution.
    It does not infer hidden or indirect sourcing.
    """

    citations: set[str] = set()

    for span in spans:
        text = span.normalized_text

        for pattern in EXPLICIT_CITATION_PATTERNS:
            for match in pattern.finditer(text):
                source = match.group("source").strip(" ,.;:")
                if source:
                    citations.add(source.casefold())

    return citations


def has_explicit_citation(
    target_spans: list[SourceSpan],
    source_name: str,
) -> bool:
    """
    Return True when the target explicitly cites the supplied source name.
    """

    normalized_source_name = source_name.strip().casefold()

    if not normalized_source_name:
        return False

    citations = extract_explicit_citations(target_spans)

    return normalized_source_name in citations


def measure_provenance_signals(
    *,
    source_spans: list[SourceSpan],
    target_spans: list[SourceSpan],
    source_name: str,
    source_published_before_target: bool | None,
) -> ProvenanceSignals:
    """
    Measure the deterministic v0.1 provenance signals for two documents.

    Measurements are returned without making any provenance judgment.
    Classification remains the responsibility of the provenance classifier.
    """

    return ProvenanceSignals(
        paragraph_similarity=paragraph_similarity(
            source_spans,
            target_spans,
        ),
        quote_overlap=quote_overlap(
            source_spans,
            target_spans,
        ),
        named_source_overlap=named_source_overlap(
            source_spans,
            target_spans,
        ),
        explicit_citation=has_explicit_citation(
            target_spans,
            source_name,
        ),
        source_published_before_target=source_published_before_target,
    )