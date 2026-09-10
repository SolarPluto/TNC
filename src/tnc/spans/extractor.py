import re

from tnc.spans.assertions import (
    AssertionCandidate,
    AssertionType,
    EpistemicOperator,
)
from tnc.spans.models import SourceSpan


ATTRIBUTION_PATTERN = re.compile(
    r"^(?P<speaker>.+?)\s+"
    r"(?P<operator>reported|confirmed|denied|estimated|alleged|expected)\s+"
    r"(?P<object>.+)$",
    re.IGNORECASE,
)


OPERATOR_MAP = {
    "reported": EpistemicOperator.REPORTED,
    "confirmed": EpistemicOperator.CONFIRMED,
    "denied": EpistemicOperator.DENIED,
    "estimated": EpistemicOperator.ESTIMATED,
    "alleged": EpistemicOperator.ALLEGED,
    "expected": EpistemicOperator.EXPECTED,
}


def extract_assertion_candidates(
    spans: list[SourceSpan],
) -> list[AssertionCandidate]:
    """
    Conservatively extract simple source assertions from provenance-bound spans.

    v0.1 deliberately recognizes only a narrow grammatical pattern:

        <speaker> <epistemic operator> <proposition>

    Every emitted candidate is bound directly to the SourceSpan that produced it.
    Unsupported or ambiguous text is ignored rather than guessed.
    """

    candidates: list[AssertionCandidate] = []

    for span in spans:
        text = span.normalized_text.strip()

        match = ATTRIBUTION_PATTERN.match(text)

        if match is None:
            continue

        speaker = match.group("speaker").strip()
        operator_text = match.group("operator").lower()
        object_text = match.group("object").strip()

        if not speaker or not object_text:
            continue

        # Passive wording does not identify a speaker in this pattern.
        if speaker.split()[-1].casefold() in {
            "am", "is", "are", "was", "were", "be", "been", "being",
        }:
            continue

        candidate_number = len(candidates)

        candidates.append(
            AssertionCandidate(
                assertion_id=(
                    f"{span.document_version_id}:assertion:{candidate_number}"
                ),
                span_ids=[span.span_id],
                subject=speaker,
                predicate=operator_text,
                object=object_text,
                assertion_type=AssertionType.SOURCE_ASSERTION,
                epistemic_operator=OPERATOR_MAP[operator_text],
                speaker=speaker,
                attribution_chain=[speaker],
                certainty_signal=operator_text,
                temporal_scope=None,
                verbatim_support=[text],
                extraction_confidence=1.0,
            )
        )

    return candidates