from dataclasses import dataclass

from tnc.spans.assertions import Assertion, AssertionCandidate
from tnc.spans.extractor import extract_assertion_candidates
from tnc.spans.models import SourceSpan
from tnc.spans.validation import (
    AssertionValidationResult,
    admit_assertion_candidate,
    validate_assertion_candidate,
)


@dataclass(frozen=True)
class RejectedAssertionCandidate:
    candidate: AssertionCandidate
    validation: AssertionValidationResult


@dataclass(frozen=True)
class AssertionPipelineResult:
    admitted: tuple[Assertion, ...]
    rejected: tuple[RejectedAssertionCandidate, ...]


def process_assertion_spans(
    spans: list[SourceSpan],
) -> AssertionPipelineResult:
    """
    Run the deterministic v0.1 assertion pipeline.

    SourceSpans
        -> candidate extraction
        -> deterministic validation
        -> canonical admission

    Invalid candidates remain inspectable as rejected proposals.
    Only validated candidates enter canonical assertion state.
    """

    candidates = extract_assertion_candidates(spans)

    admitted: list[Assertion] = []
    rejected: list[RejectedAssertionCandidate] = []

    for candidate in candidates:
        validation = validate_assertion_candidate(
            candidate,
            spans,
        )

        if not validation.valid:
            rejected.append(
                RejectedAssertionCandidate(
                    candidate=candidate,
                    validation=validation,
                )
            )
            continue

        canonical_assertion = admit_assertion_candidate(
            candidate,
            spans,
        )

        if canonical_assertion is None:
            raise RuntimeError(
                "Validated assertion candidate failed canonical admission."
            )

        admitted.append(canonical_assertion)

    return AssertionPipelineResult(
        admitted=tuple(admitted),
        rejected=tuple(rejected),
    )
