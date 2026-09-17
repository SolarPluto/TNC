from dataclasses import dataclass

from tnc.spans.assertions import Assertion, AssertionCandidate
from tnc.spans.models import SourceSpan


@dataclass(frozen=True)
class AssertionValidationResult:
    valid: bool
    errors: tuple[str, ...]


def validate_assertion_candidate(
    assertion: AssertionCandidate,
    spans: list[SourceSpan],
) -> AssertionValidationResult:
    """
    Deterministically validate provenance coordinates and verbatim support.

    This validator does not judge whether the proposition is true.
    It only checks whether the assertion is anchored to the supplied evidence.

    Validation is staged:
    1. Verify provenance coordinates.
    2. Only if all referenced spans exist, verify verbatim support.

    This prevents secondary errors from being reported when the underlying
    evidence coordinates are already invalid.
    """

    span_lookup = {
        span.span_id: span
        for span in spans
    }

    missing_span_ids = [
        span_id
        for span_id in assertion.span_ids
        if span_id not in span_lookup
    ]

    if missing_span_ids:
        return AssertionValidationResult(
            valid=False,
            errors=(
                "Unknown span IDs: "
                + ", ".join(sorted(missing_span_ids)),
            ),
        )

    referenced_spans = [
        span_lookup[span_id]
        for span_id in assertion.span_ids
    ]

    combined_support_text = " ".join(
        span.normalized_text
        for span in referenced_spans
    ).casefold()

    errors: list[str] = []

    for support in assertion.verbatim_support:
        normalized_support = support.strip().casefold()

        if not normalized_support:
            errors.append("Verbatim support cannot be empty.")
            continue

        if normalized_support not in combined_support_text:
            errors.append(
                f"Verbatim support not found in referenced spans: {support!r}"
            )

    return AssertionValidationResult(
        valid=not errors,
        errors=tuple(errors),
    )


def admit_assertion_candidate(
    assertion: AssertionCandidate,
    spans: list[SourceSpan],
) -> Assertion | None:
    """
    Admit a candidate into canonical assertion state only if validation passes.

    The candidate layer may contain model-generated proposals.
    The canonical layer only receives deterministically validated assertions.
    """

    validation = validate_assertion_candidate(
        assertion,
        spans,
    )

    if not validation.valid:
        return None

    return Assertion(
        assertion_id=assertion.assertion_id,
        span_ids=tuple(assertion.span_ids),
        subject=assertion.subject,
        predicate=assertion.predicate,
        object=assertion.object,
        assertion_type=assertion.assertion_type,
        epistemic_operator=assertion.epistemic_operator,
        speaker=assertion.speaker,
        attribution_chain=tuple(assertion.attribution_chain),
        certainty_signal=assertion.certainty_signal,
        temporal_scope=assertion.temporal_scope,
        verbatim_support=tuple(assertion.verbatim_support),
    )
