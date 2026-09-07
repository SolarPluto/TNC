from datetime import datetime, timezone

from tnc.spans.assertions import (
    Assertion,
    AssertionCandidate,
    AssertionType,
    EpistemicOperator,
)
from tnc.spans.models import SourceSpan, SpanType
from tnc.spans.validation import (
    admit_assertion_candidate,
    validate_assertion_candidate,
)


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


def make_assertion(**overrides) -> AssertionCandidate:
    data = {
        "assertion_id": "assertion-001",
        "span_ids": ["version-001:span:1"],
        "subject": "officials",
        "predicate": "reported",
        "object": "five people were injured",
        "assertion_type": AssertionType.SOURCE_ASSERTION,
        "epistemic_operator": EpistemicOperator.REPORTED,
        "speaker": "officials",
        "attribution_chain": ["officials"],
        "certainty_signal": "reported",
        "temporal_scope": None,
        "verbatim_support": [
            "Officials reported that five people were injured."
        ],
        "extraction_confidence": 0.95,
    }

    data.update(overrides)

    return AssertionCandidate(**data)


def test_valid_assertion_passes_validation():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    assertion = make_assertion()

    result = validate_assertion_candidate(assertion, spans)

    assert result.valid is True
    assert result.errors == ()


def test_unknown_span_id_fails_validation():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    assertion = make_assertion(
        span_ids=["version-001:span:999"],
    )

    result = validate_assertion_candidate(assertion, spans)

    assert result.valid is False
    assert result.errors == (
        "Unknown span IDs: version-001:span:999",
    )


def test_verbatim_support_must_exist_in_referenced_spans():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    assertion = make_assertion(
        verbatim_support=[
            "Officials confirmed that ten people were injured."
        ],
    )

    result = validate_assertion_candidate(assertion, spans)

    assert result.valid is False
    assert len(result.errors) == 1
    assert "Verbatim support not found" in result.errors[0]


def test_verbatim_support_can_span_multiple_referenced_spans():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that",
        ),
        make_span(
            "version-001:span:2",
            "five people were injured.",
        ),
    ]

    assertion = make_assertion(
        span_ids=[
            "version-001:span:1",
            "version-001:span:2",
        ],
        verbatim_support=[
            "Officials reported that five people were injured."
        ],
    )

    result = validate_assertion_candidate(assertion, spans)

    assert result.valid is True
    assert result.errors == ()


def test_empty_verbatim_support_entry_fails_validation():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    assertion = make_assertion(
        verbatim_support=["   "],
    )

    result = validate_assertion_candidate(assertion, spans)

    assert result.valid is False
    assert result.errors == (
        "Verbatim support cannot be empty.",
    )


def test_validator_can_report_multiple_errors():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    assertion = make_assertion(
        span_ids=["version-001:span:1"],
        verbatim_support=[
            "Officials confirmed that ten people were injured.",
            "The bridge reopened immediately.",
        ],
    )

    result = validate_assertion_candidate(assertion, spans)

    assert result.valid is False
    assert len(result.errors) == 2
    assert "Verbatim support not found" in result.errors[0]
    assert "Verbatim support not found" in result.errors[1]


def test_valid_candidate_is_admitted_as_canonical_assertion():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    candidate = make_assertion()

    admitted = admit_assertion_candidate(candidate, spans)

    assert isinstance(admitted, Assertion)
    assert admitted.assertion_id == candidate.assertion_id
    assert admitted.span_ids == ("version-001:span:1",)
    assert admitted.verbatim_support == (
        "Officials reported that five people were injured.",
    )
    assert not hasattr(admitted, "extraction_confidence")


def test_invalid_candidate_is_not_admitted():
    spans = [
        make_span(
            "version-001:span:1",
            "Officials reported that five people were injured.",
        )
    ]

    candidate = make_assertion(
        span_ids=["version-001:span:999"],
    )

    admitted = admit_assertion_candidate(candidate, spans)

    assert admitted is None