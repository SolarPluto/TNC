import pytest
from pydantic import ValidationError

from tnc.spans.assertions import (
    AssertionCandidate,
    AssertionType,
    EpistemicOperator,
)


def make_assertion(**overrides) -> AssertionCandidate:
    data = {
        "assertion_id": "assertion-001",
        "span_ids": ["version-001:span:2"],
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


def test_assertion_candidate_can_be_created():
    assertion = make_assertion()

    assert assertion.assertion_id == "assertion-001"
    assert assertion.span_ids == ["version-001:span:2"]
    assert assertion.assertion_type == AssertionType.SOURCE_ASSERTION
    assert assertion.epistemic_operator == EpistemicOperator.REPORTED


def test_assertion_requires_at_least_one_span_id():
    with pytest.raises(ValidationError):
        make_assertion(span_ids=[])


def test_assertion_confidence_must_be_between_zero_and_one():
    with pytest.raises(ValidationError):
        make_assertion(extraction_confidence=1.1)

    with pytest.raises(ValidationError):
        make_assertion(extraction_confidence=-0.1)


def test_assertion_candidate_is_immutable():
    assertion = make_assertion()

    with pytest.raises(ValidationError):
        assertion.subject = "investigators"


def test_source_assertion_and_world_state_are_distinct_types():
    source_assertion = make_assertion(
        assertion_type=AssertionType.SOURCE_ASSERTION,
    )

    world_state = make_assertion(
        assertion_id="assertion-002",
        assertion_type=AssertionType.WORLD_STATE,
        subject="five people",
        predicate="were",
        object="injured",
    )

    assert source_assertion.assertion_type != world_state.assertion_type


def test_unknown_epistemic_operator_is_supported():
    assertion = make_assertion(
        epistemic_operator=EpistemicOperator.UNKNOWN,
        certainty_signal=None,
    )

    assert assertion.epistemic_operator == EpistemicOperator.UNKNOWN