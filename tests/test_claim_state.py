from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.spans.state import (
    ClaimState,
    ClaimStateTransition,
    claim_state_at,
    current_claim_state,
)


def make_transition(
    transition_id: str,
    assertion_id: str,
    from_state: ClaimState | None,
    to_state: ClaimState,
    occurred_at: datetime,
) -> ClaimStateTransition:
    return ClaimStateTransition(
        transition_id=transition_id,
        assertion_id=assertion_id,
        from_state=from_state,
        to_state=to_state,
        occurred_at=occurred_at,
        evidence_span_ids=("version-001:span:1",),
        rationale="Test transition.",
    )


def test_first_transition_can_start_without_previous_state():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
    )

    assert transition.from_state is None
    assert transition.to_state == ClaimState.FIRST_REPORTED


def test_claim_state_transition_is_immutable():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
    )

    with pytest.raises(ValidationError):
        transition.to_state = ClaimState.REPEATED


def test_current_claim_state_returns_none_without_history():
    state = current_claim_state(
        transitions=[],
        assertion_id="assertion-001",
    )

    assert state is None


def test_current_claim_state_returns_latest_transition():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-001",
            from_state=ClaimState.FIRST_REPORTED,
            to_state=ClaimState.REPEATED,
            occurred_at=datetime(
                2026, 1, 1, 10, 15, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-003",
            assertion_id="assertion-001",
            from_state=ClaimState.REPEATED,
            to_state=ClaimState.PARTIALLY_CORROBORATED,
            occurred_at=datetime(
                2026, 1, 1, 10, 30, tzinfo=timezone.utc
            ),
        ),
    ]

    state = current_claim_state(
        transitions=transitions,
        assertion_id="assertion-001",
    )

    assert state == ClaimState.PARTIALLY_CORROBORATED


def test_current_claim_state_ignores_other_assertions():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-002",
            from_state=None,
            to_state=ClaimState.OFFICIALLY_CONFIRMED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
        ),
    ]

    state = current_claim_state(
        transitions=transitions,
        assertion_id="assertion-001",
    )

    assert state == ClaimState.FIRST_REPORTED


def test_historical_transitions_remain_available():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-001",
            from_state=ClaimState.FIRST_REPORTED,
            to_state=ClaimState.CORRECTED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
        ),
    ]

    assert len(transitions) == 2
    assert transitions[0].to_state == ClaimState.FIRST_REPORTED
    assert transitions[1].to_state == ClaimState.CORRECTED




def test_claim_state_at_returns_state_visible_at_timestamp():







    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-001",
            from_state=ClaimState.FIRST_REPORTED,
            to_state=ClaimState.REPEATED,
            occurred_at=datetime(
                2026, 1, 1, 10, 15, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-003",
            assertion_id="assertion-001",
            from_state=ClaimState.REPEATED,
            to_state=ClaimState.OFFICIALLY_CONFIRMED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
        ),
    ]

    state = claim_state_at(
        transitions=transitions,
        assertion_id="assertion-001",
        timestamp=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
    )

    assert state == ClaimState.REPEATED


def test_claim_state_at_returns_none_before_first_transition():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        )
    ]

    state = claim_state_at(
        transitions=transitions,
        assertion_id="assertion-001",
        timestamp=datetime(
            2026, 1, 1, 9, 59, tzinfo=timezone.utc
        ),
    )

    assert state is None


def test_future_confirmation_does_not_leak_into_earlier_state():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-001",
            from_state=ClaimState.FIRST_REPORTED,
            to_state=ClaimState.OFFICIALLY_CONFIRMED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
        ),
    ]

    earlier_state = claim_state_at(
        transitions=transitions,
        assertion_id="assertion-001",
        timestamp=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
    )

    assert earlier_state == ClaimState.FIRST_REPORTED
