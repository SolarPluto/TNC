from datetime import datetime, timezone

from tnc.spans.policy import (
    authorize_transition,
    evaluate_transition,
)
from tnc.spans.state import (
    ClaimState,
    ClaimStateTransition,
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


def test_new_assertion_can_only_start_as_first_reported():
    allowed = evaluate_transition(
        transitions=[],
        assertion_id="assertion-001",
        proposed_state=ClaimState.FIRST_REPORTED,
    )

    denied = evaluate_transition(
        transitions=[],
        assertion_id="assertion-001",
        proposed_state=ClaimState.OFFICIALLY_CONFIRMED,
    )

    assert allowed.allowed is True
    assert denied.allowed is False


def test_first_reported_can_move_to_repeated():
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

    decision = evaluate_transition(
        transitions=transitions,
        assertion_id="assertion-001",
        proposed_state=ClaimState.REPEATED,
    )

    assert decision.allowed is True


def test_repeated_cannot_move_back_to_first_reported():
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
    ]

    decision = evaluate_transition(
        transitions=transitions,
        assertion_id="assertion-001",
        proposed_state=ClaimState.FIRST_REPORTED,
    )

    assert decision.allowed is False


def test_corrected_state_is_terminal():
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

    decision = evaluate_transition(
        transitions=transitions,
        assertion_id="assertion-001",
        proposed_state=ClaimState.OFFICIALLY_CONFIRMED,
    )

    assert decision.allowed is False


def test_authorize_transition_creates_canonical_transition():
    occurred_at = datetime(
        2026, 1, 1, 10, 0, tzinfo=timezone.utc
    )

    transition = authorize_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        proposed_state=ClaimState.FIRST_REPORTED,
        occurred_at=occurred_at,
        evidence_span_ids=("version-001:span:1",),
        rationale="Initial report.",
        transitions=[],
    )

    assert transition is not None
    assert transition.from_state is None
    assert transition.to_state == ClaimState.FIRST_REPORTED
    assert transition.occurred_at == occurred_at
    assert transition.evidence_span_ids == (
        "version-001:span:1",
    )


def test_authorize_transition_rejects_illegal_transition():
    transition = authorize_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        proposed_state=ClaimState.OFFICIALLY_CONFIRMED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        evidence_span_ids=("version-001:span:1",),
        rationale="Attempted direct confirmation.",
        transitions=[],
    )

    assert transition is None


def test_policy_uses_history_for_only_the_requested_assertion():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-002",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        )
    ]

    decision = evaluate_transition(
        transitions=transitions,
        assertion_id="assertion-001",
        proposed_state=ClaimState.FIRST_REPORTED,
    )

    assert decision.allowed is True
