from dataclasses import dataclass
from datetime import datetime

from tnc.spans.state import (
    ClaimState,
    ClaimStateTransition,
    current_claim_state,
)


ALLOWED_TRANSITIONS: dict[ClaimState | None, frozenset[ClaimState]] = {
    None: frozenset({
        ClaimState.FIRST_REPORTED,
    }),
    ClaimState.FIRST_REPORTED: frozenset({
        ClaimState.REPEATED,
        ClaimState.PARTIALLY_CORROBORATED,
        ClaimState.OFFICIALLY_CONFIRMED,
        ClaimState.QUALIFIED,
        ClaimState.CORRECTED,
    }),
    ClaimState.REPEATED: frozenset({
        ClaimState.PARTIALLY_CORROBORATED,
        ClaimState.OFFICIALLY_CONFIRMED,
        ClaimState.QUALIFIED,
        ClaimState.CORRECTED,
    }),
    ClaimState.PARTIALLY_CORROBORATED: frozenset({
        ClaimState.OFFICIALLY_CONFIRMED,
        ClaimState.QUALIFIED,
        ClaimState.CORRECTED,
    }),
    ClaimState.OFFICIALLY_CONFIRMED: frozenset({
        ClaimState.QUALIFIED,
        ClaimState.CORRECTED,
    }),
    ClaimState.QUALIFIED: frozenset({
        ClaimState.OFFICIALLY_CONFIRMED,
        ClaimState.CORRECTED,
    }),
    ClaimState.CORRECTED: frozenset(),
}


@dataclass(frozen=True)
class TransitionDecision:
    allowed: bool
    reason: str


def evaluate_transition(
    *,
    transitions: list[ClaimStateTransition],
    assertion_id: str,
    proposed_state: ClaimState,
) -> TransitionDecision:
    """
    Deterministically decide whether a proposed claim-state transition is legal.

    The policy engine does not decide whether evidence deserves a state.
    It only governs whether the requested state transition is structurally
    permitted from the assertion's existing history.
    """

    current_state = current_claim_state(
        transitions=transitions,
        assertion_id=assertion_id,
    )

    allowed_states = ALLOWED_TRANSITIONS[current_state]

    if proposed_state not in allowed_states:
        return TransitionDecision(
            allowed=False,
            reason=(
                f"Transition from {current_state!r} "
                f"to {proposed_state!r} is not permitted."
            ),
        )

    return TransitionDecision(
        allowed=True,
        reason=(
            f"Transition from {current_state!r} "
            f"to {proposed_state!r} is permitted."
        ),
    )


def authorize_transition(
    *,
    transition_id: str,
    assertion_id: str,
    proposed_state: ClaimState,
    occurred_at: datetime,
    evidence_span_ids: tuple[str, ...],
    rationale: str | None,
    transitions: list[ClaimStateTransition],
) -> ClaimStateTransition | None:
    """
    Create an immutable transition only when deterministic policy authorizes it.

    Proposed state changes do not write directly into canonical history.
    """

    decision = evaluate_transition(
        transitions=transitions,
        assertion_id=assertion_id,
        proposed_state=proposed_state,
    )

    if not decision.allowed:
        return None

    previous_state = current_claim_state(
        transitions=transitions,
        assertion_id=assertion_id,
    )

    return ClaimStateTransition(
        transition_id=transition_id,
        assertion_id=assertion_id,
        from_state=previous_state,
        to_state=proposed_state,
        occurred_at=occurred_at,
        evidence_span_ids=evidence_span_ids,
        rationale=rationale,
    )
