from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ClaimState(StrEnum):
    FIRST_REPORTED = "first_reported"
    REPEATED = "repeated"
    PARTIALLY_CORROBORATED = "partially_corroborated"
    OFFICIALLY_CONFIRMED = "officially_confirmed"
    QUALIFIED = "qualified"
    CORRECTED = "corrected"


class ClaimStateTransition(BaseModel):
    """
    Immutable record of one epistemic state transition.

    Transitions are append-only. Earlier state is never rewritten.
    """

    model_config = ConfigDict(frozen=True)

    transition_id: str
    assertion_id: str

    from_state: ClaimState | None
    to_state: ClaimState

    occurred_at: datetime

    evidence_span_ids: tuple[str, ...] = ()
    rationale: str | None = None


def current_claim_state(
    transitions: list[ClaimStateTransition],
    assertion_id: str,
) -> ClaimState | None:
    """
    Return the latest recorded state for one assertion.

    State is derived from immutable transition history rather than stored
    as a mutable field.
    """

    matching = [
        transition
        for transition in transitions
        if transition.assertion_id == assertion_id
    ]

    if not matching:
        return None

    latest = max(
        matching,
        key=lambda transition: transition.occurred_at,
    )

    return latest.to_state