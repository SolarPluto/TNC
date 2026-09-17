from datetime import datetime

from pydantic import BaseModel, ConfigDict

from tnc.spans.state import (
    ClaimState,
    ClaimStateTransition,
    claim_state_at,
)


class SnapshotClaim(BaseModel):
    """
    Immutable record of one claim's epistemic state inside a TIB snapshot.
    """

    model_config = ConfigDict(frozen=True)

    assertion_id: str
    state: ClaimState
    evidence_span_ids: tuple[str, ...] = ()


class Snapshot(BaseModel):
    """
    Immutable TIB snapshot representing what TNC knew at one replay timestamp.
    """

    model_config = ConfigDict(frozen=True)

    snapshot_id: str
    event_id: str
    captured_at: datetime

    claims: tuple[SnapshotClaim, ...] = ()


def build_snapshot(
    snapshot_id: str,
    event_id: str,
    captured_at: datetime,
    transitions: list[ClaimStateTransition],
) -> Snapshot:
    """
    Build an immutable snapshot using only claim state visible at captured_at.

    Future transitions must never leak backward into the snapshot.
    """

    assertion_ids = sorted(
        {
            transition.assertion_id
            for transition in transitions
            if transition.occurred_at <= captured_at
        }
    )

    claims: list[SnapshotClaim] = []

    for assertion_id in assertion_ids:
        state = claim_state_at(
            transitions=transitions,
            assertion_id=assertion_id,
            timestamp=captured_at,
        )

        if state is None:
            continue

        evidence_span_ids = tuple(
            dict.fromkeys(
                span_id
                for transition in transitions
                if (
                    transition.assertion_id == assertion_id
                    and transition.occurred_at <= captured_at
                )
                for span_id in transition.evidence_span_ids
            )
        )

        claims.append(
            SnapshotClaim(
                assertion_id=assertion_id,
                state=state,
                evidence_span_ids=evidence_span_ids,
            )
        )

    return Snapshot(
        snapshot_id=snapshot_id,
        event_id=event_id,
        captured_at=captured_at,
        claims=tuple(claims),
    )
