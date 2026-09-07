from datetime import datetime

from pydantic import BaseModel, ConfigDict

from tnc.spans.snapshot import Snapshot, build_snapshot
from tnc.spans.state import ClaimStateTransition


class EvidenceAvailability(BaseModel):
    """
    Immutable record of when one evidence span became available to TNC.
    """

    model_config = ConfigDict(frozen=True)

    span_id: str
    available_from: datetime


def transition_has_future_evidence(
    transition: ClaimStateTransition,
    evidence_availability: dict[str, EvidenceAvailability],
) -> bool:
    """
    Return True when a transition relies on evidence that became available
    after the transition itself occurred.

    Unknown evidence IDs are not treated as future evidence here; a separate
    provenance-completeness check can handle missing coordinates.
    """

    for span_id in transition.evidence_span_ids:
        evidence = evidence_availability.get(span_id)

        if evidence is None:
            continue

        if evidence.available_from > transition.occurred_at:
            return True

    return False


def replay_snapshots(
    event_id: str,
    timestamps: list[datetime],
    transitions: list[ClaimStateTransition],
) -> tuple[Snapshot, ...]:
    """
    Reconstruct TNC's epistemic state across historical timestamps.

    Each snapshot is built independently using only transitions visible
    at or before that timestamp.
    """

    ordered_timestamps = sorted(timestamps)

    snapshots = [
        build_snapshot(
            snapshot_id=f"{event_id}:snapshot:{index:04d}",
            event_id=event_id,
            captured_at=timestamp,
            transitions=transitions,
        )
        for index, timestamp in enumerate(
            ordered_timestamps,
            start=1,
        )
    ]

    return tuple(snapshots)