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


class TemporalIntegrityError(ValueError):
    """
    Raised when replay input violates TIB temporal integrity rules.
    """


def transition_has_missing_evidence(
    transition: ClaimStateTransition,
    evidence_availability: dict[str, EvidenceAvailability],
) -> bool:
    """
    Return True when a transition references evidence with no availability
    record.
    """

    return any(
        span_id not in evidence_availability
        for span_id in transition.evidence_span_ids
    )


def transition_has_future_evidence(
    transition: ClaimStateTransition,
    evidence_availability: dict[str, EvidenceAvailability],
) -> bool:
    """
    Return True when a transition relies on evidence that became available
    after the transition itself occurred.
    """

    for span_id in transition.evidence_span_ids:
        evidence = evidence_availability.get(span_id)

        if evidence is None:
            continue

        if evidence.available_from > transition.occurred_at:
            return True

    return False


def validate_replay_temporal_integrity(
    transitions: list[ClaimStateTransition],
    evidence_availability: dict[str, EvidenceAvailability],
) -> None:
    """
    Reject replay input with missing or future evidence coordinates.
    """

    for transition in transitions:
        if transition_has_missing_evidence(
            transition,
            evidence_availability,
        ):
            raise TemporalIntegrityError(
                "Transition references evidence with no availability record: "
                f"{transition.transition_id}"
            )

        if transition_has_future_evidence(
            transition,
            evidence_availability,
        ):
            raise TemporalIntegrityError(
                "Transition relies on evidence that was not yet available: "
                f"{transition.transition_id}"
            )


def replay_snapshots(
    event_id: str,
    timestamps: list[datetime],
    transitions: list[ClaimStateTransition],
    evidence_availability: dict[str, EvidenceAvailability] | None = None,
) -> tuple[Snapshot, ...]:
    """
    Reconstruct TNC's epistemic state across historical timestamps.

    Each snapshot is built independently using only transitions visible
    at or before that timestamp.

    When evidence availability is supplied, replay fails closed if any
    transition lacks evidence coordinates or relies on future evidence.
    """

    if evidence_availability is not None:
        validate_replay_temporal_integrity(
            transitions,
            evidence_availability,
        )

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