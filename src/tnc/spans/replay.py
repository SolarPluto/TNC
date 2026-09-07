from datetime import datetime

from tnc.spans.snapshot import Snapshot, build_snapshot
from tnc.spans.state import ClaimStateTransition


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