from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.spans.snapshot import (
    Snapshot,
    SnapshotClaim,
    build_snapshot,
)
from tnc.spans.state import ClaimState, ClaimStateTransition


def make_transition(
    transition_id: str,
    assertion_id: str,
    from_state: ClaimState | None,
    to_state: ClaimState,
    occurred_at: datetime,
    evidence_span_ids: tuple[str, ...],
) -> ClaimStateTransition:
    return ClaimStateTransition(
        transition_id=transition_id,
        assertion_id=assertion_id,
        from_state=from_state,
        to_state=to_state,
        occurred_at=occurred_at,
        evidence_span_ids=evidence_span_ids,
        rationale="Test transition.",
    )


def test_snapshot_claim_stores_claim_state_and_evidence():
    claim = SnapshotClaim(
        assertion_id="assertion-001",
        state=ClaimState.FIRST_REPORTED,
        evidence_span_ids=("version-001:span:1",),
    )

    assert claim.assertion_id == "assertion-001"
    assert claim.state == ClaimState.FIRST_REPORTED
    assert claim.evidence_span_ids == ("version-001:span:1",)


def test_snapshot_is_immutable():
    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        event_id="event-001",
        captured_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        claims=(),
    )

    with pytest.raises(ValidationError):
        snapshot.event_id = "event-002"


def test_snapshot_preserves_historical_claim_state():
    claim = SnapshotClaim(
        assertion_id="assertion-001",
        state=ClaimState.FIRST_REPORTED,
        evidence_span_ids=("version-001:span:1",),
    )

    snapshot = Snapshot(
        snapshot_id="snapshot-001",
        event_id="event-001",
        captured_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        claims=(claim,),
    )

    assert snapshot.claims[0].state == ClaimState.FIRST_REPORTED


def test_build_snapshot_uses_state_visible_at_capture_time():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
            evidence_span_ids=("version-001:span:1",),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-001",
            from_state=ClaimState.FIRST_REPORTED,
            to_state=ClaimState.REPEATED,
            occurred_at=datetime(
                2026, 1, 1, 10, 15, tzinfo=timezone.utc
            ),
            evidence_span_ids=("version-002:span:1",),
        ),
        make_transition(
            transition_id="transition-003",
            assertion_id="assertion-001",
            from_state=ClaimState.REPEATED,
            to_state=ClaimState.OFFICIALLY_CONFIRMED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
            evidence_span_ids=("version-003:span:1",),
        ),
    ]

    snapshot = build_snapshot(
        snapshot_id="snapshot-001",
        event_id="event-001",
        captured_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        transitions=transitions,
    )

    assert len(snapshot.claims) == 1
    assert snapshot.claims[0].state == ClaimState.REPEATED


def test_build_snapshot_excludes_future_evidence():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
            evidence_span_ids=("version-001:span:1",),
        ),
        make_transition(
            transition_id="transition-002",
            assertion_id="assertion-001",
            from_state=ClaimState.FIRST_REPORTED,
            to_state=ClaimState.OFFICIALLY_CONFIRMED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
            evidence_span_ids=("future-version:span:1",),
        ),
    ]

    snapshot = build_snapshot(
        snapshot_id="snapshot-001",
        event_id="event-001",
        captured_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        transitions=transitions,
    )

    claim = snapshot.claims[0]

    assert claim.state == ClaimState.FIRST_REPORTED
    assert claim.evidence_span_ids == ("version-001:span:1",)
    assert "future-version:span:1" not in claim.evidence_span_ids


def test_build_snapshot_excludes_future_claims():
    transitions = [
        make_transition(
            transition_id="transition-001",
            assertion_id="assertion-001",
            from_state=None,
            to_state=ClaimState.FIRST_REPORTED,
            occurred_at=datetime(
                2026, 1, 1, 11, 0, tzinfo=timezone.utc
            ),
            evidence_span_ids=("future-version:span:1",),
        )
    ]

    snapshot = build_snapshot(
        snapshot_id="snapshot-001",
        event_id="event-001",
        captured_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        transitions=transitions,
    )

    assert snapshot.claims == ()
