from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.spans.snapshot import Snapshot, SnapshotClaim
from tnc.spans.state import ClaimState


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