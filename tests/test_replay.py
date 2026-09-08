from datetime import datetime, timezone

import pytest

from tnc.spans.models import SourceSpan, SpanType
from tnc.spans.replay import (
    EvidenceAvailability,
    TemporalIntegrityError,
    evidence_availability_from_spans,
    replay_snapshots,
    transition_has_future_evidence,
    transition_has_missing_evidence,
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
        rationale="Replay test transition.",
    )


def test_replay_orders_snapshots_chronologically():
    timestamps = [
        datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
        datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
        datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc),
    ]

    snapshots = replay_snapshots(
        event_id="event-001",
        timestamps=timestamps,
        transitions=[],
    )

    assert [snapshot.captured_at for snapshot in snapshots] == sorted(
        timestamps
    )


def test_replay_reconstructs_claim_state_over_time():
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
                2026, 1, 1, 10, 30, tzinfo=timezone.utc
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

    snapshots = replay_snapshots(
        event_id="event-001",
        timestamps=[
            datetime(2026, 1, 1, 10, 15, tzinfo=timezone.utc),
            datetime(2026, 1, 1, 10, 45, tzinfo=timezone.utc),
            datetime(2026, 1, 1, 11, 15, tzinfo=timezone.utc),
        ],
        transitions=transitions,
    )

    assert snapshots[0].claims[0].state == ClaimState.FIRST_REPORTED
    assert snapshots[1].claims[0].state == ClaimState.REPEATED
    assert (
        snapshots[2].claims[0].state
        == ClaimState.OFFICIALLY_CONFIRMED
    )


def test_replay_does_not_leak_future_confirmation_backward():
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

    snapshots = replay_snapshots(
        event_id="event-001",
        timestamps=[
            datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc),
            datetime(2026, 1, 1, 11, 30, tzinfo=timezone.utc),
        ],
        transitions=transitions,
    )

    earlier = snapshots[0].claims[0]
    later = snapshots[1].claims[0]

    assert earlier.state == ClaimState.FIRST_REPORTED
    assert "future-version:span:1" not in earlier.evidence_span_ids

    assert later.state == ClaimState.OFFICIALLY_CONFIRMED
    assert "future-version:span:1" in later.evidence_span_ids


def test_transition_detects_future_evidence():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        evidence_span_ids=("version-001:span:1",),
    )

    evidence_availability = {
        "version-001:span:1": EvidenceAvailability(
            span_id="version-001:span:1",
            available_from=datetime(
                2026, 1, 1, 10, 30, tzinfo=timezone.utc
            ),
        )
    }

    assert transition_has_future_evidence(
        transition,
        evidence_availability,
    )


def test_transition_accepts_evidence_available_before_transition():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        evidence_span_ids=("version-001:span:1",),
    )

    evidence_availability = {
        "version-001:span:1": EvidenceAvailability(
            span_id="version-001:span:1",
            available_from=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        )
    }

    assert not transition_has_future_evidence(
        transition,
        evidence_availability,
    )


def test_replay_rejects_future_evidence():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        evidence_span_ids=("version-001:span:1",),
    )

    evidence_availability = {
        "version-001:span:1": EvidenceAvailability(
            span_id="version-001:span:1",
            available_from=datetime(
                2026, 1, 1, 10, 30, tzinfo=timezone.utc
            ),
        )
    }

    with pytest.raises(TemporalIntegrityError):
        replay_snapshots(
            event_id="event-001",
            timestamps=[
                datetime(
                    2026, 1, 1, 10, 15, tzinfo=timezone.utc
                )
            ],
            transitions=[transition],
            evidence_availability=evidence_availability,
        )


def test_replay_accepts_temporally_valid_evidence():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 30, tzinfo=timezone.utc
        ),
        evidence_span_ids=("version-001:span:1",),
    )

    evidence_availability = {
        "version-001:span:1": EvidenceAvailability(
            span_id="version-001:span:1",
            available_from=datetime(
                2026, 1, 1, 10, 0, tzinfo=timezone.utc
            ),
        )
    }

    snapshots = replay_snapshots(
        event_id="event-001",
        timestamps=[
            datetime(
                2026, 1, 1, 10, 45, tzinfo=timezone.utc
            )
        ],
        transitions=[transition],
        evidence_availability=evidence_availability,
    )

    assert len(snapshots) == 1
    assert snapshots[0].claims[0].state == ClaimState.FIRST_REPORTED
def test_transition_detects_missing_evidence():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        evidence_span_ids=("missing-version:span:1",),
    )

    assert transition_has_missing_evidence(
        transition,
        evidence_availability={},
    )


def test_replay_rejects_missing_evidence_coordinates():
    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        evidence_span_ids=("missing-version:span:1",),
    )

    with pytest.raises(TemporalIntegrityError):
        replay_snapshots(
            event_id="event-001",
            timestamps=[
                datetime(
                    2026, 1, 1, 10, 30, tzinfo=timezone.utc
                )
            ],
            transitions=[transition],
            evidence_availability={},
        )
def test_evidence_availability_is_derived_from_source_spans():
    available_from = datetime(
        2026, 1, 1, 9, 30, tzinfo=timezone.utc
    )

    span = SourceSpan(
        span_id="version-001:span:1",
        document_version_id="version-001",
        ordinal=0,
        span_type=SpanType.PARAGRAPH,
        raw_text="Agency A reported 14 injuries.",
        normalized_text="Agency A reported 14 injuries.",
        available_from=available_from,
        content_hash="hash-001",
    )

    availability = evidence_availability_from_spans([span])

    assert availability["version-001:span:1"].span_id == span.span_id
    assert availability["version-001:span:1"].available_from == available_from

def test_replay_uses_source_span_availability_end_to_end():
    span = SourceSpan(
        span_id="version-001:span:1",
        document_version_id="version-001",
        ordinal=0,
        span_type=SpanType.PARAGRAPH,
        raw_text="Agency A reported 14 injuries.",
        normalized_text="Agency A reported 14 injuries.",
        available_from=datetime(
            2026, 1, 1, 9, 30, tzinfo=timezone.utc
        ),
        content_hash="hash-001",
    )

    transition = make_transition(
        transition_id="transition-001",
        assertion_id="assertion-001",
        from_state=None,
        to_state=ClaimState.FIRST_REPORTED,
        occurred_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        evidence_span_ids=(span.span_id,),
    )

    evidence_availability = evidence_availability_from_spans([span])

    snapshots = replay_snapshots(
        event_id="event-001",
        timestamps=[
            datetime(
                2026, 1, 1, 10, 30, tzinfo=timezone.utc
            )
        ],
        transitions=[transition],
        evidence_availability=evidence_availability,
    )

    assert len(snapshots) == 1
    assert len(snapshots[0].claims) == 1
    assert snapshots[0].claims[0].assertion_id == "assertion-001"
    assert snapshots[0].claims[0].state == ClaimState.FIRST_REPORTED
    assert snapshots[0].claims[0].evidence_span_ids == (span.span_id,) 
