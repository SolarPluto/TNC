import json
from datetime import datetime
from pathlib import Path
import pytest

from tnc.spans.models import SourceSpan
from tnc.spans.replay import (
    TemporalIntegrityError,
    evidence_availability_from_spans,
    replay_snapshots,
)
from tnc.spans.state import ClaimState, ClaimStateTransition


FIXTURE_PATH = Path("tests/fixtures/tib/run_a.json")


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_run_a_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_run_a_replay_matches_expected_states():
    fixture = load_run_a_fixture()

    spans = [
        SourceSpan(
            **{
                **span,
                "available_from": parse_timestamp(span["available_from"]),
            }
        )
        for span in fixture["spans"]
    ]

    transitions = [
        ClaimStateTransition(
            **{
                **transition,
                "to_state": ClaimState(transition["to_state"]),
                "from_state": (
                    ClaimState(transition["from_state"])
                    if transition["from_state"] is not None
                    else None
                ),
                "occurred_at": parse_timestamp(transition["occurred_at"]),
            }
        )
        for transition in fixture["transitions"]
    ]

    timestamps = [
        parse_timestamp(value)
        for value in fixture["replay_timestamps"]
    ]

    snapshots = replay_snapshots(
        event_id=fixture["event_id"],
        timestamps=timestamps,
        transitions=transitions,
        evidence_availability=evidence_availability_from_spans(spans),
    )

    observed_states = [
        snapshot.claims[0].state.value if snapshot.claims else None
        for snapshot in snapshots
    ]

    assert observed_states == fixture["expected_states"]

def test_run_a_rejects_future_evidence():
    fixture_path = Path(
        "tests/fixtures/tib/run_a_future_evidence.json"
    )
    fixture = json.loads(
        fixture_path.read_text(encoding="utf-8")
    )

    spans = [
        SourceSpan(
            **{
                **span,
                "available_from": parse_timestamp(span["available_from"]),
            }
        )
        for span in fixture["spans"]
    ]

    transitions = [
        ClaimStateTransition(
            **{
                **transition,
                "to_state": ClaimState(transition["to_state"]),
                "from_state": (
                    ClaimState(transition["from_state"])
                    if transition["from_state"] is not None
                    else None
                ),
                "occurred_at": parse_timestamp(transition["occurred_at"]),
            }
        )
        for transition in fixture["transitions"]
    ]

    timestamps = [
        parse_timestamp(value)
        for value in fixture["replay_timestamps"]
    ]

    with pytest.raises(TemporalIntegrityError):
        replay_snapshots(
            event_id=fixture["event_id"],
            timestamps=timestamps,
            transitions=transitions,
            evidence_availability=evidence_availability_from_spans(spans),
        )
