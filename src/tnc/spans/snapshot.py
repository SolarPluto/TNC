from datetime import datetime

from pydantic import BaseModel, ConfigDict

from tnc.spans.state import ClaimState


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