from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AssertionType(StrEnum):
    SOURCE_ASSERTION = "source_assertion"
    WORLD_STATE = "world_state"


class EpistemicOperator(StrEnum):
    REPORTED = "reported"
    CONFIRMED = "confirmed"
    DENIED = "denied"
    ESTIMATED = "estimated"
    ALLEGED = "alleged"
    EXPECTED = "expected"
    UNKNOWN = "unknown"


class AssertionCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    assertion_id: str
    span_ids: list[str] = Field(min_length=1)

    subject: str
    predicate: str
    object: str

    assertion_type: AssertionType
    epistemic_operator: EpistemicOperator

    speaker: str | None = None
    attribution_chain: list[str] = Field(default_factory=list)

    certainty_signal: str | None = None
    temporal_scope: str | None = None

    verbatim_support: list[str] = Field(default_factory=list)
    extraction_confidence: float = Field(ge=0.0, le=1.0)