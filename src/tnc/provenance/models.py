from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SourceRelationType(StrEnum):
    """Judgment about how one source document relates to another."""

    EXPLICITLY_CITES = "explicitly_cites"
    LIKELY_DERIVED_FROM = "likely_derived_from"
    REPRINT_OF = "reprint_of"


class ProvenanceSignals(BaseModel):
    """Observable evidence used to assess source independence."""

    model_config = ConfigDict(frozen=True)

    paragraph_similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    quote_overlap: float | None = Field(default=None, ge=0.0, le=1.0)
    named_source_overlap: float | None = Field(default=None, ge=0.0, le=1.0)

    explicit_citation: bool = False
    entity_alignment: float | None = Field(default=None, ge=0.0, le=1.0)

    source_published_before_target: bool | None = None


class SourceRelation(BaseModel):
    """
    A provenance judgment between two document versions.

    Signals are stored separately from the judgment so the decision
    remains inspectable and can be recalibrated later.
    """

    model_config = ConfigDict(frozen=True)

    relation_id: str

    source_version_id: str
    target_version_id: str

    relation_type: SourceRelationType

    confidence: float = Field(ge=0.0, le=1.0)

    signals: ProvenanceSignals

    rationale: str | None = None