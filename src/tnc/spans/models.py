from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SpanType(StrEnum):
    """Structural type of a source span."""

    PARAGRAPH = "paragraph"
    HEADING = "heading"
    QUOTE = "quote"
    CAPTION = "caption"
    LIST_ITEM = "list_item"
    TABLE_CELL = "table_cell"
    CORRECTION = "correction"
    UPDATE_NOTICE = "update_notice"


class Document(BaseModel):
    """A logical source document, independent of any particular revision."""

    model_config = ConfigDict(frozen=True)

    document_id: str
    canonical_url: str
    publisher_id: str


class DocumentVersion(BaseModel):
    """One observed version of a document at a particular point in time."""

    model_config = ConfigDict(frozen=True)

    version_id: str
    document_id: str

    observed_at: datetime
    effective_from: datetime | None = None

    headline: str | None = None

    body_hash: str
    content_hash: str

    supersedes_version_id: str | None = None


class SourceSpan(BaseModel):
    """An immutable structural unit extracted from one document version."""

    model_config = ConfigDict(frozen=True)

    span_id: str
    document_version_id: str

    ordinal: int = Field(ge=0)
    span_type: SpanType

    raw_text: str
    normalized_text: str

    char_start: int | None = Field(default=None, ge=0)
    char_end: int | None = Field(default=None, ge=0)

    available_from: datetime
    available_until: datetime | None = None

    parent_span_id: str | None = None
    previous_span_id: str | None = None
    next_span_id: str | None = None

    content_hash: str