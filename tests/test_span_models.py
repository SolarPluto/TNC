from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.spans.models import SourceSpan, SpanType


def make_span() -> SourceSpan:
    return SourceSpan(
        span_id="span-001",
        document_version_id="version-001",
        ordinal=0,
        span_type=SpanType.PARAGRAPH,
        raw_text="Officials said the bridge had collapsed.",
        normalized_text="Officials said the bridge had collapsed.",
        char_start=0,
        char_end=47,
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        content_hash="test-hash-001",
    )


def test_source_span_can_be_created():
    span = make_span()

    assert span.span_id == "span-001"
    assert span.ordinal == 0
    assert span.span_type == SpanType.PARAGRAPH


def test_source_span_rejects_negative_ordinal():
    with pytest.raises(ValidationError):
        SourceSpan(
            span_id="span-invalid",
            document_version_id="version-001",
            ordinal=-1,
            span_type=SpanType.PARAGRAPH,
            raw_text="Test",
            normalized_text="Test",
            available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            content_hash="test-hash",
        )


def test_source_span_is_immutable():
    span = make_span()

    with pytest.raises(ValidationError):
        span.raw_text = "Changed text"