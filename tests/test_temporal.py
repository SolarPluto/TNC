from datetime import datetime, timezone

from tnc.spans.models import DocumentVersion, SourceSpan, SpanType
from tnc.spans.temporal import select_document_version_at, select_spans_at


def make_version(
    version_id: str,
    observed_at: datetime,
    effective_from: datetime | None = None,
) -> DocumentVersion:
    return DocumentVersion(
        version_id=version_id,
        document_id="document-001",
        observed_at=observed_at,
        effective_from=effective_from,
        headline=None,
        body_hash=f"body-{version_id}",
        content_hash=f"content-{version_id}",
    )


def make_span(
    span_id: str,
    available_from: datetime,
    available_until: datetime | None = None,
) -> SourceSpan:
    return SourceSpan(
        span_id=span_id,
        document_version_id="version-001",
        ordinal=0,
        span_type=SpanType.PARAGRAPH,
        raw_text="Example text.",
        normalized_text="Example text.",
        available_from=available_from,
        available_until=available_until,
        content_hash=f"hash-{span_id}",
    )


def test_select_document_version_returns_latest_available_version():
    version_1 = make_version(
        "version-001",
        datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
    )
    version_2 = make_version(
        "version-002",
        datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
    )

    selected = select_document_version_at(
        [version_1, version_2],
        datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc),
    )

    assert selected == version_1


def test_select_document_version_returns_none_before_first_version():
    version = make_version(
        "version-001",
        datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
    )

    selected = select_document_version_at(
        [version],
        datetime(2026, 1, 1, 9, 59, tzinfo=timezone.utc),
    )

    assert selected is None


def test_select_document_version_prefers_effective_from():
    version = make_version(
        "version-001",
        observed_at=datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc),
        effective_from=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
    )

    selected = select_document_version_at(
        [version],
        datetime(2026, 1, 1, 10, 15, tzinfo=timezone.utc),
    )

    assert selected == version


def test_select_spans_respects_availability_window():
    span = make_span(
        "span-001",
        available_from=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
        available_until=datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
    )

    assert select_spans_at(
        [span],
        datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc),
    ) == [span]

    assert select_spans_at(
        [span],
        datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
    ) == []


def test_future_span_does_not_leak_into_earlier_timestamp():
    early_span = make_span(
        "span-early",
        available_from=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
    )

    future_span = make_span(
        "span-future",
        available_from=datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
    )

    visible = select_spans_at(
        [early_span, future_span],
        datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc),
    )

    assert visible == [early_span]
    assert future_span not in visible
