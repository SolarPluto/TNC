from datetime import datetime

from tnc.spans.models import DocumentVersion, SourceSpan


def select_document_version_at(
    versions: list[DocumentVersion],
    timestamp: datetime,
) -> DocumentVersion | None:
    """
    Return the newest document version available at or before timestamp.

    Versions without effective_from fall back to observed_at.
    """

    eligible = [
        version
        for version in versions
        if (version.effective_from or version.observed_at) <= timestamp
    ]

    if not eligible:
        return None

    return max(
        eligible,
        key=lambda version: version.effective_from or version.observed_at,
    )


def select_spans_at(
    spans: list[SourceSpan],
    timestamp: datetime,
) -> list[SourceSpan]:
    """
    Return spans available at timestamp.

    A span is available when:
    - available_from <= timestamp
    - available_until is unset, or timestamp < available_until
    """

    return [
        span
        for span in spans
        if (
            span.available_from <= timestamp
            and (
                span.available_until is None
                or timestamp < span.available_until
            )
        )
    ]