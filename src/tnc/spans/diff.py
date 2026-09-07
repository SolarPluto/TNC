from difflib import SequenceMatcher
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from tnc.spans.models import SourceSpan


class SpanChangeType(StrEnum):
    """How a source span changed between two document versions."""

    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    INSERTED = "inserted"
    REMOVED = "removed"
    MOVED = "moved"


class SpanChange(BaseModel):
    """One structural change between two document versions."""

    model_config = ConfigDict(frozen=True)

    change_type: SpanChangeType
    old_span: SourceSpan | None = None
    new_span: SourceSpan | None = None


def span_key(span: SourceSpan) -> tuple[str, str]:
    """Structural identity used to align unchanged spans."""

    return span.span_type.value, span.content_hash


def text_similarity(old_span: SourceSpan, new_span: SourceSpan) -> float:
    """Measure textual similarity between two spans."""

    return SequenceMatcher(
        None,
        old_span.normalized_text,
        new_span.normalized_text,
        autojunk=False,
    ).ratio()


def diff_replaced_chunk(
    old_chunk: list[SourceSpan],
    new_chunk: list[SourceSpan],
) -> list[SpanChange]:
    """
    Diff a changed region while respecting structural span types.

    Old and new spans of the same structural type are paired as MODIFIED.
    Unmatched old spans become REMOVED.
    Unmatched new spans become INSERTED.
    """

    changes: list[SpanChange] = []
    unmatched_new = set(range(len(new_chunk)))
    matched_pairs: list[tuple[int, int]] = []

    for old_index, old_span in enumerate(old_chunk):
        candidates = [
            new_index
            for new_index in unmatched_new
            if new_chunk[new_index].span_type == old_span.span_type
        ]

        if not candidates:
            continue

        best_new_index = max(
            candidates,
            key=lambda new_index: text_similarity(
                old_span,
                new_chunk[new_index],
            ),
        )

        matched_pairs.append((old_index, best_new_index))
        unmatched_new.remove(best_new_index)

    matched_old = {old_index for old_index, _ in matched_pairs}

    events: list[tuple[float, SpanChange]] = []

    for old_index, new_index in matched_pairs:
        events.append(
            (
                float(new_index),
                SpanChange(
                    change_type=SpanChangeType.MODIFIED,
                    old_span=old_chunk[old_index],
                    new_span=new_chunk[new_index],
                ),
            )
        )

    for new_index in sorted(unmatched_new):
        events.append(
            (
                float(new_index),
                SpanChange(
                    change_type=SpanChangeType.INSERTED,
                    new_span=new_chunk[new_index],
                ),
            )
        )

    for old_index, old_span in enumerate(old_chunk):
        if old_index not in matched_old:
            events.append(
                (
                    len(new_chunk) + old_index + 0.5,
                    SpanChange(
                        change_type=SpanChangeType.REMOVED,
                        old_span=old_span,
                    ),
                )
            )

    events.sort(key=lambda event: event[0])

    return [change for _, change in events]


def diff_spans(
    old_spans: list[SourceSpan],
    new_spans: list[SourceSpan],
) -> list[SpanChange]:
    """
    Produce a deterministic structural diff between two ordered span lists.

    Exact matches are aligned using structural type plus content hash.

    Within changed regions:
    - same-type spans are paired as MODIFIED
    - unmatched new spans are INSERTED
    - unmatched old spans are REMOVED

    MOVED is reserved for a later refinement.
    """

    old_keys = [span_key(span) for span in old_spans]
    new_keys = [span_key(span) for span in new_spans]

    matcher = SequenceMatcher(
        a=old_keys,
        b=new_keys,
        autojunk=False,
    )

    changes: list[SpanChange] = []

    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            for old_span, new_span in zip(
                old_spans[old_start:old_end],
                new_spans[new_start:new_end],
                strict=True,
            ):
                changes.append(
                    SpanChange(
                        change_type=SpanChangeType.UNCHANGED,
                        old_span=old_span,
                        new_span=new_span,
                    )
                )

        elif tag == "replace":
            changes.extend(
                diff_replaced_chunk(
                    old_spans[old_start:old_end],
                    new_spans[new_start:new_end],
                )
            )

        elif tag == "delete":
            for old_span in old_spans[old_start:old_end]:
                changes.append(
                    SpanChange(
                        change_type=SpanChangeType.REMOVED,
                        old_span=old_span,
                    )
                )

        elif tag == "insert":
            for new_span in new_spans[new_start:new_end]:
                changes.append(
                    SpanChange(
                        change_type=SpanChangeType.INSERTED,
                        new_span=new_span,
                    )
                )

    return changes