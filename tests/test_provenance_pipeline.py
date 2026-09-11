from datetime import datetime, timezone

from tnc.provenance.models import SourceRelationType
from tnc.provenance.pipeline import infer_source_relation
from tnc.spans.models import SourceSpan, SpanType


def make_span(
    span_id: str,
    text: str,
    span_type: SpanType = SpanType.PARAGRAPH,
) -> SourceSpan:
    return SourceSpan(
        span_id=span_id,
        document_version_id="version-001",
        ordinal=0,
        span_type=span_type,
        raw_text=text,
        normalized_text=text,
        available_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        content_hash=f"hash-{span_id}",
    )


def test_pipeline_classifies_strong_overlap_as_reprint():
    source = [
        make_span(
            "source-paragraph",
            "Officials said five people were injured after the bridge failure.",
        ),
        make_span(
            "source-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        ),
    ]

    target = [
        make_span(
            "target-paragraph",
            "Officials said five people were injured after the bridge failure.",
        ),
        make_span(
            "target-quote",
            "We are still assessing the situation.",
            SpanType.QUOTE,
        ),
    ]

    relation = infer_source_relation(
        relation_id="relation-001",
        source_version_id="source-version",
        target_version_id="target-version",
        source_spans=source,
        target_spans=target,
        source_name="Reuters",
        source_published_before_target=True,
    )

    assert relation is not None
    assert relation.relation_type == SourceRelationType.REPRINT_OF
    assert relation.signals.paragraph_similarity == 1.0
    assert relation.signals.quote_overlap == 1.0


def test_pipeline_explicit_citation_has_priority():
    source = [
        make_span(
            "source-paragraph",
            "Officials closed the bridge.",
        )
    ]

    target = [
        make_span(
            "target-paragraph",
            "According to Reuters, officials closed the bridge.",
        )
    ]

    relation = infer_source_relation(
        relation_id="relation-002",
        source_version_id="source-version",
        target_version_id="target-version",
        source_spans=source,
        target_spans=target,
        source_name="Reuters",
        source_published_before_target=True,
    )

    assert relation is not None
    assert relation.relation_type == SourceRelationType.EXPLICITLY_CITES
    assert relation.signals.explicit_citation is True


def test_pipeline_returns_none_for_weak_evidence():
    source = [
        make_span(
            "source-paragraph",
            "Officials closed the bridge.",
        )
    ]

    target = [
        make_span(
            "target-paragraph",
            "A storm moved across the region overnight.",
        )
    ]

    relation = infer_source_relation(
        relation_id="relation-003",
        source_version_id="source-version",
        target_version_id="target-version",
        source_spans=source,
        target_spans=target,
        source_name="Reuters",
        source_published_before_target=True,
    )

    assert relation is None

def test_pipeline_passes_reviewed_shared_source_evidence():
    spans = [
        make_span("paragraph", "Amy Elliott said the count was revised."),
        make_span("quote", "Some victims were counted twice.", SpanType.QUOTE),
    ]
    kwargs = dict(
        relation_id="shared-wire", source_version_id="a", target_version_id="b",
        source_spans=spans, target_spans=spans, source_name="Publisher A",
        source_published_before_target=True,
    )
    assert infer_source_relation(**kwargs).relation_type == SourceRelationType.REPRINT_OF
    assert infer_source_relation(
        **kwargs, shared_source_evidence="Reviewed pair: common AP lineage."
    ) is None
