from datetime import datetime, timezone

from tnc.ingestion.parser import parse_article
from tnc.provenance.pipeline import infer_source_relation
from tnc.provenance.signals import (
    measure_provenance_signals,
    paragraph_similarity,
)
from tnc.spans.models import SpanType


SPAN_KEYS = {
    "span_id",
    "document_version_id",
    "ordinal",
    "span_type",
    "raw_text",
    "normalized_text",
    "char_start",
    "char_end",
    "available_from",
    "available_until",
    "parent_span_id",
    "previous_span_id",
    "next_span_id",
    "content_hash",
}

SIGNAL_KEYS = {
    "paragraph_similarity",
    "quote_overlap",
    "named_source_overlap",
    "explicit_citation",
    "entity_alignment",
    "source_published_before_target",
    "shared_source_evidence",
}

RELATION_KEYS = {
    "relation_id",
    "source_version_id",
    "target_version_id",
    "relation_type",
    "confidence",
    "signals",
    "rationale",
}


def test_source_provenance_walkthrough_public_contract():
    """Protect the public interfaces and serialized shapes used by the walkthrough."""

    observed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    source_spans = parse_article(
        html="<article><p>Officials closed the bridge.</p></article>",
        document_version_id="walkthrough-contract-source",
        available_from=observed_at,
    )
    target_spans = parse_article(
        html=(
            "<article><p>According to Reuters, officials closed the bridge."
            "</p></article>"
        ),
        document_version_id="walkthrough-contract-target",
        available_from=observed_at,
    )

    for document in (source_spans, target_spans):
        assert isinstance(document, list)
        assert document
        assert document[0].span_type is SpanType.PARAGRAPH
        assert set(document[0].model_dump(mode="json")) == SPAN_KEYS

    similarity = paragraph_similarity(source_spans, target_spans)
    assert type(similarity) is float

    shared_source_evidence = (
        "Walkthrough contract fixture: common reporting context may explain overlap."
    )
    inputs = dict(
        source_spans=source_spans,
        target_spans=target_spans,
        source_name="Reuters",
        source_published_before_target=None,
        shared_source_evidence=shared_source_evidence,
    )

    signals = measure_provenance_signals(**inputs)
    signal_dump = signals.model_dump(mode="json")
    assert set(signal_dump) == SIGNAL_KEYS
    assert signal_dump["source_published_before_target"] is None
    assert signal_dump["shared_source_evidence"] == shared_source_evidence

    relation = infer_source_relation(
        relation_id="walkthrough-contract",
        source_version_id="walkthrough-contract-source",
        target_version_id="walkthrough-contract-target",
        **inputs,
    )
    assert relation is not None

    relation_dump = relation.model_dump(mode="json")
    assert set(relation_dump) == RELATION_KEYS
    assert set(relation_dump["signals"]) == SIGNAL_KEYS
