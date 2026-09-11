import pytest

from tnc.provenance.classifier import classify_source_relation
from tnc.provenance.models import ProvenanceSignals, SourceRelationType


def classify(signals: ProvenanceSignals):
    return classify_source_relation(
        relation_id="relation-001",
        source_version_id="source-version",
        target_version_id="target-version",
        signals=signals,
    )


def test_explicit_citation_has_highest_priority():
    signals = ProvenanceSignals(
        paragraph_similarity=0.99,
        quote_overlap=0.99,
        explicit_citation=True,
        source_published_before_target=True,
    )

    relation = classify(signals)

    assert relation is not None
    assert relation.relation_type == SourceRelationType.EXPLICITLY_CITES
    assert relation.confidence == 1.0


def test_strong_overlap_can_be_classified_as_reprint():
    signals = ProvenanceSignals(
        paragraph_similarity=0.95,
        quote_overlap=0.90,
        source_published_before_target=True,
    )

    relation = classify(signals)

    assert relation is not None
    assert relation.relation_type == SourceRelationType.REPRINT_OF


def test_substantial_overlap_can_be_likely_derivation():
    signals = ProvenanceSignals(
        paragraph_similarity=0.78,
        quote_overlap=0.55,
        source_published_before_target=True,
    )

    relation = classify(signals)

    assert relation is not None
    assert relation.relation_type == SourceRelationType.LIKELY_DERIVED_FROM


def test_named_source_overlap_can_support_likely_derivation():
    signals = ProvenanceSignals(
        paragraph_similarity=0.75,
        named_source_overlap=0.70,
        source_published_before_target=True,
    )

    relation = classify(signals)

    assert relation is not None
    assert relation.relation_type == SourceRelationType.LIKELY_DERIVED_FROM


def test_later_source_is_not_classified_as_origin():
    signals = ProvenanceSignals(
        paragraph_similarity=0.99,
        quote_overlap=0.99,
        source_published_before_target=False,
    )

    relation = classify(signals)

    assert relation is None


def test_weak_overlap_produces_no_relation_judgment():
    signals = ProvenanceSignals(
        paragraph_similarity=0.40,
        quote_overlap=0.20,
        named_source_overlap=0.20,
        source_published_before_target=True,
    )

    relation = classify(signals)

    assert relation is None


@pytest.mark.parametrize(
    "paragraph,quote,named",
    [(1.0, 1.0, 1.0), (0.90, 0.80, 0.0), (0.70, 0.50, 0.0),
     (0.70, 0.0, 0.60)],
)
def test_shared_source_blocks_overlap_labels_at_all_rule_boundaries(paragraph, quote, named):
    signals = ProvenanceSignals(
        paragraph_similarity=paragraph,
        quote_overlap=quote,
        named_source_overlap=named,
        source_published_before_target=True,
        shared_source_evidence="Reviewed pair: both credit the same AP wire lineage.",
    )
    assert classify(signals) is None
    assert signals.paragraph_similarity == paragraph
    assert classify(signals.model_copy(update={"shared_source_evidence": None})) is not None


def test_shared_source_does_not_override_direct_citation():
    signals = ProvenanceSignals(
        explicit_citation=True,
        shared_source_evidence="Review: common medical-examiner authority.",
    )
    relation = classify(signals)
    assert relation.relation_type == SourceRelationType.EXPLICITLY_CITES
    assert relation.signals == signals


@pytest.mark.parametrize("order", [False, None])
def test_unknown_or_reversed_order_remains_unresolved(order):
    assert classify(ProvenanceSignals(
        paragraph_similarity=1.0, quote_overlap=1.0,
        source_published_before_target=order,
        shared_source_evidence="Review: common wire lineage.",
    )) is None
