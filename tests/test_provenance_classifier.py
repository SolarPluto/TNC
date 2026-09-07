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