import pytest
from pydantic import ValidationError

from tnc.provenance.models import (
    ProvenanceSignals,
    SourceRelation,
    SourceRelationType,
)


def test_provenance_signals_can_be_created():
    signals = ProvenanceSignals(
        paragraph_similarity=0.92,
        quote_overlap=0.80,
        named_source_overlap=0.75,
        explicit_citation=True,
        entity_alignment=0.88,
        source_published_before_target=True,
    )

    assert signals.paragraph_similarity == 0.92
    assert signals.explicit_citation is True


def test_provenance_signal_scores_must_be_between_zero_and_one():
    with pytest.raises(ValidationError):
        ProvenanceSignals(
            paragraph_similarity=1.2,
        )


def test_source_relation_can_be_created():
    signals = ProvenanceSignals(
        paragraph_similarity=0.95,
        explicit_citation=True,
        source_published_before_target=True,
    )

    relation = SourceRelation(
        relation_id="relation-001",
        source_version_id="version-source",
        target_version_id="version-target",
        relation_type=SourceRelationType.EXPLICITLY_CITES,
        confidence=0.99,
        signals=signals,
        rationale="The target article explicitly attributes reporting to the source.",
    )

    assert relation.relation_type == SourceRelationType.EXPLICITLY_CITES
    assert relation.confidence == 0.99
    assert relation.signals.explicit_citation is True


def test_source_relation_confidence_must_be_between_zero_and_one():
    signals = ProvenanceSignals()

    with pytest.raises(ValidationError):
        SourceRelation(
            relation_id="relation-001",
            source_version_id="version-source",
            target_version_id="version-target",
            relation_type=SourceRelationType.LIKELY_DERIVED_FROM,
            confidence=1.5,
            signals=signals,
        )


def test_source_relation_is_immutable():
    signals = ProvenanceSignals()

    relation = SourceRelation(
        relation_id="relation-001",
        source_version_id="version-source",
        target_version_id="version-target",
        relation_type=SourceRelationType.REPRINT_OF,
        confidence=0.95,
        signals=signals,
    )

    with pytest.raises(ValidationError):
        relation.confidence = 0.50