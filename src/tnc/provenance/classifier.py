from tnc.provenance.models import (
    ProvenanceSignals,
    SourceRelation,
    SourceRelationType,
)


def classify_source_relation(
    *,
    relation_id: str,
    source_version_id: str,
    target_version_id: str,
    signals: ProvenanceSignals,
) -> SourceRelation | None:
    """
    Apply deterministic v0.1 rules to provenance measurements.

    Priority:
    1. Explicit citation
    2. Strong reprint evidence
    3. Likely derivation
    4. Otherwise no relation judgment

    Measurements remain stored in ProvenanceSignals.
    This function only converts them into an inspectable judgment.
    """

    if signals.explicit_citation:
        return SourceRelation(
            relation_id=relation_id,
            source_version_id=source_version_id,
            target_version_id=target_version_id,
            relation_type=SourceRelationType.EXPLICITLY_CITES,
            confidence=1.0,
            signals=signals,
            rationale="The target explicitly cites the source.",
        )

    if (
        signals.source_published_before_target is True
        and signals.paragraph_similarity is not None
        and signals.paragraph_similarity >= 0.90
        and signals.quote_overlap is not None
        and signals.quote_overlap >= 0.80
    ):
        return SourceRelation(
            relation_id=relation_id,
            source_version_id=source_version_id,
            target_version_id=target_version_id,
            relation_type=SourceRelationType.REPRINT_OF,
            confidence=0.95,
            signals=signals,
            rationale=(
                "The source predates the target and the documents have "
                "very high paragraph similarity and quote overlap."
            ),
        )

    if (
        signals.source_published_before_target is True
        and signals.paragraph_similarity is not None
        and signals.paragraph_similarity >= 0.70
        and (
            (
                signals.quote_overlap is not None
                and signals.quote_overlap >= 0.50
            )
            or (
                signals.named_source_overlap is not None
                and signals.named_source_overlap >= 0.60
            )
        )
    ):
        return SourceRelation(
            relation_id=relation_id,
            source_version_id=source_version_id,
            target_version_id=target_version_id,
            relation_type=SourceRelationType.LIKELY_DERIVED_FROM,
            confidence=0.80,
            signals=signals,
            rationale=(
                "The source predates the target and the documents share "
                "substantial textual or sourcing overlap."
            ),
        )

    return None