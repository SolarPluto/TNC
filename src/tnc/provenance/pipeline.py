from tnc.provenance.classifier import classify_source_relation
from tnc.provenance.models import SourceRelation
from tnc.provenance.signals import measure_provenance_signals
from tnc.spans.models import SourceSpan


def infer_source_relation(
    *,
    relation_id: str,
    source_version_id: str,
    target_version_id: str,
    source_spans: list[SourceSpan],
    target_spans: list[SourceSpan],
    source_name: str,
    source_published_before_target: bool | None,
    shared_source_evidence: str | None = None,
) -> SourceRelation | None:
    """
    Measure provenance signals and apply the deterministic v0.1 classifier.

    The measurement layer and classification layer remain separate.
    This function only orchestrates them. Supply reviewed shared-source evidence
    when common lineage or authority could explain overlap. None results do not
    establish source independence.

    Public usage: docs/source_provenance_walkthrough.md. Re-verify the recipe
    when changing this interface or its behavior; follow its upkeep trigger.
    """

    signals = measure_provenance_signals(
        source_spans=source_spans,
        target_spans=target_spans,
        source_name=source_name,
        source_published_before_target=source_published_before_target,
        shared_source_evidence=shared_source_evidence,
    )

    return classify_source_relation(
        relation_id=relation_id,
        source_version_id=source_version_id,
        target_version_id=target_version_id,
        signals=signals,
    )
