from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

import pytest

from tnc.ingestion.parser import parse_article
from tnc.provenance.classifier import classify_source_relation
from tnc.provenance.signals import measure_provenance_signals

CORPUS = Path(__file__).parent.parent / "corpus" / "tib_run_a"
PAIRS = json.loads((CORPUS / "shared_source_pairs.json").read_text())["pairs"]


@pytest.mark.parametrize("pair", PAIRS, ids=lambda p: p["source_version_id"])
@pytest.mark.parametrize("reverse", [False, True])
def test_reviewed_corpus_pairs_remain_unresolved(pair, reverse):
    spans = []
    for side in ("source", "target"):
        digest = pair[f"{side}_body_hash"]
        body = (CORPUS / "objects" / digest).read_bytes()
        assert sha256(body).hexdigest() == digest
        spans.append(parse_article(
            html=body.decode("utf-8"),
            document_version_id=pair[f"{side}_version_id"],
            # Test observation only; never historical replay admission.
            available_from=datetime(2026, 9, 10, tzinfo=timezone.utc),
        ))
    if reverse:
        spans.reverse()
    signals = measure_provenance_signals(
        source_spans=spans[0], target_spans=spans[1],
        source_name="CBS News" if reverse else (
            "MPR News" if pair["source_version_id"] == "mpr-ap-early" else "ABC News"
        ),
        source_published_before_target=None,
        shared_source_evidence=pair["shared_source_evidence"],
    )
    assert signals.shared_source_evidence == pair["shared_source_evidence"]
    assert not signals.explicit_citation
    assert signals.paragraph_similarity < 0.70
    assert signals.source_published_before_target is None
    for reviewed in (signals, signals.model_copy(update={"shared_source_evidence": None})):
        assert classify_source_relation(
            relation_id="reviewed-pair", source_version_id="a", target_version_id="b",
            signals=reviewed,
        ) is None


def test_all_inventory_bodies_match_recorded_hashes():
    inventory = json.loads((CORPUS / "sources.json").read_text())
    for entry in inventory["sources"] + inventory["archive_versions"]:
        digest = entry.get("body_hash", entry.get("html_body_hash"))
        assert sha256((CORPUS / "objects" / digest).read_bytes()).hexdigest() == digest
