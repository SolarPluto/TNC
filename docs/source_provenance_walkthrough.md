# From local HTML to a source-provenance analysis

This worked example connects the documented `tnc parse` CLI to the public parser
and provenance APIs. It compares two existing frozen article versions; it does
not acquire new articles, establish claim truth, or admit historical replay.

**Validation status:** prepared from an environment-blocked documentation audit
and static inspection of public interfaces at
`d2909c139524c43d083679d0f5cd2e48632ef8f1`. The example has not been executed
against TNC in that audit environment. The output illustration below is a shape,
not a captured run. Numerical reproduction and runtime usability remain open.

## 1. Use an actual checkout and locked environment

Start in the repository root, with `pyproject.toml`, `uv.lock`, `src/`, and the
original `corpus/tib_run_a/objects/` files present. A rendered GitHub preview is
not a replacement for the original bytes. Follow the [README setup](../README.md)
and record the actual revision and environment before running:

```powershell
git rev-parse HEAD
git status --short
uv --version
uv sync --locked
uv run python --version
```

Stop on setup failure. Network access may be needed for the selected interpreter,
build requirements, and locked dependencies. A source archive alone does not
make installation offline-capable. Record any local changes; the analysis record
identifies HEAD but does not prove a clean working tree or hash all installed code.
For comparison to the original review, retain the baseline SHA above alongside
the actual checkout SHA rather than claiming every later checkout is equivalent.

The exact inputs are listed in [the corpus inventory](../corpus/tib_run_a/sources.json):

| Role | Version ID | SHA-256 of original body bytes |
| --- | --- | --- |
| ABC correction archive | `abc-archive-20130521155330` | `39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704` |
| CBS/AP correction live capture | `cbs-ap-correction` | `78a9a32f42c2adb5f4f9ab978394d4a3eac8c816eb40df73cb279bf83f318438` |

The ABC archive timestamp belongs only to that archived payload. The historical
availability of this CBS live payload remains unresolved. Neither a publisher
label nor the ABC capture dates the CBS bytes. Keep publication order unknown.

## 2. Inspect CLI spans, then cross to the API

These PowerShell commands inspect the text using the existing CLI:

```powershell
$objects = "corpus/tib_run_a/objects"
$abcHash = "39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704"
$cbsHash = "78a9a32f42c2adb5f4f9ab978394d4a3eac8c816eb40df73cb279bf83f318438"
uv run tnc parse "$objects/$abcHash"
uv run tnc parse "$objects/$cbsHash"
uv run tnc parse "$objects/$abcHash" --span 2
```

CLI rows contain ordinal, structural type, and normalized text. They are for
inspection, not a serialized `SourceSpan` interchange format. Do not parse those
rows back into records. The API route reads the same HTML and calls
`tnc.ingestion.parser.parse_article` to obtain the structured records directly.
Only trust the selected bodies after the raw-byte hash checks in the next step.

Three call inputs need explicit choices:

- `document_version_id` comes from the inventory, not the publisher name.
- `source_name` is the publisher name to look for in the *target's* explicit
  textual citations: `ABC News` for ABC-to-CBS and `CBS News` for CBS-to-ABC.
  It is not the shared medical-examiner authority. The textual matcher is not an
  authority-identity resolver; a false citation signal does not prove no citation.
- `shared_source_evidence` is the nonempty **string** from the exact matching
  [pair annotation](../corpus/tib_run_a/shared_source_pairs.json), or `None` when
  unreviewed/unrecorded. No special evidence object is required. The API does not
  load or authenticate the sidecar. This example verifies its pair identifiers
  and body hashes and records its file hash; the review remains a human input.

## 3. Run the two-direction comparison

Paste this complete here-string into PowerShell from the repository root.
Alternatively, save the Python between `@'` and `'@` in an external scratch file
and run `uv run python <path-to-that-file>` from the repository root.
The example reads files and prints JSON; it does not change repository data.

```powershell
@'
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from tnc.ingestion.parser import parse_article
from tnc.provenance.pipeline import infer_source_relation
from tnc.provenance.signals import measure_provenance_signals, paragraph_similarity
from tnc.spans.models import SpanType

root = Path.cwd()
if not (root / "pyproject.toml").is_file():
    raise SystemExit("Run from the TNC repository root.")
corpus = root / "corpus/tib_run_a"
versions = ("abc-archive-20130521155330", "cbs-ap-correction")
hashes = (
    "39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704",
    "78a9a32f42c2adb5f4f9ab978394d4a3eac8c816eb40df73cb279bf83f318438",
)
publishers = ("ABC News", "CBS News")
annotation_bytes = (corpus / "shared_source_pairs.json").read_bytes()
annotation = json.loads(annotation_bytes)
pairs = [p for p in annotation["pairs"] if (
    p["source_version_id"], p["target_version_id"]
) == versions]
if len(pairs) != 1:
    raise SystemExit("Expected exactly one annotation for these versions.")
pair = pairs[0]
if (pair["source_body_hash"], pair["target_body_hash"]) != hashes:
    raise SystemExit("Annotation does not match the pinned body hashes.")
evidence = pair["shared_source_evidence"]
if not isinstance(evidence, str) or not evidence.strip():
    raise SystemExit("Expected a nonempty reviewed-evidence string.")

html_bodies = []
for expected in hashes:
    raw = (corpus / "objects" / expected).read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise SystemExit(f"Body hash mismatch: expected {expected}, got {actual}")
    html_bodies.append(raw.decode("utf-8"))

# Local analysis observation only: never backdate the CBS live payload.
analysis_at = datetime.now(timezone.utc)
spans = [parse_article(
    html=html, document_version_id=version, available_from=analysis_at,
) for html, version in zip(html_bodies, versions)]
if any(not document for document in spans):
    raise SystemExit("No spans in at least one input; stop and inspect the parser.")

results = []
for source, target in ((0, 1), (1, 0)):
    inputs = dict(
        source_spans=spans[source], target_spans=spans[target],
        source_name=publishers[source],
        source_published_before_target=None,
        shared_source_evidence=evidence,
    )
    signals = measure_provenance_signals(**inputs)
    relation = infer_source_relation(
        relation_id=f"walkthrough:{source}-to-{target}",
        source_version_id=versions[source],
        target_version_id=versions[target], **inputs,
    )
    results.append({
        "source_version_id": versions[source],
        "target_version_id": versions[target],
        "source_name_for_citation_check": publishers[source],
        "signals": signals.model_dump(mode="json"),
        "relation": None if relation is None else relation.model_dump(mode="json"),
        "relation_meaning": (
            "No document-level judgment; not evidence of independence."
            if relation is None else "Classifier judgment; inspect signals and rationale."
        ),
    })

# Public singleton-paragraph comparisons locate candidates for manual inspection.
# Score rank is navigation, not evidence of copying or a claim-level conclusion.
paragraph_pairs = [{
    "score": paragraph_similarity([a], [b]),
    "abc_ordinal": a.ordinal, "cbs_ordinal": b.ordinal,
    "abc_text": a.normalized_text, "cbs_text": b.normalized_text,
} for a in spans[0] if a.span_type == SpanType.PARAGRAPH
  for b in spans[1] if b.span_type == SpanType.PARAGRAPH]
paragraph_pairs.sort(key=lambda p: (-p["score"], p["abc_ordinal"], p["cbs_ordinal"]))

# These ordinals come from the prior manual review, not automated claim matching.
review_ordinals = ({0, 1, 2}, {3, 4, 7, 8, 9})
selected = {}
for version, document, wanted in zip(versions, spans, review_ordinals):
    if not wanted.issubset({s.ordinal for s in document}):
        raise SystemExit(f"Review span ordinals missing for {version}; inspect changes.")
    selected[version] = [s.model_dump(mode="json") for s in document if s.ordinal in wanted]

head = subprocess.run(
    ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
).stdout.strip()
record = {
    "repository_head": head,
    "analysis_observed_at_utc": analysis_at.isoformat(),
    "available_from_semantics": "Local analysis observation, not historical availability.",
    "inputs": [{"version_id": v, "verified_body_sha256": h}
               for v, h in zip(versions, hashes)],
    "annotation_file_sha256": hashlib.sha256(annotation_bytes).hexdigest(),
    "review_reference": annotation["review"],
    "review_supplied_evidence": evidence,
    "directions": results,
    "prior_review_selected_spans": selected,
    "top_five_paragraph_pairs_for_manual_review": paragraph_pairs[:5],
    "unresolved": [
        "Historical availability and publication order of the exact CBS live body.",
        "Direct copying and independent confirmation are not established by overlap.",
    ],
}
print(json.dumps(record, indent=2, ensure_ascii=True))
'@ | uv run python -
if ($LASTEXITCODE -ne 0) { throw "Comparison failed; retain the error and stop." }
```

The separate measurement call preserves signals even if classification abstains.
`infer_source_relation` also measures internally; this example deliberately repeats
measurement rather than reaching into private helpers. Both directions use the
same review string because this exact pair's recorded evidence is symmetric.

## 4. Read and retain the analysis record

The following is an **illustrative output shape, not observed output**. Angle
brackets stand for values produced by a future execution; no score is supplied
from the prior review as though it had just been measured.

```text
repository_head: <actual local HEAD>
inputs: <both version IDs and locally verified raw-body SHA-256 hashes>
review_supplied_evidence: <the exact sidecar string>
directions[0]:
  source_version_id: abc-archive-20130521155330
  target_version_id: cbs-ap-correction
  signals: <measured values, publication-order null, supplied review evidence>
  relation: <serialized classifier judgment or null>
  relation_meaning: <judgment or abstention explanation>
directions[1]: <reverse-direction measurements and judgment>
prior_review_selected_spans: <IDs, ordinals, text, hashes, local observation time>
top_five_paragraph_pairs_for_manual_review: <scores, ordinals, and both texts>
unresolved: <explicit limits; not an automatically generated completeness claim>
```

Keep the complete emitted JSON outside the frozen corpus, together with setup
output and any analyst notes. Distinguish four layers when writing a conclusion:
raw-file integrity and source text; algorithmic measurements; review-supplied
interpretation; and classifier judgment or abstention. A signal is not necessarily
an established fact: `explicit_citation` reflects a bounded textual matcher.
Similarity is not a probability of copying, agreement, or independent reporting.
A relation's `confidence`, if returned, is not independent corroboration.

Inspect the quoted source wording yourself. The selected ordinals are navigation
from the [prior review](../corpus/tib_run_a/casualty_provenance_review.md), not a
fresh proof of its conclusion. Preserve qualifiers, attribution, name spellings,
and headline/body discrepancies. The highest-scoring paragraph need not concern
the casualty claim. The printed unresolved list is analyst framing supplied by
this example, not something inferred by TNC.

Compare fresh numbers and the route taken with the prior review only after saving
the new record. Agreement is not independent confirmation when the review's own
annotation was supplied as input. Disagreement is a reason to inspect the pinned
bytes, versions, paragraph selection, and actual code revision, not to edit frozen
objects or force the old numbers. Hash, setup, or API failures are valid stopping
points. This example does not create a historical replay fixture or change an
admission decision.
