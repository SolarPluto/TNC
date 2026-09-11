# TIB Run A: Moore tornado, 20 May 2013

Status: six live responses and three historical ABC captures are frozen locally.
Archive payload fingerprints have been verified against saved archive indexes.
Historical replay admission remains pending; no historical replay fixture exists.

## Scope and selection

Use the Newcastle–Moore tornado of 20 May 2013. Limit news reconstruction to
20–22 May in America/Chicago (CDT, UTC−05:00). This compact event supports an
initial erroneous fatality estimate, an explicit downward correction, evolving
rescue status, and provisional versus retrospective storm classification.

Six source slots are listed in sources.json. The intended minimum is one frozen
response per slot, plus a second capture of one news URL if a genuine historical
revision is recoverable. Different URLs are separate documents until lineage is
demonstrated; chronological stories are not automatically document revisions.

- MPR/AP supplies the early report: at least 51 deaths, more than 120 hospital
  patients, and a preliminary EF4 assessment. These are attributed reports, not
  established event truth.
- CBS/AP early coverage supplies an AP-derived comparison, not another independent
  confirmation. A shared wire credit proves contribution, not exact reprinting.
- CBS/AP correction coverage supplies a later casualty correction.
- ABC supplies separately credited reporting of the reduction from 51 to 24.
  Shared medical-examiner sourcing still prevents counting that casualty claim as
  independently established. Assess independence per claim, not per domain.
- CBS/AP follow-up supplies changing rescue status.
- NWS Norman supplies retrospective adjudication: EF5, 24 deaths, 212 injuries.
  Match the Moore tornado row, not aggregate outbreak totals. Hospital treatment
  counts and final injury totals have different scopes and need not contradict.

The candidate URLs were inspected through web retrieval/search on 2026-09-08.
That research is discovery evidence only; it does not supply raw HTTP artifacts.
Subsequent acquisition verified three ABC captures, including a same-URL
headline revision described below. A CSMonitor AP
correction candidate returned 403 during research and was omitted from the minimum.

## Frozen artifacts and verified archive versions

`sources.json` lists six live captures under `sources` and three historical ABC
captures under `archive_versions`. `manifest.jsonl` records live acquisitions;
`archive_manifest.jsonl` records archive HTML and index responses. Hash-named
objects preserve downloaded bodies, with Git text conversion disabled.

The three ABC captures are from May 21, 2013 (UTC):

- 12:00:16: the separate early article reports 51 deaths, including 20 children,
  attributed to the Oklahoma Chief Medical Examiner. Its reviewed parser output
  contains 21 spans.
- 15:53:30: the correction article reports 24 total deaths. Its headline says
  7 children while its opening paragraph says nine. Both statements are preserved.
- 17:57:57: the same correction URL has a headline saying 9 children. Of the
  22 parsed spans, only the headline differs in ordinal, type, or normalized text;
  all 21 body spans match the earlier correction capture.

The correction pair establishes an observed headline revision. Its exact edit
time is unknown. The early 51-death article has a different URL and remains a
separate document; it is not established as an earlier version of the correction
document.

Each capture has an evidence sidecar preserving its body and index hashes,
capture time, publisher labels, and limitations. Historical observations
obs-007, obs-008, and obs-009 link these records. Golden tests cover the first
correction and early captures; a comparison test covers the later correction.

Capture times apply to the corresponding archived payloads. They do not date the
separately frozen live responses or establish first publication or claim truth.
All three archive versions remain pending historical replay admission.

CBS archive searches recorded in `acquisition_attempts.jsonl` were inconclusive.
Timeouts and the unsupported wildcard query do not establish missing captures.

## Version and time discipline

Keep retrieval time, archive capture time, publisher-displayed publication/update
time, event time, and derived historical availability separate. Store verbatim
timestamp labels and timezone evidence before normalization. The MPR page displays
May 20 at 3:35 PM without an explicit timezone in the inspected text, while its
body describes later developments. That label cannot date all its current text.
CBS early coverage also displays both an initial timestamp and a later update.

For every candidate, obtain an exact archive capture URL and capture timestamp if
available. Save the archive response and its index/metadata response independently;
verify the final URL and article body rather than accepting redirects, consent
pages, archive wrappers, or HTTP 200 alone. Do not invent capture timestamps.
An archive capture establishes observation by that time, not first publication.
Missing capture intervals remain unknown; do not interpolate a revision time.

Use existing fetch_and_store with a corpus-relative storage_root and manifest_path
from the repository root. It preserves response.content (HTTPX-decoded response
body), not compressed wire bytes or a complete WARC. Keep each later retrieval as
its own manifest record, even when its content hash repeats. Pin local bytes by
SHA-256; a mutable live URL alone is not a reproducible version identifier.

For live responses retrieved now, leave DocumentVersion.effective_from unset and
use actual retrieval time as observed_at. Do not backdate SourceSpan.available_from
to a publisher label. Historical replay admission requires independently supported
version availability; otherwise retain the response for discovery/retrospective
use only. Where only a bounded interval is known, preserve that interval in metadata
and use its conservative upper bound only after review. No engine change is needed.

Keep NWS retrospective evidence outside the historical replay evidence map. Its
event date is not its publication date. Later truth must not repair what the system
could know earlier. Corrections qualify or supersede earlier assertions; preserve
the original report and distinguish factual correction from a genuinely changing
world state. Do not hard-code a 91-death intermediate step without a frozen source.

## Acquisition and acceptance checklist

Step 1 is complete. Steps 2 and 3 have verified ABC evidence; broader historical
coverage and claim-level provenance review remain incomplete.

1. Fetch the six live responses through existing ingestion into objects/ and an
   append-only manifest.jsonl; inspect every body before marking a slot frozen.
2. Locate historical captures around the early and corrected reports, prioritizing
   a before/after pair for one URL. Record failed acquisition attempts separately
   from the success manifest. If none survive, mark historical replay incomplete.
3. Add an annotation sidecar linking source slot, body hash, exact capture URL,
   raw timestamp labels, time uncertainty, byline/wire credit, and relevant spans.
   Never put candidate URLs into CorpusManifestEntry with fabricated hashes.
4. Manually inspect AP overlap. Shared origin is sufficient to avoid double counting;
   reprint direction needs dated versions and textual evidence. Unknown is not
   independent. Compare ABC's attributed claims to their underlying authority.
5. Only then create a separate historical replay fixture. Preserve the existing
   synthetic run_a.json and its negative controls unchanged.

Acceptance tests for that later fixture must verify local artifact hashes and
manifest links, reject evidence before supported availability, exclude retrospective
truth, retain corrected assertions, avoid independent-confirmation promotion from
AP copies, and reproduce snapshots offline. Exact replay cutoffs remain unset until
version availability is established. A date-stamped current page is insufficient.

## Original repository baseline (before corpus acquisition)

Baseline b148974 has 132 tests. Existing Run A is a two-span synthetic injury claim
with first_reported and officially_confirmed transitions, plus future/missing
evidence negative fixtures. corpus/ and migrations/ were empty; README.md was empty.
Existing ingestion already provides content-addressed storage and append-only
manifest persistence. Existing temporal selection falls back to observed_at when
effective_from is absent. The HTML parser requires an article element, so inspect
NWS markup before attempting parsing; do not expand the parser for this plan.

Those baseline notes describe the initial planning milestone. Subsequent work
added frozen artifacts, parser adapters, evidence records, and regression tests.
The latest full test run passed 166 tests. Historical replay is not yet validated.
