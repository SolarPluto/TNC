# Casualty provenance review

Status: initial manual review; historical replay admission remains pending.
These findings concern casualty reporting for the May 20, 2013 Moore tornado.

## ABC early archive

Body: d1410eb00ab2c487e0dbc3da645f1f6be4e83a2ff0096e8d95dc14013985884f
Version: abc-early-archive-20130521120016
Relevant span: 1.

The report attributes the casualty statement to the Oklahoma Chief Medical
Examiner. Preserve the wording "At least 20 of the 51 people killed".
The publisher is ABC News; the attributed authority is the medical examiner.

## ABC correction archive

Body: 39eff51df623753297b9f12d7a00bdf6f0b04c0d1164f128cc1a5f1ea1055704
Version: abc-archive-20130521155330
Relevant spans: 1 and 2.

Span 1 attributes the revision from 51 to 24, including nine children, to the
medical examiner's office. Span 2 names spokeswoman Amy Elliot and qualifies
the double-counting explanation as her belief.

The headline in span 0 says 7 children. Preserve its discrepancy with the body.
The later capture, abc-archive-20130521175757, changes the headline to 9 children;
its 21 parsed body spans match this capture in ordinal, type, and normalized text.

## CBS/AP correction live capture

Body: 78a9a32f42c2adb5f4f9ab978394d4a3eac8c816eb40df73cb279bf83f318438
Source: cbs-ap-correction.
Relevant spans: 3, 4, 7, 8, and 9.

Span 3 reports "At least 24" deaths, including "at least nine children".
Span 4 identifies the state medical examiner's office as revising the estimate.
Span 7 names Amy Elliott and retains her belief that some victims were counted
twice. Preserve the spelling difference from ABC's "Amy Elliot".
Span 9 reports that authorities initially said "as many as 51".

These passages support a shared underlying medical-examiner authority with ABC's
correction coverage. They do not establish that one publisher copied the other.

## MPR/AP early live capture

Body: 542607b75d87b2be33810bc444ea3a6b01fe420d91b8c15dcc37f77ba72ae525
Source: mpr-ap-early.
Relevant spans: 2 and 3; full parsed article reviewed.

Span 2 credits Tim Talley and Associated Press.
Span 3 reports "At least 51" deaths, including "at least 20 children".
The phrase "officials said" explicitly attributes the expectation that the toll
would rise. The underlying authority for the count is not named in the reviewed
text and remains unresolved. Do not fill it in from another article.

## CBS/AP early live capture

Body: 7d3fd4d11470ee0e8b9694ef95faf1ee16ab6151e64cfac2ff342244c2c4af53
Source: cbs-ap-early.
Relevant span: 3. Scope exclusion: span 17.

Span 3 attributes "at least 51" deaths to "The Oklahoma City Medical Examiner".
Preserve this authority wording; equivalence to the differently named offices
in other articles is not established solely by similar casualty figures.

Span 17 concerns Sunday's Shawnee storms and names spokeswoman Amy Elliot.
It must not supply the speaker or casualty count for Monday's Moore report.

## Review implications and remaining work

- ABC and CBS correction reporting share an attributed medical-examiner authority.
  Do not count the publishers as independent confirmation of the casualty claim.
- Preserve exact counts, qualifiers, authority labels, and speaker spellings.
- AP credits identify reporting contribution or lineage, not proof that every
  claim is a reprint or that a particular document copied another.
- No document-level citation, reprint, or derivation relation is assigned here.
  A classifier result of None does not establish independence.
- Live captures retain unresolved historical availability. Archive capture
  times apply only to the corresponding archived payloads.
- Complete AP textual-overlap review and any required authority-identity
  resolution before finalizing provenance decisions for historical replay.

## MPR/AP and CBS/AP early textual comparison

Compared the two frozen early-report bodies identified above after verifying
their SHA-256 hashes. Used the existing paragraph_similarity function on all
parsed paragraph spans.

- MPR to CBS: 0.35304475782829786.
- CBS to MPR: 0.3513571143518113.
- Highest-scoring paragraph pair: MPR span 38 and CBS span 16, approximately
  0.4674. Both mention the 1999 tornado but contain different statements.

The five highest-scoring pairs were manually reviewed. They provide no strong
textual evidence that these saved documents are reprints of each other.
Character similarity is not a probability of copying or a measure of factual
agreement. Low similarity does not establish independent reporting.

AP contribution remains relevant, but its claim-level extent and any copying
direction remain unresolved. Historical publication order of these exact live
capture bodies is also unresolved. No document relation is assigned.

This comparison covers only the MPR/AP and CBS/AP early pair; broader AP overlap
review remains incomplete.

## ABC archive and CBS/AP correction textual comparison

Compared ABC archive version abc-archive-20130521155330 with the CBS/AP
correction live body identified above. Both body SHA-256 hashes were verified.
Used paragraph_similarity on all parsed paragraph spans.

- ABC to CBS: 0.39302673133421223.
- CBS to ABC: 0.35260045747565233.
- Highest-scoring pair: ABC span 18 and CBS span 40, approximately 0.6711.
  This pair concerns disaster assistance rather than casualty attribution.
- ABC span 2 and CBS span 7: approximately 0.4786. Both attribute the belief
  that victims were counted twice to the medical examiner's spokeswoman.
  Preserve the Elliot/Elliott spelling difference and the belief qualification.

The five highest-scoring pairs were manually reviewed. Similar wording in the
casualty explanation supports the shared-authority finding already recorded.
It does not establish direct copying, an explicit citation between publishers,
or independent confirmation of the casualty figures.

The scores measure character similarity, not copying probability or factual
agreement. No document-level reprint or derivation relation is assigned.
The exact historical availability of the CBS live body remains unresolved;
ABC's archive capture time must not be used to date it.

The [source-provenance walkthrough](../../docs/source_provenance_walkthrough.md)
later exercised the documented CLI-to-public-API route for this exact pair. Its
Windows execution receipt at
`f05e1d061452bf347cdd43096c77225ce483342d` reproduced the two directional
paragraph-similarity values above while preserving unknown publication order and
classifier abstention. That receipt is route-equivalence evidence for the
documented measurement path, not independent confirmation of the reporting or
proof of copying direction.

## Classifier shared-source guardrail

`shared_source_pairs.json` records the two reviewed comparisons above, tied to
exact body hashes. The evidence applies symmetrically and only to those versions.
It distinguishes shared AP contribution from shared medical-examiner authority;
it does not assert AP lineage for ABC or assign any new relationship label.

Pass each pair's `shared_source_evidence` to `infer_source_relation` (or
`measure_provenance_signals`) when comparing these exact bodies. The classifier
retains explicit citation priority, then abstains from similarity-based reprint
and derivation judgments when reviewed shared-source evidence is present, even
at perfect overlap. Unannotated pairs retain the existing behavior. The API does
not automatically load corpus sidecars or infer lineage from a wire-service name.

Keep the measured signals for inspection even when the classifier returns None.
None means no document-level judgment, never independent confirmation. Publication
order and historical replay admission remain unresolved for these live bodies.

## Frozen-body integrity check

The classifier audit checks all nine article-body hashes. Three CBS objects in
Git's stored revision differed from the original local frozen files, despite the
original working tree reporting clean. The working copy restores the original
local bytes for CBS early, correction, and status; each matches its existing
SHA-256 object name. No reacquisition or content normalization was used. These
byte-preserving repairs must accompany the hash regression test in a future commit.

Frozen objects also disable whitespace linting in `.gitattributes`: their exact
bytes are evidence and must not be reformatted to satisfy code-style checks.

## Corpus impact verification

Compared all 72 directed pairs of the nine frozen article versions. All nine
body hashes match the inventory. With exact historical publication order left
unknown, all pairs return None before and after the guardrail; no stored labels
or historical replay admissions are changed. The two reviewed pairs reproduce
the paragraph scores above in both directions. This is a conservative offline
comparison, not validation of historical replay or proof of independence.
Synthetic boundary tests separately show that recorded shared-source evidence
blocks both reprint and derivation labels even when publication order is known
and overlap reaches the existing thresholds or 1.0; direct citations survive.
