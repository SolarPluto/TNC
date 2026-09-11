# Historical admission evaluator

`tnc.provenance.admission.evaluate_historical_admission` evaluates one exact
archived document version at one query time. It returns an immutable decision;
it does not parse HTML, modify evidence, approve reviews, or create claim states.

## Contract

```python
def evaluate_historical_admission(
    *,
    document_id: str,
    version_id: str,
    query_time: datetime,
    corpus: FrozenCorpus,
    availability: ArchiveAvailabilityRecord | None,
    review: HistoricalAdmissionReview | None,
) -> HistoricalAdmissionDecision:
    ...
```

Only `decision.status == HistoricalAdmissionStatus.ADMITTED` permits downstream
processing. Both REJECTED and UNVERIFIED block it. Decisions are for the requested
query time; rejection because of a future capture is not permanent rejection of
the document. Decisions must not be tested by object truthiness.

- `FrozenCorpus` is an immutable in-memory input: a tuple of identified versions
  with body bytes and actual observation timestamps, plus saved archive-index objects.
- `ArchiveAvailabilityRecord` binds the exact document/version, original URL,
  body hash, capture time, index hash, archive payload digest, and evidence record ID.
- `HistoricalAdmissionReview` embeds that complete availability record. Approval
  requires a reviewer, an aware review timestamp no earlier than actual observation,
  and a nonblank rationale. A modern review can authorize evaluation at a historical
  query time; review time is not substituted for historical availability.
- `HistoricalAdmissionDecision` records status, requested identity/time, expected
  corpus body hash when known, verified availability if established, one reason
  code, and supplied evidence/review IDs. IDs on a rejected decision identify what
  was evaluated; they do not certify that the supplied records were valid.

Models follow the project's frozen Pydantic convention and forbid extra fields.
Incomplete/malformed model input raises ValidationError at the model boundary;
it cannot yield admission. The evaluator reports missing optional records and
semantic verification failures using the reason codes below.

## Verification order and stable reasons

The evaluator reports the first blocking check in this order. This makes the
result deterministic; it does not promise to list every possible input defect.

| Check | Reason codes | Status |
| --- | --- | --- |
| Query timestamp is aware | INVALID_QUERY_TIME | REJECTED |
| Unique version and matching document | UNKNOWN_VERSION, AMBIGUOUS_VERSION, DOCUMENT_IDENTITY_MISMATCH | REJECTED |
| Saved body and actual observation | MISSING_BODY, BODY_HASH_MISMATCH, INVALID_RETRIEVAL_TIME | REJECTED |
| Availability exists and binds exact identity | MISSING_AVAILABILITY, AVAILABILITY_BINDING_MISMATCH | REJECTED |
| Capture time is aware, at whole-second CDX precision, and no later than actual observation | INVALID_CAPTURE_TIME | REJECTED |
| Saved index exists uniquely and matches its SHA-256 | MISSING_ARCHIVE_INDEX, INVALID_ARCHIVE_INDEX, ARCHIVE_INDEX_HASH_MISMATCH | REJECTED |
| CDX JSON structure and unique successful HTML row match capture time and original URL | INVALID_ARCHIVE_INDEX, ARCHIVE_CAPTURE_MISMATCH | REJECTED |
| Body SHA-1/base32 matches both CDX digest and availability digest | ARCHIVE_PAYLOAD_MISMATCH | REJECTED |
| Verified capture is at or before the query | CAPTURE_TIME_AFTER_QUERY | REJECTED |
| Review is present | MISSING_REVIEW | UNVERIFIED |
| Review binds the complete verified availability record | REVIEW_BINDING_MISMATCH | REJECTED |
| Review is pending | REVIEW_PENDING | UNVERIFIED |
| Review explicitly rejects | REVIEW_REJECTED | REJECTED |
| Approval has reviewer, rationale, and valid review time | MISSING_REVIEW_PROVENANCE | REJECTED |
| All requirements pass | ADMISSION_REQUIREMENTS_MET | ADMITTED |

SHA-256 verifies exact locally recorded bytes. The archive's base32 SHA-1 is used
for compatibility with the saved CDX payload identifier, not as a replacement for
SHA-256. Supported indexes are CDX JSON tables with timestamp, original, statuscode,
mimetype, and digest columns. No network access or guessed timestamp is involved.

A capture proves existence by its timestamp. It is an upper bound on first
availability, used here as a conservative inclusive visibility cutoff. First
publication remains unknown. Actual observation/retrieval stays in observed_at.

## Trust and integration boundary

The caller must construct corpus inputs from its trusted frozen inventory and
obtain reviews from a trusted review store. The evaluator checks consistency and
bytes; it does not authenticate reviewers, validate their permissions, discover
reviews, or prove that an arbitrary caller-supplied inventory is authoritative.
Review model construction is not a governance approval workflow.

The caller must parse the same verified body bytes, rather than reopening a path
that might have changed after verification. Once parsed, check span membership,
version binding, and every transition's evidence references before replay. Always
supply the validated availability map to replay_snapshots.

This first module does not install a corpus loader, review store, CLI command,
or mandatory production replay wrapper. Existing generic replay remains unchanged
and still permits omission of its availability map. Thus this evaluator is a
building block, not an end-to-end enforced production historical replay gate.

## Current corpus and test scope

All three real ABC archive captures remain pending. Tests exercise each with no
review and with a test representation of pending review: both block admission as
UNVERIFIED. A real CBS live body with no archived availability binding is REJECTED.
All approval tests use synthetic bodies and synthetic review provenance.

The unit tests cover inclusive capture boundaries, timezones, byte tampering,
CDX row validation, ambiguous versions, mismatched or reused reviews, absent
records, invalid timestamps, deterministic audit records, and immutable results.
No corpus bytes, historical admission records, or existing temporal rules change.

Run from the TNC project root:

```powershell
uv run pytest -q tests/test_historical_admission.py
uv run pytest -q
```
