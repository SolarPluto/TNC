# In-memory review store

Implementation: `tnc.provenance.review_store.InMemoryReviewStore`.
Status: an in-memory ledger for testing review rules. Not a durable store,
production authentication service, or enforced historical replay wrapper.

## Implemented contract

The store implements the `ReviewReader` and `ReviewWriter` protocols:

```python
reader.resolve(document_id="doc", version_id="version")
writer.append(request=request, actor=reviewer_context, expected_head_sequence=None)
```

Resolution returns an immutable `ReviewResolution` with status `missing` or `found`,
the current record (including rejections/revocations), global store revision, and
head hash. Lookup is by document and version; there is deliberately no body/index
filter or historical query-time argument that could retrieve an older approval.
Only the returned record's verdict APPROVED can support later admission, and the
wrapper must still compare its full availability binding to current trusted evidence.
A stored APPROVED verdict does not itself establish technical archive validity.

`ReviewRequest` embeds the complete existing `ArchiveAvailabilityRecord`, verdict,
review ID, aware reviewed_at, rationale, and revision links. It does not accept
reviewer identity, store sequence, or recorded_at from request JSON. Store receipt
metadata lives on `StoredReviewRecord`; the original request is retained within it.
Model fields are immutable and extra fields are rejected.

## Evidence fingerprints

Canonicalization version 1 encodes the complete availability record in UTF-8 JSON
with sorted keys, compact separators, and a fixed canonicalization-version field.
The capture time is normalized to UTC with six fractional digits and Z; CDX times
with nonzero microseconds are rejected, not rounded. Other strings, including URLs,
are preserved exactly. Equivalent timezone offsets hash identically. SHA-256 of
these bytes is stored as availability_fingerprint.

Each ledger entry also hashes its canonical request, writer/receipt metadata,
sequence, evidence fingerprint, and preceding entry hash. Every read or append
validates the whole chain against an in-memory revision/head checkpoint, plus
semantic checks. Corruption yields ReviewIntegrityError rather than MISSING or
fallback to an older approval. The checks use explicit conditionals, not Python
assert statements that disappear in optimized execution.

These hashes detect inconsistent bytes; they are not signatures or authentication.
An attacker who can replace the entire coherent ledger and its in-memory checkpoint
can still forge history. No external rollback anchor exists in this implementation.

## Write rules

- The store checks a host-configured reviewer allowlist. ReviewerContext is a
  host-asserted identity, not a credential or proof of authentication.
- A lock covers validation, head comparison, sequence allocation, and append. The
  sequence is globally increasing, while expected_head_sequence is per version.
- Initial review: expected_head_sequence and supersedes_review_id must both be None.
  A replacement must name the current head's sequence and review ID.
- Equal reviewed_at timestamps are permitted; sequence decides order. Backdated
  per-version reviews, future decision times, reviews before capture, naive times,
  and a backwards store receipt clock are rejected without appending.
- A document version cannot change its document identity, body hash, or original
  URL. New index/availability evidence for the same version requires an explicit
  replacing review; lookup will not fall back to an older matching binding.
- REVOKED must target the active APPROVED record for the same complete evidence.
  A later approval requires an explicit replacement of that blocking head.
- Exact retries (same review ID, request, actor, and original expected sequence)
  return the existing receipt without appending or changing the head. Retrying an
  old approval after revocation does not reactivate it. Its receipt must not be
  interpreted as the current authorization; use resolve for that.
- Same review ID with different content/actor/precondition is a conflict.
- `history()` returns a validated immutable tuple. There is no supported edit,
  delete, arbitrary seed-record, or old-head resolution API.

The store does not have corpus retrieval timestamps. A later evaluator still
checks approval chronology against actual observation, as well as body/index bytes.
Reviewed_at is a governance timestamp, not the historical query time.

## Errors and boundary

ReviewAuthorizationError blocks unlisted writers. ReviewConflictError reports
stale heads and duplicate/revision conflicts. ReviewIntegrityError blocks corrupted
history. Other invalid operations raise ReviewStoreError; malformed model input
raises Pydantic ValidationError. None of these is permission to proceed or use a
cached/older approval.

The reader and writer protocols describe allowed interfaces, not security isolation.
Giving query code the concrete store object exposes its writer method. A production
host must provide a restricted reader/service interface and establish actor identity
outside public query input. The allowlist test cannot prevent a same-process caller
from manufacturing an allowed ReviewerContext. Private Python attributes are not
access controls.

## Verification and deferred work

Tests use synthetic reviews for approval, replacement, rejection, revocation, and
reapproval. They cover concurrent conflicting writes and exact retries; canonical
fingerprints; altered records/chains; time/identity/link failures; immutable history;
and complete real-ABC absence/pending state. No actual ABC reviews are appended.

No SQLite backend, crash recovery, restart persistence, authenticated writer
boundary, or production wrapper is implemented here. A new store instance is empty.
Likewise, a revision in a read result is only a checkpoint: the future wrapper must
coordinate a head check with result release if concurrent revocation must prevent
an in-flight result. This code does not claim that guarantee.

Run from the project root:

```powershell
uv run pytest -q tests/test_review_store.py
uv run pytest -q
```
