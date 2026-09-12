# Pure client request journal

`client_request_journal_logic.py` defines the `tnc-client-journal-v1` frozen
records and pure proposal APIs. It adds no journal database, schema, dispatch
route, network call, signing operation, or clock source. Caller identity and
independent trust inputs remain host-owned synthetic evidence in this milestone.

## Intent, retention, and receipt bindings

An operation ID is an opaque idempotency key, not a credential. Its immutable
intent contains the complete retained v2 request, principal, client-anchor digest,
public trust store and checkpoint, and creation/expiry bounds. The intent hash is
SHA-256 over `b"TNC-CLIENT-JOURNAL-INTENT-v1:" + canonical_bytes(intent)`.
The digest is different from the existing `AdvancementRequest` digest in local
receipts; the implementation explicitly validates both bindings.

Register at `created_at` before dispatch. Registration does not prove the request
was transmitted. Fresh registration requires the intent's valid interval to fit
within the request and pinned trust intervals. Exact registration retries return
`UNCHANGED` without refreshing timestamps, including after expiry.

Retention preserves the exact canonical UTF-8 response bytes through a JSON text
field. Decoding and cryptographic validation do not normalize malformed input.
The first retention verifies the v2 signature and context at `retained_at`.
Identical retention retries preserve the original event, while different bytes
under the same operation are conflicts. Historical retention is not permission
to commit a currently expired response.

Limits: 64 sorted unique operations; 16 MiB canonical images and outcomes; 2 MiB
intents; 16 KiB request bytes; 32 KiB response bytes; 64 KiB receipt bytes. Each
entry's local sequence is exactly its lifecycle phase (1, 2, or 3). UTC integer
times, exact types, bounded reason codes, canonical byte checks, and positive
validity intervals reject coercion and malformed data. No monotonic deadline is
persisted. All time inputs are supplied explicitly.

## Pure operations

- `register_intent`: propose `AWAITING_RESPONSE`, or return an identical retry.
- `retain_response`: propose `RETAINED_RESPONSE` with immutable response bytes.
- `evaluate_recovery`: examine retained state and checked high-water history;
  propose terminal receipt acknowledgement or emit a bounded audit result.

Functions never mutate their inputs. Proposed images must be explicitly applied
by a future caller. Principal checks precede image inspection and operation
disclosure. Missing operations and wrong principals use a generic access error.
Image validation replays retained signatures at their original retention times
and validates terminal receipt evidence historically.

## Separate-store reconciliation

`evaluate_recovery` checks for an exact existing high-water receipt **before**
checking current response expiry. This resolves a high-water commit followed by
a lost journal acknowledgement without contacting upstream, even after later
high-water advancements. The complete history is validated against the supplied
initial client anchor using the existing high-water validator.

A terminal `JournalReceiptBinding` retains that synthetic, full high-water image
as `high_water_evidence`. This is a deliberate pure-model detail: later journal
validation can replay the original receipt evidence rather than trust a bare
receipt or a boolean flag. The full image remains subject to the journal's total
byte cap; evidence is never silently truncated. A future durable adapter must
define protected acquisition and storage of this evidence. The object itself is
not proof that a real database transaction happened.

The exact history entry must match the reconstructed `AdvancementRequest`
byte-for-byte. Its receipt cannot predate response retention. A conflicting
operation blocks reconciliation. Invalid or unavailable high-water evidence
returns `INDETERMINATE`, never assumed absence.

If a validated high-water image has no matching receipt, a currently valid
response yields `READY_TO_APPLY`. That is only an audit proposal containing the
existing exact request. The high-water store still checks signature validity and
lineage under its own transaction lock. Stale, forked, or skipped heads can still
be rejected there. A successful apply can be `UNCHANGED` or `VALID_ADVANCE`.

An expired response without an existing receipt returns `RESPONSE_EXPIRED`,
preserving retained bytes. Fresh observation requires a fresh operation; it does
not overwrite the original intent or response. Terminal retries recover original
receipt bytes without rechecking live grants or requiring an upstream signer.
An external high-water read is unnecessary once the journal contains validated
terminal evidence.

## Explicit limits

Separate journal and high-water files will not have an atomic shared commit.
A receipt committed while the journal remains retained is a supported recovery
state. A valid absence snapshot can race with a later high-water commit; the
future apply path must keep using the existing exact request and retry rules.

A response received only in memory can be lost before retention commits. Neither
an operation ID nor an awaiting entry reconstructs those lost bytes. This module
does not close the network-to-disk gap or infer delivery from registration.

No code here proves external authenticity, production caller identity, trusted
time, or whole-database rollback resistance. SQLite persistence, migrations,
cancellation, cleanup, durable dispatch, production authentication, and external
witnesses remain deferred. Expiry and delivery errors are outcomes; they never
erase audit evidence.

## Validation

The dedicated suite covers canonical and fixed digest vectors, exact byte caps,
frozen models, bounds, intent conflicts, invalid signatures and contexts,
retention immutability, clock regression, expiry edges, illegal phase jumps,
forged or unavailable high-water evidence, lost terminal acknowledgement after
expiry and later advancement, offline receipt recovery, and zero I/O/clock use.
