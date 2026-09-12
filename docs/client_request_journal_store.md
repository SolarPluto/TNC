# Isolated SQLite client request journal — test-only adapter

`TestClientRequestJournalStore` persists the existing `tnc-client-journal-v1`
logical image. It is a host-owned test adapter, not a production authentication,
dispatch, or provisioning route. Caller principals and trust anchors remain
explicit host-fixture inputs. It never applies a high-water transition, requests
a fresh observation, signs, or publishes a checkpoint.

## Explicit creation and connection profile

Creation is a separate `create_for_testing` operation. It exclusively creates the
file, enables WAL, and executes schema creation and initial anchor/image insertion
in one `BEGIN IMMEDIATE` transaction. Statements execute individually; no
`executescript`, `CREATE IF NOT EXISTS`, schema migration, or silent repair occurs.

Normal reads open `mode=ro`, enable `query_only`, and use `BEGIN` for a consistent
read snapshot. Normal transition calls open an existing file with `mode=rw` and
use `BEGIN IMMEDIATE`. Writer connections require `synchronous=FULL`,
`foreign_keys=ON`, and `trusted_schema=OFF`. `synchronous` is a per-connection
setting; every writer configures it explicitly.

The isolated schema has application ID `0x544E434A` and user version 1. Foreign
application IDs, altered layouts, missing files, missing singleton rows, extra
tables/indexes/triggers, or invalid canonical data fail closed. An interrupted
creation may leave an existing but uninitialized file: normal opening rejects it;
the adapter does not delete, overwrite, or silently provision it on retry.

## Schema and immutable projections

All six tables are `STRICT`. Canonical JSON is stored as UTF-8 BLOBs so byte
comparison does not depend on SQLite text encoding or collation.

| Table | Content and constraints |
| --- | --- |
| `journal_anchor` | Single immutable canonical independently supplied `ClientAnchor` and digest. |
| `journal_image` | Single current canonical image, digest and operation-count projection. |
| `journal_intents` | Immutable operation ID, unique intent digest, canonical intent, creation and expiry times. |
| `journal_responses` | Immutable canonical retention record, exact response bytes, response digest and retention time; foreign key to intent. |
| `journal_receipts` | Immutable canonical receipt binding with synthetic high-water history, original receipt bytes and reconciliation time; foreign key to response. |
| `journal_heads` | Current phase, phase sequence and last-event time for each intent. |

Indexes cover head state and intent expiry. SQL triggers prohibit updates/deletes
to immutable records, prohibit head/image deletion, require initial heads to be
awaiting, require the correct predecessor phase before response/receipt insertion,
and permit only one-step head advancement with a matching inserted record.

The loader also runs the pure full-image validator and compares every projection
row exactly against reconstructed rows. SQL constraints alone do not verify
signatures or full model consistency. Missing, extra, changed, or noncanonical
projections are rejected rather than rebuilt.

Before fetching application BLOBs, the loader bounds schema size/count, table row
counts, per-column byte lengths, and total projected bytes. The pure image limit
remains 16 MiB and 64 operations. The duplicated storage representation has a
48 MiB aggregate logical byte limit. Anchor and receipt bytes are capped at 64 KiB,
intent bytes at 2 MiB, raw responses at 32 KiB, and canonical retained-response
records at 128 KiB to allow JSON string escaping. Full receipt evidence and image
BLOBs retain the 16 MiB limit. Foreign-key and SQLite quick integrity checks run
before returning a valid image.

## Public API

```python
store = TestClientRequestJournalStore(
    existing_path,
    trusted_client_anchor=anchor,
    high_water_store=optional_host_owned_test_high_water_store,
    clock=host_clock,
    busy_timeout=1,
)
store.register_intent(intent, caller_principal=principal)
store.retain_response(operation_id, exact_response_bytes, caller_principal=principal)
store.recover(operation_id, caller_principal=principal)
store.load(caller_principal=principal, now=explicit_time)
```

Principal checks precede opening the journal. The busy timeout must be finite and
between zero and five seconds. Methods return frozen audit results with status,
reason, optional exact advancement request, and optional original receipt bytes.
There is no arbitrary SQL, callback, or checked-evidence argument on a mutation API.

Each transition acquires the journal lock, reads the host clock, validates the
entire persisted image, and invokes the existing pure operation. Only a proposed
image produces inserts/head updates. The adapter reloads and validates the target
and checks the outcome again at finalization time; expiry or clock regression
rolls back pending changes. Registered intent creation time remains the exact
locked evaluation time required by the pure contract. Timing checks are
cooperative host checks, not an operating-system authorization primitive.

Exact retries preserve original timestamps, phase sequences and application rows.
Retained-response retries are not permission to commit expired observations.
If a commit was attempted but its acknowledgement is uncertain, the adapter
returns `OUTCOME_UNKNOWN` as an exception: it does not claim rollback or success.
An exact retry or validated reload resolves durable state.

## High-water recovery remains a separate operation

The optional high-water store must be the existing `TestClientHighWaterStore`,
bound to the same independently supplied anchor and a distinct path/file identity.
The adapter checks isolation again on evidence acquisition. It never attaches
the databases or shares their write locks.

For a retained response, recovery invokes that store's read-only validated loader
while holding only the journal's write transaction. Invalid/unavailable evidence
produces `INDETERMINATE`; it is not treated as a missing receipt. Historical
commit evidence is checked before current response expiry. A matching receipt
produces the journal terminal record and preserves original local receipt bytes.
The full synthetic evidence snapshot is retained as specified by the pure model.

With validated absence and a currently valid response, recovery returns
`READY_TO_APPLY` and the exact `AdvancementRequest`. It does **not** call the
high-water writer. The host must apply the request separately and then invoke
journal recovery again. A receipt can commit after an absence snapshot: that is
an expected race, resolved by the high-water store's exact retry semantics.

Once terminal evidence is stored, offline recovery needs neither the high-water
database nor any upstream grant, connection, signer, or signing handoff. It still
requires the caller principal and independently supplied journal anchor.

## Crash and security limits

Journal creation, registration, retention and terminal acknowledgement are atomic
within their own SQLite transactions. A high-water commit followed by a crash
before journal acknowledgement leaves the journal retained; recovery can find
the exact committed receipt even after the observation expires.

Neither WAL nor FULL makes two separate database commits atomic or proves
power-loss durability for every filesystem/device. Process-exit tests exercise
SQLite crash recovery under temporary local stores. Received bytes can still be
lost before retention commits. Whole-file rollback detection, protected host
paths, external witnesses, cleanup/cancellation, durable dispatch and production
identity integration remain outside this milestone.

## Tests

Tests cover creation and DDL rollback, strict schema/projection validation,
immutable and phase SQL guards, exact bytes and retries, no automatic high-water
apply, missing/invalid evidence, post-lock/finalization expiry, clock regression,
read snapshots under active writers, busy handling, concurrent identical and
conflicting retention, abrupt process exits before/after every journal commit,
creation-process exits, and a real separate high-water commit/journal crash gap.
Concurrency uses barriers and events, not sleeps. Child processes receive only
public canonical records and temporary database paths.
