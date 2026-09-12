# External witness store, Phase 1

`TestExternalWitnessStore` is an isolated temporary-store creation and audit loader.
It persists synthetic witness evidence; it does not provide authenticated witness
service, signing, submission, policy replacement, current observation or client
recovery endpoints. No existing database schema or execution route is modified.

## API and initial trust

`create_for_testing(path, trusted_initial=..., now=...)` exclusively creates one
store context per database. It validates the independently supplied initial record
and exact integer time before creating the file. Existing main files, orphan SQLite
sidecars and missing parent directories fail; no directory or ACL is created or
repaired. The explicit initial record can pin a nominated starting sequence; no
genesis sequence is inferred from an incoming request or missing database.

`TestExternalWitnessStore(path, trusted_initial=...).load_audit(now=...)` opens an
existing file with `mode=ro`, `query_only=ON`, `trusted_schema=OFF`, foreign-key
checking and a `BEGIN` read snapshot. It never requests `BEGIN IMMEDIATE`, repairs
projections or creates schema. All current and historical records must match the
independently retained initial record. Historical evidence is replayed at its saved
acceptance time, so audit loading remains possible after request/policy expiry.
The last accepted timestamp must not exceed the caller-supplied audit time.

File locations, owners and permissions remain trusted temporary-host prerequisites.
This phase does not implement native path/ACL acquisition. SQLite may manage WAL
shared-memory sidecars according to its own read-only/WAL requirements; the API
performs no application-table writes during audit.

## Schema

Application ID: `0x544E4357`; schema version: `1`. Explicit creation selects WAL,
`synchronous=FULL`, `STRICT` tables and `BEGIN IMMEDIATE`. DDL is executed statement
by statement inside the transaction. There is no `IF NOT EXISTS` or implicit seed.

| Table | Canonical record and validated projections |
| --- | --- |
| `witness_anchor` | Exact independent initial record and its digest |
| `witness_image` | Complete WitnessImage, digest and receipt count |
| `witness_receipts` | Exact request/receipt bytes, owner, unique request ID, unique witness sequence and request digest, receipt/state digests |
| `witness_head` | Full current WitnessStateRecord and sequence/local-sequence/checkpoint/epoch projections |

The full records retain all context, trust, policy, checkpoint and epoch fields;
projection columns are accelerators, never substitutes for canonical evidence.
Receipts and the initial anchor have unconditional UPDATE/DELETE guards. Image and
head deletion is blocked. The schema permits no two receipts at a witness sequence
and no rebinding of a request ID. There are no signature-shaped placeholder columns.

The loader enforces exact schema equality, including indexes and triggers. Canonical
row counts and bytes must match the pure image exactly: missing or extra rows,
changed owners, digests, sequences or payloads fail without rebuilding anything.
The genesis head has no receipt; subsequent head/receipt linkage is validated by
the complete pure replay and exact projection comparison.

## Bounds and replay

- At most 64 receipts and one row in each singleton table.
- At most 1 MiB for the canonical image and 256 KiB per other bounded record.
- At most 4 MiB aggregate projected column bytes.
- At most 64 schema objects and 64 KiB of stored schema SQL.

Schema and column lengths/counts are checked before loading canonical blobs. The
loader then invokes `validate_witness_image` with the independent initial record,
reconstructs all expected projections, and checks SQLite foreign-key and quick
integrity results. It does not maintain a second version of CAS or authorization
rules. Bounds are logical parsing limits, not a claim to bound every kernel I/O
operation, total file scan or SQLite integrity-check duration.

Synthetic historical policy, caller and lineage inputs remain fixture evidence.
Persisting or replaying them does not authenticate their original provider or
prove currently active policy. Audit return values are data, not bearer tokens or
permission to advance any external store.

## Failure behavior

Ordinary loading returns fixed `INVALID_WITNESS_STORE` errors without paths or
stored payloads. Creation failures return `WITNESS_STORE_CREATION_FAILED`. An
interrupted pre-commit creation can leave an invalid empty file, which ordinary
loading rejects. Failure after commit but before return can leave a valid store;
the creation error does not promise rollback. Independently pinned audit loading
can inspect the outcome. No overwrite retry or automatic cleanup is provided.

Creation uses FULL synchronization, but durability depends on SQLite, the operating
system and storage. Tests inject exceptions at DDL, initial-row, pre-commit and
post-commit boundaries; they do not establish hardware power-loss immunity.

The witness database cannot detect restoration of its own complete old image when
the independently supplied initial anchor still matches. A test demonstrates that
limitation. A production witness requires independently durable monotonic state,
authenticated freshness, non-equivocation and protected administration.

## Tests and deferred phase

Tests populate advanced temporary histories directly from pure-model proposals;
that helper is not an application submission API. Coverage includes restart and
expired historical audit, exact receipt bytes, independent context binding,
exclusive creation, rollback and lost creation return, corruption, immutable/unique
constraints, bounded decoding, full 64-receipt images, pure evidence replay and
read-only WAL snapshots while another connection holds an uncommitted write.

Phase 2 remains separate: transactional submission, a coordinated current policy
provider, authorization-before-lookup, exact historical retries, locked CAS and
pre-commit rechecks, OUTCOME_UNKNOWN, process-exit and competing-writer tests.
