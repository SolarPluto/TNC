# Test-provider update transactions

`update_durable_writer.py` implements `TestUpdateStoreWriter` for temporary stores
using schema version 1. No schema migration, CLI, production provider, or locator
publisher is added. The class name and required `LocalCheckpointForTesting` profile
make this boundary explicit; they are not an OS security boundary.

## API and authority

The host test harness constructs the writer with identity, administration,
observation, checkpoint, and clock providers. Public methods are `register`,
`prepare`, `commit`, `recover`, and `record_authority(expected_revision=...)`.
There is no arbitrary transaction callback, public SQL context, cached constructor
trust store, or request-supplied authority/drain record. The administration provider
supplies synthetic AUTHORITY snapshots and a test authorization verdict. It is not
an authenticated administrative enrollment implementation.

Each operation opens an existing database with `mode=rw`, enables/validates foreign
keys and FULL synchronization, and uses `BEGIN IMMEDIATE`. The complete committed
image and projections are reloaded under that transaction. Authority changes and
update commitments use that same cross-process SQLite ordering.

Current signing trust, identities, grants, and revocations come from the latest
stored AUTHORITY event. Live identity-provider results must match its principal,
credential, and registry revision; the session must remain consistent and valid
through the final check. The existing evaluation/recovery permission profile is
used only for this synthetic harness; it is not promoted to a production write
permission.

## Transitions and exact retries

REGISTER stores the full canonical intent, original signature envelope, and
credential. Repeating the identical pending registration appends nothing. Changed
intent bytes or signature bytes conflict. Ownership and current scoped permission
checks precede disclosure of operation results.

PREPARE records preparation history. Repeating the current exact preparation is
unchanged after current validation. A new valid preparation appends history.
Drain observations belong to COMMIT, not PREPARE. COMMIT must use the exact latest
saved preparation and valid synthetic drain evidence; it cannot silently replace
the saved preparation.

COMMIT constructs the receipt, resulting head, and archival signature associations
from a newly evaluated transition. It inserts the event and projections and
updates the local state/checkpoint in one transaction, validating the proposed and
persisted images before committing. Time regression, expired evidence, invalid
signatures, stale head, capacity exhaustion, or failed final checks roll back.
The event time is a logical decision time, not proof of physical commit time.

An exact committed retry requires current recovery permission and exact original
intent/signature bindings, and returns canonical bytes of the original receipt.
It does not acquire new observations or check the old signing key as current.
Historical replay still validates stored evidence at its recorded times. Fresh
sessions may recover the same principal's receipt; historical actors are preserved.
RECOVER of a valid pending operation returns UNCHANGED with no receipt.

An identical latest AUTHORITY snapshot can be retried with either its current
revision or its immediately preceding AUTHORITY revision. A changed snapshot
requires the exact current revision. This is bounded latest-view idempotency, not
a general administrative request journal; there is no promise to recover arbitrary
old authority requests after subsequent authority changes.

## Failure and durability boundary

All writes are append-only except the transactional local state projection.
There is no history truncation or automatic rebase. At the finite image limits,
new events stop; an unchanged retry can still recover. Production capacity
reservation, segmentation, and emergency administrative continuity remain open
requirements.

Failures before COMMIT roll back the transaction. COMMIT errors and lost
acknowledgements require exact recovery; no caller should infer rollback from an
uncertain result. The private fault hook is solely a test seam and must not be
exposed to clients. Process-exit tests demonstrate SQLite recovery after abrupt
termination, not physical power-loss durability.

`LocalCheckpointForTesting` reads the serialized local checkpoint and therefore
provides internal consistency only. It is deliberately not an independent current
authority and cannot detect a fully rewritten/rolled-back database with matching
hashes. The unchanged read-only loader still requires an explicitly supplied
checkpoint. External checkpoint reconciliation remains a production activation
gate.

The provider and file-opening interfaces here do not establish protected Windows
deployment, real mTLS administration, real process termination, or fencing of
external processes. Observation-provider calls run inside the bounded test
transaction and must remain short; real staging/drain work needs a separate host
protocol. No filesystem pointer promotion, process control, or service startup is
implemented. Existing journal execution guards and ABC quarantine remain intact.

## Tests

Temporary-store tests cover lifecycle/retries, original receipt recovery after key
expiry/revocation, fresh sessions, conflicts and owner isolation, current permission
checks, all commit write boundaries, preparation binding, authority changes, clock
and expiry failures, contention, corrupt projections, and capacity exhaustion.
Separate spawned processes check identical commits, distinct competing updates,
revocation ordering, and abrupt exits immediately before/after COMMIT. IPC events
coordinate live processes; abruptly exiting children do not leave event cleanup
dependent on synchronization objects they may have abandoned.
