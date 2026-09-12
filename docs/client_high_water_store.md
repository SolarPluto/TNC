# Test-only durable client high-water store

`TestClientHighWaterStore` persists the existing pure model in an isolated version-1
SQLite database. It does not modify authority, runtime, review, or outbox schemas.
Caller identity and trust snapshots remain host-fixture inputs, not production
authentication or an independently secured trust loader.

Creation is explicit: `create_for_testing(path, trusted_initial_anchor=..., now=...)`
exclusively creates the file and initializes its anchor and empty history in one
DDL/data transaction. It never overwrites or silently provisions missing storage.
A failed initialization may leave an invalid empty file for explicit cleanup.

Normal `load(now=...)` opens mode=ro/query_only with a read snapshot. It bounds schema
objects/text, row counts, individual values and aggregate bytes before decoding;
checks the independently supplied anchor; replays the full pure history; compares
every state and receipt projection exactly; and runs SQLite integrity checking.
Missing files, schema drift, corrupt records or missing projections fail closed.
No silent rebuilding is performed. SQLite may manage WAL sidecar bookkeeping.

`apply(request, caller_principal=...)` opens existing storage mode=rw, uses WAL/FULL
and BEGIN IMMEDIATE, samples the host clock after acquiring the lock, reloads the
validated state and invokes the pure transition function. Receipt insertion and
state replacement occur in one transaction, followed by projection validation and
another current-time signature/interval check for newly accepted observations.
Backward clock movement rejects the transaction. Remote trust changes do not share
this lock, and no claim of release-time remote authorization is made.

Accepted same-head evidence increments the local sequence only. Direct advances
require exact predecessor continuity. Blocked stale/fork/missing-link outcomes do
not append rows. Exact historical retries return original persisted receipt bytes
without current observation expiry checks or head regression, under the existing
synthetic caller-scoping contract. Production current recovery grants remain absent.

The immutable anchor and receipt tables have update/delete guards. The state row
is a validated canonical image with exact projections. Limits retain 64 entries,
16 MiB state, 64 KiB small columns, 32 MiB aggregate stored column bytes, and bounded
schema metadata. Capacity rejection must not trim history.

COMMIT-attempt or post-commit acknowledgement failures return OUTCOME_UNKNOWN;
exact retry resolves the saved result. Earlier exceptions roll back. Busy timeouts
fail without cached-state fallback. Test-only private fault hooks exercise these
boundaries; production signer and verifier APIs are unchanged.

Tests demonstrate process-exit crash recovery and SQLite serialization in temporary
stores. They do not prove physical power-loss durability or detect replacement of
the entire database with an older valid copy. A local sequence and genesis anchor
cannot establish latestness. No checkpoint distribution, runtime activation or
production protected-file provisioning was added.
