# Explicit request-journal schema migration

The SQLite adapter now supports layout versions 1 and 2. New provisioning still
creates version 1; opening a database never upgrades it implicitly. Trusted host
code explicitly calls:

```python
store = SqliteReviewStore.open_existing(
    path=host_database_path,
    allowed_reviewers=host_allowlist,
)
store.migrate_to_v2()
```

This is schema preparation only. Registration, principal checks, worker fencing,
candidate preparation and atomic journal/outbox finalization are not implemented.
There is no migration command or recovery-token option in the CLI. Tests operate
on temporary synthetic databases; no deployed database or real review is changed.

## Atomic upgrade

Migration acquires BEGIN IMMEDIATE and validates the complete existing schema,
review history, outbox and checkpoints. Only a valid version-1 database receives
the bundled extension. Version-2 retries validate the complete target and succeed
without modifying it. Unknown versions, altered layouts, corrupted records or
inconsistent checkpoints fail closed.

The extension creates request_intents, prepared_requests, request_events,
journal_state, their indexes and immutable-row guards. It reserves release IDs
without requiring nonexistent outbox rows; only COMMITTED events reference actual
receipts. The final statement sets PRAGMA user_version=2. Target schema and data
are validated again before COMMIT.

Statements are executed individually with sqlite3.complete_statement framing,
including whole trigger definitions. The migration does not use executescript,
which could commit a pending transaction before running the supplied script in
the selected Python transaction mode. No CREATE IF NOT EXISTS, implicit migration,
or loose missing-table repair is used.

DDL, journal checkpoint initialization and the layout-version change share the
same transaction. Failure before commit rolls them all back. An uncertain commit
is handled by reopening and explicitly retrying migration; either the validated
source or target layout is accepted. Existing review/outbox rows, stored BLOBs,
hashes, sequences and ledger checkpoints are not rewritten.

PRAGMA user_version is the database layout version. The existing
store_state.schema_version remains 1 because that ledger/outbox schema and its
hash representation are unchanged. journal_state.codec_version is separately 1.
These identifiers describe different scopes; a layout upgrade does not rehash
legacy history or manufacture journal entries for old releases.

## Transitional guard

The current version-2 adapter accepts only an empty journal: all three record
tables must be empty and the journal checkpoint must equal its initial state.
Any externally inserted intent/candidate/event or altered journal checkpoint
blocks adapter operations, including legacy release. This prevents the existing
release method from operating around journal ownership rules that do not exist
yet. A future manager must replace this temporary guard with full event/binding
validation and enforce reserved release ownership within a shared transaction.

With an empty journal, normal review and release operations continue on version
2. Old receipts remain recoverable by exact candidate retry after revocation.
Opening still validates only the ledger/outbox schema and ledger content for
ordinary operations; release/outbox audit validate outbox data. Migration is
stricter: it validates both histories before altering the layout.

Old application builds that recognize only version 1 will reject a migrated
database. Deployment must coordinate application upgrade and explicit migration;
there is no downgrade operation. The code does not configure file permissions,
perform backups, authenticate administrators, or protect against coherent rollback
of an entire database. Those remain host deployment responsibilities.

## Verification

Fourteen migration tests cover byte-for-byte record preservation, old receipt
recovery after revocation, empty upgrades, no implicit migration, idempotent target
validation, unknown/altered/corrupt source rejection, partial-DDL rollback,
post-DDL validation rollback, new version-2 writes, the empty-journal guard,
bounded writer contention, and process termination immediately before/after
COMMIT using IPC events. These are process-crash tests, not power-loss simulations.

Next implementation step: the journal registration, recovery and worker-claim
manager, followed by journal-aware preparation and coordinated finalization.
