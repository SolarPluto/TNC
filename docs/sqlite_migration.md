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

Migration prepares the schema. The separate RequestJournalManager now implements
registration, principal scoping, worker fencing, preparation and finalization;
see `request_journal.md` for its host-only trust boundary.
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

## Journal-aware validation

The initial empty-journal guard has been replaced with full intent, prepared
candidate, event-chain and checkpoint validation. Standalone release refuses
journal-reserved IDs; journal finalization checks the worker generation inside
the same transaction as outbox insertion and the COMMITTED event. Arbitrary
externally inserted rows without valid canonical history still block operations.

With an empty journal, normal review and release operations continue on version
2. Old receipts remain recoverable by exact candidate retry after revocation.
Opening validates schema, ledger and structural journal history for ordinary
operations; release/outbox audit also validate outbox data and journal receipt
bindings. Migration is
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

The manager is implemented separately; authenticated deployment and CLI journal
integration remain future work.
