# Storage-only authorization migration (version 3)

`SqliteReviewStore.migrate_to_v3()` explicitly upgrades a validated version-2
database. Version 1 requires the existing explicit v2 migration first. Opening a
database never migrates it. A retry on v3 validates the complete target and returns
without rewriting historical records. Calling migrate_to_v2 on v3 is rejected.

The migration runs source validation, individual DDL statements, boundary creation,
target validation, foreign-key checks and user_version update within one
BEGIN IMMEDIATE transaction. It does not use executescript inside that transaction.
Existing review/outbox/journal bytes, hashes, sequences and codec versions remain
unchanged. PRAGMA user_version becomes 3; store_state.schema_version remains 1.

## Transitional storage

New tables hold future authorization events, execution authorizations, worker
assignments and release authorization receipts. Their checkpoints start empty.
The immutable migration boundary records the legacy journal and release heads.

No authorization writer exists yet. Eight unconditional insert guards block the
four journal/outbox tables and four new authorization record tables. Adapter
validation additionally requires empty authorization history, initial checkpoints,
the exact schema and unchanged journal/release boundary. Removing a guard or
inserting a premature record is an integrity failure, not a bootstrap mechanism.

Current journal mutation methods reject v3 before performing work, including
otherwise idempotent write retries. prepare is blocked before parsing. The internal
standalone release helper also rejects v3, including exact prior release retries.
Use validated read-only recovery or release_history for historical audit instead.

RequestJournalManager.recover retains its existing principal-scoped host-library
contract and now supports v3. This is not an authenticated network recovery route;
CallerContext and host allowlists remain internal assertions. No dispatcher or
new permissions are enabled.

Existing governed review append/resolve/history operations remain supported.
Outbox corruption blocks migration and release recovery, while an intact review
ledger can still accept an administrative revocation. This preserves the adapter's
existing separation; no TLS identity is automatically granted review authority.

## Remaining activation work

A subsequent explicit schema migration must replace the closed-write guards
together with the authenticated administrative writer, typed authorization-event
validation, bootstrap procedure, execution bindings and transaction-scoped release
checks. The v3 validator intentionally does not accept even plausible authorization
rows. Table definitions alone do not implement their future state machine.

No source approvals, service accounts, credentials, grants, certificate installation,
OS permissions or real database migration occur merely by adding this code. The
historical CLI remains unchanged. Existing ABC captures remain unapproved.

## Verification

The 35 new tests use real adapter-created temporary databases and canonical project
fixtures. They cover preserved REGISTERED/PREPARED/COMMITTED/FAILED history,
standalone historical receipts, revoked reviews, reopened recovery, repeat migration,
version selection, all eight direct SQL insert guards, legacy write API rejection,
source/target corruption, target-validation failure, rollback after every DDL
statement, bounded lock contention, concurrent process migrations and process
termination immediately before/after commit.

The tests also verify that corrupted outbox payloads still permit a governed review
revocation against an intact ledger. SQLite constraints and canonical validation do
not defend against a privileged attacker replacing an entire database with an older
valid copy; external rollback protection remains separate.
