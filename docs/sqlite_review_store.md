# SQLite review ledger and outbox

`tnc.provenance.sqlite_review_store.SqliteReviewStore` implements the existing
resolve, append, history, commit_release and release_history interfaces. The CLI
still starts with its empty in-memory store. No real ABC reviews are created.

## Host API

```python
store = SqliteReviewStore.provision(
    path=host_database_path,
    allowed_reviewers=frozenset({host_reviewer_id}),
)
# On subsequent starts:
store = SqliteReviewStore.open_existing(
    path=host_database_path,
    allowed_reviewers=frozenset({host_reviewer_id}),
)
```

Only trusted host code supplies paths and reviewer allowlists. Neither proves
authentication. Provision uses exclusive file creation and refuses to overwrite
even an existing empty file. Failed provisioning leaves the file for explicit
inspection; it never deletes or replaces it automatically. The directory must
already exist with host-managed permissions. open_existing and every subsequent
operation use SQLite URI mode=rw so a missing file cannot become a new empty store.
No migrations or automatic directory creation are performed.

## Transaction and semantic rules

Each operation creates and closes its own connection with isolation_level=None
and explicit legacy transaction-control selection. Writes issue BEGIN IMMEDIATE;
reads use one BEGIN transaction. Connections verify WAL, foreign keys, recursive
triggers and synchronous=FULL. Lock waits have a finite host-configured timeout
(default five seconds); contention fails closed instead of retrying with cached
authority. This uses Python's explicit transaction mode described in the
[sqlite3 documentation](https://docs.python.org/3.12/library/sqlite3.html).

Every operation compares the stored schema with the bundled version-1 schema,
checks its version and checkpoint, reconstructs full canonical records, validates
all SQL projections, and verifies the ledger. Release and outbox reads additionally
validate the complete outbox against its checkpoint and historical review prefixes.
No max(sequence) shortcut substitutes for chain/checkpoint validation.

The adapter rebuilds a private, transient InMemoryReviewStore inside the database
transaction to reuse the existing semantic validators and hashing functions. This
object is not a cache or independent authority; no state survives between calls.
The adapter deliberately depends on those module internals, and shared contract
tests cover changes to them. SQLite's write transaction supplies cross-process
coordination; the temporary Python lock does not.

New rows and checkpoints commit together. Exact review/release retries return the
original record without inserting or incrementing a sequence. Release comparison
includes full request metadata and exact payload bytes; a reused ID with different
policy, evidence, query or review expectations conflicts even if payload is equal.
An unrelated constraint violation is not treated as idempotency. Unexpected SQL
constraint failures become integrity errors. Corrupt/invalid database errors are
integrity failures; lock/I/O failures are unavailable or potentially uncertain
commit outcomes. No result is returned until COMMIT completes.

An outbox data-integrity failure blocks release and outbox history, but a valid
review ledger can still receive revocations. open_existing validates the ledger
only for this reason; it is not a certificate that the outbox is valid. Schema
corruption blocks all operations. Guard triggers reject supported SQL updates and
deletes; full process/file owners can bypass them and are outside this boundary.

## Serialization

Version-1 storage uses canonical UTF-8 JSON BLOBs: sorted keys, compact separators,
UTC timestamps with six fractional digits, and hex-encoded payload bytes inside
ReleaseRequest. Outbox payload is also stored as a raw BLOB and must match the
decoded request exactly. Reconstructed models must reproduce the same canonical
bytes. Existing entry, evidence and receipt hash algorithms remain unchanged.
Sequence/checkpoint allocation preserves the existing contiguous-history contract.

## Recovery and limitations

The durable release point is database COMMIT. An exact previously committed
candidate can recover its receipt after restart and later revocation, without a
new release. Before-commit failures roll back both row and checkpoint. Failure to
receive an acknowledgement does not prove rollback: a commit may already exist.
Recover on a new connection with the same candidate; the adapter does not perform
automatic retries or fabricate a replacement ID.

The current engine and CLI generate a new release ID for each execution. Therefore
this adapter does not provide end-to-end CLI retry recovery. A durable operation
journal and an explicit recovery API remain necessary. release_history is a trusted
audit of historical payloads, not renewed authorization or a public retrieval API.

SQLite WAL is intended here for a local database shared by processes on one host,
not a network share. Protect database, directory, WAL/SHM files and backups with
Windows service-account DACLs. FULL sync still depends on filesystem/storage
behavior. Coherent rollback to an older entire database is not detected by internal
hashes/checkpoints alone; external rollback anchors and backup policy are deferred.
Refer to [SQLite transaction semantics](https://www.sqlite.org/lang_transaction.html)
for writer serialization. No service identity or OS permissions are configured by
this code, and no production authentication claim is made.

## Verification

Disk-backed tests reuse existing in-memory governance/release contract cases.
Additional tests verify reopen/exact receipts, SQL guards, missing files, schema
and record corruption, outbox corruption with continued revocation, bounded lock
failure, stable read snapshots and separate-process conflicting writers. Process
tests terminate a worker immediately before or after COMMIT using IPC events, then
reopen and recover without duplicate receipts. These demonstrate process-crash
behavior, not sudden power loss or hardware durability.

Run `uv run pytest -q tests/test_sqlite_review_store.py tests/test_sqlite_release.py`.
