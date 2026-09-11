# Bounded SQLite update-store inspection

This step introduces `UpdateDurableStore`, a loader for an isolated schema-v1
installer-update database. It does not extend the existing review/journal database.

`create_empty_for_testing(path, image, trusted_checkpoint=...)` explicitly creates
only an empty, independently bound image. Exclusive file creation rejects existing
paths. DDL and initial records commit together; failed initialization can leave an
unusable empty file for explicit test cleanup. This helper is not authenticated
bootstrap and must not be exposed through a production command.

`load(trusted_checkpoint=...)` opens an existing database with SQLite `mode=ro`,
uses one read transaction, checks the exact application/schema identifiers and
schema objects, and bounds row counts and stored column lengths before fetching
payloads. It reconstructs the canonical image, runs pure replay against the
independently supplied checkpoint, and compares every projection to expected rows.
Missing, extra, noncanonical, or mismatched state returns a bounded `INVALID_STORE`
exception. It does not repair data or derive trust from the local checkpoint.

The schema has canonical events, registration/preparation/commit/publication
projections, immutable metadata, and a local state/checkpoint projection. STRICT
tables, foreign keys, unique keys, and append-only triggers supplement application
checks. Read connections enable query-only mode and foreign keys; test creation
uses WAL and FULL synchronization with explicit transactions. Loading can inspect
an intact committed WAL snapshot while another connection has uncommitted changes.
Read-only SQLite access may still involve SQLite-managed shared-memory sidecars;
this is not a promise of metadata-only filesystem inspection or zero OS effects.

Bounds remain 256 events, four MiB per event, and sixteen MiB per canonical image.
The loader also bounds all raw columns to four MiB each, schema text to 64 KiB,
schema objects to 64, and aggregate stored column bytes to 32 MiB before retrieval.
These finite limits are not a production pagination or retention scheme. SQLite
queries and integrity checks have no hard execution deadline in this milestone.

Tests materialize nonempty fixtures directly through test-owned SQL; there is no
public import, append, authority-change, commit, or publication method. Coverage
includes exact round trips, projection corruption, schema changes, bounds,
canonical rejection, missing stores, exclusive creation, initialization rollback,
append guards, repeated publication observations, and read snapshot isolation.

Host authentication, protected pathname-to-SQLite opening, independent checkpoint
reconciliation, real drain evidence, multiprocess commit/crash recovery, and native
locator publication remain unimplemented. Synthetic recorded authority is still
test evidence. Production execution guards and ABC quarantine remain unchanged.
