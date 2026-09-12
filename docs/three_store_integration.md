# Three-store local lifecycle harness

`tests/test_three_store_integration.py` connects three distinct temporary SQLite
files: runtime update, authority acceptance, and client high-water. The verifier
and ephemeral signing fixture are components, not stores. Each file retains its
own schema/application ID; no attachment or cross-store transaction is used.

The runtime test writer registers, prepares and commits an update. The temporary
authority accepts the resulting exact image using explicit synthetic batch evidence.
The existing reader integration fixture captures its single validated snapshot,
assembles a v2 response and signs it with a temporary key. The client store receives
the full retained request/trust context and verifies again under its own write lock.
Trust inputs and caller identity remain test-host assumptions.

Spawned processes exit after standalone verification, before client COMMIT, and
after client COMMIT. The tests distinguish an unchanged client from a committed
receipt whose acknowledgement was lost. Exact retries recover original receipt bytes.
Other tests cover later-head historical retries, stale/forked/skipped observations,
expiry, signature tampering, trust mismatches, and unchanged upstream state.
An authority AUTHORITY event supplies a genuine second acceptance revision when
testing skipped and sequential advancements; authority rows are not fabricated.

The parent fixture retains exact request inputs across child exits. This is not a
durable distributed request coordinator. The deliberately forked observation is
signed only by the test fixture to exercise client conflict detection; it is not
issued by a production signing service. No private keys are saved to disk.

The suite asserts separate database identities and no runtime publication records.
It does not activate runtime processing, distribute checkpoints, implement network
recovery, authenticate host trust loading, detect whole-store rollback, or prove
physical power-loss durability. All existing synthetic and production boundaries
remain unchanged; only tests and documentation are added.
