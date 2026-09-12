# Durable distribution heads with a test policy provider

`protected_trust_distribution_store.py` adds an isolated SQLite persistence
adapter around the existing pure trust-distribution verifier. The public class is
explicitly named `TestProtectedTrustDistributionStore`: it validates transaction
and recovery semantics with synthetic host policy authority, not a production
distribution endpoint or protected filesystem service.

No existing observation, configuration, journal, review, outbox or authority
database schema is changed. All test databases are separate temporary files.

## Host anchor and API

`DistributionStoreAnchor` pins a local store ID, initial policy/checkpoint inputs,
and creation time. The anchor is supplied independently to creation and every
subsequent store instance. The complete canonical anchor must match the persisted
anchor. Fixed bootstrap scope, issuer, epoch, signing key and checkpoint revision
remain bound to that anchor; changing them requires a separate provisioning design.

Main operations:

- `create_for_testing(path, trusted_anchor=..., now=...)`: explicit exclusive
  initialization. It does not create directories or replace existing files.
- `load_audit(now=...)`: bounded, read-only snapshot reconstruction and historical
  replay. It does not establish that stored trust is currently usable.
- `apply(bundle, provider=...)`: locked verification against the current provider
  snapshot, atomic persistence, and final re-verification.

Normal opening uses `mode=ro` or `mode=rw`, never implicit creation. Missing or
invalid storage fails. Orphan WAL/SHM/journal sidecars prevent explicit creation.
An interrupted initialization can leave an uninitialized main file; it is not
silently repaired or treated as an ordinary first run.

Paths and filesystem permissions remain trusted test-host prerequisites. This
adapter does not perform the native path/ACL acquisition from the protected caller
configuration loader. Connecting protected storage ownership and a production
policy provider remains separate work.

## Bounded schema

The dedicated store has application ID `0x544E4344`, schema version 1, STRICT
tables, WAL mode, `synchronous=FULL`, foreign-key enforcement, and
`trusted_schema=OFF`.

| Table | Purpose |
| --- | --- |
| `distribution_anchor` | Immutable canonical independent anchor and digest |
| `distribution_image` | Complete bounded logical image, digest and local sequence |
| `distribution_receipts` | Immutable canonical ingestion inputs and verification receipts |
| `distribution_head` | Exact current head and distribution public-key projection |

Update/delete triggers protect the anchor and receipts. Image/head deletion is
blocked. The head references an existing receipt sequence. Schema comparison
includes every SQLite schema object; extra tables or changed triggers are errors,
not ignored accelerators.

Limits are 64 accepted distinct ingestion records, 512 KiB per ingestion/anchor,
16 MiB per logical image, 4 KiB per receipt, and 40 MiB aggregate projected data.
Counts and blob lengths are checked before decoding large records. Exact current
retries still work at capacity because they do not append a receipt. New ingestions
fail with `CAPACITY_EXCEEDED`; there is no automatic pruning or compaction.

The current key projection contains the public distribution key that was checked
for the head. It is not a private key, mTLS identity, observation signing key, or
claim that the key remains authorized outside its recorded/current checks.

## Historical reconstruction

Each distinct ingestion retains the exact canonical bundle, policy and independent
policy-checkpoint inputs. Its receipt binds those bytes by digest, the complete
pure verification result, checkpoint revision/digest, acceptance time and local
sequence.

Loading replays every ingestion through `verify_trust_distribution` at its saved
verification time. It checks scope/bootstrap bindings to the independent anchor,
policy floors, exact receipt/result digests, sequence continuity, unique request
digests and final head equality. It then validates the last successful current
recheck recorded in the head, all SQL projections, foreign keys and SQLite's
integrity check. Projections are never rebuilt to conceal disagreement.

Saved policy inputs are historical test-provider evidence. The reader does not
invent a cryptographic policy distribution chain for those records. The initial
anchor and the provider's authority at each write remain trusted host inputs.

Audit loading works after checkpoint expiry because replay uses recorded valid
times. Returning an audit image is not current trust acceptance. An expired
checkpoint submitted to `apply` is rejected even if its old receipt is present.

## Locked write sequence

1. Open the existing database and acquire `BEGIN IMMEDIATE`.
2. Acquire the test provider's policy gate and capture its immutable inputs.
3. Reload and validate the locked image. Obtain the current host clock and run the
   pure verifier against that image's head and the captured provider inputs.
4. For a distinct ingestion, append immutable request/receipt evidence. Persist the
   canonical image and exact head/public-key projections in the same transaction.
5. Recheck clock monotonicity, checkpoint/key expiry and provider snapshot identity.
   Persist the recorded verification head, validate complete replay/projections,
   and repeat the current checks immediately before commit.
6. Commit while still holding the provider gate. A post-commit guard checks that
   return can be confirmed without presenting expired or changed policy as current.

Returned verification metadata matches the head persisted by the transaction.
The post-commit guard does not claim a later verification timestamp was written.
The result's operation status records `INITIAL`, `ADVANCE` or `UNCHANGED`; its
verification is the final current recheck, which can itself classify the now-saved
checkpoint as `UNCHANGED`.

If a failure occurs before commit, the transaction rolls back. Once commit is
attempted, any ambiguous completion, injected acknowledgement loss, expiry or
policy change preventing a confirmed return produces `OUTCOME_UNKNOWN`. It does
not claim rollback. Audit loading can inspect the durable receipt; a current retry
must still satisfy current verification.

## Exact current retries and revision rules

The pure contract is preserved: lower checkpoint revisions and equal-revision
forks are rejected; an identical current checkpoint is permitted while fresh.
Checkpoint sequence, observation trust-store revision, and policy revision remain
separate.

An exact repeat of the latest full canonical ingestion returns the original
receipt bytes without appending history, changing the acceptance time, or advancing
checkpoint/epoch sequence. It can update the head's recorded check time. It does
not extend the signed issuance/expiry window.

If the same checkpoint is successfully checked under newer independently supplied
policy inputs, that is distinct audit evidence: it appends a receipt and durably
advances the policy pin without inventing a new checkpoint revision. A subsequent
older policy is rejected against that persisted pin.

An older checkpoint after an authority advance remains available through audit
history, but submitting it does not republish it as current. This API does not
implement a network historical-recovery permission route.

## Provider coordination and remaining trust boundary

`TestDistributionPolicyProvider` owns immutable policy inputs and a shared
in-process gate. Its explicit test-only replacement method uses an expected input
digest and rejects policy regression or equal-revision policy forks. Replacements
on another thread wait while an ingestion holds the gate through commit. Same-
thread test mutations are detected by generation/input rechecks and roll back
before commit, or report uncertainty after commit.

SQLite serializes writers across processes, but separate in-memory providers are
not a distributed policy authority. This milestone does not establish global
revocation coordination or authenticate newly supplied policy pins. Production
must supply a real shared freshness/authorization mechanism; a callback or an old
independently instantiated provider is not sufficient proof of current policy.

The local store rejects observed regressions and inconsistent records under normal
operation. A privileged restore of a complete older database and matching old
inputs can remain internally valid; a test demonstrates that limitation. External
rollback detection and fresh independent state evidence remain necessary.

## Fault testing

The suite uses actual SQLite transactions and spawned processes that exit after
lock acquisition, receipt insertion, image writes, immediately before commit, and
after commit. It checks original-receipt recovery, serialized fork decisions,
bounded busy errors, provider-replacement ordering, strict schemas, signature
replay, malformed projections, size/capacity limits and read-only audit snapshots.

These are process-failure tests around logical transaction boundaries. They do not
claim to interrupt a specific OS WAL-write instruction or prove storage hardware's
power-loss behavior. WAL/FULL durability remains subject to SQLite, OS and storage
guarantees. No private keys are persisted; ephemeral test signing occurs outside
the storage adapter.
