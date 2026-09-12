# External witness transactions with a synthetic provider

`external_witness_writer.py` adds `TestExternalWitnessWriter` over an already
provisioned Phase 1 database. No schema migration, production authorization,
signature generation, network endpoint or checkpoint publication is introduced.
The existing store remains the read-only audit and explicit creation API.

## API

```python
writer = TestExternalWitnessWriter(
    path, trusted_initial=initial, clock=clock,
    busy_timeout=1, provider_timeout=1,
)
result = writer.submit(request, provider=provider, evidence=lineage_evidence)
```

Requests and new-operation lineage evidence are existing frozen simulation records.
The initial record is independently supplied and must match the existing store.
`TestWitnessPolicyProvider` supplies immutable `TestWitnessProviderInputs` containing
a synthetic policy and request-bound caller evidence. That evidence is a host test
fixture, not proof of possession, a live mTLS session or a production credential.

Success returns frozen `WitnessWriteResult` with `SUCCESS` or `HISTORICAL_RECEIPT`,
original `receipt_bytes`, audit_only=True and signature_verified=False. Denials and
storage errors raise `WitnessWriterError` with a fixed reason code and no stored
payload, SQL message or filesystem path. There is no generic SQL callback API.

## Locking and provider replacement

Ordinary opening uses mode=rw, never implicit creation. Each submission configures
FULL synchronization, foreign keys and trusted_schema=OFF, acquires BEGIN IMMEDIATE,
then acquires the provider gate. Both SQLite and provider acquisition timeouts must
be finite numbers between zero and five seconds; they bound lock acquisition, not
the total duration of replay or a filesystem operation.

The provider owns an RLock, immutable inputs and a generation. Replacement compares
the full expected input digest, fixes context, and rejects policy regression or
equal-revision policy forks. The caller's policy digest must match the supplied
policy. A new request requires appropriately request-bound synthetic caller input.

Replacement takes only the provider gate and never SQLite. The writer holds that
gate through commit and the return guard. Separate threads wait for the current
lease; reentrant test changes are detected by generation and input-digest checks.
Expiry remains checked while locks are held. Timeout releases acquired resources.

This coordinates one shared provider instance only. Separate processes in the
tests use consistent synthetic fixtures and rely on SQLite for acceptance ordering;
their independent providers do not implement shared policy distribution. Rejected
requests, provider replacements and historical retries do not persist a new policy
floor. Accepted receipts preserve the existing floor. Current independently supplied
provider inputs remain necessary after restart, including for unseen revocations.

## New acceptance

Under both locks, read the clock and check current context/caller authorization
before loading operation history. Reload and validate the full Phase 1 image, then
invoke the existing pure `evaluate_witness_advance` with the captured inputs.
The writer does not duplicate CAS, epoch, lineage or permission rules.

On SUCCESS, append one immutable receipt and update image/head projections inside
the same transaction. Preserve all prior receipts and the initial record. The
resulting image is reloaded and exactly compared through Phase 1 validation.

Before commitment, recheck clock progression, provider generation/input identity,
and the pure decision against the retained **pre-append image**. This retains new
operation semantics: advance permission is required, recovery permission is not,
and request/lineage expiry cannot be bypassed through the historical retry branch.
Keep the original accepted_at and receipt bytes; a later successful re-evaluation
does not rewrite the acceptance timestamp or claim that a later clock was stored.

Fetch the receipt bytes from SQLite and compare them with the original proposal.
Immediately before COMMIT, repeat the time/provider/pure guard. After commit, a
return guard repeats those same new-operation semantics. Once commitment has been
attempted, any exception preventing confirmed return becomes OUTCOME_UNKNOWN.
No rollback or failed acceptance is claimed in that case.

## Historical retry

The pure evaluator checks current recovery permission, exact owner, request ID and
complete canonical request. Sequence or digest coincidence alone is insufficient.
Original lineage input is not interpreted on this path; the validated stored
receipt already preserves historical evidence. Original request and evidence expiry
do not prevent recovery, but current caller and policy validity remain required.

Fetch and compare the exact stored receipt bytes. Recheck recovery authorization
against the pre-existing image, release the read-only transaction with ROLLBACK,
and perform the return guard while still holding the provider gate. No application
table, head, timestamp, receipt or sequence changes. An old receipt can be recovered
after later advances or at capacity without publishing it as current state.

A retry-only failure is reported as its actual failure, not OUTCOME_UNKNOWN for a
new acceptance that was never attempted. Current recovery revocation can deny
access to a durable historical receipt without deleting that receipt.

## Failure and integrity boundaries

Pure denial codes are preserved, including UNAUTHORIZED_CLIENT, OPERATION_CONFLICT,
CAS_MISMATCH, STATE_FORK, INDETERMINATE, INVALID_LINEAGE and CAPACITY_EXCEEDED.
Additional fixed codes include INVALID_INPUT, INVALID_WITNESS_STORE, STORE_BUSY,
POLICY_BUSY, POLICY_CHANGED, POLICY_CONFLICT, POLICY_REGRESSION, CLOCK_INVALID,
CLOCK_REGRESSION and OUTCOME_UNKNOWN.

Missing/malformed storage fails closed. An exception before commitment rolls back
the active transaction. Connections and gates are released on failures. A successful
commit followed by a lost acknowledgement leaves the complete receipt/image/head
group available for an authorized exact retry after restart.

The existing 64-receipt and 1 MiB image limits, strict schema and projection bounds
remain intact. No automatic compaction, repair, sidecar cleanup, cross-store lock,
rollback to a prior head or external state promotion occurs.

WAL/FULL durability remains dependent on SQLite, OS and hardware behavior. The
witness's own whole-database restoration remains outside local detection. Public
audit records, synthetic policies and byte-exact receipts are not execution tokens.

## Tests

The suite covers new acceptance and exact original-byte recovery, advance-only and
recovery-only permissions, authorization before lookup, cross-owner denial,
request-ID conflicts, stale CAS, forks, pre-append expiry enforcement, independent
caller/policy/lineage expiry, preserved timestamps, provider replacement ordering,
clock regression, lock timeouts, policy CAS/floors, current revocation and missing/
corrupt stores. Historical retries are traced to confirm zero application writes.

Spawned processes exit after lock acquisition, receipt insertion, image writes,
immediately before commit and after commit. Restart verifies rollback or original
receipt recovery. Barrier-controlled competing processes exercise distinct stale
requests and exact duplicates. Tests also cover capacity, persisted policy floors,
FULL synchronization and actual audit snapshots during an uncommitted submission.

These are logical transaction-boundary process tests, not interruption inside an
OS WAL instruction or certification of power-loss immunity. Live signing, protected
provider acquisition, persistent policy administration, witness networking, client
reconciliation and runtime activation remain separate milestones.
