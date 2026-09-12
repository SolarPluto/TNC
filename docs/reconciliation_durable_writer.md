# Transactional temporary checkpoint authority

`TestCheckpointAuthorityWriter` extends the test-only inspection store with
`submit` and `replace_policy_for_testing`. The separate loader retains its read-only
API. No schema migration or runtime/review database changes are required.

Each call opens the existing authority file with mode=rw, FULL synchronous mode,
foreign keys and a bounded busy timeout, then acquires BEGIN IMMEDIATE. It reloads
and validates canonical state and projections before evaluating the transition.
New acceptance rows and canonical state updates are validated again and committed
as one transaction. Permission changes use that same SQLite serialization gate.

SUBMIT invokes the existing pure simulation with exact synthetic caller and batch
records. New requests require matching predecessor revision and envelope digest.
Accepted retries require current recovery rights and exact request bytes; they
return original persisted acceptance bytes without a new candidate, acceptance
time, or revision. A RECOVER-shaped command is also accepted by this method.
Historical recovery never changes the current head or publishes an envelope.

Policy replacement is a host-fixture capability, not an authenticated administrative
endpoint. Changed policy requires a higher revision and exact expected current
revision/digest. Identical-current policy is a no-op only when that same current CAS
pair is supplied. A stale original pair returns POLICY_CONFLICT, including after a
lost policy acknowledgement. The host may inspect current state and explicitly
reconcile; there is no persisted policy-operation retry journal. Existing acceptance
history and its policy snapshots are preserved, but policy changes with no acceptance
between them are not retained as a complete administrative history.

Inputs use a supplied synthetic time and caller evidence; there is no live credential
or lease recheck. The stored policy is current at SQLite serialization. Production
authentication, independent batch approval, signatures, fresh external checkpoints,
process control, and filesystem publication remain excluded. Separate authority and
runtime files preserve the cross-store gap; this adapter never advances runtime
checkpoints or establishes whole-store rollback protection.

Results carry only a status, optional permitted acceptance bytes, and synthetic/audit
markers. Denials do not disclose store contents or raw SQLite messages. Failures once
COMMIT is attempted return OUTCOME_UNKNOWN; exact submission retry resolves whether
an acceptance exists. Earlier failures roll back. Busy errors fail without cached
state fallback. The test harness uses private hooks, spawned processes and events
for transaction collisions, policy ordering, and abrupt exits around commit.
Process-exit recovery is not a guarantee about physical power-loss durability.
