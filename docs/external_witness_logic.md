# External witness: pure synthetic simulation

`external_witness_logic.py` defines frozen `tnc-external-witness-v1` records
and deterministic proposals. It does not authenticate signatures, open stores,
contact a witness, consume challenges, mint execution authority, or change any
existing production route. Every result is audit-only and signature_verified=False.

## Scope and independent inputs

The context binds deployment ID, store-instance ID, local store ID and independently
pinned bootstrap-anchor digest. The initial witness record is also supplied
independently on each replay. Neither is discovered from client-provided history.

The protected target is one distribution store's **accepted ingestion/receipt
history frontier**. Its local sequence and history digest cover canonical accepted
history, not the whole SQLite file or mutable checked_at timestamps. It carries
checkpoint, epoch, observation-trust and policy bindings. No client high-water
database is combined into an implicitly atomic aggregate. Mapping actual durable
store records to this frontier remains a future adapter contract.

Witness acceptance sequence, local history sequence, checkpoint revision, epoch
counter, observation trust revision and policy revision remain distinct. Policy-only
local ingestions can advance local and witness sequences with the checkpoint fixed.

Synthetic caller, policy, lineage and observation evidence are explicit trusted
harness inputs. A client signature field or a boolean would not establish their
authenticity. Historical receipts retain these inputs and replay their bindings;
this does not turn an attacker-supplied synthetic policy into real authorization.
The fixture provider must independently supply current policy. An unseen revocation
cannot be detected from an old internally consistent set of fixture inputs.

## Canonical and bounded records

Existing canonical JSON decoding rejects duplicate keys, noncanonical bytes, extra
fields and non-finite numbers. Counters and UTC epoch seconds are exact signed-64-bit
nonnegative integers; positive counters exclude zero. Identifiers and SHA-256 values
reuse bounded project contracts. Validity windows are positive and at most 300 seconds.
Histories contain at most 64 receipts; canonical images are capped at 1 MiB and other
records at 256 KiB when checked. There is no pruning or automatic provisioning.

Digests use SHA256(b"TNC-WITNESS-BINDING-v1:" + canonical_bytes(record)). These are
simulation binding digests, not signatures or production signing preimages.

## Advancement and retries

`evaluate_witness_advance` checks current synthetic client permissions before
looking up request IDs or returning receipts. Requests bind exact context, owner,
request ID, predecessor witness sequence and full predecessor state digest, target
head and positive time bounds. Request IDs are idempotency keys; full canonical
request equality is required for recovery. Another principal cannot recover a
receipt merely by knowing its ID.

A new acceptance requires direct witness and local-history successors, exact CAS,
and independently supplied synthetic lineage evidence bound to the entire request.
Checkpoint revisions cannot regress or skip; equal revisions require equal checkpoint
digests. Trust/policy revisions cannot regress, and equal revisions bind exact digests.
Epoch changes require a direct epoch successor, changed epoch ID, checkpoint advance
and explicit synthetic root-transition evidence. Epoch changes never reset counters.

Each accepted receipt preserves policy/caller/lineage evidence and resulting state.
Replay checks authority at historical acceptance time and enforces policy revision
floors. Equal policy revisions with different policy records fail closed.

Exact historical retries require current recovery permission but do not require
still-valid original request or lineage evidence. They return the original receipt
without proposing state replacement, consuming sequence numbers or publishing a head.
An old competing advance is CAS_MISMATCH, not proof that storage was rolled back.

Pure evaluation is not atomic persistence: two calls can propose conflicting
successors from the same image. The simulator applies one and re-evaluates the other
against it. A future witness service must implement this ordering durably under a
single transactional CAS boundary, with current authorization in that boundary.

## Fresh observations and comparison

`observe_witness_current` requires current observation permission and a retained
request containing a mandatory 64-hex challenge. Its synthetic response binds the
exact request digest, principal, challenge, current full state and bounded times.
Challenge unpredictability, generation, single-use tracking, issuer trust and actual
signature verification are not implemented.

`compare_witness_observation` requires independent synthetic evidence pinning the
exact observation and request. It never accepts a historical receipt as a current
observation. Timeout, missing evidence, stale windows or context mismatches yield
INDETERMINATE. All comparisons are audit findings, never execution permissions.

| Relationship | Outcome |
| --- | --- |
| Exact local and freshly observed witness state | MATCHED |
| Local direct extension awaiting witness acceptance | LOCAL_EXTENSION_PENDING |
| Witness sequence ahead of locally retained acceptance | ROLLBACK_OR_STATE_LOSS |
| Same witness sequence with inconsistent local state | STATE_FORK |
| Local claims witness acceptance beyond observed witness | INDETERMINATE |

Local extension classification is pending reconciliation, not proof authorizing
advancement. The advance path must still validate synthetic lineage and CAS.

If a local commit reaches N+1 while the witness stays at N, restoring the local
store to N is indistinguishable from never committing N+1. A test preserves that
limitation explicitly. If the witness accepted N+1, a fresh observation can expose
restoration to N as rollback or state loss. A MATCHED result cannot prove that an
unwitnessed commit never existed.

Future witness-dependent operations must remain blocked pending reconciliation;
no such operational gate is enabled by this milestone. Witness independence,
durable monotonicity, authenticated freshness, authorization, non-equivocation,
key custody and protected bootstrap provisioning remain external requirements.
There are no automatic repair, state regression, audit-erasure or quarantine actions.

## Tests

The pure suite covers canonical bounds, immutable proposals, permission and context
checks, policy floors, lineage and epoch rules, historical replay, deterministic
CAS collisions, exact retry recovery after later advances and expiry, capacity,
fresh challenge bindings, tampering, timeouts and both witnessed and unwitnessed
rollback scenarios. An explicit side-effect guard blocks file/socket/SQLite and
wall-clock calls during evaluation. No process or power-loss durability is claimed.
