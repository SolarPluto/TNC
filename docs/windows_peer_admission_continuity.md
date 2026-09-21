# Native Windows Peer Admission Continuity Contract

## Scope and decision

This document defines the v1 continuity contract required before `ADMITTED` may become reachable in the native Windows peer-admission gate.

The central decision is:

> A positive admission is non-transferable and live-continuity-bound. A frozen admission result or audit record is evidence that an evaluation occurred; neither is a bearer token and neither authorizes later privileged use by itself.

The continuity object is a separate runtime artifact with a shorter lifetime than the durable audit records. It exists to bridge the gap between evaluation time and privileged use time without pretending that a frozen record can prove the peer is still the same live process and connection.

This contract deliberately precedes implementation. The expected implementation sequence is:

1. continuity object and use-time revalidation, without an `ADMITTED` status;
2. `ADMITTED` integration only after the continuity artifact exists and its invariants are tested.

## Why a separate continuity object is required

The existing `OwnedProcessLease` has an intentionally bounded acquisition lifecycle. Calling `finish()` produces a frozen `ProcessLeaseAudit` and releases the lease's native handle ownership. That is correct for durable audit evidence but insufficient for use-time authorization.

Three possible meanings of "lease-bound admission" are not equivalent:

- **Bind only to `ProcessLeaseAudit`: rejected.** The audit is inert and durable. It cannot prove that the underlying process instance remains live or that the original connection remains the active connection at a later use point.
- **Keep `OwnedProcessLease` live after `finish()`: rejected.** This changes `finish()` from an ownership-release boundary and conflates durable audit production with transient authorization lifetime.
- **Create a separate continuity object: required.** The audit remains durable evidence; the continuity object owns the transient native resources required to revalidate the same process/connection at use time.

The continuity object must acquire its independent native ownership **before** `OwnedProcessLease.finish()` releases the original lease ownership. The implementation may use a safe ownership transfer or duplicated native handle(s), but the resulting continuity object must have independent, exception-safe ownership. Merely copying PID, creation time, operation IDs, or audit fields is not continuity.

## Artifact roles

V1 has three distinct artifacts with deliberately different semantics:

| Artifact | Lifetime | Serializable | Meaning |
| --- | --- | --- | --- |
| `ProcessLeaseAudit`, peer audit, and `PipePeerAdmissionEvidence` | Durable | Yes | Frozen evidence about what was established during evaluation. |
| `NativePeerAdmissionResult` | Evaluation record | May be serialized for audit | Coarse policy result. Even when `ADMITTED`, it is not a capability and cannot authorize use by itself. |
| Admission continuity object | Live transaction-scoped | **No** | Runtime proof carrier that owns the native continuity resources and can be revalidated before each privileged use. |

The continuity object must not be reconstructible from serialized IDs or from a saved `ADMITTED` result. A caller cannot regain authority by deserializing an old result.

The persistent audit may record that admission occurred and may record the immutable continuity binding identifiers for diagnosis, but replaying that audit must never recreate live authority.

## Binding identity

The continuity object must be created from the same live connection/process instance used by the admission producer. At minimum its immutable binding view must correspond to the producer evidence fields:

- `connection_operation_id`;
- `pipe_lease_id`;
- `process_lease_operation_id`;
- `process_pid`;
- `process_creation_filetime`.

Those fields are correlation metadata, not the authority themselves. Authority comes from the continuity object's live native ownership plus successful use-time revalidation.

Creation must fail closed if the object cannot establish independent ownership before the original lease is finished. An implementation must not silently fall back to audit-only binding and still permit `ADMITTED`.

## Native ownership

The continuity object must own the minimum native resources needed to establish continued identity and connection validity. V1 requires, at minimum:

- a process-instance handle whose lifetime is independent of the finished `OwnedProcessLease`, with only the rights needed for liveness/identity revalidation;
- the admitted connected pipe endpoint, or an ownership form that can prove the same connection remains the use target.

The pipe-client token handle is **not** retained for the whole transaction. AppContainer classification remains a capture-time fact: the exact pipe-client thread token is captured, the server reverts, the token is classified and snapshotted, and that token handle is closed. Revalidation must not substitute a later process PRIMARY token or a token captured from another connection.

The continuity object's resources must be closed exactly once. Closure is terminal: a closed continuity object cannot be reactivated or replaced from its serialized binding fields.

## Five continuity axes

### 1. Lifetime

Continuity begins only after the continuity object has successfully acquired independent native ownership from the live admission connection/process instance. It ends on explicit close, transaction completion, or any invalidation condition.

The object is transaction-scoped, not account-scoped, process-scoped across reconnects, or reusable for a second pipe connection.

### 2. Artifact semantics

`ADMITTED` is a policy decision, not an authorization token.

The caller may proceed to a privileged operation only while it holds both:

- the positive admission result produced for this evaluation; and
- the live continuity object paired with that result.

The result alone is inert. The continuity object alone is also insufficient: it carries continuity, not proof that the full admission policy passed.

### 3. Grants and signing axes

The initial `ADMITTED / ADMISSION_REQUIREMENTS_MET` result means only that peer admission requirements were satisfied.

For this first positive state:

- `admission_granted = True`;
- `authorization_granted = False`;
- `grants_evaluated = False`;
- `signing_evaluated = False`.

Admission therefore does not smuggle grant evaluation, authorization, custody, or signing into the peer gate. Those remain separate phases with their own contracts.

### 4. Invalidation

Continuity becomes invalid when any required live invariant can no longer be established. V1 invalidation includes at least:

- the retained process instance has exited or the retained process handle is unusable;
- the admitted pipe connection is closed, disconnected, replaced, or no longer the use target;
- immutable binding metadata presented with the use request does not match the continuity object;
- the admission policy revision no longer matches the revision under which admission was evaluated;
- the current revocation view says the admission/peer/transaction is revoked;
- the admission/evidence freshness deadline has expired;
- continuity ownership has been explicitly closed or released;
- a native revalidation query fails in a way that prevents proof of continuity.

Invalidation is fail-closed and terminal for that continuity object. A new connection requires a new capture, evidence set, continuity object, and admission evaluation.

Revocation is effective at the next privileged-use boundary. A revocation observed after an irreversible native operation has already crossed its authorization boundary cannot retroactively undo that completed side effect; callers must therefore revalidate immediately before each privileged operation.

### 5. Revalidation contract

V1 uses **revalidation at use**, not full re-evaluation at use.

A privileged consumer must call the continuity revalidation function immediately before crossing each privileged-use boundary. Revalidation checks the facts that can change after evaluation while preserving the capture-time facts that cannot be meaningfully reacquired on the original connection.

At minimum, use-time revalidation must verify:

1. the continuity object is open and internally valid;
2. the retained process instance is still live;
3. the intended use targets the same admitted pipe connection;
4. the supplied immutable binding identity matches the continuity object's binding;
5. the current policy revision is the admitted revision;
6. the current time remains within the admitted freshness/expiry bound;
7. the current revocation view does not invalidate the admission.

Revalidation must not re-query the original pipe-client token after the capture window. The original token classification is immutable evidence bound to the connection; continuity protects the identity of the connection/process from evaluation through use.

A failure to prove any required item yields a use-time continuity failure. The coarse reason is `CONTINUITY_INVALID`; implementations may retain more specific diagnostic metadata internally or in a separate audit record, but no failure may degrade into permission to proceed.

## Evaluation phase versus use phase

The two phases have different outputs and must not be conflated.

### Evaluation phase

`evaluate_native_peer_admission` remains the sole producer of `NativePeerAdmissionResult`.

Before continuity integration, an otherwise successful evaluation returns:

`INDETERMINATE / PEER_ADMISSION_NOT_IMPLEMENTED`.

After continuity integration, that path may become:

`ADMITTED / ADMISSION_REQUIREMENTS_MET`.

The positive pair is legal only when a live continuity object has already been established for the same producer binding and is available to the caller as part of the same in-process transaction.

Failure to establish required continuity at evaluation time must remain non-admitted. The implementation should use a distinct fail-closed reason such as `ADMISSION_CONTINUITY_UNAVAILABLE` rather than misreporting an identity denial or pretending the frozen audit provides continuity.

### Use phase

Use-time revalidation consumes the existing continuity object. It does **not** mint a new `ADMITTED` result and does not regenerate the original evidence chain.

A successful use-time check means only "the continuity requirements for this already-admitted transaction still hold now." A failed check returns `CONTINUITY_INVALID` and the privileged operation must not begin.

The use-time result should be a separate type from `NativePeerAdmissionResult` so an evaluation decision cannot be confused with a continuity check.

## Single-producer rule for ADMITTED

The public model must not permit arbitrary callers to manufacture an authoritative positive admission.

The implementation must ensure that `evaluate_native_peer_admission` is the only production path that can synthesize `ADMITTED / ADMISSION_REQUIREMENTS_MET`. Acceptable enforcement mechanisms include a private positive-result constructor/factory or an equivalent module-internal capability that cannot be reconstructed from serialized fields.

A validator that only checks the string pair is insufficient by itself: if any caller can instantiate the model with those two strings, the object is forgeable as a positive-looking record. The design must distinguish "schema-valid positive-looking data" from "an authoritative result emitted by the evaluator."

Even an authoritative `ADMITTED` result remains non-transferable: use still requires the paired live continuity object.

## Policy revision and revocation view

Admission must bind to a stable policy revision identifier. Revalidation compares that captured revision with the current revision before use. A policy change invalidates the continuity object rather than silently applying a different policy to an old admission.

Revocation must be checked through a current trusted view at use time. This document does not prescribe the storage implementation, but the interface must make freshness and failure behavior explicit. An unavailable revocation check is fail-closed.

A later design may distinguish revocation classes or permit narrowly defined policy changes that do not invalidate existing admissions. V1 does not: any relevant revision mismatch invalidates continuity.

## Concurrency and transfer

The continuity object is an in-process owned resource, not a serialized capability.

It may move between threads after construction if its native handles and implementation are thread-safe, but it must not cross a process boundary by serialization, IPC, database storage, or reconstruction from identifiers. If ownership is transferred between components in the same process, that transfer must preserve exactly-one live owner or another explicit ownership discipline that prevents double close and use-after-close.

Concurrent privileged uses require independent revalidation at each use boundary. Closing or invalidating the continuity object races conservatively: once closure/invalidation is observed, no new privileged operation may start.

## Required implementation tests

The continuity implementation PR must, before `ADMITTED` exists, pin at least:

- continuity ownership is acquired before `OwnedProcessLease.finish()` releases the original lease handle;
- the continuity object remains capable of process-liveness revalidation after the original lease is finished;
- process exit causes fail-closed `CONTINUITY_INVALID`;
- pipe disconnect/close causes fail-closed `CONTINUITY_INVALID`;
- binding substitution between connections/process instances is rejected;
- policy revision mismatch is rejected;
- expiry is rejected;
- revocation is rejected and revocation-check failure is fail-closed;
- explicit close is terminal and native resources close exactly once;
- the object cannot be serialized into an authorization capability;
- no revalidation path reacquires or substitutes a process PRIMARY token for the original pipe-token classification.

The later ADMITTED integration PR must pin:

- `PEER_ADMISSION_NOT_IMPLEMENTED` is replaced only on the all-requirements-passed path;
- the sole positive pair is `ADMITTED / ADMISSION_REQUIREMENTS_MET`;
- positive admission sets `admission_granted=True` while leaving authorization/grants/signing unevaluated;
- no positive result is emitted without a matching live continuity object;
- the serialized result alone cannot authorize a use;
- every privileged-use integration performs continuity revalidation immediately before use.

## Non-goals

This contract does not:

- turn peer admission into general authorization;
- define grant selection or signing policy;
- retain the pipe-client token for transaction lifetime;
- permit a saved `ADMITTED` record to be replayed;
- require a new pipe-token capture at every use;
- define cross-process transfer of continuity;
- make `ProcessLeaseAudit` itself a live lease;
- make `OwnedProcessLease.finish()` retain native resources.

Those boundaries are intentional. The durable evidence answers what was established at evaluation time; the continuity object answers whether the same admitted transaction is still live at the moment of use.
