# Native Windows Peer Admission Continuity Contract

## Scope and decision

This document defines the v1 continuity contract required before `ADMITTED` may become reachable in the native Windows peer-admission gate.

The central decision is:

> A positive admission is non-transferable and live-continuity-bound. A frozen admission result or audit record is evidence that an evaluation occurred; neither is a bearer token and neither authorizes later privileged use by itself.

The continuity object is a separate runtime artifact with a shorter lifetime than the durable audit records. It exists to bridge the gap between evaluation time and privileged use time without pretending that a frozen record can prove the peer is still the same live process and connection.

The continuity object and use-time revalidation described here are implemented as of PR #40. The remaining implementation sequence is:

1. preserve the continuity invariants and API boundary in this document;
2. integrate `ADMITTED` only under the separate authority contract after its additional prerequisites and tests are satisfied.

## Why a separate continuity object is required

The existing `OwnedProcessLease` has an intentionally bounded acquisition lifecycle. Calling `finish()` produces a frozen `ProcessLeaseAudit` and releases the lease's native handle ownership. That is correct for durable audit evidence but insufficient for use-time authorization.

Three possible meanings of "lease-bound admission" are not equivalent:

- **Bind only to `ProcessLeaseAudit`: rejected.** The audit is inert and durable. It cannot prove that the underlying process instance remains live or that the original connection remains the active connection at a later use point.
- **Keep `OwnedProcessLease` live after `finish()`: rejected.** This changes `finish()` from an ownership-release boundary and conflates durable audit production with transient authorization lifetime.
- **Create a separate continuity object: required.** The audit remains durable evidence; the continuity object owns the transient native resources required to revalidate the same process/connection at use time.

The continuity object must acquire its independent native ownership **before** `OwnedProcessLease.finish()` releases the original lease ownership.

V1 chooses an explicit two-phase lease API rather than a callback inside `finish()` or a shared-handle handoff:

1. while the original `OwnedProcessLease` is still live, call a one-shot `prepare_continuity(...)` operation on that lease;
2. `prepare_continuity(...)` opens a **new** process handle with the minimum continuity rights against the pinned PID while the original retained handle still prevents that process instance from disappearing and its PID from being reused;
3. before returning, it verifies the new handle's process ID and creation FILETIME against the lease pin, rechecks pipe-client PID/endpoint identity, and establishes the continuity object's independent endpoint claim;
4. only after `prepare_continuity(...)` succeeds may the caller invoke `OwnedProcessLease.finish()`; `finish()` keeps its existing semantics and releases only the original lease ownership;
5. after `finish()`, the continuity object alone owns the independent process handle and continuity claim until terminal close/invalidation.

`prepare_continuity(...)` is not a general callback hook and must not execute caller-supplied code while the lease is live. Native acquisition uses the exact trusted native API boundary. The second process open requests exactly `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` (`0x00101000`), non-inheritable — the same rights as the current process lease. `PROCESS_QUERY_LIMITED_INFORMATION` is sufficient for `GetProcessId` and `GetProcessTimes`; `SYNCHRONIZE` is required for zero-time `WaitForSingleObject` liveness checks. `PROCESS_QUERY_INFORMATION`, `PROCESS_ALL_ACCESS`, and any other broader rights are forbidden.

The fresh `OpenProcess` performed by `prepare_continuity(...)` is the **sole permitted second open** for this process instance: it occurs while the original retained handle is still live, is immediately checked against the pinned PID/creation FILETIME and pipe PID, and is never retried with broader rights. No process reopen is permitted after `prepare_continuity(...)` returns or after `finish()`. Failure to prepare continuity leaves no positive admission path; the original lease must still be finished or aborted through its ordinary cleanup contract.

Merely copying PID, creation time, operation IDs, or audit fields is not continuity.

## Artifact roles

V1 has three distinct artifact roles with deliberately different semantics:

| Artifact | Lifetime | Serializable | Meaning |
| --- | --- | --- | --- |
| `ProcessLeaseAudit`, peer audit, and `PipePeerAdmissionEvidence` | Durable | Yes | Frozen evidence about what was established during evaluation. |
| Durable admission audit projection | Durable | Yes | Records that an admission evaluation occurred, including an `ADMITTED` outcome when applicable, but is never authority to act. |
| Authoritative positive admission paired with the admission-continuity object | Live transaction-scoped | **No** | In-process authority to proceed, valid only while paired with the live continuity resources and only after successful use-time revalidation. |

The current serializable `NativePeerAdmissionResult` model must not simply gain a replayable authoritative `ADMITTED` value. Before the positive path lands, implementation must split durable audit from live authority.

V1 chooses a structural split:

- `PeerAdmissionAuditRecord` is the frozen Pydantic audit projection. It may record the historical evaluation status/reason, but it contains no live continuity reference, use token, grant, signing, custody, or authorization capability and is never accepted by a privileged decision path.
- the authoritative positive admission is a plain in-process live object, not a Pydantic `Model`. It uses a closed runtime type (for example `__slots__`), holds a strong reference to the exact live admission-continuity object, rejects pickling/reduction, exposes no JSON/model-dump reconstruction surface, and is created only by the evaluator's private positive constructor.

The authoritative positive artifact therefore cannot exist without the live continuity object and cannot be reconstructed from serialized state. Both the authoritative positive artifact and the continuity-use token must implement `__reduce__` and `__reduce_ex__` that raise `TypeError`; the continuity object itself must do the same. Each live object also owns a `threading.Lock`, which is intentionally non-picklable and provides the synchronization primitive for lifecycle/token state. Tests must assert that `pickle.dumps(...)` fails for all three live artifact types. No public validation/deserialization path may manufacture authoritative `ADMITTED` from bytes, JSON, database rows, IPC payloads, pickle, or copied identifiers.

The admission-continuity object likewise must not be reconstructible from serialized IDs or from a saved audit record. A caller cannot regain authority by deserializing an old result.

The persistent admission audit may record that admission occurred and may record immutable continuity binding identifiers for diagnosis, but replaying that audit must never recreate live authority.

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

## Authority adoption API boundary

The authority contract in `docs/windows_peer_admission_authority_v1.md` owns the
positive-admission semantics. This document owns the continuity object's API and
lifecycle boundary.

Before authoritative admission adopts a continuity object:

- the orchestrator owns the continuity reference;
- `close()` is a public explicit cleanup operation;
- the orchestrator must close continuity on denied/indeterminate evaluation or other
  paths that do not transfer ownership.

Use-token minting is an internal continuity primitive. Production callers do not
treat bare continuity as authority; after authority integration the underlying mint
entry point is internal (for example `_mint_use_token(...)`) and enforces the same
allowed-`ContinuityUseKind` restriction as the authoritative admission.

Successful authority adoption is one-shot and transfers production lifecycle/use
ownership to the exact authoritative admission object. Continuity is `IDLE` before
adoption and terminal `ADOPTED` afterward. Public mutating lifecycle/use methods
reject direct external mutation once `ADOPTED`; authority-bound private operations
are the production path. V1 relies on the synchronous single-threaded evaluation
ownership contract for adoption and introduces no observable intermediate
`ADOPTING` state.

The authority's explicit `close()`/context-manager path performs the continuity
release after adoption. Garbage collection is never a native-resource cleanup
mechanism.

## Five continuity axes

### 1. Lifetime

Continuity begins only after the continuity object has successfully acquired independent native ownership from the live admission connection/process instance. It ends on explicit close, transaction completion, or any invalidation condition.

The object is transaction-scoped, not account-scoped, process-scoped across reconnects, or reusable for a second pipe connection.

### 2. Artifact semantics

`ADMITTED` is a policy decision, not an authorization token.

The caller may proceed to a privileged operation only while it holds the authoritative in-process positive admission artifact paired with the live continuity object for this evaluation.

A durable audit projection is inert and cannot substitute for that live pair. The continuity object alone is also insufficient: it carries continuity, not proof that the full admission policy passed.

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
- the trusted current admission-policy snapshot no longer matches the revision and canonical digest captured at evaluation;
- the admission/evidence freshness deadline has expired;
- continuity ownership has been explicitly closed or released;
- a native revalidation query fails in a way that prevents proof of continuity.

Invalidation is fail-closed and terminal for that continuity object. A new connection requires a new capture, evidence set, continuity object, and admission evaluation.

Peer-admission revocation is not part of initial continuity v1 because no authoritative source exists yet. A later revocation contract must define its own use-boundary semantics; it must not be inferred from the review store or from caller input.

### 5. Revalidation contract

V1 uses **revalidation at use**, not full re-evaluation at use, and does not rely on callers remembering to invoke a boolean check.

The continuity object exposes a gate operation that revalidates continuity and, on success, mints exactly one **single-use, non-serializable continuity-use token**.

The token contract is fixed as follows:

- **Clock/bound:** token time is measured only with the continuity object's monotonic clock. `MAX_CONTINUITY_USE_TOKEN_MS = 1000`; `use_deadline = min(minted_tick + 1000, continuity_deadline, operation_deadline)`. Wall clock is not consulted for token age. A token at or past `use_deadline` is invalid and consumed as a failure. This is point-in-time capability authorization: successful token consumption authorizes that specific operation to begin; later continuity expiry does not retroactively cancel the already-started operation.
- **Operation binding:** the token carries an exact host-issued `operation_id` plus a closed `ContinuityUseKind` enum owned by the continuity module. Callers cannot supply arbitrary free-form operation-kind strings. The integration PR that introduces a privileged consumer must add its explicit enum member and require a matching kind at consumption.
- **Single use:** consumption atomically changes the token from `UNUSED` to `CONSUMED`; any second consume fails closed.
- **Concurrency:** each continuity object permits at most one outstanding unconsumed token. Mint and consume run under the continuity object's `threading.Lock`. A concurrent mint while a token is outstanding fails closed with `USE_TOKEN_OUTSTANDING`; it does not mint a second token. This intentionally serializes privileged-use authorization per continuity object: two operations on the same admitted connection cannot both hold valid use tokens concurrently. After successful consumption, a later operation may request a new token only after fresh revalidation.

The token is also bound by object identity to the exact continuity object that minted it. It cannot be refreshed or recreated from serialized fields.

Every privileged consumer covered by this admission contract must require the exact continuity-use-token type as an input and consume it exactly once before beginning the privileged operation. A durable audit record, the authoritative positive admission object by itself, a binding-ID tuple, or a prior successful revalidation is not accepted as a substitute. This creates an enforceable gate without running arbitrary caller callbacks while native continuity resources are live.

The gate revalidation checks the facts that can change after evaluation while preserving capture-time facts that cannot be meaningfully reacquired on the original connection. At minimum it must verify:

1. the continuity object is open and internally valid;
2. the retained process instance is still live, established by `WaitForSingleObject(process_handle, 0) == WAIT_TIMEOUT`; `WAIT_OBJECT_0` means the process exited and invalidates continuity, while `WAIT_FAILED` or any unexpected wait result is an inability to prove liveness and also invalidates continuity;
3. the intended use targets the same admitted pipe connection;
4. the supplied immutable binding identity matches the continuity object's binding;
5. the current trusted policy snapshot matches the admitted policy snapshot;
6. the current time remains within the admitted freshness/expiry bound.

Revalidation must not re-query the original pipe-client token after the capture window. The original token classification is immutable evidence bound to the connection; continuity protects the identity of the connection/process from evaluation through use.

A failure to prove any required item yields a use-time continuity failure. The coarse reason is `CONTINUITY_INVALID`; implementations may retain more specific diagnostic metadata internally or in a separate audit record, but no failure may degrade into permission to proceed. A failed gate call terminally invalidates the continuity object.

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

A successful use-time gate means only "the continuity requirements for this already-admitted transaction hold now for this specific imminent operation" and returns one continuity-use token. A failed gate returns `CONTINUITY_INVALID`, terminally invalidates that continuity object, and the privileged operation must not begin. It does not rewrite the durable evaluation audit: "admission passed at evaluation time" and "continuity failed at use time" are separate facts.

The continuity-use token is a separate live type from the evaluation result/audit, is single-use, and is required by the privileged consumer.

## Single-producer rule for ADMITTED

Public schema construction must not permit arbitrary callers to manufacture an authoritative positive admission.

The implementation must ensure that `evaluate_native_peer_admission` is the only production path that can synthesize the authoritative `ADMITTED / ADMISSION_REQUIREMENTS_MET` artifact. The positive constructor/factory must be module-private or guarded by an equivalent in-process capability that cannot be reconstructed from serialized fields.

A validator that only checks the string pair is insufficient: if a caller can deserialize or directly instantiate the authoritative positive object from those two strings, the object is forgeable. The durable admission-audit schema may record the pair, but that record is explicitly non-authoritative. The live positive artifact must reject serialization/reconstruction and must remain paired with the matching continuity object.

Even an authoritative `ADMITTED` result remains non-transferable: use still requires successful revalidation of the paired live continuity object.

## Policy-state source

The current native peer policy models do not expose a stable revision source, so continuity must not invent one from process-local object identity or timestamps.

V1 provides a host-owned `PeerAdmissionPolicyProvider` boundary and immutable `PeerAdmissionPolicySnapshot`. The snapshot contains at least a monotonically increasing policy revision and the canonical digest of the exact native peer-admission policy used for evaluation.

Provider ownership is constructor-time injection, not a module singleton and not a per-revalidation argument. The trusted host passes the provider to `prepare_continuity(...)`; the continuity object stores a strong reference to that exact provider for its entire lifetime. Evaluation captures the provider's exact current snapshot and stores that evaluated-policy revision and canonical digest immutably in continuity state. Every later use-token gate asks the same stored provider object for its **current** snapshot and compares current-vs-evaluated: both revision and digest must exactly equal the stored evaluation-time values. Revalidation never adopts or substitutes the provider's newer policy for the policy under which admission was evaluated. Any policy change therefore invalidates the existing continuity object and requires a new admission evaluation. A caller cannot swap providers between evaluation and use by passing a different provider to revalidation.

Production construction must accept only the trusted production provider boundary; tests use an explicit test-only provider path rather than subclassing or relabelling arbitrary caller objects as trusted. Provider replacement in the host therefore affects only newly prepared continuity objects unless the existing provider object's current snapshot changes; replacing the reference itself does not retarget already-live continuity objects.

The provider is infrastructure, not caller evidence: ordinary request data cannot nominate its own policy revision/digest. Provider unavailability, malformed snapshots, rollback, or mismatch invalidates continuity fail-closed.

## Revocation source

There is currently no peer-admission revocation store or other authoritative peer-admission revocation source. The existing review store is scoped to review/release records and must not be repurposed as an admission revocation oracle.

Accordingly, **peer-admission revocation is absent from continuity v1 by design**. V1 does not add a placeholder callback, caller-supplied boolean, or synthetic "not revoked" field. The continuity object implements process/connection/binding/policy/freshness invalidation only.

Adding revocation later requires a separate contract amendment that names the authoritative store/interface, its lookup key and freshness semantics, and fail-closed behavior. Once such a source exists, it becomes an additional mandatory use-token-gate check; until then, documentation and code must not claim revocation is checked.

## Concurrency and transfer

The continuity object is an in-process owned resource, not a serialized capability.

It may move between threads after construction if its native handles and implementation are thread-safe, but it must not cross a process boundary by serialization, IPC, database storage, or reconstruction from identifiers. If ownership is transferred between components in the same process, that transfer must preserve exactly-one live owner or another explicit ownership discipline that prevents double close and use-after-close.

Concurrent privileged uses require independently minted single-use tokens. Token mint/consume and continuity close/invalidation must use an ownership discipline that prevents double consumption and post-close minting. Closing or invalidating the continuity object races conservatively: once closure/invalidation is observed, no new token may be minted and no unconsumed token may authorize a new privileged operation.

## Required implementation tests

The continuity implementation PR must, before `ADMITTED` exists, pin at least:

- continuity ownership is acquired before `OwnedProcessLease.finish()` releases the original lease handle;
- the continuity object remains capable of process-liveness revalidation after the original lease is finished;
- process exit causes fail-closed `CONTINUITY_INVALID`;
- pipe disconnect/close causes fail-closed `CONTINUITY_INVALID`;
- binding substitution between connections/process instances is rejected;
- the same provider object captured by `prepare_continuity()` is consulted at use; provider substitution is impossible through the gate API; provider unavailability, rollback, revision mismatch, and digest mismatch are rejected;
- expiry is rejected;
- no revocation claim exists in initial v1 and the review store is not consulted as an admission revocation oracle;
- explicit close is terminal and native resources close exactly once;
- `prepare_continuity()` is one-shot, occurs before `finish()`, and does not execute caller callbacks;
- the continuity object, authoritative positive artifact, and continuity-use token each reject `pickle.dumps()`, `copy.copy()`, and `copy.deepcopy()` via explicit reduction guards and cannot be reconstructed;
- the second `OpenProcess` requests exactly `0x00101000` with inheritance disabled and no broader-rights retry exists;
- use-token deadline uses the continuity monotonic clock, is capped at 1000 ms and by continuity/operation deadlines;
- liveness revalidation pins `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT` as the only alive result; signaled, failed, or unexpected wait results invalidate continuity;
- operation kind is a closed `ContinuityUseKind`, not a caller free-form string;
- concurrent minting allows at most one outstanding token and token consumption is atomic under the continuity lock;
- no revalidation path reacquires or substitutes a process PRIMARY token for the original pipe-token classification.

The later ADMITTED integration PR must pin:

- `PEER_ADMISSION_NOT_IMPLEMENTED` is replaced only on the all-requirements-passed path;
- the sole positive pair is `ADMITTED / ADMISSION_REQUIREMENTS_MET`;
- positive admission sets `admission_granted=True` while leaving authorization/grants/signing unevaluated;
- no positive result is emitted without a matching live continuity object;
- no authoritative positive result can be serialized or reconstructed across a process/persistence boundary, and the durable audit projection alone cannot authorize a use;
- every privileged-use integration requires a fresh exact continuity-use-token type, rejects audit/result/binding substitutes, and consumes the token once;
- expired, reused, wrong-operation, wrong-continuity, and post-invalidation tokens are rejected.

## Non-goals

This contract does not:

- turn peer admission into general authorization;
- define grant selection or signing policy;
- retain the pipe-client token for transaction lifetime;
- permit a saved `ADMITTED` record to be replayed;
- require a new pipe-token capture at every use;
- use module-global policy-provider state or accept a caller-selected provider at revalidation time;
- define cross-process transfer of continuity;
- claim peer-admission revocation checking before an authoritative revocation source is separately specified;
- make `ProcessLeaseAudit` itself a live lease;
- make `OwnedProcessLease.finish()` retain native resources.

Those boundaries are intentional. The durable evidence answers what was established at evaluation time; the continuity object answers whether the same admitted transaction is still live at the moment of use.
