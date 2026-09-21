# Native Windows Peer Admission Authority v1

Version: 0.1-draft
Effective date: 2026-09-21
Frozen by: pre-implementation authority-contract workstream
Supersedes: none
Reviewed against implementation: N/A — positive path not yet reachable

## Normative status

This document is the normative specification for the first reachable positive native
Windows peer-admission result and its live authority object.

**The failure table in this document is the specification of the evaluator's branch
structure. The implementation must conform to the table; the table is not derived
from the implementation.**

Any decision that arises during implementation but is not determined by this
contract is a contract gap. The contract must be amended before code chooses a new
semantic rule.

The document and the runtime legal-pair sets are independent artifacts. Neither is
mechanically generated from the other. Any change to this failure table, the bridge
violation vocabulary, or the evaluator's legal result-pair set requires coordinated
contract review.

Internal programming/invariant failures are outside the operational terminal table.
They raise `AdmissionEvaluatorInvariantError`; they are bugs, not peer-admission
outcomes.

## Scope

V1 introduces the first authoritative positive peer admission while preserving the
existing separation between durable evidence and live authority.

A successful evaluation may produce:

`ADMITTED / ADMISSION_REQUIREMENTS_MET`

only when every required predicate in this document has passed and a matching live
continuity object has been adopted into the authoritative admission object.

Admission is not general authorization. The initial positive state means:

- `admission_granted=True`;
- `authorization_granted=False`;
- `grants_evaluated=False`;
- `signing_evaluated=False`.

## Complete positive predicate

Positive admission requires all of the following:

1. the native process lease is the exact required native source and has the exact
   successful pair `CORRELATED / AUDIT_MATCHED`;
2. the existing native peer audit has no concrete violation and all existing
   identity, retained-read, endpoint, descriptor, integrity, token-profile,
   process-correlation, scope, and freshness checks have passed;
3. the exact pipe-client token classification proves non-AppContainer;
4. the correlated process PRIMARY token classification independently proves
   non-AppContainer;
5. live admission continuity exists for the same connection/process binding;
6. the continuity object is bound to the exact policy snapshot under which the
   admission evaluation is performed;
7. authority adoption/construction succeeds.

No subset is sufficient.

## Dual AppContainer evidence

The producer must emit two distinct classifications under one live process-lease
boundary:

- pipe-client token classification;
- correlated process PRIMARY-token classification.

The two axes answer different questions and must never be collapsed into one
generic classification.

The pipe classification describes the security context presented by the thread that
established this specific named-pipe connection. The process-primary classification
describes the sandbox state of the correlated process instance.

PR #37 established that a non-AppContainer process can connect while carrying an
AppContainer thread token and that the pipe observes the thread context. Therefore
process-primary exclusion cannot substitute for pipe-context exclusion.

The inverse case must also be excluded: a process whose PRIMARY token is
AppContainer does not become admissible merely because its connecting thread
presents a non-AppContainer impersonation token.

Only:

`pipe = PROVEN_NON_APPCONTAINER AND process_primary = PROVEN_NON_APPCONTAINER`

may proceed beyond the AppContainer phases.

### Producer requirements

Process-primary classification is captured by the producer, not by the evaluator.
The evaluator performs no native token acquisition.

The producer uses the existing live `OwnedProcessLease` process handle and opens
the process token with `OpenProcessToken(..., TOKEN_QUERY)`.

The acquisition/classification sequence is fixed:

1. impersonate the named-pipe client;
2. open the exact pipe-client thread token;
3. perform the mandatory `RevertToSelf`;
4. only after successful revert, register the retained pipe-token handle in one
   post-revert structured cleanup scope and classify it;
5. open the correlated process PRIMARY token from the live lease process handle;
6. register that process-primary token in the same cleanup scope, classify it, and
   build the process-primary axis;
7. construct the immutable `PeerAdmissionEvidence` wrapper;
8. close the process-primary token and then the pipe token as the cleanup scope
   unwinds.

The post-revert cleanup scope uses `contextlib.ExitStack` (or an equivalent single
structured ownership scope). The lease-owned process handle is not registered
because the producer does not own it. `RevertToSelf` failure remains the unique
process-fatal path with exit code `0xE401` and performs no subsequent Python
cleanup/evidence/classification work. Process-primary acquisition/query failure
occurs only after successful revert and therefore produces unavailable process-axis
evidence where explicitly mapped; it is not process-fatal.

It classifies the PRIMARY token while the same process instance is retained and
correlated, closes the token, and emits both classifications in one immutable
evidence record bound to:

- `connection_operation_id`;
- `pipe_lease_id`;
- `process_lease_operation_id`;
- `process_pid`;
- `process_creation_filetime`;
- the producer capture ordinal.

V1 treats the process-primary AppContainer classification as a stable fact of that
correlated process instance and does not re-query it at use time.

`PeerAdmissionEvidence` uses containment, not extension:

- `pipe_context: PipePeerAdmissionEvidence`;
- `process_primary: ProcessPrimaryAppContainerEvidence`.

The existing `PipePeerAdmissionEvidence` schema remains the pipe-axis record and
keeps its current fields, including `classification_source='PIPE_TOKEN'`.
`ProcessPrimaryAppContainerEvidence` is a discriminated union of separate frozen
Pydantic variants mirroring the existing pipe-axis pattern:

- `CAPTURED_APPCONTAINER`;
- `CAPTURED_NON_APPCONTAINER`;
- `CAPTURED_CLASSIFICATION_CONFLICT`;
- `CAPTURED_CLASSIFICATION_UNAVAILABLE`.

Every process-primary variant carries
`classification_source='PROCESS_PRIMARY_TOKEN'`. Both axes carry the full common
binding tuple:

- `connection_operation_id`;
- `pipe_lease_id`;
- `process_lease_operation_id`;
- `process_pid`;
- `process_creation_filetime`;
- `capture_ordinal=1`.

The ordinal identifies the single v1 evidence transaction, not sequential capture
order. The wrapper validates exact equality of the complete binding tuple across
both axes. Source fields are retained even though wrapper position already implies
the axis so that each durable axis record remains self-describing; their Literal
types make an axis/source mismatch invalid.

For process-primary `CAPTURED_CLASSIFICATION_UNAVAILABLE`, the diagnostic payload
is structured:

- `failed_stage: Literal['OPEN_PROCESS_TOKEN', 'GET_TOKEN_INFORMATION']`;
- `information_class: Literal[29, 31] | None`;
- `failure_reason: ProcessPrimaryFailureReason`;
- `winerror: int | None`.

`ProcessPrimaryFailureReason` is a closed Literal vocabulary rather than the
general-purpose `Identifier` alias:

- `OPEN_PROCESS_TOKEN_FAILED`;
- `QUERY_FAILED`;
- `QUERY_LENGTH_INVALID`;
- `QUERY_BOOLEAN_INVALID`;
- `QUERY_SIZE_PROBE_FAILED`;
- `QUERY_BOUND_INVALID`;
- `QUERY_RETURN_LENGTH_INVALID`;
- `APPCONTAINER_INFO_HEADER_INVALID`;
- `APPCONTAINER_SID_INVALID`.

The existing `Identifier` type remains the repository-wide constrained identifier
string (`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}# Native Windows Peer Admission Authority v1

Version: 0.1-draft
Effective date: 2026-09-21
Frozen by: pre-implementation authority-contract workstream
Supersedes: none
Reviewed against implementation: N/A — positive path not yet reachable

## Normative status

This document is the normative specification for the first reachable positive native
Windows peer-admission result and its live authority object.

**The failure table in this document is the specification of the evaluator's branch
structure. The implementation must conform to the table; the table is not derived
from the implementation.**

Any decision that arises during implementation but is not determined by this
contract is a contract gap. The contract must be amended before code chooses a new
semantic rule.

The document and the runtime legal-pair sets are independent artifacts. Neither is
mechanically generated from the other. Any change to this failure table, the bridge
violation vocabulary, or the evaluator's legal result-pair set requires coordinated
contract review.

Internal programming/invariant failures are outside the operational terminal table.
They raise `AdmissionEvaluatorInvariantError`; they are bugs, not peer-admission
outcomes.

## Scope

V1 introduces the first authoritative positive peer admission while preserving the
existing separation between durable evidence and live authority.

A successful evaluation may produce:

`ADMITTED / ADMISSION_REQUIREMENTS_MET`

only when every required predicate in this document has passed and a matching live
continuity object has been adopted into the authoritative admission object.

Admission is not general authorization. The initial positive state means:

- `admission_granted=True`;
- `authorization_granted=False`;
- `grants_evaluated=False`;
- `signing_evaluated=False`.

## Complete positive predicate

Positive admission requires all of the following:

1. the native process lease is the exact required native source and has the exact
   successful pair `CORRELATED / AUDIT_MATCHED`;
2. the existing native peer audit has no concrete violation and all existing
   identity, retained-read, endpoint, descriptor, integrity, token-profile,
   process-correlation, scope, and freshness checks have passed;
3. the exact pipe-client token classification proves non-AppContainer;
4. the correlated process PRIMARY token classification independently proves
   non-AppContainer;
5. live admission continuity exists for the same connection/process binding;
6. the continuity object is bound to the exact policy snapshot under which the
   admission evaluation is performed;
7. authority adoption/construction succeeds.

No subset is sufficient.

## Dual AppContainer evidence

The producer must emit two distinct classifications under one live process-lease
boundary:

- pipe-client token classification;
- correlated process PRIMARY-token classification.

The two axes answer different questions and must never be collapsed into one
generic classification.

The pipe classification describes the security context presented by the thread that
established this specific named-pipe connection. The process-primary classification
describes the sandbox state of the correlated process instance.

PR #37 established that a non-AppContainer process can connect while carrying an
AppContainer thread token and that the pipe observes the thread context. Therefore
process-primary exclusion cannot substitute for pipe-context exclusion.

The inverse case must also be excluded: a process whose PRIMARY token is
AppContainer does not become admissible merely because its connecting thread
presents a non-AppContainer impersonation token.

Only:

`pipe = PROVEN_NON_APPCONTAINER AND process_primary = PROVEN_NON_APPCONTAINER`

may proceed beyond the AppContainer phases.

### Producer requirements

Process-primary classification is captured by the producer, not by the evaluator.
The evaluator performs no native token acquisition.

The producer uses the existing live `OwnedProcessLease` process handle and opens
the process token with `OpenProcessToken(..., TOKEN_QUERY)`.

The acquisition/classification sequence is fixed:

1. impersonate the named-pipe client;
2. open the exact pipe-client thread token;
3. perform the mandatory `RevertToSelf`;
4. only after successful revert, register the retained pipe-token handle in one
   post-revert structured cleanup scope and classify it;
5. open the correlated process PRIMARY token from the live lease process handle;
6. register that process-primary token in the same cleanup scope, classify it, and
   build the process-primary axis;
7. construct the immutable `PeerAdmissionEvidence` wrapper;
8. close the process-primary token and then the pipe token as the cleanup scope
   unwinds.

The post-revert cleanup scope uses `contextlib.ExitStack` (or an equivalent single
structured ownership scope). The lease-owned process handle is not registered
because the producer does not own it. `RevertToSelf` failure remains the unique
process-fatal path with exit code `0xE401` and performs no subsequent Python
cleanup/evidence/classification work. Process-primary acquisition/query failure
occurs only after successful revert and therefore produces unavailable process-axis
evidence where explicitly mapped; it is not process-fatal.

It classifies the PRIMARY token while the same process instance is retained and
correlated, closes the token, and emits both classifications in one immutable
evidence record bound to:

- `connection_operation_id`;
- `pipe_lease_id`;
- `process_lease_operation_id`;
- `process_pid`;
- `process_creation_filetime`;
- the producer capture ordinal.

), but it is intentionally too open
for this failure vocabulary. Native error numbers are stored separately in
`winerror`; they are not embedded into `failure_reason`.

The variant validator requires `information_class is None` for
`OPEN_PROCESS_TOKEN` and `information_class in {29,31}` for
`GET_TOKEN_INFORMATION`. Class-30 capability telemetry remains audit-only and does
not create a classification-unavailable terminal.

This is an existing implementation baseline, not a new schema expansion in this PR:
`AppContainerTokenEvidence.capability_sids` is already
`tuple[SID, ...] | None`; the native probe already converts unusable class-30
telemetry to `None` while continuing classes 29 and 31; and the probe tests already
pin class-30 bound/query failure as audit-only without changing classifier
disposition. The dual-classification producer therefore inherits that behavior and
must not reinterpret class-30 unavailability as a process-axis classification
failure.

Only expected native/probe failures are translated into this unavailable variant.
Unexpected exception types propagate as producer errors. Likewise, an unmapped
classifier result, impossible classifier result, or wrapper/model validation failure
is a producer programming-contract error and raises; none may be laundered into
unavailable evidence or a partially populated wrapper.

## Classification outcomes

For each classification axis, distinguish three classes of non-success:

1. **Unavailable** — a required native query, token open, payload validation, or
   equivalent evidence acquisition could not be completed. This maps to
   `PEER_EVIDENCE_UNAVAILABLE`.
2. **Classification conflict** — the evidence object is model-valid and all
   required raw evidence is available, but the classifier's pinned truth table
   cannot produce one unique classification for that same axis. This is a
   first-class runtime terminal.
3. **Invalid evidence** — the object itself violates schema/exact-type/evaluator
   boundary requirements. This belongs to phase 1, not to classification conflict.

Different results on the two independent axes are not a conflict. For example,
pipe AppContainer plus process-primary non-AppContainer is a valid quadrant and is
a denial.

### Conflict production

V1 does not add a new public `CONFLICT` member to
`AppContainerExclusionResult.status`. The existing classifier remains closed over
`PROVEN_NON_APPCONTAINER`, `APPCONTAINER`, `UNPROVEN`, and `INDETERMINATE`.

A classification-conflict terminal is produced by the evidence producer when the
classifier returns the specific model-valid contradiction outcome
`INDETERMINATE / APPCONTAINER_SIGNAL_CONFLICT`. The producer normalizes that
classifier result into the axis-specific evidence variant
`CLASSIFICATION_CONFLICT`; the wrapper then preserves which axis produced it.
Required-query/acquisition failures remain `CLASSIFICATION_UNAVAILABLE` (or
capture unavailable) and therefore stay mechanically distinct from conflict.

Other classifier `INDETERMINATE` or `UNPROVEN` reasons are not automatically
relabelled as conflict. Their producer mapping must be explicitly specified before
they can become authority evidence. If the producer receives a classifier
status/reason pair for which no mapping is defined, that is a producer/classifier
programming-contract failure and the producer raises its invariant error; it must
not silently convert the unknown mapping to unavailable evidence.

The wrapper itself does not invent conflicts by reinterpreting raw facts
independently of the classifier. This keeps the classifier as the owner of raw-fact
consistency semantics while the producer owns the explicit translation from
classifier vocabulary into the admission evidence vocabulary.

## Evaluation order and terminal table

Evaluation uses phase precedence. Phases and sub-checks execute in the listed
order. The first failing operational check determines the terminal result. Later
facts may remain in the durable audit projection, but they do not replace the
earlier terminal reason.

| Phase | Ordered check/action | Operational result |
| --- | --- | --- |
| 1 | Exact input/schema/evaluator contract | failure -> `INDETERMINATE / INVALID_ADMISSION_EVIDENCE` |
| 2.1 | Process lease source is native | failure -> `INDETERMINATE / NATIVE_PROCESS_LEASE_REQUIRED` |
| 2.2 | Process lease exact success pair is `CORRELATED / AUDIT_MATCHED` | failure -> `DENIED / PROCESS_LEASE_NOT_CORRELATED` |
| 2.3 | Process lease contract invariants hold | failure -> `INDETERMINATE / PROCESS_LEASE_CONTRACT_VIOLATION` |
| 3.1 | Peer-audit contract invariants hold | failure -> `INDETERMINATE / PEER_AUDIT_CONTRACT_VIOLATION` |
| 3.2 | Peer audit has no `VIOLATIONS` result | violation -> `DENIED / <exact bridge reason>`; bridge-pair outside its declared closed set -> `AdmissionEvaluatorInvariantError` |
| 3.3a | Bridge reason `CAPTURE_UNAVAILABLE` is absent | failure -> `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE` |
| 3.3b | Bridge reason `APP_CONTAINER_EXCLUSION_UNPROVEN` is the expected handoff to the authority AppContainer phases | success -> continue to phase 4 |
| 3.3c | Any other allowed bridge `INDETERMINATE` reason | propagate that exact existing `INDETERMINATE` reason |
| 4.1a | Pipe-token classification evidence is available and validated | failure -> `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE` |
| 4.1b | Pipe-token classifier outcome maps to a defined axis variant | `CLASSIFICATION_CONFLICT` -> `INDETERMINATE / PIPE_CONTEXT_CLASSIFICATION_CONFLICT` |
| 4.2 | Pipe context is proven non-AppContainer | AppContainer -> `DENIED / PIPE_CONTEXT_APP_CONTAINER_DENIED` |
| 5.1a | Process-primary classification evidence is available and validated | failure -> `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE` |
| 5.1b | Process-primary classifier outcome maps to a defined axis variant | `CLASSIFICATION_CONFLICT` -> `INDETERMINATE / PROCESS_PRIMARY_CLASSIFICATION_CONFLICT` |
| 5.2 | Process PRIMARY is proven non-AppContainer | AppContainer -> `DENIED / PROCESS_PRIMARY_APP_CONTAINER_DENIED` |
| 6.1 | Matching live continuity is established and bound | failure -> `INDETERMINATE / ADMISSION_CONTINUITY_UNAVAILABLE` |
| 6.2 | Exact evaluated-policy binding is proven | failure -> `INDETERMINATE / POLICY_BINDING_UNAVAILABLE` |
| 6.3 | Continuity remains valid/open at authority-adoption start | failure -> `INDETERMINATE / ADMISSION_CONTINUITY_UNAVAILABLE` |
| 7.1 | Atomically adopt continuity and construct authoritative admission | failure -> `INDETERMINATE / AUTHORITY_CONSTRUCTION_FAILED`; success -> `ADMITTED / ADMISSION_REQUIREMENTS_MET` |

### Phase 1 reachability

Phase 1 is primarily a defensive runtime boundary around Python's unenforced
parameter types and exact-record requirements. Proper internal producer/evaluator
records should not fail phase 1.

Examples include wrong concrete model type, dict/duck-typed input, malformed
serialized reconstruction routed through the evaluator boundary, or failure of an
evaluator-specific exact-copy requirement.

### Bridge vocabulary coupling and AppContainer handoff

Phase 3.2 preserves the bridge's exact single violation reason unchanged only when
the pair is a member of the bridge's own closed vocabulary:
`NATIVE_PEER_AUDIT_RESULT_PAIRS` in
`src/tnc/provenance/windows_pipe_auth_bridge.py`.

Every operational `NativePeerAuditResult(status='VIOLATIONS', reason=...)`
produced by the bridge must itself be a member of that declared set. That is a
bridge-owned closure invariant. The authority layer relies on it and does not
broaden or reinterpret the bridge vocabulary. If a bridge result reaches the
authority with a pair outside that declared set, that is a bridge/evaluator
programming invariant failure and raises `AdmissionEvaluatorInvariantError`; it is
not converted to an admission terminal.

Before `ADMITTED` becomes reachable, the bridge's AppContainer verdict is retired
as an admission decision. The bridge remains responsible for its identity,
correlation, descriptor, integrity, token-profile, scope, and freshness checks, but
phases 4 and 5 become the sole AppContainer decision source. The expected bridge
handoff for an otherwise-clean peer is therefore
`INDETERMINATE / APP_CONTAINER_EXCLUSION_UNPROVEN`, which phase 3.3b treats as a
phase pass into the fuller dual-classification authority evidence.

The phase-3.3 mappings are fixed:

- `CAPTURE_UNAVAILABLE` -> `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE`;
- `APP_CONTAINER_EXCLUSION_UNPROVEN` -> phase pass into phase 4;
- any other allowed bridge `INDETERMINATE` reason -> propagate that exact existing
  `INDETERMINATE` reason.

This removes duplicate AppContainer decision sources: a pipe-context AppContainer
denial is selected in phase 4, not earlier by the bridge.

Any change to the bridge violation or indeterminate vocabulary requires authority
compatibility review.

### Process-correlation reason distinction

`PROCESS_LEASE_NOT_CORRELATED` belongs to phase 2 and is produced from the
`ProcessLeaseAudit` failure path.

`PROCESS_CORRELATION_MISMATCH` belongs to phase 3 and is an existing
`NativePeerAuditResult` violation from separate peer-correlation evidence.

A phase-2 failure wins before phase 3 is authoritative for the terminal result.

## AppContainer denial precedence and audit preservation

Evaluation-phase precedence controls globally. Once phases 1-3 pass, the pipe axis
is evaluated before the process-primary axis.

Within the AppContainer phases:

- pipe AppContainer -> `PIPE_CONTEXT_APP_CONTAINER_DENIED`;
- pipe proven non-AppContainer + process-primary AppContainer ->
  `PROCESS_PRIMARY_APP_CONTAINER_DENIED`;
- both AppContainer -> `PIPE_CONTEXT_APP_CONTAINER_DENIED`.

The reason code reflects the most proximate decisive fact about this specific
connection. The durable audit projection retains both classifications, including a
non-decisive positive or unavailable classification on the other axis.

An unavailable later axis does not erase an already-established earlier positive
denial. Conversely, absence of a positive denial does not convert unavailable
required evidence into proven non-AppContainer.

## Authority construction barrier

The authoritative positive admission is a live, exact concrete Python type, not a
Pydantic model and not a serializable record.

V1 uses the stronger construction shape: the evaluator returns the durable audit
projection plus `authority_or_none`. No standalone construction capability is
returned to callers.

The authority is constructed inside the evaluator's successful phase-7 path from
the already-live continuity object. The public constructor is disabled.

The authority must reject or prevent all enumerated current reconstruction paths:

- direct public construction through `__init__`;
- any public/class/module factory outside the evaluator success path;
- `copy.copy`;
- `copy.deepcopy`;
- pickling/reduction and reconstruction from serialized bytes;
- production construction from audit records, IDs, evidence records, or continuity
  alone;
- authority production by a public method on `AdmissionContinuity` or evidence;
- subclass substitution.

The class must be non-subclassable or production checks must otherwise reject all
non-exact concrete types. V1 chooses an exact concrete type and a subclass barrier.

These tests cover the enumerated current public API. They do not prove that a
future public entry point cannot be added. Any new authority-related public API
requires explicit construction-barrier review.

This is an in-process API integrity boundary, not a defense against arbitrary
hostile code already executing inside the trusted Python process.

## Adoption atomicity and evaluation ownership

V1 assumes synchronous, single-threaded evaluation ownership from successful
continuity preparation through authority adoption.

During that interval, callers must not concurrently close, mutate, mint from,
transfer, or otherwise operate on the continuity object. This is a caller contract,
not a runtime-detected `ADOPTING` state.

Under that ownership rule, phase-7 adoption and authority construction have no
externally observable intermediate state.

Continuity has an explicit two-state adoption lifecycle: `IDLE` before adoption
and terminal `ADOPTED` after successful authority construction. Adoption performs
the single `IDLE -> ADOPTED` transition. Public mutating lifecycle/use methods
check the terminal `ADOPTED` state and reject direct external mutation after
adoption; authority-bound private operations are the production path. V1 introduces
no observable intermediate `ADOPTING` state.

Phase 6.3 is a defensive adoption-start guard under this model, not a claim that
normal single-threaded evaluation permits an external lifecycle transition between
phases 6.1 and 6.3. It catches continuity that is already closed/invalid when
adoption actually begins, including an evaluator-side lifecycle bug or a violation
of the caller ownership contract. The check is retained as an operational guard
because adoption must never consume an invalid continuity, but v1 does not model a
concurrent state change as normal behavior.

If concurrent evaluation ownership is introduced later, this contract must be
amended with an explicit synchronization and state-transition mechanism.

## Continuity semantics

Continuity proves:

> this is still the same admitted transaction on the same connected pipe and the
> same correlated process instance.

It does not prove persistence of the original client thread token.

The pipe-client AppContainer classification remains a capture-time fact about how
this connection was established. The process-primary classification remains a fact
bound to the retained process instance. Use-time continuity protects the identity
of the transaction/process between evaluation and use.

If a future privileged operation requires the peer's current effective thread
security context, continuity alone is insufficient; that operation requires a
separate use-boundary impersonation/current-context contract.

## Authority ownership and allowed use kinds

Once phase-7 adoption succeeds, the authoritative admission becomes the sole
production lifecycle/use owner of the continuity.

Before adoption, the orchestrator may explicitly close unused continuity. After
adoption, bare continuity is not an independent production authority path.

Production callers mint use tokens through the authority. The authority owns an
immutable allowed set of `ContinuityUseKind` values established by the positive
admission path.

The underlying continuity mint operation is internal and must enforce the same
allowed-kind invariant so an accidental direct call cannot upgrade an admission to
another operation class.

A caller cannot gain a new operation class merely by naming another enum member.

## Point-in-time capability authorization and deadlines

V1 uses **point-in-time authorization at token consumption**, not continuous
authorization over the operation.

A use token's deadline is:

`min(minted_tick + MAX_CONTINUITY_USE_TOKEN_MS, continuity_deadline, operation_deadline)`

with `MAX_CONTINUITY_USE_TOKEN_MS = 1000`.

The 1000 ms term is a maximum lifetime from the token's own mint time. Therefore a
token minted 900 ms before continuity expiry has at most 100 ms of usable life.

The token must be consumed successfully before its deadline. Successful consumption
authorizes that specific operation to begin. Subsequent continuity expiry, policy
change, connection loss, or other continuity invalidation does not retroactively
cancel that already-started operation through this subsystem.

Any intrinsic deadline, cancellation, rollback, or failure during the operation is
owned by the privileged operation's own contract.

No token may be minted or consumed after continuity has expired or invalidated.

## Intrinsic invalidation versus extrinsic revocation

V1 has intrinsic continuity invalidators:

- retained process exits or cannot be proven live;
- connection closes, disconnects, is replaced, or stops being the use target;
- binding mismatch;
- policy snapshot change/unavailability;
- freshness expiry;
- explicit continuity/authority closure;
- native revalidation failure.

These terminate the window for authorizing a new use.

V1 has **no extrinsic peer-admission revocation mechanism**. There is no
authoritative peer-admission revocation writer/store, and caller-supplied
"revoked/not revoked" state is prohibited.

Operational consequence: once a use token is consumed and a privileged operation
begins, nothing in this admission subsystem can revoke or cancel that in-flight
operation. It completes, fails under its own contract, or is interrupted by process
termination/outside mechanisms.

Adding extrinsic revocation later requires a separate contract that defines an
authenticated writer boundary, authoritative store/interface, lookup key,
freshness semantics, and the use-boundary integration.

## Legal result-pair discipline

The runtime evaluator must retain a closed legal result-pair set. Every operational
terminal in this table must be legal; illegal combinations such as
`DENIED / PEER_EVIDENCE_UNAVAILABLE` must be rejected.

The normative table and runtime set are independent. Tests must verify evaluator
branches produce legal pairs and that representative illegal combinations are
rejected. The tests must not merely duplicate a second hand-maintained copy of the
entire contract set and call that independent proof.

Correspondence between the full normative table, the bridge's closed violation
vocabulary, and runtime legal-pair set is a required review invariant on changes to
any of them.

## Evaluator interface exercised by the contract stub

The contract-test step pins the eventual evaluator call shape before native
integration:

`evaluate_native_peer_admission(*, lease, peer, peer_evidence, continuity, evaluated_policy)`

The inputs are owned as follows:

- `lease`: exact `ProcessLeaseAudit` from the process-lease module;
- `peer`: exact `NativePeerAuditResult` from the authentication bridge;
- `peer_evidence`: exact `PeerAdmissionEvidence`, a new producer-owned immutable
  wrapper for the exact connection/process binding. It contains the existing
  `PipePeerAdmissionEvidence` as its pipe-context component plus a distinct
  process-primary AppContainer-classification component. The existing
  `PipePeerAdmissionEvidence` remains the pipe-axis record and is not silently
  redefined to mean both axes; callers must pass the wrapper to the evaluator.
  Each axis component must preserve enough structure to distinguish: required
  evidence/query unavailable (phase 4.1a/5.1a), model-valid raw evidence whose
  classifier has no unique outcome (phase 4.1b/5.1b), and a successful unique
  classification that can proceed to the AppContainer denial check. A single
  undifferentiated classification enum that collapses unavailable and conflict is
  not sufficient for this interface;
- `continuity`: the exact live `AdmissionContinuity` object for that same binding;
- `evaluated_policy`: the exact `PeerAdmissionPolicySnapshot` under which this
  admission evaluation is being performed.

The explicit `evaluated_policy` input closes phase 6.2. The caller obtains the
policy snapshot used to construct the peer-audit/evaluation inputs and passes that
same immutable snapshot to the evaluator. Continuity independently retains the
snapshot captured from its stored provider at preparation time. Phase 6.2 compares
those two independently held references by exact revision and digest. The evaluator
does not pull the evaluation policy from continuity and does not accept continuity's
policy binding as a self-assertion.

The eventual evaluator returns:

`(PeerAdmissionAuditRecord, authority_or_none)`

The durable audit record owns the terminal `status` and `reason`. Every denied
or indeterminate result has `authority_or_none is None`. Only successful phase
7.1 may return the exact live authoritative admission object.

The contract tests are permanent. The temporary branch stub is only a phase-table
exerciser. Every test that exists in the stub PR must continue to pass unchanged
against the real evaluator; only the test driver/factories that construct production
inputs may change. The same file may grow with additional tests for phase 7.1,
authority construction barriers, and other behavior that is genuinely unreachable
under the stub. Adding those previously-unreachable tests does not relax the
unchanged-passing requirement for the existing assertions. Tests therefore assert
the evaluator's call signature, durable terminal pair, phase precedence, and
authority presence/absence, not private stub object shape.

### Stub coverage boundary and disposal

The temporary stub exercises phases 1 through 6 using synthetic exact input
objects. Its reachable operational terminals are:

- phase 1: `INVALID_ADMISSION_EVIDENCE`;
- phase 2.1: `NATIVE_PROCESS_LEASE_REQUIRED`;
- phase 2.2: `PROCESS_LEASE_NOT_CORRELATED`;
- phase 2.3: `PROCESS_LEASE_CONTRACT_VIOLATION`;
- phase 3.1: `PEER_AUDIT_CONTRACT_VIOLATION`;
- phase 3.2: every authority-compatible bridge `VIOLATIONS` reason plus the
  out-of-vocabulary `AdmissionEvaluatorInvariantError` path;
- phase 3.3: `PEER_EVIDENCE_UNAVAILABLE`, the AppContainer handoff, and exact
  propagation of the other allowed bridge-indeterminate reasons;
- phases 4-5: both axis-specific AppContainer denials, both classifier conflicts,
  and required-evidence unavailability;
- phases 6.1 and 6.3: `ADMISSION_CONTINUITY_UNAVAILABLE`;
- phase 6.2: `POLICY_BINDING_UNAVAILABLE`.

It deliberately does not model authority construction. Phase 7.1,
construction-barrier behavior, and evaluator-internal authority adoption require
the real evaluator and are marked `requires-real-evaluator` in the test plan.

Likewise, tests that deliberately induce internal implementation corruption rather
than malformed external inputs may require the real evaluator. The bridge
out-of-vocabulary invariant is stub-reachable because it is an explicit phase-3
contract check; arbitrary internal evaluator bugs are not claimed as stub coverage.

The stub is deleted when the real evaluator lands. It is not a maintained parallel
evaluator or general-purpose test double. A thin contract-test driver may remain
only to construct production inputs while keeping the permanent test file
unchanged.

The stub's job is to force every phase-1-through-6 input to be named, every covered
terminal to be representable, and module ownership to be concrete. If that exercise
requires a semantic or interface choice not specified here, implementation stops
and this contract is amended first.

The test-only `StubReachedPhase7` path is exercised only by the stub meta test.
Every other stub-backed contract test must terminate within phases 1-6 on the
specific terminal it is asserting; accidentally falling through to phase 7 is a
test failure, not an accepted substitute for coverage.

## Required contract and implementation tests

Before the positive path becomes reachable, the test suite must pin at least:

### Dual-classification matrix

- pipe non-AC + process-primary non-AC reaches the next phase;
- pipe AC + process-primary non-AC -> pipe-context denial;
- pipe non-AC + process-primary AC -> process-primary denial;
- pipe AC + process-primary AC -> pipe-context denial by documented precedence;
- pipe AC + process-primary unavailable -> pipe-context denial while audit retains
  unavailability;
- pipe unavailable + process-primary AC -> phase-4 unavailable terminal because
  phase 5 is not authoritative after phase 4 fails;
- both unavailable -> peer evidence unavailable;
- model-valid pipe conflict -> pipe conflict terminal;
- model-valid process-primary conflict -> process-primary conflict terminal.

### Phase precedence

- phase-2 lease failure wins over previously captured later-phase evidence;
- phase-3 concrete peer violation wins before AppContainer phases;
- bridge `CAPTURE_UNAVAILABLE` maps to `PEER_EVIDENCE_UNAVAILABLE`;
- bridge `APP_CONTAINER_EXCLUSION_UNPROVEN` passes into phase 4;
- any other allowed bridge-indeterminate reason preserves its exact existing mapping;
- a bridge result outside `NATIVE_PEER_AUDIT_RESULT_PAIRS` raises
  `AdmissionEvaluatorInvariantError`;
- phase-4 failure prevents phase-5 terminal selection;
- phase 6.1 binding/unavailability precedes 6.2 policy binding, which precedes 6.3 adoption-start liveness;
- within phases 2, 3, and 6, listed sub-check ordering determines the terminal.

### Producer binding

- both classifications are captured under the same live lease binding;
- process-primary classification uses the existing lease process handle and
  `OpenProcessToken(TOKEN_QUERY)`;
- evaluator performs no native token acquisition;
- token handles are closed after immutable classification is produced.

### Construction barrier

- direct authority construction fails;
- public/class/module factories outside evaluator success do not produce authority;
- `copy.copy`, `copy.deepcopy`, and pickle/reduction fail;
- audit/evidence/ID/serialized reconstruction fails;
- continuity alone cannot produce authoritative admission;
- subclass substitution is rejected;
- only the evaluator success path returns the exact authoritative type.

### Use-kind enforcement

- authority with allowed set `{K1}` can mint `K1`;
- the same authority rejects `K2`;
- the internal continuity mint path independently rejects `K2`;
- consumer rejects wrong kind, wrong operation, wrong continuity, expired token,
  reused token, and post-invalidation token.

### Lifecycle

- denied/indeterminate evaluation leaves continuity for explicit orchestrator cleanup;
- successful adoption transfers production lifecycle ownership to authority;
- authority `close()` releases continuity exactly once;
- authority context-manager exit releases continuity;
- repeated close is idempotent;
- no `__del__` performs native cleanup;
- dropping caller references and running `gc.collect()` does not count as cleanup:
  the retained process handle and endpoint continuity claim remain owned until
  explicit close/invalidation;
- no positive result exists if adoption/construction fails.

### Deadline/use-boundary semantics

- token lifetime is capped by mint+1000 ms, continuity deadline, and operation
  deadline;
- a late-minted token receives only the remaining outer-window lifetime;
- successful consume before deadline authorizes operation start;
- later continuity expiry does not retroactively invalidate that consumed operation;
- no later token can be minted after outer-window expiry.

### Audit preservation

- durable audit records both AppContainer classifications even when one denial reason
  wins precedence;
- durable audit is never accepted as authority;
- authority/use token cannot be reconstructed from durable audit.

### Revocation scope

- no caller-supplied revocation boolean/callback is accepted;
- review store is not consulted as a peer-admission revocation oracle;
- documentation and runtime output do not claim extrinsic revocation support.

## Implementation sequence

The required sequence is:

1. land/freeze this authority contract;
2. add contract tests/stubs for vocabulary, precedence, construction barriers,
   ownership, and deadline semantics;
3. extend producer/schema with dual AppContainer classification;
4. implement evaluator/authority integration;
5. add native/integration tests;
6. on the exact reviewed head that first makes
   `ADMITTED / ADMISSION_REQUIREMENTS_MET` reachable and passes the complete gate,
   update `Reviewed against implementation` to that commit SHA;
7. only then merge the positive path.

## Non-goals

V1 does not:

- authorize arbitrary later behavior by a process merely because it remains alive;
- prove the original client thread token remains installed;
- continuously reauthorize an operation after token consumption;
- cancel in-flight operations through peer-admission expiry or revocation;
- introduce peer-admission revocation before an authoritative writer/store exists;
- make durable audit records bearer authority;
- make arbitrary in-process hostile Python code part of the supported threat model;
- introduce concurrent evaluation/adoption ownership.
