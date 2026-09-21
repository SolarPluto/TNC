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

### Reviewed-against-implementation publication

The `Reviewed against implementation` field remains
`N/A — positive path not yet reachable` through all contract-only and
producer-only work. It is not set speculatively in the implementation commit.

The evaluator/authority integration PR uses this exact sequence:

1. Push an implementation head `H` that makes
   `ADMITTED / ADMISSION_REQUIREMENTS_MET` reachable, including the production
   audit schema, runtime legal-pair update, and complete enabling tests. Leave the
   reviewed-against field at `N/A` while that head is being validated.
2. Confirm that the complete enabling gate actually executed and passed for `H`.
   A docs-only no-op check, skipped enabling tests, a green ancestor, or a green
   producer-only head is not sufficient. Retain the workflow run ID, run attempt,
   exact PR-head SHA, base SHA, and tested checkout SHA so the test evidence is
   traceable even when Actions checks out a synthetic PR merge commit.
3. Only after that confirmation, create a new documentation-only provenance commit
   `D` on top of `H`. Set this field to the full SHA of `H` and record the enabling
   run reference alongside it. `D` changes only provenance metadata, not normative
   contract text, production code, tests, dependencies, or workflow behavior.
   The field references `H`, never `D` itself and never a later merge commit.
4. Let the normal merge gate run on the new current head `D`. The provenance claim
   remains about the already-validated implementation at `H`; it does not pretend
   that a new head was tested before it existed. Do not waive current-head checks.

The current #41 workflow classifies the cumulative base-to-PR-head diff, not just
its last commit. Consequently, `D` on this still-open implementation PR continues
to select the real Windows suite because the PR still contains implementation
changes. A cheap docs-only cycle requires a separate documentation-only PR after
the implementation has merged; it is not the chosen same-PR publication sequence.

If a later change modifies implementation, tests, dependencies, workflow behavior,
the reviewed normative contract, or the tested base integration, the earlier
reference is not validation of that new combination. Restore `N/A` in that change,
obtain a successful complete gate for its replacement implementation head `H2`, and
publish `H2` in a subsequent provenance-only commit. Do not amend a validated commit
to insert its own SHA or rewrite a merge commit to manufacture provenance.

## Scope

V1 introduces the first authoritative positive peer admission while preserving the
existing separation between durable evidence and live authority.

A successful evaluation may produce:

`ADMITTED / ADMISSION_REQUIREMENTS_MET`

only when every required predicate in this document has passed and a matching live
continuity object has been adopted into the authoritative admission object.

Admission is not general authorization. Live admission authority exists only in the
separately returned authoritative object. The durable audit is a projection of the
terminal outcome, not an authority carrier, so all of its admission/grant/signing
flags are permanently inert on every terminal, including `ADMITTED`:

- `admission_granted=False`;
- `authorization_granted=False`;
- `grants_evaluated=False`;
- `signing_evaluated=False`.

The `ADMITTED / ADMISSION_REQUIREMENTS_MET` pair records that phase 7.1 completed
and a live authority was returned; the audit itself never grants admission and can
never be promoted or replayed into authority.

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
string (`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$`), but it is intentionally too open
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

For exact `ProcessLeaseAudit` and `NativePeerAuditResult` instances, phase 1
checks exact concrete type, complete declared field shape, bounded JSON
serializability, and evaluator input requirements without re-running the semantic
contract validators that phases 2.3 and 3.1/3.2 own. In particular,
`audit_only`/grant-flag violations and an out-of-vocabulary bridge pair must remain
reachable by their specified later phase. Exact evidence and evaluated-policy
records continue to use their evaluator-specific validated-copy requirements.

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

The authority is constructed inside the evaluator's successful phase-7 path. The
public constructor is disabled.

The construction barrier is bidirectional. The audit is never mutated or promoted
into authority, and authority is never reconstructed from an audit. After phases
1-6 succeed, the evaluator creates one private, non-serializable
`_ValidatedAdmissionState` containing only already-validated durable facts plus
the exact live `AdmissionContinuity` and an exact immutable copy of the evaluated
policy snapshot. The durable audit and live authority are sibling outputs projected
from that internal state; neither is an input to construction of the other.

`_ValidatedAdmissionState` has no public constructor or external factory, rejects
copy/deepcopy/pickle/subclass construction paths, and is created at exactly one
module-private evaluator factory. The state is not a Pydantic/durable record and is
never serialized. Runtime construction still relies on exact live continuity
identity/lifecycle state rather than claiming hostile same-process Python code
cannot forge private objects.

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

The orchestrator retains ownership of the exact live `AdmissionContinuity` until
phase 7.1 commits. Passing continuity into the evaluator does not transfer
ownership. Denied/indeterminate terminals and exceptions before adoption commit do
not close or consume continuity inside the evaluator; the orchestrator remains
responsible for unused continuity.

Phase 7.1 is a transaction with two distinct boundaries:

1. the **adoption commit**, where continuity moves from IDLE to ownership by the
   already-complete authority object; and
2. the **caller handoff**, where the already-constructed
   `(PeerAdmissionAuditRecord, authority)` tuple is returned.

The caller handoff is the ownership commit to the caller. Between adoption commit
and caller handoff, the evaluator owns the authority and must dispose of it on every
abnormal exit.

The implementation obeys all of these rules:

1. `AuthorityConstructionUnavailable` has a closed operational vocabulary. The
   evaluator catches exactly that type; it does not widen the clause to
   `OSError`, `RuntimeError`, `Exception`, or `BaseException`. New expected
   operational adoption failures are classified by the adoption helper.
2. Raising `AuthorityConstructionUnavailable` certifies that no authority exists
   and continuity ownership is not ambiguous: continuity is either still valid,
   IDLE, and orchestrator-owned, or has been completely and successfully closed.
   Failed or uncertain cleanup is containment/fatal and cannot be represented by
   this operational exception.
3. Construction of the pre-adoption
   `INDETERMINATE / AUTHORITY_CONSTRUCTION_FAILED` audit is deliberately not
   transaction-wrapped. No authority exists on that path; if audit projection
   itself is broken, the original exception propagates directly.
4. Every potentially failing validation, allocation, allowed-use-kind construction,
   callback construction, native/liveness check, and authority initialization is
   completed before adoption commit.
5. Adoption is represented by one state-bearing field on continuity,
   `_adopted_by: None | _AuthoritativePeerAdmission`. `None` means IDLE;
   storing the exact already-complete authority means ADOPTED. This makes
   "ADOPTED but ownerless" structurally unrepresentable.
6. `AdmissionContinuity._adopt(authority)` performs all precondition validation
   before any state mutation. The `None -> authority` assignment is its first and
   only state-bearing mutation.
7. The adoption assignment is the adoption helper's last executable operation other
   than `return authority`. No allocation, logging, metric, callback, lazy
   attribute access, formatting, or other fallible work occurs between the
   assignment and helper return.
8. Post-adoption construction of the
   `ADMITTED / ADMISSION_REQUIREMENTS_MET` audit and construction of the frozen
   two-element return tuple are transaction-protected. If either raises, the
   evaluator closes the authority before propagating.
9. If that authority close succeeds, including the ordinary already-successfully-
   closed idempotent return, the original handoff exception is re-raised unchanged.
10. If the handoff operation fails and authority cleanup also fails, the evaluator
    raises `AdmissionHandoffFailure`, a `BaseExceptionGroup` subclass containing
    both failures. The subclass identity is regression-tested because CPython's
    exact-base `BaseExceptionGroup` constructor otherwise demotes all-Exception
    groups to `ExceptionGroup`. The raise uses `from None` only to suppress the
    redundant outer exception context; neither contained failure is discarded.
11. After the protected audit and tuple construction succeeds, `return outcome`
    is the final success-path statement. No fallible telemetry, logging, allocation,
    callback, or correlation work occurs between tuple creation and return.
12. Only successful return of that tuple transfers authority ownership from the
    evaluator to the caller.

The phase-7 property is therefore: **there is no representable intermediate state
in which adoption succeeded but no complete owner exists.**

`AuthorityConstructionUnavailable` may cover only known recoverable adoption
refusals for which its ownership postcondition can be certified, including an
expected adoption-start continuity/liveness refusal. Generic programming failures,
`MemoryError`, impossible state, and containment are not normalized into this
terminal. The helper owns the translation from its explicitly enumerated
operational causes to `AuthorityConstructionUnavailable`.

During evaluation ownership, callers must not concurrently close, mutate, mint
from, transfer, or otherwise operate on continuity. V1 introduces no observable
`ADOPTING` state.

Phase 6.3 remains the defensive check that continuity is valid/open immediately
before phase-7 construction begins. If concurrent evaluation ownership is
introduced later, this contract must be amended with an explicit synchronization
and transition model.

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
change, connection loss, explicit continuity/authority closure, or other continuity
invalidation does not retroactively cancel, abort, or wait for that already-started
operation through this subsystem.

Explicit close invalidates and burns any outstanding token that has been minted but
not yet consumed. Consumption attempted after close fails and does not authorize
the operation. A successfully consumed token is the point-in-time boundary; close
affects only future admission-side use and releases continuity-owned resources.

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

The evaluator/authority integration PR must update the production
`LEGAL_RESULT_PAIRS`, production audit-schema validation, and phase-7.1 evaluator
branch together in the same enabling implementation commit. That commit must add
exactly `('ADMITTED', 'ADMISSION_REQUIREMENTS_MET')` as the sole positive pair and
retire `('INDETERMINATE', 'PEER_ADMISSION_NOT_IMPLEMENTED')` when its placeholder
branch is replaced. The change is not deferred to the later provenance-only
commit. All other operational terminals in this table, including
`INDETERMINATE / AUTHORITY_CONSTRUCTION_FAILED`, must also have legal production
mappings when their branches become reachable.

The positive-path test must call the real evaluator through successful adoption,
assert the exact positive pair is in the production set, and assert that the
matching live authority is returned. A separately constructed audit model or a
membership-only assertion does not exercise the enabling branch. The retired
placeholder pair and an `ADMITTED` result with any other reason must be rejected.

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

The evaluator is a pure admission-composition layer over already-captured inputs.
It must not import, instantiate, or invoke `PipeContextProducer`,
`NativeAppContainerProbe`, `NativePipeTokenAPI`, or any other native evidence
acquisition component. `peer_evidence` is captured before evaluator entry and is
supplied by the caller as an exact input. A production import dependency from the
evaluator module to the producer module is a layering violation.

Core evaluator contract tests are platform-independent. They construct exact
production record types and deterministic continuity fixtures without invoking
native acquisition, so phases 1-7 ordering, legal-pair closure, precedence,
construction barriers, and authority lifecycle logic run on non-Windows CI as well
as Windows. Windows-only tests are reserved for end-to-end native acquisition and
continuity integration that actually requires Win32 resources. The integration PR
must not make the evaluator's branch-structure test suite Windows-only.

The eventual evaluator returns:

`(PeerAdmissionAuditRecord, authority_or_none)`

The durable audit record owns the terminal `status` and `reason`. Every denied
or indeterminate result has `authority_or_none is None`. Only successful phase
7.1 may return the exact live authoritative admission object.

### PeerAdmissionAuditRecord schema

`PeerAdmissionAuditRecord` is a frozen Pydantic durable projection. Its production
shape is part of this contract and is not left to evaluator implementation choice.

It contains at least these fields:

- `status: Literal['DENIED', 'INDETERMINATE', 'ADMITTED']`;
- `reason`, from the evaluator's closed operational reason vocabulary, with the
  pair `(status, reason)` required to be a member of `LEGAL_RESULT_PAIRS`;
- `terminal_phase: Literal['1', '2.1', '2.2', '2.3', '3.1', '3.2', '3.3',
  '4.1a', '4.1b', '4.2', '5.1a', '5.1b', '5.2', '6.1', '6.2', '6.3', '7.1']`;
- `admission_granted: Literal[False]`;
- `authorization_granted: Literal[False]`;
- `grants_evaluated: Literal[False]`;
- `signing_evaluated: Literal[False]`;
- both AppContainer-axis audit dispositions, projected independently as
  `pipe_context_classification` and `process_primary_classification`, each one
  of `APPCONTAINER`, `NON_APPCONTAINER`, `CLASSIFICATION_CONFLICT`, or
  `UNAVAILABLE`;
- the exact evidence binding fields:
  `connection_operation_id`, `pipe_lease_id`,
  `process_lease_operation_id`, `process_pid`,
  `process_creation_filetime`, and `capture_ordinal`;
- `evaluated_policy_revision` and `evaluated_policy_digest`.

`PeerAdmissionAuditRecord` is a durable projection of the evaluator terminal, not
an authorization capability. It records that admission occurred through its
`status/reason` pair but never grants admission or authorization itself.
Accordingly, `admission_granted`, `authorization_granted`,
`grants_evaluated`, and `signing_evaluated` are permanently inert
(`Literal[False]`) on every terminal, including `ADMITTED`. Live admission
authority exists only in the separately returned authoritative object. No
production admission/use path may accept the audit, its flags, its status/reason,
or a deserialized copy in place of that exact live authority and its continuity
gate. Later authority closure or invalidation does not rewrite the durable audit.

The legacy `NativePeerAdmissionResult` is retired by the evaluator/authority
integration rather than widened. `PeerAdmissionAuditRecord` becomes the sole
durable evaluator terminal record.

`terminal_phase` is the closed string Literal above, not a free-form string or
numeric phase number. It records the phase that selected the terminal, not the
latest phase whose facts are represented in the audit. The audit label `'3.3'`
groups terminal sub-checks 3.3a and 3.3c; sub-check 3.3b is a pass-through and does
not itself emit a terminal. Only phase `'7.1'` may carry `ADMITTED`.

For a phase-1 `INVALID_ADMISSION_EVIDENCE` terminal, exact input validation has
not completed. The audit must not partially trust or mix fields from invalid
inputs. In that one case, both classification projections, all binding fields, and
the evaluated-policy revision/digest are `None` as one all-or-nothing projection.

Immediately after all phase-1 input validation succeeds, and before phase 2 begins,
the evaluator snapshots both axis dispositions and the complete common binding
from validated `peer_evidence`, plus revision/digest from validated
`evaluated_policy`. Every operational terminal selected by phases 2 through 7
carries that same complete immutable projection, regardless of which of those
phases wins. Fields are not progressively populated by their corresponding policy
phases. In particular, a phase-2 denial still records both already-captured axes,
and phase-6.2 policy-binding failure records the supplied validated evaluation
policy rather than replacing it with continuity's policy.

A validated unavailable axis projects the literal `UNAVAILABLE`, not `None`;
`None` here means phase-1 validation did not complete. Projection copies validated
input facts only: it performs no later native acquisition, does not turn those
facts into passed policy checks, and never overrides first-failure precedence.

The audit record contains no live continuity reference, authority object, use token,
native handle, callable, or reconstruction capability.

The contract tests are permanent. The temporary branch stub is only a phase-table
exerciser. Every test that exists in the stub PR must continue to pass unchanged
against the real evaluator; only the test driver/factories that construct production
inputs may change. The same permanent test file is expected to grow with additional
tests for phase 7.1, the construction barrier, authority lifecycle, and authority
use-kind behavior that are genuinely unreachable under the stub. Those additions
are required integration coverage, not a violation of the unchanged-passing
criterion. Adding previously-unreachable tests does not relax the requirement that
all pre-existing phase-1-through-6 test bodies and assertions continue to pass
unchanged against the production evaluator. Tests therefore assert the evaluator's
call signature, durable terminal pair, phase precedence, and authority
presence/absence, not private stub object shape.

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
- phase-1 invalid input yields no partial axis, binding, or policy projection;
- an early phase-2 terminal still retains the complete validated input projection;
- phase-6.2 mismatch retains the validated evaluated-policy values without adoption;
- unavailable validated evidence is `UNAVAILABLE`, while unvalidated phase-1 fields
  are `None`;
- `admission_granted`, `authorization_granted`, `grants_evaluated`, and
  `signing_evaluated` remain exactly `False` on every durable audit terminal,
  including `ADMITTED`;
- authority closure does not rewrite the durable positive status/reason audit;
- `terminal_phase` accepts only the closed Literal vocabulary, with `'3.3'`
  representing its documented terminal sub-checks and `'7.1'` the sole positive phase;
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
4. implement evaluator/authority integration, the production audit schema, and the
   complete runtime legal-pair changes in the same enabling implementation commit;
5. add native/integration tests and obtain a complete successful enabling gate for
   the exact implementation head `H`, leaving reviewed-against metadata at `N/A`;
6. append the provenance-only documentation commit `D` that records `H` and its run
   reference, as specified in Reviewed-against-implementation publication;
7. pass the current-head gate on `D`, then merge the positive path. No validated
   commit is amended to refer to itself and the field does not name the merge commit.

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
