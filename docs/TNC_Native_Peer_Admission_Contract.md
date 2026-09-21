# Native Windows Peer Admission Contract

## Scope

This document defines the v1 decision contract for native Windows peer admission. It is a policy and schema contract. The pipe-context producer and fail-closed evaluator are implemented; the terminal `ADMITTED` path remains intentionally absent until the separate continuity contract in [`windows_peer_admission_continuity.md`](windows_peer_admission_continuity.md) is implemented.

The existing AppContainer evidence rules remain normative in
[`TNC_AppContainer_Evidence_Model.md`](TNC_AppContainer_Evidence_Model.md). This document references that classifier rather than duplicating its truth table.

V1 keeps authorization, grants, custody, and signing outside the admission decision.

## Result semantics

The coarse status axis represents whether the gate reached a definitive policy decision:

| Status | Meaning |
| --- | --- |
| `INDETERMINATE` | Required evidence is invalid, unavailable, or insufficient to establish a definitive admission-policy fact. |
| `DENIED` | Sufficient evidence establishes a disqualifying fact. |
| `ADMITTED` | Reserved for the future successful path after every required admission fact has been evaluated and passed. It is not implemented by the current gate. |

Before pipe-context producer integration, the ordinary peer path terminated at `INDETERMINATE / APP_CONTAINER_EXCLUSION_UNPROVEN`. The current evaluator retires that terminal reason: unresolved AppContainer acquisition maps to `PEER_EVIDENCE_UNAVAILABLE`, conflicting AppContainer facts map to `PIPE_CONTEXT_CLASSIFICATION_CONFLICT`, and a proven non-AppContainer pipe context that passes every other implemented check terminates at `PEER_ADMISSION_NOT_IMPLEMENTED` until the continuity-backed `ADMITTED` path exists.

## Closed status/reason relation

Status and reason are not independent strings. The implementation must define one immutable set of legal pairs and validate membership against that set. Tests should derive the valid-pair cases from the same declaration and separately verify that illegal cross-pairings are rejected.

At minimum, v1 must preserve these categories:

| Status | Reason | Meaning |
| --- | --- | --- |
| `INDETERMINATE` | `PEER_EVIDENCE_UNAVAILABLE` | Required admission evidence was not obtained, regardless of whether failure occurred during peer interaction, native capture, or post-capture server-side classification. The producer status and failure metadata on the evaluator input identify the stage. |
| `INDETERMINATE` | `PIPE_CONTEXT_CLASSIFICATION_CONFLICT` | Required pipe-context evidence was obtained, but the AppContainer signals conflict and cannot yield a clean classification. |
| `INDETERMINATE` | `PEER_ADMISSION_NOT_IMPLEMENTED` | All currently implemented required admission checks passed, including proven non-AppContainer pipe context, but the terminal `ADMITTED` path is not implemented yet. |
| `INDETERMINATE` | existing invalid/capture-unavailable contract reasons | The supplied or produced evidence cannot support a trustworthy decision. |
| `DENIED` | `PEER_CLASS_UNSUPPORTED` | The peer was successfully characterized and falls outside the v1 supported process class. |
| `DENIED` | `APP_CONTAINER_DENIED` | Positive AppContainer status was established. |
| `DENIED` | existing identity/process/endpoint/descriptor mismatch reasons | A required binding was affirmatively disproven. |

The validator error for an illegal pair must include the rejected `(status, reason)` values and the legal pairs, rather than returning a generic invalid-combination message.

The initial positive pair is reserved as exactly `ADMITTED / ADMISSION_REQUIREMENTS_MET`. It may become reachable only after the continuity contract is implemented. The evaluator is the sole producer of that pair, and it may synthesize it only after all required facts pass and a live admission-continuity object has been established and bound to the same connection/process instance. The serialized result alone is never an authorization capability.


### Evaluator input and result shape

The evaluator consumes the producer's frozen `PipePeerAdmissionEvidence` union directly. The `pipe_context` argument is required; omission is not a third evidence state. A failed acquisition attempt is represented explicitly by `CAPTURE_UNAVAILABLE`.

The evaluator's result is a coarse policy projection, not a standalone audit record. `NativePeerAdmissionResult` need not duplicate the producer's detailed failure stage, Win32 error, connection binding, or classification metadata. Audit interpretation therefore requires the result together with the exact evaluator inputs. This permits both `CAPTURE_UNAVAILABLE` and `CAPTURED_CLASSIFICATION_UNAVAILABLE` to map to `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE` without erasing the operational distinction from the evidence record.

`CAPTURED_CLASSIFICATION_CONFLICT` is not an availability failure. It maps to `INDETERMINATE / PIPE_CONTEXT_CLASSIFICATION_CONFLICT`, while the producer record preserves the underlying classifier reason such as `APPCONTAINER_SIGNAL_CONFLICT`.


### Current terminal-state mapping

The evaluator requires `pipe_context: PipePeerAdmissionEvidence` and maps the producer statuses as follows:

| Pipe-context status | Evaluator behavior |
| --- | --- |
| `CAPTURED_APPCONTAINER` | `DENIED / APP_CONTAINER_DENIED` |
| `CAPTURED_NON_APPCONTAINER` | Continue all remaining admission checks; if every implemented requirement passes, return `INDETERMINATE / PEER_ADMISSION_NOT_IMPLEMENTED`. |
| `CAPTURED_CLASSIFICATION_CONFLICT` | `INDETERMINATE / PIPE_CONTEXT_CLASSIFICATION_CONFLICT` |
| `CAPTURED_CLASSIFICATION_UNAVAILABLE` | `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE` |
| `CAPTURE_UNAVAILABLE` | `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE` |

`APP_CONTAINER_EXCLUSION_UNPROVEN` is retired from the native peer admission evaluator. It described the old IDENTIFICATION-level blocker and would be factually incorrect after a `CAPTURED_NON_APPCONTAINER` result. The closed status/reason relation therefore adds `(INDETERMINATE, PIPE_CONTEXT_CLASSIFICATION_CONFLICT)` and `(INDETERMINATE, PEER_ADMISSION_NOT_IMPLEMENTED)` and removes `(INDETERMINATE, APP_CONTAINER_EXCLUSION_UNPROVEN)`.



### Post-finish lease-binding boundary

`PipePeerAdmissionEvidence` is bound by its producer to the live `OwnedProcessLease` before that lease is finished. The current `ProcessLeaseAudit` intentionally projects only correlation status/reason/source and does not serialize the lease operation ID, pipe lease ID, PID, or creation time. Consequently, the current evaluator cannot recompute or independently cross-check the producer snapshot's connection/process binding from `ProcessLeaseAudit` after `finish()`.

The evaluator therefore requires an exact `ProcessLeaseAudit` and an exact producer `PipePeerAdmissionEvidence`, while relying on the producer's live-object binding as the provenance link between them. Adding a second evaluator-side binding check would require a future `ProcessLeaseAudit` schema extension carrying matching identity fields; the evaluator must not fabricate such a comparison from absent data.

### Admission continuity boundary

A future positive admission must not be represented by a frozen audit/result alone. `OwnedProcessLease.finish()` releases the lease's native ownership and returns a durable `ProcessLeaseAudit`; therefore a post-`finish()` audit record cannot establish live process continuity at use time.

Before `ADMITTED` becomes reachable, the implementation must introduce a separate, non-serializable admission-continuity object. It must acquire independent ownership of the native resources needed for use-time continuity before the original process lease is finished, bind itself to the same connection/process identity carried by the producer evidence, and remain live until the privileged transaction is complete or explicitly released. The exact lifecycle, revalidation requirements, invalidation events, and phase separation are normative in [`windows_peer_admission_continuity.md`](windows_peer_admission_continuity.md).

### Evaluator precedence

The evaluator must preserve the existing non-AppContainer failure behavior one-for-one. The evaluator therefore uses this precedence after exact input validation:

1. A positively classified pipe context (`CAPTURED_APPCONTAINER`) is an unconditional hard exclusion and returns `DENIED / APP_CONTAINER_DENIED`.
2. Existing lease and peer-audit violations retain their current specific reasons. A pipe-context conflict or unavailable state must not mask an already-established identity, process-correlation, endpoint, descriptor, integrity, restriction, or peer-class denial.
3. If those existing checks pass, `CAPTURED_CLASSIFICATION_CONFLICT` returns `INDETERMINATE / PIPE_CONTEXT_CLASSIFICATION_CONFLICT`, while either unavailable variant returns `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE`.
4. Only `CAPTURED_NON_APPCONTAINER` may continue to the all-current-checks-passed terminal state, which is `INDETERMINATE / PEER_ADMISSION_NOT_IMPLEMENTED` until an `ADMITTED` result exists.

The terminal reason `PEER_ADMISSION_NOT_IMPLEMENTED` is procedural, not epistemic: it means all currently implemented admission requirements were satisfied and the implementation intentionally lacks the final admitted state. It does not imply peer ambiguity or missing evidence.

PR B tests must migrate existing failure cases without changing their asserted reason codes merely to reach the new terminal state. In particular, non-AppContainer context is the neutral context for tests of unrelated lease/peer failures.

A parametrized fail-closed invariant test must cover every legal `PipePeerAdmissionEvidence` variant and assert that both `admission_granted` and `authorization_granted` remain false and that the returned `(status, reason)` pair belongs to the evaluator's closed legal-pair set.

## Facts, not verdicts

Admission evidence records contain facts only. They must not contain fields whose type or meaning is an admission outcome, such as `verdict`, `admissible`, `admission_granted`, or caller-supplied equivalents.

Typical fact-shaped fields include peer/process identity, token type and level, integrity level, AppContainer classification, process protection class, scope, and observation time.

Callers may supply favorable-looking facts, but they cannot manufacture `ADMITTED`; the evaluator alone consumes the facts and produces the terminal admission result.

## V1 supported peer-process class

The initial policy target is deliberately bounded:

- ordinary, non-protected local processes;
- the expected account relationship, either the same account or an explicitly enumerated peer account;
- peer integrity at the server integrity level or lower.

Higher-integrity peers, protected/PPL processes, and unapproved cross-account peers are outside the v1 supported class unless a later contract explicitly extends the policy.

Two failure modes must remain distinct:

- **evidence unobtainable:** process or token acquisition/query fails, so a required fact was not established -> `INDETERMINATE / PEER_EVIDENCE_UNAVAILABLE`;
- **class unsupported:** acquisition succeeds and the peer is characterized, but its class is outside this contract -> `DENIED / PEER_CLASS_UNSUPPORTED`.

The distinction is operationally significant and must not be collapsed into one generic access failure.

## Required admission facts

V1 admission requires all of the following facts to be established:

| Fact | Current evidence source | Current state |
| --- | --- | --- |
| Identity and scope binding | Native pipe token capture plus peer-correlation audit | Obtainable |
| Process-instance/lease correlation | Retained native process handle, PID, creation time, liveness, and pipe-client PID checks | Obtainable |
| Supported peer-process class | Process/token observations under the v1 policy above | Policy defined; producer details incomplete |
| AppContainer exclusion for the actual pipe-client security context | Captured pipe token at `SecurityImpersonation`, classified after successful revert | Producer contract defined; implementation pending |
| Evidence freshness | Policy timestamp/expiry, observation time, evaluation time | Obtainable |
| Continuity through privileged release/use | Separate live admission-continuity object acquired from the bound connection/process instance before `OwnedProcessLease.finish()`; see `windows_peer_admission_continuity.md` | Contract defined; implementation pending |
| Revocation state at release/use | Use-time continuity revalidation against the current revocation/policy view | Contract defined; implementation pending |

AppContainer exclusion is a hard v1 requirement. It is not a tier gate in this version because no admitted-profile or grant-tier schema exists yet.

## Pipe-token versus process-token continuity

The process-primary shortcut is not a valid admission invariant. The continuity experiment on Windows Server 2025 build 26100 constructed a client whose process PRIMARY token was independently non-AppContainer while the connecting thread carried an AppContainer impersonation token. The named-pipe observation followed the connecting thread and produced `THREAD_TOKEN`, while the client-attested PID matched `GetNamedPipeClientProcessId`. That positive observation is scoped to the tested build and construction. The design consequence is general: one counterexample is sufficient to refute the universal assumption that the pipe-client security context is equivalent to the process PRIMARY token.

V1 therefore uses the pipe-client token itself as the AppContainer evidence source. The admission connection must use `SECURITY_IMPERSONATION`, and the producer must capture the exact pipe-client token before interpreting classes 29/31. PID, creation time, and `OwnedProcessLease` remain required for process-instance correlation; they are not the AppContainer classification source.

The required native sequence is:

1. call `ImpersonateNamedPipeClient` on the admission connection;
2. on the same thread, call `OpenThreadToken(..., TOKEN_QUERY, TRUE, ...)`; `TOKEN_QUERY` is the only requested token access right, and `OpenAsSelf=TRUE` is mandatory so the access check is performed against the server process security context rather than the impersonated peer;
3. on that same thread, call `RevertToSelf`. Once `ImpersonateNamedPipeClient` succeeds, reversion is mandatory on every ordinary exit path, including `OpenThreadToken` failure; no function may return, raise, log, write evidence, or otherwise continue while the thread remains impersonating;
4. only after successful reversion, classify the retained token handle under the server security context and construct immutable evidence;
5. bind that evidence to the specific connection and `OwnedProcessLease`;
6. close the token handle at the end of the capture-classify-snapshot window; the admission decision consumes the immutable snapshot, not a later token re-query.

Thread affinity is required only from impersonation through successful reversion. After reversion, the retained token handle may be classified and snapshotted on another thread.

### Reversion failure is process-fatal

A failed `RevertToSelf` is a server security-state integrity failure, not an ordinary classification failure. Microsoft documents that execution continues in the client's context if reversion fails and recommends terminating the process rather than continuing: <https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself>.

The implementation must define exactly one module-level constant `EXIT_REVERT_FAILED = 0xE401` for this path and call `TerminateProcess(GetCurrentProcess(), EXIT_REVERT_FAILED)` immediately when `RevertToSelf` returns false. No Python-level cleanup, logging, exception formatting, evidence write, classification, or other statement may execute between observing the failed revert and the native termination call. This does not forbid a `try/finally` or equivalent structure around the impersonation/capture region; it requires that every ordinary exit after successful impersonation reaches reversion, and that the `RevertToSelf == FALSE` branch itself contains no intervening Python work before native termination. The implementation comment at that call site must cite the Microsoft guidance and explain that any subsequent Python code would still execute under the peer's security context.

### Classification and evidence binding

After successful reversion, class-29/class-31 queries and ABI validation execute under the server's own security context. Failures at this stage are server-side classification failures against an already captured handle; they must never be reported as peer refusal. The evaluator may use the coarse policy reason `PEER_EVIDENCE_UNAVAILABLE` for these failures because required evidence was not obtained, but the producer status and failure metadata must preserve that the failure occurred during post-capture server-side classification rather than peer interaction or token capture.

Token-handle ownership must be structurally exception-safe. A `try/finally` (or equivalent native ownership primitive) must span retained-handle classification and snapshot construction so `CloseHandle` is guaranteed on successful classification, class-29/class-31 query failure, ABI-shape/extent rejection, and any other ordinary abandonment path. Reversion failure is the sole exception: that path terminates the process immediately and intentionally performs no Python-level unwinding.

The immutable snapshot must be self-describing enough to reject substitution between connections. At minimum it must bind the captured classification to the admission connection identity, the corresponding `OwnedProcessLease` identity/process instance, and a monotonic capture order within the transaction. A timestamp may accompany that order as supplementary context but does not replace it. The classification result itself must state that it derives from the captured pipe token. The live token handle is temporary machinery and need only survive the bounded capture-classify-snapshot window.

## Required versus audit-only token evidence

Whether a token information class is admission-required is a fixed evaluator policy declaration, not a per-call option supplied by callers. The native probe remains a fact collector: it reports which classes were observed and which were unavailable, while the evaluator decides whether a missing fact is fatal to admission.

For the current AppContainer classifier:

- class 29 (`TokenIsAppContainer`) is admission-relevant;
- class 31 (AppContainer SID) is admission-relevant as a consistency/conflict signal;
- class 30 (capabilities) is audit-only.

A required-fact acquisition failure produces an indeterminate admission result. Failure of audit-only telemetry must not, by itself, invalidate an otherwise sufficient admission decision.

The implemented evidence shape uses `AppContainerTokenEvidence.capability_sids: tuple[SID, ...] | None`: `()` means class 30 was successfully queried and the capability set was observed empty; `None` means class 30 was unavailable. Class-30 failure does not alter AppContainer classification. A silent fallback from query failure to `()` would manufacture the false fact `no capabilities`. Class 29/31 failures remain classification-unavailable outcomes. This policy is fixed in the producer/evaluator contract and is not caller-configurable.

## Producer ownership boundary

Native acquisition must remain internally owned. Do not run arbitrary caller callbacks while a process lease or captured pipe-token handle is live.

`OwnedProcessLease` and the captured pipe token serve different roles and neither replaces the other:

- the process lease, PID, creation time, liveness, and pipe-client PID establish process-instance correlation;
- the captured pipe token supplies the security-context facts used for AppContainer classification.

The producer freezes those facts into one immutable, connection-bound evidence record before releasing native handles. A later admission stage may consume the snapshot after the token handle has been closed, but it must not substitute a process PRIMARY token or a token from a second connection for the captured pipe-token classification.

A post-`finish()` process query is too late because the process-handle binding has already been released.

## Continuity-experiment preconditions

The thread-token continuity experiment is interpretable only if all of these preconditions hold:

1. **Construction feasibility:** obtain a known AppContainer source token, open it with the rights required for duplication, create an impersonation token at `SecurityImpersonation`, and assign it to the connecting thread with `SetThreadToken`. If this construction is denied on the target runner, record that as a producer/harness limitation rather than as evidence about named-pipe token selection. The inverse construction (AppContainer process with a non-AppContainer thread token) is an acceptable substitute if it is easier to construct.
2. **Independent source oracle:** before duplication or pipe connection, raw `GetTokenInformation(TokenIsAppContainer)` on the source token must establish the source AppContainer state independently of the TNC classifier/probe path.
3. **Captured-level gate:** after `ImpersonateNamedPipeClient`, independently require the captured pipe token to be an impersonation token at `SecurityImpersonation` before classifying classes 29/31. A downgraded or unqueryable result is a producer/harness outcome.

Windows documents `SetThreadToken` as assigning an impersonation token to a thread and `DuplicateTokenEx` as able to create an impersonation token from a duplicable token. That establishes API shape, not target-runner feasibility for an AppContainer source token; token-object access checks can still reject the requested duplication/impersonation rights.

## Producer decision

The AppContainer evidence-source question is closed for v1. The producer must capture the pipe-client token at `SecurityImpersonation`, revert immediately, classify that exact retained handle under the server context, bind the resulting immutable classification to the connection and `OwnedProcessLease`, and close the handle at a bounded point.

The build-26100 continuity observation is the positive experimental result supporting this path. Its observation is build-scoped; its counterexample to process-primary equivalence invalidates that shortcut as a general design assumption.
