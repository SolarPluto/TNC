# Ordinary-client pipe level comparison

This experiment supplements PR #8; it does not replace its independent positive
PRIMARY oracle or imply that its PRIMARY control was a second pipe level.

## Protocol and interpretation fixed before the run

Establish the current process as an ordinary client using raw PRIMARY-token
GetTokenInformation queries: TokenIsAppContainer must be zero and
TokenAppContainerSid must be null. Then open two disposable real pipe connections
from that same process, requesting IDENTIFICATION and IMPERSONATION respectively.
Verify the client PID, captured user SID, token type, and actual level. Keep each
connection alive through probing and a bounded completion-byte exchange. Reuse
PR #8's bounded overlapped I/O and shared observation reporting.

Both endpoints belong to the current process, so this is self-impersonation.
It does not establish external-process client equivalence. PR #7 also uses a
same-process client, in a separate thread; PR #8 launches an external AppContainer
process. The ordinary PRIMARY oracle additionally requires class 31 to return a
pointer-sized structure containing a null SID. If a different build rejects the
query or returns another size, the test fails oracle setup before measuring
either pipe token. The observed local success is not a portability guarantee.

Record each evidence shape before asserting safety. Both results must remain
audit-only and grant neither admission nor authorization. IDENTIFICATION must
never produce exclusion proof. After both observations, check the precommitted
expectations: negative flag/null SID at both levels, UNPROVEN at IDENTIFICATION,
and PROVEN_NON_APPCONTAINER at IMPERSONATION. Capability count is recorded, not
used to decide either branch.

Safety assertions intentionally remain immediate: an actual safety failure at
the first level stops the experiment. The promise to retain both observations
before checking expectations applies to the final branch-expectation assertions,
not to failures of setup, measurement, or the independent safety invariants.

- Failure of the raw PRIMARY oracle means the ordinary-client premise was not
  established. Setup, PID/user/level, or handshake failures are harness failures.
- A probe/query error is a native measurement failure, not evidence that the
  evaluator has no exclusion path.
- A safety assertion failure is a security-model failure even if an observation
  line is present. A failed branch expectation retains its observation and is
  investigated without weakening the expected result to make the run green.
- A PROVEN_NON_APPCONTAINER observation on a green IMPERSONATION run establishes
  that branch's native reachability for this client and environment. It does not
  prove reliability for all clients, Windows versions, or downstream trust uses.
- UNPROVEN would require inspecting the measured level/evidence and classifier:
  the current classifier returns UNPROVEN only for a valid negative
  IDENTIFICATION token. That status alone cannot establish that Windows lacks
  an exclusion path.

The existing evaluator also permits exclusion for consistent negative PRIMARY
and DELEGATION evidence. Those branches and the IMPERSONATION branch already have
synthetic-evidence unit coverage: the tests construct evidence records rather
than showing Windows produces those records. That is not equivalent to live
coverage. This experiment closes a native ordinary-pipe coverage gap.
No production policy or admission behavior changes. Excluding AppContainer is
one property of a peer, not proof that the peer is safe or trusted.

## Scope of the existing observations

PR #7 and hardened PR #8 observed, on Server 2025:

| Client | Token | Flag / SID / caps | Status |
| --- | --- | --- | --- |
| Ordinary | IDENTIFICATION pipe | False / None / 0 | UNPROVEN |
| AppContainer | IDENTIFICATION pipe | True / matching SID / 0 | APPCONTAINER |
| AppContainer | PRIMARY control | True / matching SID / 0 | APPCONTAINER |

These observations refute universal loss of the positive flag at IDENTIFICATION;
they do not establish a universal ordinary/AppContainer truth table. The
AppContainer-at-IMPERSONATION pipe quadrant remains a separate experiment.
The AppContainer launch explicitly requests zero capabilities; empty capability
observations alone are not proof of complete retrieval.

## Local result

The new real-pipe experiment and related evaluator, native probe, and observation
reporting tests passed locally: **36 passed in 1.91s**. One process (PID 1280)
passed the raw PRIMARY oracle and produced:

| Level | Flag / SID / caps | Status | Reason |
| --- | --- | --- | --- |
| IDENTIFICATION | False / None / 0 | UNPROVEN | IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN |
| IMPERSONATION | False / None / 0 | PROVEN_NON_APPCONTAINER | TOKEN_IS_APPCONTAINER_FALSE_USABLE |

Both observations were recorded and all independent safety assertions passed.
The measured flag/SID/capability shape stayed the same; the verified level changed
the classifier's treatment of negative evidence. This supports native branch
reachability locally, not a claim that the level changed the flag's information.
This establishes exclusion-branch reachability for an ordinary client at
IMPERSONATION on one local host. It does not establish negative reliability
across builds, SKUs, restricted/filtered/low-integrity token variants, or safety
for downstream trust decisions. The local output did not record a build number.
Hosted Server 2025 validation has not run for this follow-up.

The live evaluator-result matrix is:

| Client / level | Evidence category and scope |
| --- | --- |
| Ordinary / IDENTIFICATION | Live negative, UNPROVEN; PR #7 hosted and this follow-up local |
| AppContainer / IDENTIFICATION | Live positive, APPCONTAINER; PR #8 hosted |
| AppContainer / PRIMARY | Live positive, APPCONTAINER mechanism control; PR #8 hosted |
| Ordinary / IMPERSONATION | Live negative, PROVEN_NON_APPCONTAINER; this follow-up local only |
| Ordinary / PRIMARY exclusion | No dedicated live negative evaluator control in this experiment |
| Either polarity / DELEGATION | No live control in these experiments |

The new raw PRIMARY oracle did observe a live negative flag/null SID, but it does
not call the TNC probe or evaluator. It must not be counted as a live
PRIMARY-negative exclusion result. The existing native PRIMARY smoke test accepts
several statuses and does not establish that specific result either.

## Cleanup review follow-up

NativePipeTokenAPI.close and revert are stateless wrappers over CloseHandle and
RevertToSelf; neither tracks consumed handles. The positive harness now registers
token cleanup in ExitStack so a failed close cannot be retried by the outer
finally. Close failure still runs reversion. False returns and ordinary exceptions
from close fail normal cleanup or become notes on an existing assertion.

All three pipe diagnostics now use a shared revert-or-fail-fast callback. A false
return or exception invokes the existing NativePipeTokenAPI.fail_fast mechanism,
which exits the native process with code 78. There is no retry or normal pytest
continuation in an unconfirmed client context. Microsoft specifically recommends
process shutdown after failed [RevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).
This fatal path takes precedence over ordinary cleanup/summary guarantees.

The package-only DACL failure is consistent with Microsoft's documented
[dual-principal access model](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer#appcontainer-overview):
both the user/group portion and the AppContainer portion must grant access;
effective access is their intersection. The local timeout itself did not record
a kernel access-check trace, so this is the documented explanation consistent
with the narrowed user-plus-package ACL succeeding, not a traced diagnosis.

Initial local cleanup/diagnostic validation: **15 passed in 5.17s**. This includes
six injected failure cases covering close False/exception, preservation of an
original failure, and revert False/exception without retry, plus all three live
pipe diagnostics and the observation tests. Evidence shapes were unchanged.
These edits have not received hosted validation and do not inherit b069984's
earlier hosted green result.

The original six injected cases use a fake API whose fail_fast raises a sentinel.
They establish dispatch/callback behavior, not real process termination.
Two later Windows subprocess cases now inject revert False/exception while
keeping the real NativePipeTokenAPI.fail_fast and os._exit implementation. Each
child selects the native API and writes a startup marker; the parent requires
exit code 78 and absence of finally, continuation, and atexit markers.
No actual impersonation or naturally occurring RevertToSelf failure is induced.
This establishes local process termination without Python unwinding for those
two injected paths, not recovery or coverage of every abort mode.

Latest local cleanup/diagnostic validation: **17 passed in 3.30s**, with unchanged
live evidence shapes. The two additional cases are the subprocess tests above.
Hosted validation remains outstanding.

The helper documents why BaseException deliberately includes interrupts during
revert, and why the post-fail_fast assertion is a defensive unreachable guard for
the supplied implementations. Subprocess tests explicitly require tnc importable
by a bare sys.executable, independently of pytest's test-path insertion.
After these comment-only clarifications, the focused cleanup suite was rerun:
**8 passed in 0.96s**, including both original-exception preservation cases and
both direct-close failure cases. No behavior changed in this clarification.
