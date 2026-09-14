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

Record each evidence shape before asserting safety. Both results must remain
audit-only and grant neither admission nor authorization. IDENTIFICATION must
never produce exclusion proof. After both observations, check the precommitted
expectations: negative flag/null SID at both levels, UNPROVEN at IDENTIFICATION,
and PROVEN_NON_APPCONTAINER at IMPERSONATION. Capability count is recorded, not
used to decide either branch.

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
unit coverage; this experiment closes a native ordinary-pipe coverage gap.
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
Hosted Server 2025 validation remains pending.
