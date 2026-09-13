# Disposable native pipe-token tests

`tests/test_windows_pipe_native_token.py` adds ten Windows-only process tests.
They reuse the existing bounded JSON supervisor and native pipe helpers. Each
server and client is a disposable spawned process; parent cleanup terminates and
joins unfinished children. No signing or application request parsing is connected.

## Verified paths

- Real 37-byte preamble delivery and native effective-token capture at both
  identification and impersonation SQOS levels.
- Actual `OpenThreadToken` calls request exactly `TOKEN_QUERY` and `OpenAsSelf=True`;
  a forwarding test observer records those arguments without replacing the call.
- User/logon identity and token statistics are captured as audit facts. The
  current operator SID is checked independently after reversion.
- Replaying a consumed boundary performs no additional token opens.
- Wrong preambles, expired inspection budgets, injected extraction errors, and
  anonymous SQOS produce no identity evidence.
- Normal paths release the read, endpoint, tokens, events, and inspector. The
  final native process handle count matches its baseline. The inspector owns a
  Python synchronization handle, so it is released before that final comparison.
- Injected close/reversion failure after real impersonation, and a real
  pre-existing impersonation token, terminate the worker with exit code 78. No
  result is released. Once the client closes, the pipe name can be created again.
- An anonymous client token is denied by the unchanged pipe DACL with access
  denied; the disposable client then verifies its own successful reversion.

## Native compatibility finding

On the tested Windows host, `TokenHasRestrictions` succeeds with a one-byte
return length even though Microsoft documents a DWORD result. The adapter retains
a four-byte allocation and accepts only one- or four-byte return lengths, decoding
only the reported bytes and requiring a boolean value. Other scalar classes keep
their exact-size checks. Four additional fake regressions cover one-byte acceptance
and rejection of lengths two, three, and five.

Microsoft's documented behavior for
[token information classes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
remains the reference; this compatibility case comes from the native test result.

## Scope limits

Allowed peers use the existing operator account through the service ACE. The
tests do not provision a second account, change privileges, relax the DACL, or
claim distinct-user enrollment coverage. Anonymous denial is a real different
security context; it does not prove all low-integrity or AppContainer cases.

Cleanup failure is deliberately injected at the adapter seam after actual native
impersonation. The tests verify the real fail-fast process exit, not a spontaneous
kernel failure of `RevertToSelf`. This follows Microsoft's requirement to
[shut down on reversion failure](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).

The expired-budget test uses a controlled clock after real preamble completion.
It does not claim to interrupt a stalled synchronous kernel call. Source labels
remain native for native capture; fault scenarios are identified explicitly by
their tests. Process-lifetime helpers only support this supervised harness and
are not a production mutual-authentication service.

Results remain audit-only. Policy grants, integrity admission, AppContainer
exclusion, production mutual authentication, and signing remain disconnected.
