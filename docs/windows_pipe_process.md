# Disposable native Windows pipe harness — Deliverable 3

`tests/test_windows_pipe_process.py` exercises the bounded adapter with real
kernel pipes in disposable spawned processes. The parent exchanges only bounded
JSON control messages and owns process teardown. The test never creates accounts,
enables privileges, changes machine policy, signs data, or publishes runtime state.

## Native coverage

Thirteen scenarios verify:

- Pending connect and early-connect (`ERROR_PIPE_CONNECTED`) round trips.
- Native client/server PID and process-creation-time correlation.
- Cancellation of pending connect, read, and backpressured write operations.
- Real request-deadline expiry followed by bounded cancellation cleanup.
- Client disconnect while a read is pending.
- First-instance/name collision denial without fallback. Windows may report
  ACCESS_DENIED or PIPE_BUSY depending on which creation constraint rejects first.
- Client rejection of a mismatched server PID or creation time before data transfer.
- Anonymous client access denial with successful thread reversion checked afterward.
- Supervisor termination of a worker with pending I/O, followed by successful
  creation of the same name in a replacement worker.
- Containment with actual pending I/O and an injected invalid clock, retained
  allocations, and supervisor termination. This is deliberately a mixed
  native/fault-injected case, not evidence of an actual clock or kernel failure.

Normal cleanup paths compare process handle counts before endpoint creation and
after disposal. Pending buffers remain in the adapter registry until completion
or process exit. No synchronization events are signaled after killing a child.

## Identities and descriptor verification

Normal test peers run under the already-available operator identity. The service
ACE grants this principal access; the policy retains a distinct well-known client
ACE. These tests do not impersonate an enrolled second service/client account or
claim validation of that second account's enrollment. The original DACL is not
relaxed to accommodate test identities.

The server reads back the actual owner and DACL, compares their exact projections
with the generated descriptor, and verifies DACL protection. The read uses a
bounded size probe and parses within that allocation. On this host the successful
GetKernelObjectSecurity call clears LengthNeeded, so it is not used as the returned
payload length. The existing bounded descriptor parser checks every offset.

The anonymous test uses the OS anonymous token in a disposable client thread and
checks RevertToSelf before further work. A failed reversion terminates the child.
It requires no newly provisioned identity or enabled privilege.

## Limits

Kernel PID/creation-time checks here are fixture correlation, not a complete
production peer-authentication protocol. Native effective pipe-token inspection,
enrollment/grant enforcement, and signing-service integration remain separate.
Successful same-account tests do not prove resistance to hostile code with the same
account privileges or delegated handles.

The adapter remains test-only. Unknown completion states require worker
containment; this supervisor demonstrates the termination obligation. No general
production supervisor is installed. Process-exit tests do not simulate power loss,
prove universal memory safety, or cover every Windows version and architecture.
Non-Windows environments skip the native tests explicitly; native setup failures
on Windows fail the tests rather than silently weakening the profile.

## API references

- [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)
- [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
- [GetKernelObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getkernelobjectsecurity)
- [ImpersonateAnonymousToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateanonymoustoken)
