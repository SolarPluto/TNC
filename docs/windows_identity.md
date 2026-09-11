# Read-only Windows operator identity

`read_windows_operator_identity()` inspects the current local process and returns
an immutable WindowsOperatorIdentity containing user SID, process ID, thread ID
and an elevation fact. It accepts no caller-supplied SID, token handle, process ID,
username or identity override. It does not authorize provisioning.

The initial profile rejects any thread impersonation token. Only ERROR_NO_TOKEN
from OpenThreadToken permits inspecting the process token. Other failures deny;
there is no revert-to-service-identity fallback. The helper observes thread-token
absence again before returning and closes any acquired token handles.
[Microsoft OpenThreadToken reference](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken).

Native access requests TOKEN_QUERY only. GetTokenInformation reads TokenType,
TokenUser and TokenElevation. The variable TokenUser buffer has a bounded allocation;
fixed-size scalar fields use their defined buffers directly. Return lengths are
checked before interpreting data.
[Microsoft GetTokenInformation reference](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).

The SID pointer and variable-length structure must lie within the returned buffer
before native SID validation/conversion. The converted SID string allocation is
released with LocalFree.
[Microsoft SID conversion reference](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsidw).

The implementation uses standard-library ctypes, explicit native function signatures
and system-directory DLL loading. It adds no dependencies and makes no privilege,
token, account, certificate, database or ACL changes. Acquired token handles and SID
string allocations are released on success and failure. The public helper returns
a generic WindowsIdentityError when inspection or cleanup fails. Non-Windows calls
fail without a username/environment fallback.

## Limits

Elevation is an observed fact, not TNC administrative permission. The reader identifies
its own process user, not a remote client or the person operating another process.
It is intended for a future local provisioning entry point, not for inferring a
requester's identity from a service's process token.

Repeated thread-token observations do not provide an atomic guarantee against hostile
code changing token state inside the same process. The trusted host/process boundary
still applies. A future provisioning session must independently check protected
operator policy, deployment binding, manifest and nominated certificate validation.

No allowlist, provisioning adapter, activation command or transport route is connected
to this reader. Existing journal execution guards and real ABC review state remain
unchanged.

## Verification

33 tests cover identity facts, primary-token requirements, impersonation rejection,
API failures, handle cleanup, bounded native buffers, SID pointer/length checks,
string allocation cleanup, generic errors and rejection of input overrides.

Two tests run against actual Windows tokens: one compares the SID with the Windows
whoami utility and checks process/thread IDs; the other repeats native reads. They
do not print identity/token contents or grant the current user permissions. Native
tests are skipped on non-Windows hosts; failure-path tests explicitly use fakes.

The real tests exposed TokenElevation's rejection of a zero-length size probe on
this host. The implementation now reads fixed-size token classes directly and tests
both successful results and invalid native return lengths.
