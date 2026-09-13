# Windows pipe token capture

This milestone adds `windows_pipe_token.py` and fake-injected tests. It does not
authorize peers, invoke signing, create workers, or connect native token capture
to a production endpoint. The explicit ctypes path still requires disposable
native-process acceptance tests before integration.

## Ownership and capture

`PipeTokenInspector.capture_preamble` accepts an endpoint-owned, completed READ
operation containing exactly `TNCP`, version byte 1, and a 32-byte host-retained
challenge. The operation must remain the endpoint's active operation. It cannot
be disposed or replaced before inspection. The normal endpoint API consequently
cannot perform another read that would change the last-message security context.

The returned boundary is opaque, non-serializable, process/thread bound, and
single use. A process-local weak registry also prevents another inspector from
claiming the same operation. Each inspector permits at most 64 claims. Inspection
consumes a known boundary before validation, including denied attempts. These
Python ownership checks assume trusted host code; they do not constrain arbitrary
same-process memory modification or direct Win32 calls outside the adapter.

Capture rejects a pre-existing thread token. It attempts impersonation only after
checking the completed preamble and its original monotonic deadline. It opens the
effective thread token with exactly `TOKEN_QUERY`, using `OpenAsSelf=True` for the
access check. It never substitutes the process token. Anonymous, missing, or
unavailable effective tokens produce no identity evidence.

The query sequence captures user SID, enabled logon SID, authentication LUID,
session, token type/level, integrity RID, restriction indicators, and the reported
AppContainer flag. Token identity and modification statistics are compared before
and after extraction. The result is an immutable audit record, always carrying
`authorization_granted=False`; it is not a credential or a policy decision.

## Bounds and cleanup

Each token buffer is limited to 64 KiB; cumulative allocations, including discarded
growth buffers, are limited to 256 KiB. Group lists are limited to 256 entries.
Variable queries permit one strictly growing retry. Fixed-size queries require
their exact return length. SID pointers and complete SID extents must lie within
the returned buffer, after the associated header; decoding never follows an
unchecked native pointer. Duplicate groups and ambiguous/disabled logon identities
are rejected.

The original read deadline is checked around token queries and before returning
facts. Clock regression and exact-deadline arrival fail closed. These checks do
not interrupt a blocked synchronous kernel call: a future disposable-worker
supervisor must supply that containment bound. Cleanup runs even after expiration.
Only trusted internal clock functions, or explicit test clocks, may be supplied.

Token closure and `RevertToSelf` are independent cleanup actions. Reversion is
attempted even after an unsuccessful impersonation call. Closure/reversion failure,
a pre-existing token, or a residual token marks the endpoint and inspector fatal.
Fake bindings raise `TokenContainmentRequired`; the explicit native binding calls
`os._exit(78)` without unwinding. Native use must therefore be confined to the
intended disposable broker process. The fake tests do not execute this native exit.

## API distinctions

`TokenIsRestricted` is reserved. This adapter queries documented `TokenHasRestrictions`
and `TokenRestrictedSids` instead. The former indicates filtering history, not a
complete authorization conclusion. A false `TokenIsAppContainer` result on an
identification-level token is insufficient exclusion evidence; the output therefore
always sets `app_container_exclusion_proven=False`. A future policy bridge must
resolve that uncertainty or deny, rather than copy the boolean into an allow rule.
See Microsoft's [token information classes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class).

`TOKEN_STATISTICS.ExpirationTime` is unsupported and is not used as a token expiry
gate. Token IDs and modification IDs are consistency evidence, not a lock against
changes after capture. See [TOKEN_STATISTICS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics).

The relevant cleanup and access contracts are documented in
[OpenThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken),
[ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient),
and [RevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).

## Test coverage and remaining work

The 58 fake-injected tests exercise ABI declarations, exact access rights, read
ownership and replay, clock bounds, buffer growth/limits, malformed SID pointers,
group ambiguity, token changes, cleanup exceptions, and residual impersonation.
Side-effect guards reject native DLL loading and external I/O during fake capture.

Native token acquisition, process-handle lifetime correlation, mutual server
authentication, revised pure policy mapping, and live grant checks remain separate
milestones. No signing, key custody, persistence, or application payload parsing is
introduced. Same-account and privileged compromise remain outside this adapter's
protection.
