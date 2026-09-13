# Bounded Windows pipe adapter — fake acceptance milestone

`windows_pipe_native.py` supplies explicit ctypes bindings and an owned-operation
controller for inert test bytes. Importing the module loads no DLL and creates no
pipe. `NativePipeApi()` explicitly loads kernel32 on Windows; the fake acceptance
suite instead injects fake functions and blocks WinDLL loading. The separate
`test_windows_pipe_process.py` suite now exercises native disposable processes;
see `windows_pipe_process.md`. No signing or production peer authentication is connected.

## Native bindings

The binding declares argument/return types for CreateNamedPipeW, CreateEventW,
ConnectNamedPipe, ReadFile, WriteFile, WaitForSingleObject, GetOverlappedResult,
CancelIoEx, and CloseHandle. Fixed-width DWORD/BOOL, pointer-sized fields, the
OVERLAPPED union, and SECURITY_ATTRIBUTES sizes/offsets are checked for the current
process layout. Untested architectures are not thereby certified.

Creation uses the exact name from a revalidated WindowsPeerPolicy, first-instance
and overlapped flags, byte-mode duplex operation, remote rejection, one instance,
and non-inheritable handles. A bounded self-relative descriptor is generated from
the pinned distinct service/client SIDs with a protected DACL and existing exact
rights masks; the existing parser checks its projection. There is no default ACL
or name-collision fallback. This does not implement effective-token inspection.

The profile is documented by Microsoft's [CreateNamedPipe reference](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
and [OVERLAPPED structure](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped).
The code uses the Unicode W function.

## Ownership and containment

OwnedPipeEndpoint registers itself before creation and holds every issued operation.
OwnedPipeOperation allocates a private buffer and OVERLAPPED before dispatch; the
registry retains them even if a caller abandons its reference. Each operation gets
a dedicated manual-reset event. There is one active operation per endpoint,
at most 16 retained endpoints and 64 issued operations per endpoint. Logical IDs
cannot be recycled. Disposed operations release their native allocations while
retaining their audit ledger. Endpoint handles outlive individual operations.

Operations are bound to the creating process/thread. Known terminal results permit
explicit disposal; pending results do not. Native cleanup precedes the DISPOSED
audit projection. Partial-close and post-dispatch ledger failures mark the worker
fatal and retain remaining references, preventing unsafe retries or finalizer
cleanup. No finalizer is installed.

WorkerContainmentRequired is a supervisor contract, not actual termination. The
disposable-process harness enforces it by terminating the failed worker when
containment is required. Continuing a production broker after catching
this error is unsupported. Registry retention is intentional until process exit.

The existing FAKE_COMPLETION_LEDGER is reused solely as an audit projection of
normalized inputs; it is never represented as authenticated native evidence or
used to own ctypes memory. Native return values are retained before ledger updates.

## Completion and deadlines

Initiation IO_PENDING differs from completion-query IO_INCOMPLETE. A new connect
reporting PIPE_CONNECTED is immediate success. Connect counts are ignored;
read/write counts must fit the private buffer. See [ConnectNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
and [GetOverlappedResult](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult).

Completion failures are conservatively limited to understood pipe/aborted results.
Unexpected query errors, invalid handles, malformed results, and failed waits
require containment, never inferred completion. Native behavior is covered on the
tested host by the separate process suite. Short successful transfers are reported as such; this module does not
silently retry partial writes or implement the higher-level framing protocol.

Monotonic integer millisecond checks cover dispatch, return, waiting, cancellation,
and result release. Plans retain their original request/cleanup deadlines. A shorter
wait returns whether completion was observed; it cannot renew a plan. An observed
terminal result is not itself permission to release late data. Cleanup has a
separate fixed budget; per-wait iterations and ledger capacity are also bounded.

Cancellation addresses the exact OVERLAPPED. Acceptance, NOT_FOUND, and cancellation
failure all require completion confirmation. Cancellation suppresses results even
when normal completion wins the race. [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
does not wait for completion. No infinite waits, blocking GetOverlappedResult,
FlushFileBuffers teardown, IOCP, or implicit handle-wide cancellation is used.

## Acceptance coverage and remaining boundary

Fake tests cover ABI declarations, creation flags/descriptors, last-error capture,
immediate and pending connect, short transfers, cancellation races, unknown query
errors, allocation retention, post-dispatch faults, close failures, bounded waits,
clock regression, deadline expiry, capacity checks, and foreign-thread rejection.

Fake tests do not prove kernel memory safety or live identity enforcement. The
separate native suite covers real disposable peers, kernel process correlation,
anonymous denial/reversion, and teardown. Full server authentication and effective
pipe-token acquisition remain separate. The fake suite opens no real pipes;
neither suite connects signing or configuration-store mutation.
