# Owned process lease — fake API milestone

`windows_pipe_process_lease.py` owns one process handle across acquisition and
final correlation. This milestone implements only the explicitly injected
`ProcessAPIForTesting` boundary: no Win32 bindings or native tests are added here.
Results are permanently labeled `FAKE_PROCESS_API` and are audit-only.

## Acquisition and lifetime

Acquisition requires an exact connected, idle `OwnedPipeEndpoint`, a canonical
process-instance pin, and a bounded lease plan. The pin must agree with the
independently supplied endpoint policy. Request budgets are at most five seconds;
cleanup budgets add at most one second. There is no default clock or implicit pin
derived from the current PID lookup.

Register strong ownership before dispatch. Query the pipe PID and open once with
`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` (0x101000), non-inheritable.
Retain the returned handle before checking the clock again. Check its PID and
creation FILETIME against the pin and re-query the pipe PID. Zero-time process
waits must return WAIT_TIMEOUT both before and after these queries. Signaled,
failed, malformed, and unexpected waits reject correlation; no exit-time field
is used as a live-process signal.

The endpoint close method refuses closure while a process lease is active.
The same worker may perform subsequent pipe operations while the lease is held;
this milestone does not bind those reads to token capture. `finish()` checks the
same retained handle again, closes it, and returns an audit result. `abort()`
closes it without a matched result. Neither operation can be repeated. An endpoint
permits one acquisition attempt, including a failed attempt after dispatch
registration. There are at most sixteen retained leases in this test worker.

## Cleanup and containment

The lease is process/thread bound and non-serializable. A foreign-thread call
cannot mutate it or close its handle; the owning thread remains responsible for
cleanup. A strong registry retains leases even if callers drop their references.
There is no finalizer performing native-style cleanup.

Request expiration does not bypass cleanup. Known-handle closure is attempted
even if the clock or cleanup budget is invalid. Uncertain opening, invalid handle
returns, or failed/late cleanup make the endpoint fatal and retain the lease for
fake-worker containment. `ProcessLeaseContainment` is a test signal; a future
native supervisor must provide actual process containment. No retry with broader
rights or reopened PID occurs. Definitive unavailable-process results perform no
handle close, and all recoverable denials release registry ownership.

## Tests and remaining work

43 tests exercise exact rights, original budgets, independent pins, one-handle
retention, liveness, creation and PID changes, late opening, endpoint substitution,
single-use/capacity bounds, wrong-thread access, unknown allocation, close failures,
strong-reference ownership, and side-effect guards. The native endpoint receives
only an active-lease close guard; existing transport behavior is otherwise intact.

This is not an authoritative identity provider. No primary token substitutes for
an effective thread token; no AppContainer exclusion proof is introduced. Native
handle acquisition and supervised process tests are the next separate step,
followed by reviewed exclusion mechanics. Grants and signing remain disconnected.
Trusted injection methods can execute arbitrary host code; the test API class and
Python private fields are not a security boundary against hostile same-process
code. Liveness checks do not keep the peer alive after the observation.
