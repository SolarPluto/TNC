# Pure Windows pipe operation ledger

`windows_pipe_operation_logic.py` is a test-only, deterministic model of the
event-based overlapped I/O lifecycle. It allocates no native handles, invokes no
Windows APIs, reads no clocks, and performs no cancellation or resource release.
Its events are synthetic evidence, not proof of kernel completion.

## Records and replay

Frozen canonical plans bind an operation to distinct symbolic pipe-lease, event,
OVERLAPPED, and buffer identities. CONNECT uses zero data capacity; READ and WRITE
require positive capacity, bounded to 64 KiB. All ticks are supplied integer
monotonic milliseconds from one fixture clock. Request budgets are at most five
seconds, followed by at most one second for cleanup. Cleanup never extends the
response authorization window.

Each ledger contains at most 64 contiguous events. Canonical decoding is bounded
to 64 KiB and rejects altered shapes, duplicate JSON keys, and noncanonical bytes.
Replay reconstructs state from the complete history; callers cannot supply an
authoritative state projection. `propose_pipe_event` returns an immutable audit
proposal that the harness must explicitly adopt.

## Ownership and cancellation

The lifecycle is CREATED → PENDING → TERMINAL → DISPOSED, with immediate completion
permitted from CREATED. Expiration before submission produces NOT_SUBMITTED.
Only TERMINAL permits symbolic disposal. Every earlier state retains ownership.

SUBMIT/PENDING models asynchronous initiation. POLL/INCOMPLETE models a completion
query that has not completed; those outcomes are intentionally distinct.
Confirmed SUCCESS, ABORTED, or ERROR from a pending operation terminates it.
Cancellation acceptance, NOT_FOUND, and cancellation failure never establish
completion. They retain ownership and suppress response release, including when
normal completion wins the race.

At the request deadline, response release is suppressed. An operation still
pending at the cleanup deadline is quarantined and requires shutdown. Reversion
failure likewise requires shutdown. These flags are sticky. Later completion
can establish safe symbolic disposal, but cannot restore response eligibility
or withdraw the shutdown requirement. The model itself never shuts down a process.

`validate_pipe_ownership` accepts at most 16 ledgers and rejects identity reuse,
including identities belonging to disposed operations. A pipe-lease identity is
an allocation fixture, not an assertion that a real pipe handle can never serve
successive operations. This first profile models independent outstanding leases;
it is not an IOCP or shared-handle scheduler.

Capacity exhaustion rejects further proposals without freeing anything. A future
native adapter must treat an exhausted tracker as a containment failure, retaining
uncertain allocations until completion is confirmed or its disposable process
is terminated. `result_available` describes the last supplied event time, not a
live authorization token; release requires a fresh deadline check.

## Validation scope

The tests exercise cancellation/completion races, deadline boundaries, failed
reversion, invalid result mappings, transfer bounds, forged histories, canonical
decoding, capacity exhaustion, resource aliasing, and forbidden side effects.
They establish model invariants, not native memory safety or power-loss durability.
The bounded ctypes adapter and disposable native process tests are separate in
`windows_pipe_native.py` and `test_windows_pipe_process.py`; see their documentation
for tested scope and limitations. Signing, credentials, persistent stores, and
execution routes are unchanged.
