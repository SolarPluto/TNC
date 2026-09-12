# Pure Windows custody peer policy and fake inspection

`windows_custody_peer.py` defines frozen policy and observation records plus a
fake-API inspection contract. It contains no WinDLL binding, pipe creation,
privilege adjustment, real impersonation, signing or process shutdown. Observations
are explicitly FAKE_WINDOWS_API evidence. CONFORMS is audit-only and never grants
execution authority or mints a signing handoff.

## Pinned policy

The initial strict profile expects one exact local `TNC-` pipe name, distinct
service/client SIDs, exact logon SID, authentication LUID, session and process
lifetime (PID plus creation FILETIME). Creation timestamps are raw Windows fields,
not UTC seconds. Policy validity uses explicit nonnegative UTC epoch seconds.
SID strings reject aliases such as decimal leading zeroes and oversized fields.

Effective tokens must be identification-level impersonation tokens with the
expected enabled logon identity. Primary/anonymous/delegation tokens, restricted
tokens and app containers are denied by this initial profile. This is an explicit
test policy choice, not a claim those Windows token classes are inherently unsafe.

The descriptor requires a protected DACL and exactly two ordered explicit ordinary
allow ACEs: the service's full local mask and the client's minimal data/query mask.
Generic write and the create-pipe-instance bit are not granted to clients. Real
deployments may need a separately reviewed richer profile; defaults are not inferred.

## Fake acquisition API

The supplied fake implements:

- `open_thread_token(TOKEN_QUERY, True)`: returns None only for modeled no-token;
  unexpected errors raise. No process-token fallback exists.
- `pipe_information(pipe)`: bounded local server-end/name facts.
- `security_descriptor(pipe, 65536)`: bounded self-relative bytes, decoded by the
  existing security parser and restricted to at most 32 ordinary allow ACEs.
- `client_process_id(pipe)`, `open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)`
  and `process_information(handle)`: modeled retained process lifetime facts.
- `impersonate_pipe_client(pipe)`, `token_information(handle, 65536)`,
  `revert_to_self()` and `close(handle)`: exact success booleans where applicable.

The inspector rejects preexisting thread impersonation, retains the process
handle, models pipe impersonation, reads only the effective thread token, closes
that token, and attempts reversion even after a failed impersonation call. It then
checks for residual impersonation and changed endpoint, process or descriptor
facts. All acquired handles receive cleanup attempts; the borrowed pipe is not
closed by this helper. No descriptor or process query occurs while impersonated.

Reversion and handle cleanup failures suppress observations and produce
BROKER_SHUTDOWN_REQUIRED. This is a result for the future owning broker to enforce,
not actual process termination. Other failures produce INDETERMINATE; policy
mismatches produce VIOLATIONS. Explicit integer monotonic ticks and a deadline
cover acquisition and cleanup, including negative/regressing clocks. There is no
implicit wall-clock read, timeout reset or durable freshness guarantee.

## Tests and limits

Tests exercise canonical records, SID/logon/session mismatches, process changes,
descriptor bounds and rights, query-only API arguments, all acquisition failures,
preexisting/residual impersonation, cleanup and reversion failures, deadlines and
side-effect guards blocking files, sockets, SQLite, clocks and WinDLL loading.

Fake facts are not kernel-authenticated evidence. Repeated PID/process/descriptor
checks do not prove freedom from handle delegation, same-user compromise or races
after return. Client-side server authentication, actual token/descriptor decoding
from Windows buffers, overlapped pipe I/O, native cancellation and disposable
native process tests remain unimplemented. The existing local operator identity
reader intentionally rejects impersonation and is unchanged.
