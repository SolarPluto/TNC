# Read-only host preflight runner

`run_host_preflight(request, trusted_anchor=anchor)` is an internal host API.
It is not a CLI, network route, provisioning capability, or service readiness gate.

`PreflightAuditRequest` contains three distinct absolute local Windows paths for
the envelope, external anchor, and descriptor, the expected phase, and an integer
cooperative timeout from one to ten seconds. Trusted host configuration must
choose these public input files. Do not expose arbitrary input paths to clients
or point them at private keys, database files, or other secrets.

The independent `ExternalInstallationAnchor` is a mandatory typed host argument.
It must arrive through a separately authenticated installation channel. Loading
an anchor from the same caller-controlled files does not satisfy this contract.
This runner does not implement installer authentication or signature verification.

Input acquisition opens existing objects through retained ancestor handles,
rejects reparse points and multiple file links, denies write/delete sharing on
input files, bounds each input to 256 KiB, checks retained metadata again, and
closes all acquired handles. Input ACLs are not themselves treated as proof of
authenticity. Instead, canonical anchor bytes must match the independent host
anchor, which binds the envelope digest and, transitively, the descriptor digest.
The descriptor input path must also match its inventory expectation. The requested
phase is compared to the envelope phase; it cannot override the inventory.

The native inspection adapter performs the deployment audit, including its own
ACL checks and metadata-only database/private-key observations. The runner passes
the remaining elapsed-time budget into inspection and checks deadlines throughout
acquisition. The timeout is cooperative, not a hard upper bound on a stalled
Windows API call or cleanup. `execution_time_ms` records observed elapsed time;
it may exceed the requested limit. Invalid clocks produce an indeterminate result.

`PreflightAuditResult` includes status, optional report, fixed reason codes,
inspected-object count, and elapsed milliseconds. When input validation or
acquisition fails, the result is `INDETERMINATE`, with no report and zero counted
objects. It does not fabricate a deployment identity or partial report from
untrusted inputs. On completion, status and count must agree with the embedded
report. Count follows the validator's definition, including recognized absent
objects but excluding unreadable objects. Errors expose no exception messages,
paths, SID details, certificate material, or file contents. Reports retain
installer-defined object identifiers, which should therefore be non-sensitive.

The runner performs no repairs, SQLite connections, account/permission changes,
provisioning, service launches, or authorization promotion. A conforming report
is still only an observation; it does not establish a durable filesystem snapshot.

Tests combine synthetic input loading with the real inspection orchestration and
pure evaluator, plus native Windows input loading from temporary files. They
cover conforming and violating reports, missing sidecars, changed objects,
independent anchor binding, phase checks, malformed input, cleanup, size limits,
clock/deadline failures, and generic error reporting. Existing native adapter tests
continue to cover full temporary inventories and concurrent SQLite WAL activity.
