# Host-only Windows provisioning session

`WindowsProvisioningSession(descriptor)` assembles the protected file loader,
current Windows operator reader, certificate gate and bounded lease calculation.
Use it as a context manager around `AdministrationWriter.migrate_to_v4`.
There is no new command-line or network entry point.

The descriptor is independently installed host configuration, not loaded from
untrusted request parameters. The native loader reads the policy, manifest and
certificate/CRL artifacts named by that configuration. A file cannot establish
the trust of its own descriptor or owner allowlist.

## Verification lifecycle

Every `verify_activation(manifest)` invalidates the previous proof, closes its
snapshot and performs fresh checks. It reads the current non-impersonating Windows
identity, requires the anchor's operator SID, loads a protected snapshot and matches
the exact supplied manifest. It then validates the nominated certificate and reads
identity again. SID, process ID, thread ID and elevation observations must agree.
The pure lease calculator checks policy membership and all recorded bindings.

The monotonic deadline is the earlier of the policy's maximum lifetime measured
from verification start and the remaining certificate/CRL/policy/manifest/anchor/
enrollment/grant validity. The UTC interval remains in ProvisioningAuthorization.
Validation time consumes the lease; it is not added back after expensive work.
Both clocks are checked for rollback and invalid values.

The session retains exact proof bytes and open snapshot handles. Proofs are host
objects, not portable or client-authenticatable tokens. The session is confined to
its constructing process/thread and must be explicitly closed. Any failed refresh
invalidates previous authority. A failed transaction check invalidates the proof
without performing handle cleanup inside the database lock; close releases handles.

## Mandatory writer boundary

ProvisioningSession now requires `verify_commit(proof, database_path=...)`.
The writer calls it after acquiring its SQLite transaction and again immediately
before leaving that transaction, including the already-activated retry branch.
Missing callbacks and non-None results fail closed; legacy sessions are not silently
accepted. Existing synthetic test fixtures explicitly implement this contract.

The real callback checks the live monotonic deadline, UTC interval, exact proof,
open snapshot, current process/thread and configured database pathname. It performs
no file, token, certificate or network I/O. Database path comparison is a binding
check, not filesystem protection: SQLite/WAL/SHM ownership, ACLs and path stability
remain a deployment responsibility. No database security is inferred from the
configuration directory's permissions.

Expiry while waiting for the database or while performing DDL rolls the transaction
back. The last check is the authorization decision point preceding SQLite commit;
this does not claim that a physical disk flush can be interrupted at lease expiry.
The original bootstrap anchor/session ID remains the seed identity. Freshly verified
retries preserve the original receipt without rewriting historical evidence.

## Tests and deployment boundary

Tests cover full assembly ordering, repeated identity observations, protected-load
and certificate failures, elapsed verification, every live expiry mode, rollback,
proof alteration, path mismatch, missing callbacks, thread confinement and refresh
invalidation. Deterministic transaction-delay tests use events and injected clocks,
not sleeps. Native Windows tests combine real file handles, token inspection,
CryptoAPI/supplied-CRL validation and temporary v3-to-v4 SQLite activation/recovery.

The native fixture nominates observed ACL SIDs solely to exercise temporary test
orchestration. Production must use an independently installed reviewed allowlist;
the test fixture is not a provisioning recipe. Temporary activation is not real
deployment, and no actual service account, production policy or certificate has
been enrolled. Existing journal execution guards and real ABC quarantine remain.

Policy changes do not instantaneously revoke an already issued bounded lease.
Immediate external-policy revocation would require a shared transaction-visible
coordinator. The filesystem loader still has cooperative rather than interruptible
native-call timeouts. Protected installation, descriptor/anchor distribution,
database storage protection and any administrative transport remain explicit host
deployment work.
