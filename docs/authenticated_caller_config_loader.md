# Protected caller configuration loading

`authenticated_caller_config_loader.py` adds protected Windows file ingestion,
explicit SQLite head provisioning and serialized configuration refresh. It builds
on the pure `tnc-caller-config-v1` verifier without modifying transport, bridge,
signer, enrollment-provider or client-journal APIs.

## Host inputs and trust boundary

`SecureConfigLoader(policy)` accepts a frozen, independently provisioned
`CallerConfigLoadPolicy`. The policy fixes the configuration ID, exact local
configuration/state paths, expected NTFS volume GUID and serial, permitted
installer SIDs, state-writer SIDs and cooperative timeout (1–10 seconds).

Configuration and state use distinct, non-nested dedicated directories. Each
file is a direct child of its nominated root. Relative paths, UNC paths, alternate
streams, traversal, reserved device names and malformed Windows path components
are rejected by the existing `LocalPath` validator. The loader neither discovers
paths nor creates directories nor adjusts host ACLs.

`load(trusted_key=..., trusted_checkpoint=...)` requires independently supplied
host inputs on **every call**. It never reads a trust checkpoint from inside the
presented configuration. The current configuration authority key and checkpoint
must come from a trusted host source. Implementing that source's distribution,
authentication and rotation protocol remains separate work.

The returned `LoadedCallerConfiguration` is frozen audit data. It is not a bearer
token, TLS identity, observation grant, provisioning authorization or permission
to sign. The module provides no public cached-snapshot getter. Existing live
bridge/signer checks remain unchanged; integrating this loader into their current
providers is not part of this milestone.

## Protected acquisition

The existing native `_InspectionAPI` supplies handle-relative traversal and
security metadata. Each acquisition pins ancestors and checks:

- Exact nominated NTFS volume GUID and serial.
- Object type, reparse-point rejection and single-link regular files.
- Owner membership in the permitted SID set.
- Protected DACLs beneath the configuration root and on state directories.
- No unsupported rights or unauthorized write-capable allow ACEs, including
  inherited or inherit-only grants. Deny ACEs do not compensate for unsafe allows.

Only installer SIDs may own/write configuration paths or their ancestors. State
paths additionally allow nominated state-writer SIDs. These SID lists are trusted
host policy, not claims read from the configuration file.

Configuration content uses write/delete-denying sharing. The main state file and
existing sidecars use metadata access with read/write sharing and delete denial;
their types are checked independently of the native sharing selector. Ancestor
handles are retained through the SQLite transaction. Existing `-wal`, `-shm` and
`-journal` files are checked before SQLite opens. Newly created sidecars depend on
the protected state directory and its permitted writers; those writers and host
maintenance administrators remain inside the host trust boundary.

New SQLite files may inherit their protected state directory's ACL. Their own
owner and every write-capable allow grant are still checked, even when the child
does not carry the protected-DACL control bit. This permits exclusive creation
without silently performing an ACL modification. The state directory itself must
be protected.

Only the configuration JSON is read as content by the native adapter. It is
limited to **65,536 bytes**, below the pure model's 256 KiB maximum. Canonical
decoding retains the existing strict field/type, duplicate-key, non-finite-number
and exact-byte rules. Legitimate bounded enrollment/grant arrays are allowed;
arbitrary extra structures are not.

Native facts are checked again before commitment. Mutable SQLite files may
change size but not identity or security metadata. Directory size changes caused
by SQLite sidecar creation are permitted. File sizes for SQLite and existing
sidecars are bounded to 8 MiB each. Handle acquisition is bounded to 128 handles.
The deadline is cooperative: it detects over-budget native calls when control
returns, rather than forcibly interrupting the Windows kernel or SQLite.

## Explicit state provisioning

`provision_state()` is a separate, explicit host operation. Normal `load()` never
initializes missing state. Provisioning validates the state directory and rejects
an existing database or sidecar, creates the nominated main file exclusively,
then initializes the schema inside `BEGIN IMMEDIATE`.

The isolated store uses application ID `0x544E4346`, schema version 1, WAL mode,
`synchronous=FULL`, `trusted_schema=OFF`, and STRICT singleton tables:

- `anchor`: exact canonical loading policy, immutable via update/delete triggers.
- `head`: bounded canonical snapshot of the last checked document, key/checkpoint,
  acceptance/check timestamps and local sequence; deletion is prohibited.

Normal opening uses SQLite `mode=rw`, never implicit creation. Validation checks
the exact schema, application/version markers, WAL mode, singleton shape, byte
bounds, canonical policy equality, `quick_check`, and historical signature and
validity of the stored snapshot at its recorded check time. No schema repair or
projection rebuilding is attempted. A failed initial creation can leave an
uninitialized existing file; subsequent ordinary access rejects it.

This local state is crash-consistent under SQLite's platform/storage assumptions.
It does not independently prove that a privileged actor has not restored an older
database, configuration and checkpoint together. A newer independent checkpoint
rejects the old configuration; replaying all internally consistent older inputs
cannot reveal an unseen update. Hardware power-loss behavior and external rollback
detection are not established by process-exit tests.

## Refresh and revision rules

An in-process lock serializes refreshes on one loader. SQLite `BEGIN IMMEDIATE`
serializes separate instances/processes using the same store. After the write
lock is acquired, the loader validates stored state, reads protected canonical
configuration, checks the independent signature/checkpoint and evaluates the pure
revision rules against the locked head.

| Relationship | Result |
| --- | --- |
| Lower configuration revision | `CONFIG_ROLLBACK` |
| Equal configuration revision, different payload digest | `CONFIG_FORK` |
| Higher configuration revision with lower registry revision | `REGISTRY_REGRESSION` |
| Changed enrollment records at unchanged registry revision | `REGISTRY_REVISION_CONFLICT` |
| Higher configuration revision, unchanged enrollment/registry | Allowed, including grant-only updates |
| Same exact document/key/checkpoint | Rechecked; preserves acceptance time and sequence |
| Accepted new document or independently renewed trust evidence | Advances local sequence |

Configuration revision is the primary snapshot ordering. Registry revision tracks
the enrollment lifecycle separately; it is not interchangeable with configuration
or observation trust revision. A complete higher configuration can skip revisions
when the independently trusted checkpoint pins that exact snapshot, consistent
with the existing pure verifier.

Wall time must not regress within a load or behind the stored check time. The
loader repeats expiry/signature checks before commit and after commit. Full
canonical state is persisted atomically before swapping the internal frozen
snapshot. Rejected refreshes clear internal active state instead of falling back
to an older potentially revoked configuration.

The database transaction and in-memory pointer are not one cross-system atomic
operation. If commit is attempted and an error, deadline, expiry or cleanup fault
prevents a confirmed result, the call reports `OUTCOME_UNKNOWN`. It does not claim
rollback. A subsequent validated load reconstructs durable state. A previously
returned audit snapshot can remain in a caller's memory; it cannot serve as proof
of current authorization.

SQLite busy timeout is 250 ms and returns `STATE_BUSY`. Other failures expose only
bounded internal reason codes, not native paths, exception messages or payloads.
No network error mapping is added here.

## Validation and remaining work

The focused tests use real temporary SQLite files and synthetic native metadata
for conforming trees. They cover immutable snapshots, restart/retry behavior,
registry and configuration conflicts, malformed input, owner/DACL/volume/object
failures, cleanup, bounded state files, expiry and clock regression, thread
publication, process lock contention, and abrupt exits before/after commitment.
A native Windows test verifies denial on an untrusted temporary tree without
changing any host ACL. The suite explicitly demonstrates the whole-state restore
limitation. No positive production installation or hardware durability claim is
made from these tests.

Remaining integration includes protected current key/checkpoint distribution,
live enrollment/grant provider construction, coordinated provider refresh during
execution, rate-limit counters, operational provisioning/rotation procedures and
versioned journal audit-field integration. No credentials, production policies,
signing services, execution routes or existing database schemas are changed by
this module.
