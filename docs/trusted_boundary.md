# Trusted installation configuration boundary

`TrustedConfigurationLoader(policy, checkpoint)` provides `load()` and `audit()`.
Neither method accepts caller paths, phase overrides, credentials, or replacement
anchors. There is no CLI, network route, installer mutation, or execution permit.

## Independent installer inputs

`TrustedInstallationPolicy` fixes the deployment, installation directory, three
public input paths, phase, timeout, expected NTFS volume GUID/serial, installer
SIDs, and validity interval. `InstallationCheckpoint` independently binds the
policy digest, exact anchor digest, deployment, high-water generation, and validity
interval. Both records are frozen and canonically revalidated at construction.

These records must come from an authenticated, current installer-controlled
channel. Python types and hashes do not authenticate their own source. Do not
load the checkpoint from an arbitrary caller path or derive its expected digests
from the same files being audited. Signature/TPM/service-backed checkpoint
provisioning is not implemented by this module.

## Read-only acquisition and binding

All three files must lie beneath the fixed installation directory, outside mutable
application state. Each ancestor is opened relative to retained handles and checked
for installer ownership and unauthorized write grants, including inherited and
inherit-only grants. Ordinary deny ACEs cannot compensate for unsafe allow ACEs.
Unsupported security descriptors fail closed. The installation directory and its
input descendants require protected DACLs. Ancestors above that directory also
receive owner/write checks but need not have inheritance disabled.

The expected NTFS GUID and serial are checked, and the input loader rejects reparse
points, wrong object types, multiple file links, changed metadata, and oversized
inputs. Each input is bounded to 256 KiB and the acquisition to 128 handles.
Input files deny concurrent write/delete sharing; all retained handles are closed
on every exit. No ACLs or filesystem objects are repaired.

Canonical anchor bytes must match the checkpoint's pinned digest. The anchor
binds the envelope, which binds the descriptor. Existing deployment validation
checks remain mandatory. Installer SIDs must match the envelope's maintenance
identities; descriptor path and requested phase must match the inventory.

Both the envelope generation and anchor minimum generation must meet the trusted
checkpoint floor. A changed anchor at the same generation is rejected unless the
independent installer checkpoint explicitly binds that exact replacement. The
loader never advances or writes a checkpoint. An installer must durably provision
and supply the current checkpoint when changing generations. An existing loader
retains its construction-time checkpoint; replacement requires a new loader and
host-managed draining of older instances. A process-local record does not observe
external checkpoint revocation or supersession automatically.

## Results and limits

`load()` returns an immutable snapshot with the intersection of policy,
checkpoint, anchor, and envelope validity intervals. `audit()` passes the exact
verified input bytes to the preflight runner without reopening those files, then
returns a `PreflightAuditResult`. The runner's private input-loading hook supports
this composition; its public API is unchanged. Audit failures return
`INDETERMINATE` with fixed reason codes and no report. Loading failures raise
`TrustedConfigurationError` containing only a fixed reason code.

UTC validity and monotonic elapsed time are checked during loading and after the
audit. Clock rollback within an operation is rejected. The one-to-ten-second
deadline is cooperative and cannot interrupt a blocked Windows API call. Wall
clock accuracy across process restarts is a host responsibility.

This enforces rollback rejection relative to the supplied trusted checkpoint.
It cannot detect rollback of the entire machine, including that checkpoint and
its trust source. Achieving that stronger guarantee requires independently
protected persistent state, such as a trusted service or hardware-backed counter.
No such mechanism is claimed here.

Loaded snapshots and conforming reports are observations, not provisioning or
execution authorization. The loader does not connect to SQLite, write a journal,
change permissions, launch services, or approve the real ABC captures.

Tests cover canonical bindings, generation floors, same-generation substitution,
expiry, path policy, owner/ACL failures, changed/oversized inputs, cleanup,
clock/deadline failures, exact-byte runner integration, and native Windows owner
denial before content reads. Conforming boundary tests use synthetic security
descriptors; they do not certify an installed production host.
