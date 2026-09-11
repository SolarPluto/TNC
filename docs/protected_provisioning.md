# Protected Windows provisioning file loader

`load_protected_provisioning(descriptor)` loads `policy.json`, `manifest.json` and
the policy's fixed artifact names. The descriptor must come from independently
trusted host configuration. No public route, provisioning command or certificate
validator is enabled by this implementation.

Use the returned snapshot as a context manager. It retains the exact immutable
artifact bytes and all opened handles until close. File reads use those handles;
there is no path re-open for parsing. Closed snapshots deny artifact access. Close
attempts every handle even if an earlier close fails. Explicit close is required;
there is no reliance on garbage collection to manage locks.

## Native checks

The root is opened read-only and must resolve to a volume GUID root on NTFS.
UNC, substituted subdirectory roots and non-NTFS roots are rejected. Every child
is opened relative to its retained parent with NtCreateFile, FILE_OPEN, synchronous
read/query rights, FILE_OPEN_REPARSE_POINT, and only FILE_SHARE_READ. The loader
checks the resulting file type and reparse attribute before descending. It never
creates files or requests write/delete/backup privileges. Relative handle lookup
avoids resolving the original drive path again during traversal.
[Microsoft NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).

All ancestors from the volume root are checked. DACL and owner information is read
from actual handles using GetSecurityInfo; its allocated descriptor is freed after
copying bounded bytes. Self-relative offsets, SID extents and ACE sizes are checked
before decoding. Only ordinary allow/deny ACEs are supported. Unsupported ACEs,
null DACLs, untrusted owners and untrusted effective write grants are rejected.
Generic write/all, deletion, delete-child, write-data/append, write attributes/EA,
WRITE_DAC and WRITE_OWNER are included. Deny entries do not cancel a suspicious
allow for purposes of this conservative acceptance policy. Inherit-only entries
do not apply to their current object; each actual child's ACL is checked separately.
[Microsoft GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).

Files require exactly one hard link and bounded nonzero size. Reads require the
expected byte count and EOF, and metadata/security observations are compared before
and after reads and again across the completed snapshot. The existing pure validator
checks canonical records, exact digest bindings and the complete artifact set.

## Scope and limits

No production allowlist is inferred from observed ACLs. A normal user directory may
be rejected because an ancestor allows writes by a SID outside the externally
installed allowlist. The loader never repairs those ACLs or expands that allowlist.
The database path is not opened or validated here; this is a configuration loader.
The external descriptor's protection remains a deployment responsibility.

Resource limits include 48 path components, 64 handles, existing byte-size limits,
and a ten-second elapsed-time check between operations. Synchronous Windows calls
cannot be interrupted by that cooperative check. This is not a hard wall-clock
deadline against a stalled kernel/storage driver; stronger cancellation requires a
separate supervised process before a network-facing service uses the loader.

Retained handles block ordinary writes and replacement, but do not freeze a trusted
administrator's ability to change security policy. ACL changes observed during
loading cause failure; changes after the final observation are subject to the
previously designed bounded-lease semantics. A compromised trusted writer/kernel
is outside this boundary. No certificate signatures, revocation status, operator
authorization or live-session monotonic lease are verified by this loader.

## Tests

Fake APIs cover ordering, cleanup on open/read/check failures, changed ancestors,
type/size/link/volume mismatches, ACL masks and malformed descriptors, and cooperative
budget expiry. Native Windows tests use temporary files for exact reads, writer
conflicts, file and directory rename blocking, hard links, junction handling, and
unsafe DACL rejection. API doubles verify requested rights and allocation cleanup.

The native full-loader test nominates observed SIDs solely to exercise orchestration
inside its temporary fixture; that is explicitly not a production trust discovery
mechanism. Only one new temporary file's ACL is changed by the unsafe-ACL test.
No existing user-directory permissions, accounts or real provisioning data are changed.
