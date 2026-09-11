# Pure deployment preflight validation

The installation models and deployment validator compare typed expectations with
supplied observations. They do not inspect Windows, open files or databases, verify
package signatures, create credentials, alter ACLs or authorize provisioning.

The envelope binds deployment, phase, generation, descriptor, volumes and a complete
inventory. An external anchor binds its digest and minimum generation. The caller
must obtain that anchor independently; a record is not authentication. The public
comparison function requires envelope, anchor and descriptor together, avoiding an
unbound standalone comparison result being mistaken for a trusted report.

Canonical decoding reuses the strict administration codec with a 256 KiB per-record
limit. Typed collections, paths, SIDs, ACEs and findings have explicit limits.
Revalidation rejects constructed/copy-modified invalid nested objects. Invalid
input or anchor bindings raise InstallationValidationError/ValueError and return
no report. Observation completeness failures produce INDETERMINATE reports.

Required inventory roles are code, descriptor, anchor, configuration directory,
state directory, database, WAL and SHM. Every parent up to the volume root must be
inventoried. Only sidecars may be optional. Database sidecar names are derived from
the exact database path. Case-insensitive path aliases, missing ancestors and
immutable/private-key objects under writable state storage are rejected.

Maintenance, operator and service SIDs are distinct in this initial profile.
Maintenance owns objects; configuration/code writers are maintenance-only. State
writers may include the service and, before bootstrap only, the local operator.
Even a permitted data writer cannot receive WRITE_DAC/WRITE_OWNER through this
policy. Private-key readers are separately restricted and key/database/sidecar
content observations are forbidden.

Configuration/state directories require an exact canonical AclObservation template
digest and explicit protected-DACL expectation. The evaluator checks both current
and inheritable directory write grants, including inherit-only grants that could
affect future sidecars. This deliberately narrow ACL template comparison is not a
Windows effective-access evaluator. It does not prove that a given process token
has all access needed to run the service or that future native object creation will
produce an expected descriptor; those require isolated native installation tests.

ObjectObservation contains structured owner/ACE/volume/file facts, not raw file
contents. A future native adapter must derive them consistently from the same
checked handles. Present objects require complete facts; absent and unreadable
objects cannot carry contradictory present-object fields. Exact GUID and serial
are checked independently of the declared NTFS filesystem. Supplied changed/time
flags cannot stand in for an implemented native stability check.

Results are CONFORMS, VIOLATIONS or INDETERMINATE. Missing, extra, duplicate,
unsupported or changed observations cannot pass. Definite violations are retained
when other checks are incomplete. Findings and inspected IDs are deterministically
sorted. Overflow preserves at most 255 findings plus BUDGET_EXCEEDED and returns
INDETERMINATE; a report is never silently truncated into apparent completeness.

CONFORMS means only that the supplied observations conform to this approved
inventory/profile. It is not a startup/provisioning token or a filesystem lock.
Report deserialization does not establish provenance. Native acquisition, external
envelope authentication, independent rollback checkpoints, runtime token checks
and installer/service integration remain future work.

The pure tests cover canonical records, external bindings, inventory roles/aliases,
phase policies, volume and ACL violations, missing sidecars, private-key metadata,
completeness/overflow and a check that the evaluator does not call file, SQLite or
native-library APIs. Existing execution and provenance routes are unchanged.
