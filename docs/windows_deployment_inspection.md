# Native Windows deployment inspection

`inspect_windows_deployment(envelope, external_anchor, descriptor)` acquires
observations for the pure deployment validator and returns a
`DeploymentPreflightReport`. The three inputs must be trusted, typed host records;
the adapter does not discover or authenticate its own trust anchor.

The adapter opens existing local objects with query/read rights only. It queries
volume GUIDs, serial numbers, filesystem type, file identity, link counts,
attributes, owners, and DACLs. Relative opens retain ancestor directory handles,
and reparse directories are never used as traversal parents. Canonical input and
anchor bindings are validated before opening filesystem objects.

Database, WAL, SHM, and private-key files are metadata-only. They receive no data
read access and their contents are never hashed. Metadata files permit read,
write, and delete sharing so that inspection does not prevent ordinary SQLite
WAL activity. The module never opens a SQLite connection. Public files with an
expected content digest use read sharing only while their bytes are hashed.

Retained metadata is checked again before completion. Shared metadata file names
are reopened relative to their pinned parents to detect replacement. This is an
observation check, not a permanent path lock or an atomic filesystem snapshot;
objects may change after inspection. Reports do not authorize provisioning,
database access, service startup, or journal execution.

Precise not-found errors become absent observations. Access failures and
unsupported security descriptors become unreadable observations, producing an
indeterminate result. Changed objects are reported to the pure validator. Invalid
inputs, exceeded budgets, or cleanup failures prevent a usable report. All
acquired handles are closed, including on failure, with cleanup attempted for
every retained handle.

Bounds are 128 retained handles, 4 MiB per content file, 16 MiB total content, and
a cooperative ten-second elapsed-time limit. Native calls themselves cannot be
interrupted by that deadline. Native access can also produce operating-system
audit or access-time effects; the adapter does not deliberately modify files,
ACLs, credentials, accounts, databases, or services.

Tests cover fake native API failure paths, sharing/access flags, cleanup, missing
versus inaccessible objects, replacement detection, content limits, and real
Windows volume inspection. Native tests exercise an entire temporary inventory
and SQLite WAL writes while metadata handles are retained. Test private-key bytes
are never read or included in reports.
