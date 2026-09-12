# Temporary checkpoint authority: read and reconstruction layer

This module implements only explicit initial test-store creation and host-only
read inspection. It provides no submission, policy writer, request recovery,
checkpoint publication, signatures, or production authorization routes.

`TestCheckpointAuthorityStore.create_for_testing(path, state,
trusted_initial_envelope=anchor, now=aware_time)` exclusively creates a new
database with empty acceptance history. Initial runtime image events may already
exist if they match the independently supplied initial envelope. Creation does
not overwrite existing files. Failed initialization may leave an invalid empty
file requiring explicit test cleanup.

`TestCheckpointAuthorityStore(path, trusted_initial_envelope=anchor).load(now=...)`
opens an existing database read-only and reconstructs a frozen simulation state
under one read transaction. This is a host inspection API, not an authorized
client-facing receipt endpoint. It returns full synthetic evidence to its host.

The authority database uses a separate application ID and version-1 schema.
Metadata, canonical state, and immutable acceptance projections must match
exactly. A shared pure validator checks historical policy and batch bindings,
image prefixes, envelope linkage, and acceptance contents. Missing or changed
projections are rejected, never repaired. Independent initial anchors are
required; local digests alone cannot detect whole-store rollback.

Limits are 64 history rows, 32 MiB canonical state, 64 KiB per other stored value,
and 64 MiB total stored column bytes. Schema text is bounded to 64 KiB and 64
objects. Length/count checks precede stored-value retrieval. Existing simulation
limits for images, events, and canonical records still apply. SQLite inspection
is not a hard-time-bounded hostile-file parser.

Creation uses WAL, FULL synchronous mode, and explicit transactional DDL. Loading
uses mode=ro, query_only, and normal WAL locking, not immutable mode. SQLite may
manage sidecar bookkeeping; read-only means no application-table mutation, not
a promise of zero filesystem activity. Native protected-path opening, real
independent freshness, power-loss guarantees, and authenticated policy changes
remain outside this temporary-store profile.

Tests insert accepted histories through fixture-only SQL to exercise reconstruction.
There is intentionally no adapter API for those writes. Tests cover exact history
bytes, corrupted canonical data/projections, independent-anchor mismatches,
schema differences, bounded decoding, immutable-row guards, rollback of failed
creation, and absence of submission routes. Existing simulation tests cover the
shared pure history rules.

Next: serialized test-provider acceptance and policy transactions, exact retry,
and process/concurrency tests. This layer alone does not bridge runtime commitment
to durable authority acceptance.
