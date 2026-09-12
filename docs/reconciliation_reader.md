# Read-only synthetic authority adapter

`ReadOnlyAuthorityAdapter(path, trusted_initial_envelope=anchor)` pins an
independently supplied initial envelope and opens the existing store with
mode=ro, query_only and an explicit BEGIN read snapshot. It never acquires
BEGIN IMMEDIATE, creates missing stores, or mutates application tables.
SQLite may manage WAL/shared-memory bookkeeping.

`recover_historical(request, caller=..., now=...)` requires the full canonical
ReconciliationRequest, not just an ID. It reuses the pure simulation's current
recovery permission, ownership and exact-request checks, then returns the original
persisted unsigned acceptance BLOB from the same validated snapshot. Full history
is still validated at historical acceptance times; recovery does not reauthorize
the old batch as a new submission or promote its envelope as current.

`observe_current(challenge, caller=..., now=...)` returns a SyntheticCurrentObservation
under current observation permission. The challenge is a lowercase hex SHA-256-sized
digest. Caller, challenge and envelope are bound, with the existing interval
intersection. This format is not authenticated and provides no cryptographic
freshness proof.

The static `evaluate_client_observation` takes the observation, client high-water
record, expected challenge, principal, explicit time, and optional complete chain.
It delegates to the existing pure comparator, returning UNCHANGED,
ADVANCE_PROPOSED, STALE_HISTORICAL, FORK or INDETERMINATE. Proposed marks are never
persisted. Links must be independently supplied trusted synthetic fixture evidence;
this interface does not authenticate or distribute a chain.

Permission evaluation reflects the selected read snapshot. Concurrent committed
policy changes after that snapshot affect subsequent reads, not already generated
responses. There is no release-time lock, real transport credential verifier, or
live clock/session recheck. This is a test-ready logical read boundary, not an
OS-level unprivileged sandbox or production authority endpoint.

Tests cover original bytes and historical recovery, disclosure boundaries,
challenge/identity/time validation, all comparator outcomes, missing/corrupt
stores, anchor binding, read-only operation during an active writer, uncommitted
state isolation, and a policy change after snapshot acquisition. Existing signing,
checkpoint publication, runtime execution and high-water persistence boundaries
remain unchanged.
