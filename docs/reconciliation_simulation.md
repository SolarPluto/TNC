# Pure checkpoint authority simulation

`reconciliation_simulation.py` models a bounded independent-authority protocol
using frozen synthetic records and pure state transitions. It adds no actual
authority service, signature issuance, lock, database, file, or network operation.

## State and evidence

`AuthoritySimulationState` contains a supplied initial envelope, current envelope,
accepted logical image, current synthetic policy, and up to 64 historical
acceptance entries. Each entry preserves the exact request, policy snapshot,
batch authorization, and acceptance. An independently supplied initial envelope
must match the state's initial record; this bounded profile starts at revision 1.
The input anchor is a test trust assumption, not authenticated by this module.

`SyntheticAuthorityCaller` represents separately supplied fixture identity.
`SyntheticAuthorityPolicy` grants SUBMIT, RECOVER, and OBSERVE_CURRENT independently.
`SyntheticBatchAuthorization` binds an affirmative test decision to the principal,
deployment/store, request digest, predecessor revision/hash, successor checkpoint,
ordered event batch, policy revision, and validity interval. It cannot be replaced
by a local update receipt, and the evaluator does not construct it from a proposal.

The host test driver may supply a newer policy state to simulate permission
changes. Historical policy snapshots are replayed at acceptance time; current
policy cannot regress below the last accepted policy or change bytes at that same
revision. There is no authenticated policy-update ledger or initial policy
authentication. This fixture mechanism is not a production administrative API.

## Pure authority transitions

`simulate_authority(state, command, caller=..., batch_authorization=...,
trusted_initial_envelope=..., now=...)` first revalidates bounded canonical state
and retained history. Each historical acceptance is reconstructed from its exact
image prefix and saved authorization, including deterministic ID and timestamp
bindings. Duplicate request/acceptance IDs, altered evidence, broken history,
future acceptance times, and current-head disagreement are rejected.

For new SUBMIT, current permission, request scope, and both expected predecessor
revision and envelope digest must match. The candidate must be a nonempty valid
extension, with exact successor and batch digests, plus current affirmative batch
authorization. Acceptance returns one proposed immutable state containing the new
image, envelope, request, evidence, and acceptance. Nothing is applied automatically.

Successor envelopes keep the configured issuer/key identifiers; key rotation is
not simulated in this profile. Their validity ends at the earliest request, batch
authorization, policy, or submit-grant deadline. Acceptance IDs are deterministic
simulation hashes of the predecessor envelope and next revision, not signatures.

Exact accepted-request retries require current RECOVER permission and return the
original acceptance without proposing a state change. No current batch evidence
or candidate is required for that path. Changed canonical request bytes conflict;
foreign or unauthorized requests receive a generic denial. Historical recovery
remains possible after request/envelope expiry when current recovery scope is valid.

OBSERVE_CURRENT separately checks current permission and envelope validity and
returns a synthetic response bound to the caller and explicit challenge. Responses
are never described as cryptographically authenticated by this implementation.

## Client high-water observations

`evaluate_client_observation` checks synthetic response scope, challenge, and
validity. Equal revision/same digest is UNCHANGED; equal revision/different digest
is FORK; lower revision is STALE_HISTORICAL. A higher revision requires a complete
bounded predecessor-linked envelope chain. Missing links are INDETERMINATE;
contradictory links are FORK. Historical intermediate envelopes need not still be
current, but the final response and envelope must be valid now.

ADVANCE_PROPOSED returns a frozen proposed mark only. It never writes a high-water
file or publishes an envelope. A real adapter must authenticate the observation,
protect the retained mark, and establish actual currentness. A valid old signature
or a locally retained revision alone cannot prove latest state.

## Bounds and tests

The decoder uses a fixed type whitelist: 64 KiB per small simulation record or
acceptance entry, 32 MiB per state/result, sixteen MiB plus 64 KiB per command,
and 48 MiB aggregate evaluator input. Existing sixteen-MiB images, four-MiB events,
256 image events, and canonical encoding rules remain in effect. State history is
limited to 64 acceptances; client chains to 64 successor envelopes. No history is
pruned or rebased to fit these limits.

Tests apply proposals explicitly to model interleavings. Two evaluations against
the same old state may both propose acceptance; once one is applied, the other
must be re-evaluated and conflict. This illustrates why a real serialized CAS
adapter is still necessary. Lost-acknowledgement simulation retains the selected
state and verifies exact recovery, including recovery after a later advancement.

Coverage includes all event types, batch mismatches, policy changes, owner scope,
exact/conflicting retries, altered history, expiry, no-op rejection, client forks
and skipped links, deterministic IDs, bounded decoding, frozen results, and no-I/O
execution. These tests do not prove real concurrency, crash durability, external
authority authenticity, or cryptographic freshness. Existing journal execution
guards and real ABC capture quarantine remain unchanged.
