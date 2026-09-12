# Pure observation request binding

Phase 1 provides frozen records and pure validation in
`tnc.provenance.observation_request_binding`. It does not authenticate a socket
or turn a caller-supplied identity into trustworthy evidence.

## Host-owned inputs

`bind_observation_request` accepts canonical v2 `ObservationRequest` bytes and
explicit host-owned `VerifiedIdentity`, `ObservationPolicy`,
`ObservationHostContext`, and aware evaluation time. Identity and context are
trusted fixtures at this stage. Production code must obtain them through a
verified host adapter; constructing these Python records is not authentication.

`ObservationGrant` permits only `AUTHORITY_OBSERVE_CURRENT` for an exact
principal, deployment, and store within a validity interval. Policies contain
at most 64 grants, sorted by unique grant ID. Existing replay and administrative
permissions do not implicitly grant observation access.

The host context pins the expected enrollment registry revision, observation
policy revision and canonical digest, deployment, store, and issuer. This
observation policy is separate from the authority policy asserted in a signed
observation. Matching these input records does not establish their live
freshness or serialize independent providers.

## Validation and output

Request input is limited to 16 KiB and must use the existing exact canonical v2
shape. The host hashes these exact bytes. The request's principal must equal the
verified identity; deployment, store, and issuer must match the host context.
Request lifetime is at most 60 seconds, with inclusive start and exclusive
expiry. Identity, policy, context, and the selected grant must all be active.

The immutable `BOUND` result records the request digest, transport credential
digest, connection and identity audit IDs, principal, registry revision, policy
binding, scope, grant ID, and evaluation interval. Its expiry is the earliest
input expiry. Multiple eligible grants select the longest-lived grant, breaking
ties by grant ID. A denial carries only `INVALID_INPUT` or `ACCESS_DENIED`, with
no partial binding or storage lookup.

Records use existing canonical serialization and bounded decoding. Models are
frozen; this is an API discipline, not an operating-system security boundary.

## Deliberate limitations

This module performs no file, database, network, signing, challenge-consumption,
or process operations. The byte limit is not a stream-framing implementation or
a monotonic acquisition deadline. A `BOUND` result is audit-only and neither an
execution permit nor release-time authorization. A valid fabricated host
identity fixture can pass pure rules: Phase 2 must supply the authentication
boundary using `MtlsConnection` and re-evaluate live enrollment and permissions.

The focused tests cover canonical rejection, explicit grant enforcement, scope
and principal mismatches, revision/digest mismatch, time boundaries, immutable
round trips, and the absence of I/O. Production transport, authority lookup,
signing, checkpoint distribution, and storage mutations remain outside scope.
