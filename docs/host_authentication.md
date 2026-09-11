# Identity and authorization contracts

This first implementation is transport-independent and remains disconnected from
the CLI, journal, review writer and release engine. It does not authenticate a real
connection. No certificates, service identities, production grants or file
permissions are provisioned.

## Interfaces and implementations

`CredentialVerifier.verify(TrustedTransportEvidence)` returns `VerifiedIdentity`.
`Authorizer.authorize(identity, action, resource)` returns `AuthorizedAction`.
Both raise generic public errors on rejection, malformed inputs, unavailable
state or an invalid host clock.

`RegistryCredentialVerifier` implements enrollment mapping **after** transport
verification. Its input is a host-only attestation from a future real mTLS adapter,
not a certificate, token, request header, JSON identity, or boolean claiming that
verification succeeded. The adapter must validate the real connection and supply
fresh evidence on each request. Synthetic attestations exist only in the tests.
There is no mock credential acceptance mode wired into production execution.

The verifier matches the exact credential fingerprint to an enabled enrollment,
checks aware current timestamps, and issues a bounded identity with stable principal,
credential, connection, method, verification time, expiry, registry revision and
server-generated audit ID. Lifetime is at most five minutes and also bounded by
the transport credential and enrollment expiration. Valid-from is inclusive;
expiry is exclusive. Historical query time is not accepted by these contracts.

`PolicyAuthorizer` independently reads current state, checks identity enrollment
and revision, and requires a current permission for the exact action and corpus.
Its returned decision binds the resource and policy revision, and expires no later
than the identity, enrollment, grant or applicable worker assignment.

## Role matrix and resource rules

All permissions are independent positive grants. There is no implicit superuser,
wildcard corpus matching, default principal or credential-subject role inference.

| Action | Required host-resolved resource |
| --- | --- |
| replay.submit | Exact corpus, document and version |
| replay.recover_own | Corpus, operation and owner matching the authenticated principal |
| review.append | Exact corpus, document and version |
| worker.execute | Corpus, document, version, operation, original owner and matching assignment ID |
| host.manage | Empty resource; separate explicit permission |

Worker execution additionally requires a current host assignment whose worker
principal and complete resource match. This does not mint or replace a journal
generation fence. Resource ownership and assignments are trusted host inputs,
never values to trust from client JSON. Future dispatch must resolve ownership
without exposing another principal's operations.

## State and trust boundaries

`AuthorizationStateReader.read()` must return one coherent, immutable
`AuthorizationState` snapshot. The host must increase its revision on **every**
credential, permission or assignment change. Duplicate credential or assignment
IDs are rejected. Malformed nested models are revalidated at both boundaries.

This initial design uses a shared revision for enrollment and policy. Any revision
change conservatively invalidates existing identities, even when another principal
was changed. Fresh verification and authorization are required. This simplifies
the first contract but may cause additional authentication work at scale.

The state reader is a protocol, not an authenticated configuration loader or durable
authorization store. The test implementation is a mutable in-memory reader. A
production reader must enforce coherent snapshots, protected writes and monotonic
revisions; these requirements are not provided by Python model immutability.

Typed envelopes reject dictionaries at method boundaries, but remain constructible
by trusted Python code. They are not cryptographic capabilities. Host process and
OS isolation are still required. Neither an identity nor an authorization decision
may be accepted as serialized proof from a client.

Decisions are short-lived snapshots, not authority to commit an outbox release
later. A subsequent phase must coordinate final authorization with the release
transaction, persist execution authorization, implement protected diagnostics, and
construct existing caller/reviewer/worker contexts only through authenticated
dispatch. No authorization-revocation race guarantee is added in this milestone.

## Verification

The new unit suite uses synthetic attested credentials and a host clock. It covers
all 25 pairs of independent permissions, missing and disabled credentials, expiry,
future and stale attestations, rotation, reused evidence after disablement, policy
revision changes, invalid clocks, malformed registry data, generic state failures,
cross-corpus and cross-principal denial, assignment mismatch, permission time
boundaries, decision expiry, immutable results, and rejection of identity/header
dictionaries. Real TLS chain validation, endpoint verification and JWT signatures
require later transport integration tests.

The historical CLI remains unchanged. No ABC review approvals or historical
transition mappings are added by this work.
