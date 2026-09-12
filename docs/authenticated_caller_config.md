# Authenticated caller configuration — pure validation contract

`authenticated_caller_config.py` defines frozen `tnc-caller-config-v1` records,
Ed25519 configuration verification, revision comparison and request matching.
It performs no file, database, socket, clock, key-generation or signing operations.
Temporary keys and signatures exist only in the tests. No existing transport,
bridge, signer, journal model or execution route changes in this milestone.

## Three separate identities and trust inputs

- **Transport identity:** a host-supplied `VerifiedIdentity` from the existing
  mTLS verification path, including certificate SHA-256 fingerprint, principal,
  registry revision, connection/audit IDs and validity interval. A raw fingerprint
  string or dictionary is not accepted in its place. Python objects themselves
  are not proof of a TLS handshake; the trusted host must acquire this evidence.
- **Configuration signing authority:** an independently supplied
  `ConfigurationAuthorityKey` with an Ed25519 raw public key, SHA-256-derived key
  ID, configuration/issuer scope, active status, validity and `CALLER_CONFIG_SIGN`
  permission. It is not inferred from the incoming mTLS leaf or an observation key.
- **Observation trust:** an independently supplied `ObservationTrustCheckpoint`
  defining the exact target deployment/store, observation-trust revision, digest
  and validity window. It is distinct from the configuration checkpoint and
  registry revisions. Full observation trust validation still belongs to the
  existing v2 verifier when a response is evaluated.

The caller cannot nominate a key from inside the document and thereby establish
trust. `CallerConfigCheckpoint` independently pins configuration ID, issuer, key
ID, revision and canonical **payload** digest. Its own validity must hold at the
evaluation time. These inputs are host-owned fixtures here; protected acquisition,
freshness discovery and authenticated distribution remain future work.

## Signed records and canonical rules

`CallerConfigDocument` contains a `CallerConfigPayload` and exact 64-byte Ed25519
signature encoded as 128 lowercase hex characters. The signing preimage is:

```text
b"TNC-CALLER-CONFIG-v1:" + canonical_bytes(payload)
```

Payload fields include configuration/issuer identity, signing-key ID, configuration
revision, separate enrollment-registry revision, UTC integer effective/expiry
times, enrollments and grants. The profile and all authority fields are signed.
Key IDs are the full SHA-256 digest of the raw 32-byte public key.

All records are frozen. Canonical decoding rejects duplicate keys, extra fields,
noncanonical spacing, coerced integers, invalid intervals and malformed digests.
Times and revisions are bounded strict integers up to `2**63-1`. Configuration
payload/document inputs are capped at 256 KiB; other records and request frames
at 16 KiB. Inventories contain at most 64 enrollments and 64 grants, sorted by
unique certificate fingerprint and grant ID respectively.

Each fingerprint maps to exactly one principal. Multiple distinct certificates
may map to one principal for rotation; a duplicate fingerprint cannot be assigned
to another principal. Enrollment status is active or disabled. Unknown, disabled
or expired enrollment receives `CREDENTIAL_INVALID`.

`CallerObservationGrant` is a new, separate configuration record; the existing
`ObservationGrant` type is unchanged. Each new record identifies a principal,
exact deployment ID, store instance, observation issuer and observation-trust
digest, with active/revoked status and its own validity interval. IDs keep the
existing identifier format; deployment IDs are not silently reinterpreted as
hashes. Multiple scopes require separate explicit grants. Grant principals must
appear in the enrollment inventory, and enrollment/grant intervals must fit
inside the configuration interval.

Optional `max_requests` and `window_seconds` form a complete bounded declaration.
They do not create usage counters or enforce rate limits. The output explicitly
sets `rate_limit_enforced=False`; repeated pure calls consume no quota. Among
active matching grants, selection uses longest validity then stable grant ID.
Actual rate semantics and atomic enforcement must be defined before integration.

## Signature, revision and access evaluation

`evaluate_config_revision(document, *, trusted_key, trusted_checkpoint,
retained_head, now)` first verifies the pinned configuration, signature and
current key authority. Configuration validity must fit the key validity interval;
key, configuration and checkpoint must be active at evaluation time. Effective
time is a signed policy boundary, not independent proof of when signing occurred.

The function then compares a host-owned `CallerConfigHead`:

| Relationship | Pure result |
| --- | --- |
| No retained head; independent checkpoint verifies | `INITIAL`, proposed head only. |
| Equal revision and digest | `UNCHANGED`, no refreshed acceptance timestamp. |
| Higher revision with independently pinned candidate | `ADVANCE`, proposed head only. |
| Lower revision | `CONFIG_ROLLBACK`. |
| Equal revision, differing digest | `CONFIG_FORK`. |
| Retained acceptance time exceeds supplied time | `CLOCK_REGRESSION`. |

Complete configuration snapshots may skip revisions when the independent current
checkpoint pins the candidate. This is not replay of a configuration event ledger.
No proposal is persisted, and absence of a retained head is not trust-on-first-use:
the independent key/checkpoint are still mandatory. Local head comparison is not
proof against external rollback of all supplied inputs.

`validate_caller_request` verifies that configuration and head, then requires:

1. A bounded, exact `VerifiedIdentity` currently valid at the supplied time.
2. Identity registry revision equal to the separately signed registry revision.
3. Active certificate enrollment matching both identity and request principal.
4. Canonical request bytes, the v2 request action, and a current request interval
   of at most 60 seconds.
5. A current independently supplied observation checkpoint for the request scope.
6. An active explicit grant matching deployment, store, observation issuer and
   observation-trust digest. Revoked matching grants produce `GRANT_REVOKED` when
   no active matching grant remains; absent/mismatched grants are denied.

A match returns a frozen `CallerConfigAuditBinding` with configuration digest,
revision and key ID; registry revision; verified principal and certificate;
connection/audit IDs; exact request digest; target scope/trust; and grant ID.
The validity upper bound is the intersection of all applicable intervals, with
fractional identity expiry rounded down rather than widened. Result status is
`MATCHED`, with `audit_only=True` and `signature_verified=True`, not an execution
permit. Denials carry no partial binding. Detailed reason codes are internal
diagnostics; existing public transport denials remain unchanged and sanitized.

## Chosen in-flight policy: preserve audit snapshots, keep live checks

An earlier audit binding remains immutable after a newer configuration disables
the credential or revokes/removes the grant. A new evaluation against the updated
checkpoint and configuration denies access. Supplying an old document with the
new checkpoint also fails. Prior bindings are never accepted as identity evidence
or configuration authority.

The pure function cannot detect an unseen update. An old document, old checkpoint
and old retained head that are internally consistent and unexpired can still
match as an audit snapshot. That explicitly does **not** establish latestness.
The future host provider must obtain fresh, coherent inputs and retain monotonic
state; a signed timestamp or revision alone cannot supply that guarantee.

Existing live mTLS enrollment, bridge grant and signer rechecks are unchanged.
This module does not wire configuration discovery into them or claim an atomic
revocation/release guarantee. Persisting configuration audit bindings in
`ClientJournalIntent` would change its canonical digest contract and requires a
separate versioned design/migration. No fields were added to existing journal
records, and no delivery-failure event or automatic cleanup was introduced.

## Validation and next boundary

Tests cover real in-memory Ed25519 signatures, a fixed preimage vector, independent
checkpoint/key pins, malformed canonical inputs, issuer/key status, certificate
mapping and rotation, principal/scope/trust mismatches, expiry and fractional
identity bounds, explicit credential/grant revocation, immutable prior snapshots,
revision rollback/fork/clock checks, declared-but-unenforced rates, input limits,
and zero I/O or wall-clock use.

Production loading, protected path/ACL validation, TLS enrollment-registry
construction, live configuration distribution, durable revision storage, rate
counters, key custody and journal audit-format migration remain deferred.
Cryptographic certificate validation belongs to the existing TLS/native
certificate layer: enrollment denial is a host check after authenticated peer
evidence is available, not a new TLS handshake implementation here.
