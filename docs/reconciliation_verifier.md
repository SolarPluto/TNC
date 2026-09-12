# V2 signed current observations

`reconciliation_verifier.py` defines frozen v2 request, key, trust checkpoint,
payload, response and result records, plus read-only Ed25519 verification.
V1 records and vectors remain unchanged. The v2 domain is
`TNC-SIGNED-OBSERVATION-v2:` followed by exact canonical payload JSON; the profile
is `tnc-authority-v2`, with action `OBSERVE_CURRENT`.

Observation times are strict integer epoch seconds. The embedded historical
ReconciliationEnvelope retains its existing canonical UTC-string format. It is
not rewritten. Deployment and store instance remain separate fields to avoid
ambiguous combined identifiers.

Key IDs are full SHA-256 digests of raw 32-byte Ed25519 public keys. Keys explicitly
bind scope, observer issuer, permitted envelope issuer, current status, observation
permission and validity. The envelope's logical key ID is not the observation
signing key. No certificate-fingerprint equivalence is inferred.

The verifier requires a separately supplied retained request and trust checkpoint.
It validates exact trust revision/digest/scope, key authority, signature, retained
request digest and principal/challenge/issuer/scope, time bounds, and complete
envelope digest/revision/scope/issuer binding. Request and response lifetimes are
limited to 60 seconds; timestamp <= now < expiry, without implicit clock skew.
Key/store/checkpoint must cover issuance and verification, and bound response
expiry. The envelope must cover the response as well.

Successful results contain the checked payload and response digest, with audit_only
set. They are not execution capabilities. The signed policy revision/digest is an
authenticated issuer assertion, not independently validated policy content. A
trusted checkpoint's actual freshness is a host assumption; the verifier cannot
discover a newer trust revision or detect whole-store rollback.

Canonical request/payload/key/checkpoint records are bounded to 64 KiB, trust stores
to 1 MiB and 64 unique sorted keys, responses/results to 128 KiB, and total verifier
input to 2 MiB. Duplicate JSON keys, unknown fields, noncanonical bytes, malformed
signature/key shapes, and coercive time values are rejected. Raw incoming bytes
must enter through decode_v2_record before typed verification; the typed verifier
revalidates records defensively.

There is no signer API, persistent key storage, network/file access, reader/writer
integration, historical-signature recovery, challenge consumption, high-water
mutation, or checkpoint publication. Repeated verification can succeed for the
same still-valid retained request. Tests use ephemeral private keys only in memory.
Signing authenticates a snapshot assertion, not release-time authorization.
