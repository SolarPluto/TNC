# Installer update signature verification

`update_verification.py` implements read-only Ed25519 signature verification using
the existing `cryptography` dependency. It contains no private-key generation,
signing utility, file/network access, trust-store update, authority-store mutation,
pointer replacement, or process control. Tests generate temporary keys only in
memory. No CLI or production update route is connected to the verifier.

## Fixed signature profile

The only profile is `tnc-update-ed25519-v1`. It uses existing canonical JSON rather
than offering JSON/CBOR alternatives. The exact signing bytes are:

```
b'TNC-INSTALLER-UPDATE\x00v1\x00'
|| uint32_be(len(deployment_utf8)) || deployment_utf8
|| uint64_be(len(canonical_intent_json)) || canonical_intent_json
```

Lengths count bytes. The intent already contains its domain, deployment,
publisher, signer key hash, candidate bundle, and expected authority head. A
`SignatureEnvelope` contains the fixed profile/version, deployment, key ID, and
64-byte signature encoded as lowercase hexadecimal. Header deployment and key ID
must match the signed intent. No unsigned timestamp, algorithm negotiation,
certificate URL, public-key override, or signature-stripping option is accepted.

Public keys are exactly 32 Ed25519 bytes encoded as lowercase hexadecimal. Key IDs
are SHA-256 of DER SubjectPublicKeyInfo; they are not X.509 certificate digests.
The library performs verification; failed signatures are mapped to a fixed reason.
See the [cryptography Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

## Current trust and authorization checks

`verify_update_intent_signature(intent, signature_envelope, trust_store,
trusted_checkpoint=..., now=...)` requires an independently supplied checkpoint.
The checkpoint pins deployment, exact store revision/digest, and validity. The
store contains bounded, sorted key history, current publish permissions,
generation bounds, active/retired state, and an explicit revoked-key set.

Checks include canonical record validity and size, deployment equality, checkpoint
binding, current store/checkpoint validity, signer mapping, revocation, active key
state, key validity at the supplied current time, principal/publish scope,
generation limits, intent validity, activation boundary, and cryptographic
verification. Verification records are bounded to one MiB and stores to 64 keys.

A signature does not establish when it was created. This profile checks current
key eligibility and requires intent.valid_from to be no earlier than key.valid_from.
It does not claim to detect all backdating or implement trusted timestamping.
The explicit `now` must come from the trusted host, never from the request.

The trust checkpoint must likewise come from a currently authenticated host trust
source. An old store fails against a newer checkpoint. Restoring both the store
and its trusted checkpoint is outside this verifier's protection. The future
trust-store publisher must maintain monotonic revisions and revocation history;
this read-only verifier cannot prove continuity across independently supplied
snapshots, persist a high-water mark, or poll for supersession.

## Historical verification and recovery

`verify_committed_update_signature` is a separate archival check. It requires the
old intent/signature, old trust snapshot/checkpoint, receipt, and an independently
trusted `CommittedSignatureBinding`. That binding pins the exact receipt,
signature envelope, and historical trust checkpoint digests for the deployment.
The implementation also checks receipt-to-intent associations and verifies key
eligibility at the recorded commit time.

Existing `UpdateReceipt` records are not signed receipts. The binding is a new
contract for trusted archival attestation of the signature seen at commit; no
store currently writes or authenticates it. A caller-supplied binding is not proof.
Without an authentic binding, a signer-selected timestamp or forged receipt could
misrepresent a newly created signature as historical.

Retirement, expiry, or later revocation does not rewrite the evidence captured in
the pinned historical snapshot. A key revoked in that snapshot is rejected. A
later compromise does not make this check proof of the real person's historical
intent; the result establishes consistency with the trusted archival binding.

Historical results never authorize a current receipt lookup, publication, or new
commit. The host must separately authenticate and authorize the current caller,
including any rotated key, before exposing recovery data. A recovered receipt
must not be re-signed or assigned a new intent merely to make verification pass.

## Results and integration boundary

`UpdateSignatureResult` explicitly distinguishes CURRENT and HISTORICAL modes.
Success reports bound identity/digests, trust revision, and evaluation time.
Rejection carries a fixed reason without verified identity or exception details.
Neither result is an execution capability or a `SyntheticInstallerEvidence` object.

Signature verification does not validate all candidate deployment relationships
or replace the pure transition validator. Before real integration, a host must
coordinate fresh signer/trust checks with the authority store's serialized commit,
authenticate the live caller, and validate the complete transition. None of those
write paths is activated here. Existing provisioning, journal, and ABC quarantine
restrictions remain unchanged.
