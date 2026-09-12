# Pure protected trust distribution contract

`protected_trust_distribution.py` implements frozen records and read-only
cryptographic validation for public observation trust-store distribution. It
performs no file/network access, signing, persistent high-water update, policy
publication, or runtime activation. Test signatures use ephemeral in-memory keys.

## Independent inputs

`verify_trust_distribution(bundle, *, policy, trusted_policy_checkpoint,
retained_head, now)` requires:

- A signed `TrustDistributionBundle` containing the payload, exact public
  `ObservationTrustStore`, and optional root-signed epoch transition.
- A host-supplied `DistributionPolicy` and independent
  `DistributionPolicyCheckpoint` pinning that policy's revision, complete digest,
  deployment/store scope, and validity interval.
- A trusted retained `DistributionHead`, or `None` for explicit initial evaluation.
- An exact nonnegative integer UTC epoch time supplied by the host.

The bundle cannot nominate its own policy or checkpoint. Typed policy pins and
head records do not authenticate their own provenance: protected acquisition,
independent current-state authentication and durable storage remain host duties.
This module does not populate the caller-configuration loader's distinct
`CallerConfigCheckpoint`; its output concerns observation trust distribution.

Configuration-signing keys, mTLS leaf fingerprints, observation-signing keys, and
distribution/root keys retain separate roles. Policy inventory requires distinct
distribution and root key IDs. Ed25519 key IDs are full lowercase SHA-256 digests
of raw 32-byte public keys. Distribution keys require
`DISTRIBUTE_OBSERVATION_TRUST`; the root requires
`AUTHORIZE_DISTRIBUTION_EPOCH`. Both are scoped to the deployment/store.

## Canonical domains and bounds

The two domains are fixed and versioned:

```
TNC-TRUST-DISTRIBUTION-v1:
TNC-TRUST-EPOCH-TRANSITION-v1:
```

Each preimage is the corresponding domain bytes followed by the exact canonical
JSON payload bytes using the existing canonical encoder. The checkpoint payload
binds deployment/store, issuer/key ID, checkpoint revision, predecessor payload
digest, epoch counter/ID, observation store revision/digest, issuance/expiry,
maximum age, and optional transition-payload digest.

The transition uses a separate domain, and its payload digest is signed into the
checkpoint. The transition binds the previous checkpoint revision/digest, previous
epoch/key, successor epoch/key, target checkpoint revision, and exact target
observation trust-store revision/digest. It does not hash the checkpoint payload,
avoiding a circular digest dependency. Each signature is checked separately.

Records reject extra fields, duplicate JSON keys, noncanonical encoding and
non-finite numbers. Time/counter fields are strict integers bounded to signed
64-bit nonnegative/positive ranges. Signature fields are exactly 128 lowercase
hex characters. Records are capped at 128 KiB. Policies permit at most eight
sorted unique distribution keys and one distinct root. Existing observation
trust-store models retain their own 64-key bound and are not modified.

## Fixed freshness, not a sliding lease

The signed `issued_at` is an assertion by the authorized distributor, not an
independent timestamp proving when the private-key operation happened. The host
must supply a trustworthy current clock. Future issuance is rejected without
implicit skew allowance.

Acceptance requires:

```
issued_at <= now < min(expires_at,
                      issued_at + min(payload.max_age_seconds,
                                      policy.max_age_seconds))
```

Both maximum-age declarations are bounded to 1–3,600 seconds. Current policy and
independent policy checkpoint validity are enforced. The distribution key must
be active and valid at issuance and verification. The observation trust store
must already be valid at issuance and remain valid at verification. A rotation
also requires a currently active root and a fresh, valid transition manifest.

The returned observation checkpoint expiry is conservatively capped by all
applicable policy/pin/key/store/transition intervals. Retrying never changes the
signed issuance time or grants a fresh TTL. A stricter current policy can shorten
the usable window.

**A TTL is not proof of the globally latest revision.** An old, internally
consistent bundle/policy/pin combination can still verify within its remaining
window if the node has not learned of a newer state. Current independent pins and
retained state constrain that window; the pure verifier cannot discover unseen
revocations. Tests explicitly preserve this limitation.

## Three distinct revision axes

- `checkpoint_revision` orders distribution checkpoints and never resets on epoch
  rotation. Direct successors require exactly `stored + 1` and the exact stored
  checkpoint-payload digest. Skipped revisions return `MISSING_CHAIN`; this
  milestone does not implement intermediate-chain batch ingestion.
- `trust_store_revision` is the existing observation trust-store revision. It
  cannot decrease. Equal revision requires the same complete store digest. A
  higher complete store revision can skip values when the authorized checkpoint
  explicitly binds it. A new checkpoint may renew freshness for the unchanged
  trust store without pretending its store revision advanced.
- `policy.revision` orders independently pinned distributor policy. A retained
  higher revision rejects regression; equal revision with different digest is a
  policy fork. A successful unchanged-checkpoint evaluation can propose an updated
  policy pin and checked time without advancing checkpoint revision or acceptance
  time. A future persistence adapter must save that proposal atomically.

Equal checkpoint revision plus equal payload digest is `UNCHANGED`, provided all
current cryptographic and temporal checks still pass. Equal revision with a
different digest is `CHECKPOINT_FORK`; a lower revision is
`CHECKPOINT_REGRESSION`. This preserves exact current retries without treating
an expired record as current. Historical receipt retrieval is a separate concern
and is not implemented by this API.

Initial evaluation requires the independently pinned bootstrap revision, epoch
counter/ID, signing key, a zero predecessor digest, and no transition. Merely
omitting a lost head is not a permitted normal restart procedure; explicit host
provisioning must govern that choice. Local storage cannot independently detect a
restore of all older records and pins.

## Root-authorized rotation workflow

This milestone implements the **root-signed manifest option**, not dual signing:

1. Independent policy delivery makes the incoming distribution public key
   available with the required scope and permission.
2. The root signs a bounded transition manifest binding the exact predecessor,
   new key, successor epoch counter/ID, target checkpoint revision and store.
3. The incoming key signs that checkpoint, including the transition-payload digest.
4. Verification checks both signatures and all bindings against the retained head
   and independently pinned policy. The proposed head advances only one epoch and
   one checkpoint revision. The epoch ID must change and cannot reset the sequence.
5. Later routine checkpoints use the new key and retained epoch without repeating
   the transition. A different key in the same epoch is rejected.

The retiring key's signature or current validity is not required for a root-
authorized transition. This permits explicit emergency replacement of a revoked
key. It does not permit a new key to authorize its own transition. Replaying the
transition checkpoint itself still checks its manifest/root validity; historical
root evidence is not promoted into current permission. Routine successors rely
on the already accepted epoch and current independently pinned distribution policy.

Rotating the root of the independent policy trust boundary is outside this
protocol. Delivery outages, missed overlap windows or unavailable root authority
can still cause fail-closed interruptions; cryptographic overlap alone cannot
guarantee zero downtime.

## Result and integration boundary

Successful `INITIAL`, `ADVANCE`, or `UNCHANGED` results contain an immutable
proposed head, checked observation trust store and existing-format
`ObservationTrustCheckpoint`. The latter's revision is the observation store
revision, not the distribution checkpoint sequence. Rejections contain sanitized
reason codes and no checked trust artifacts.

All results are audit-only. A successful signature check is not an observation
request authorization, live mTLS proof, signing handoff, or release permission.
Existing loader, bridge, signer, high-water and client-journal modules are untouched.
The next bounded integration should connect independently acquired current policy
pins and atomic retained-head storage before any runtime consumer treats these
proposals as its active trust source.
