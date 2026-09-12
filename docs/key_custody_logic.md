# Pure key custody compatibility and attempt simulation

`key_custody_logic.py` introduces frozen `tnc-key-custody-v1` public records and
a pure observation-v2 compatibility evaluator. It does not generate/import keys,
produce or verify signatures, invoke hardware or SDKs, read clocks, acquire
handoffs, store state or change any signing/transport path.

## Public records and trust ownership

- `KeyHandleRecord`: exact provider/resource/version identifiers, full SHA-256
  digest of 32 public-key bytes, deployment/store/issuer scope, observation-v2
  purpose, creation/validity bounds, revision, lifecycle and allowed host signers.
- `CustodyCapabilities`: provider mechanism, raw byte limit, output format,
  availability and validity. These are pinned declarations, not device attestation.
- `CustodyTrustAnchor`: independently supplied scope, revision, validity and exact
  handle/capabilities digests. It is never inferred from the signing request.
- `CustodySignRequest`: attempt ID, signer identity claim, pinned handle digest,
  full existing ObservationPayload and exact preimage bytes represented as hex.

Provider resource identifiers and TNC key IDs remain different fields. An opaque
resource/version string alone does not prove a provider resource is immutable or
hardware-backed. Non-exportability, key origin, provider authentication, current
revocation and protected acquisition must be established by later adapters.

The separately supplied signer identity and anchor are trusted host inputs here.
The function cannot authenticate them from a string or establish unseen freshness.
There is no persistent revision floor; a valid old pin cannot prove it is latest.

## Exact v2 preimage and mechanism

`evaluate_custody_request` reconstructs the exact bytes using the existing
`observation_preimage` helper and requires byte equality. It preserves
`b"TNC-SIGNED-OBSERVATION-v2:" + canonical_json(payload)` without changing v1 or v2.
Alternate domains, padding, pre-hashed messages and modified payloads fail.

Only ED25519_RAW with RAW_64 output is compatible. Ed25519ph, ECDSA and DER output
are represented so capabilities can be explicitly rejected; none triggers fallback.
The module does not implement checkpoint, transition or journal signing domains.
Those purposes require separate contracts rather than a general signing oracle.

Check actual raw preimage length against the pinned provider limit. A 4,096-byte
profile is a test capability, not a global TNC limit or proof of compatibility with
any selected service. Requests exceeding their provider limit are rejected; they
are never truncated, normalized, pre-hashed or split into alternate signing calls.

The protocol's structural bound is 65,536 payload bytes plus the existing domain
prefix. Hex representation doubles only the record encoding, not the raw signing
message length. A provider acceptance gate must test its real maximum against the
actual legal payloads and APIs before any deployment is selected.

## Evaluation limits

The evaluator checks independent pin digests, provider identity, scope, permitted
host signer, active key state, mechanism, availability and current validity. ROTATING,
REVOKED and DISABLED are all denied; rotation is not permission to keep signing.

It binds the payload to the separately retained observation request by request
digest, principal, issuer, challenge and scope, and binds the payload signing key
to the handle. Times must place payload issuance inside key/capability/anchor
validity, and the entire payload lifetime must fit those bounds. A shorter internal
attempt window cannot widen the signed lifetime.

READY is only a compatibility finding, audit_only=True and signature_verified=False.
It does not replace bridge authorization, the observation trust-store/checkpoint
checks, envelope/policy validation, cryptographic verification or current live
revocation checks. Those existing components remain unchanged. The embedded
envelope's claims are not independently replayed or authenticated by this layer.

## Pure attempt model

`simulate_custody_attempt` accepts explicit start/completion times and a synthetic
provider outcome. It returns a proposed immutable state; callers choose whether
to apply it. A modeled first attempt consumes its ID even on denial or failure.
Reusing an applied ID yields ATTEMPT_ALREADY_USED or ATTEMPT_CONFLICT without a
new proposal. No attempt-ID behavior is a durable or hostile-process single-use
security boundary, and no real signing handoff is consumed.

Outcomes distinguish DENIED, SIMULATED_COMPLETION, PROVIDER_FAILED,
SIGNING_OUTCOME_UNKNOWN and RESULT_DISCARDED. A simulated successful result arriving
after validity expires is discarded. UNKNOWN does not claim no signing occurred.
SIMULATED_COMPLETION explicitly records NO_SIGNATURE_PRODUCED.

Receipts bind request/anchor digests, attempt IDs, sequences, times, outcomes and
previous receipt digests. This checks structural continuity, not independent
authenticity: someone able to replace all synthetic records can recompute hashes.
Receipts are not verifiable device signatures, hardware audit logs or execution
permissions. The simulator does not fetch changed metadata during an attempt;
live replacement and SDK behavior belong to the later fake-provider adapter.

## Bounds and tests

All new integer times/revisions are strict signed-64-bit nonnegative values
(positive where required). Nested numeric fields are range-checked when custody
records are decoded. Canonical decoding rejects duplicate/extra fields,
noncanonical encoding and non-finite numbers. Records are bounded at 512 KiB,
simulation images/results at 1 MiB, and attempt history at 32 receipts.

The 58 pure tests use deterministic public records and no generated private keys
or temporary stores. Golden vectors pin exact preimage length/hash and request
digest. Tests cover raw-length boundaries, a 4,096-byte capability, forbidden
prehash/domain changes, key/provider pins, scopes, temporal bounds, immutable
records, simulated outcomes, late results, attempt reuse and history/capacity.
A side-effect guard forbids file/socket/SQLite/clock and key-generation calls during
evaluation. No provider, account, key, credential or production route is created.
