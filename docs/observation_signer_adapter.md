# Test-only candidate-to-signed-response adapter

This module connects the temporary authority bridge to the existing v2 verifier
using an ephemeral Ed25519 key. It adds no production signer, key import, key
export, network response delivery, checkpoint publication, or persistent writes.

## Separate signing handoff

`UnsignedObservationCandidate` remains a frozen, serializable audit report.
Neither that object, a copied report, nor its canonical bytes authorize signing.
The host instead calls `TestObservationBridge.prepare_signing(connection,
request_handoff)`. This runs the same authorized snapshot path as `observe`,
consumes the original request handoff, and returns a separate non-serializable
signing handoff. The existing `observe` report API is unchanged.

The signing handoff retains canonical candidate bytes and their digest. It is
bound to the exact bridge instance, connection, process, and thread. Its deadline
is inherited unchanged from the original handoff; the five-second maximum is
not restarted after snapshot acquisition. The first attempt consumes it under a
lock, even if context, trust, time, or signing subsequently fails. Reuse raises
`CandidateAlreadyConsumedError`; other failures expose only `Signing denied`.
Copying, pickling, ordinary mutation, and unsigned-report substitution are
rejected. These remain application rules, not protection against hostile Python
code that can inspect private attributes or modify process memory.

## Public trust and ephemeral custody

`TestObservationSignerAdapter(bridge)` generates its own Ed25519 key in memory.
The API accepts no imported private key, path, secret-provider callback, or
production KMS/HSM. It exposes raw public key bytes so an independent test host
can construct a pinned public trust store and checkpoint. It never generates or
auto-trusts a checkpoint for the request.

`sign` requires the retained expected request, public trust store, and independent
checkpoint. It validates their canonical shapes, exact scope and request
bindings, checkpoint revision/digest, the SHA-256 key ID, raw public key match,
active status, observation permission, observer/envelope issuer mappings, and
validity windows before invoking the private key. Input provenance is still a
trusted-host fixture assumption; there is no live trust distribution or trust
revision provider in this adapter.

`close` drops the key reference. The API does not serialize the signer or export
its private key; Python lifetime management does not guarantee secure erasure.

## Conservative integer-time conversion

The adapter uses exact datetime delta arithmetic, avoiding floating-point epoch
rounding. Nonnegative signed-64-bit time bounds are enforced for this adapter;
the existing v2 schema is not changed.

- Datetime lower bounds are rounded up to the next whole epoch second.
- Datetime upper bounds are rounded down; expiry remains exclusive.
- Issuance uses the floor of the current host clock and must satisfy all rounded
  lower bounds. The adapter does not backdate to fit a candidate or issue a
  future timestamp.
- Expiry is the earliest request, candidate, live binding, envelope, key, trust,
  and checkpoint expiry, further limited by the whole seconds remaining on the
  original monotonic deadline.

If no positive whole-second interval exists, signing fails and the attempt is
consumed. A just-created fractional-second candidate may therefore be rejected
immediately. The adapter does not sleep or retry automatically. Tests demonstrate
that a caller arranging its first signing attempt in a later valid second can
succeed while still inside the inherited deadline. A production protocol would
need an explicit scheduling or timestamp-precision decision.

## Signing and release checks

The adapter rechecks the live transport and host grant context before signing,
constructs the existing `ObservationPayload`, and signs the exact preimage from
`observation_preimage` (`TNC-SIGNED-OBSERVATION-v2:` plus canonical JSON). It then
rechecks host authorization and time and runs `verify_observation` before
returning the `SignedObservation` container. A detected failure suppresses the
output, even if a signature has already been computed in memory.

These checks are not atomic with independent policy changes. They do not prove
latest authority state, prevent undiscovered revocation, globally consume a
challenge, or authorize runtime release. The signed policy digest authenticates
the snapshot assertion; the verifier does not independently replay that policy.
Returned bytes are never sent over the network by this adapter.

The suite exercises real loopback mTLS through the bridge and signer, independent
verification, copied-report rejection, single-use behavior, trust/key denial,
context changes, deadline preservation, conservative rounding, tampering,
post-signing suppression, and the absence of signing-stage file/database I/O.
