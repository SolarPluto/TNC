# Test-only key custody provider

`key_custody_provider.py` adds an ephemeral Ed25519 test double around the pure
custody compatibility evaluator. It changes no production route, bridge, signer,
trust distribution, database schema, or execution permission.

## Inputs and custody

`TestCustodyProvider` generates one private key in memory. Only its raw public
bytes are exposed through the API. Fixtures build a `KeyHandleRecord` (the existing
custody descriptor), capability record and independently supplied trust anchor.
The instance verifies that its public key matches the pinned descriptor exactly.
The pure evaluator checks scope, signer identity, status, validity, mechanism,
payload size and exact v2 preimage bytes before dispatch and again before release.

Only raw Ed25519 over `observation_preimage(payload)` is used. There is no hashing
fallback, alternate signing mechanism, automatic retry, SDK or hardware access.
Provider byte limits remain capability-specific, including a possible 4096-byte
profile. The entire domain prefix counts toward that limit.

## Handoffs and deadlines

`mint_handoff_for_testing(id, request, deadline=...)` captures validated canonical
request bytes in a provider-owned registry. The returned opaque object cannot be
copied or serialized through its API. A caller cannot substitute a request at sign
time. The original monotonic deadline must be live and at most five seconds away.

Each recognized handoff is consumed under a lock before checking inputs, clocks,
key status or fault mode. Failure, closure, context misuse and denial all burn it.
Reusing it returns `HANDOFF_ALREADY_CONSUMED` without dispatch. A foreign object
returns `INVALID_HANDOFF`; it cannot consume another provider's registry entry.
Handoffs are bound to their creating process and thread. The provider retains up
to 256 IDs without eviction, including consumed IDs; exhaustion requires a new
test fixture. IDs cannot be reminted within the instance.

The clock is checked at mint, entry, pre-dispatch, completion and release. Epoch
time is independently supplied for custody validity checks. Clock regression or
expired output fails closed. Injected clocks make the boundary tests deterministic.
This synchronous fake cannot cancel an indefinitely blocked hardware call; future
real adapters need their own bounded driver execution and cancellation contract.

## Fault modes and results

| Mode | Result | Dispatches |
| --- | --- | --- |
| SUCCESS | VERIFIED, locally verified SignedObservation | 1 |
| WRONG_KEY | SIGNATURE_INVALID | 1 |
| TAMPERED_SIGNATURE / INVALID_SIGNATURE | SIGNATURE_INVALID | 1 |
| UNSUPPORTED_MECHANISM | ALGORITHM_UNSUPPORTED | 0 |
| DEADLINE_EXPIRED | DEADLINE_EXCEEDED | 0 |
| AMBIGUOUS_OUTCOME | OUTCOME_UNKNOWN, signature withheld | 1 |
| LATE_RESULT_REJECTION | RESULT_DISCARDED, signature withheld | 1 |
| PROVIDER_FAILURE | PROVIDER_FAILED, definitive injected failure | 1 |

Unexpected exceptions after entering dispatch return OUTCOME_UNKNOWN, because a
signature might exist. The ambiguous mode deliberately signs and then withholds
the result. There is no signature recovery cache. Another signing attempt requires
a fresh test handoff and re-evaluation; a retained downstream committed receipt
continues to use its independent offline recovery path.

`signature_verified` means the returned signature was checked locally against
the pinned public key and exact preimage. It does not mean the observation's
policy assertions, freshness, live grants or independent observation trust are
authorized. The tests separately run the existing full v2 verifier with independent
observation trust records for a valid round trip.

## Scope and test matrix

Tests cover real round trips, wrong keys, changed preimages, no prehash fallback,
malformed signatures, unsupported capabilities, disabled/closed providers,
consumption on failures, context misuse, concurrent reuse, invalid and regressing
clocks, pre-dispatch and post-verification deadline boundaries, expired returned
payloads, ID capacity, ambiguous completion, fresh attempts, and no file/socket/
SQLite operations while signing.

This is fixture authorization, not an adapter for the existing live mTLS signing
handoff. Minting a test handoff does not establish live caller permission. Provider
private attributes are not a hostile-process security boundary. Process restart
resets this in-memory inventory, and close releases the key reference without
promising secure erasure. No production key import, persistence, hardware custody,
attestation, remote freshness or durable single-use guarantee is implemented.
