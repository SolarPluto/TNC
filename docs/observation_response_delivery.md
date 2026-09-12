# Bounded response delivery — test-only contract

This profile connects the existing ephemeral test signer to the client over real
loopback TLS. It does not add a production listener, signer cache, durable inbox,
network ACK protocol, automatic retries, or checkpoint publication.

## Wire format and deadlines

One response is a four-byte unsigned big-endian length followed by the exact
canonical JSON bytes of a v2 `SignedObservation`. Payload length must be from 1
through 32,768 bytes. This is a narrower delivery-profile limit; the existing v2
record and verifier limits are unchanged. JSON shape validation is not signature
verification. The client store must still verify the signature, retained request,
trust checkpoint, time, and high-water transition before acceptance.

The host supplies an absolute monotonic deadline. Send and receive loops use the
same deadline for every fragment and restore their previous socket timeout on
success. Partial writes, fragmented headers/bodies, zero-progress writes,
truncation, invalid sizes, malformed canonical bytes, and late completion fail
closed. Failed streams close; partial bytes are not resumed on that stream.

`MtlsConnection.send_before` pins the verified principal, credential, connection,
and enrollment revision across partial writes. `send_signed_response` also
requires the signed principal to match that live identity. These are transport
checks, not a new observation-grant authorization or atomic release gate.
The receiver requires its exact host-owned client TLS context, verified TLS 1.3,
certificate verification, and hostname checking from the existing handshake.

Socket I/O is bounded by the remaining deadline. Host enrollment callbacks are
cooperative and must themselves be bounded; late results are rejected, but Python
callbacks are not forcibly interrupted. No deadline can retract bytes already
sent. A successful send proves neither complete receipt nor a SQLite commit.

## Corrected failure and recovery matrix

| State | Required behavior |
| --- | --- |
| No complete retained response | No client transaction. A new request requires fresh mTLS/grant checks, snapshot and signing handoffs. It may observe a later authority head. |
| Complete response retained, no commit | Reuse the exact retained full `AdvancementRequest` locally if still valid. If expired, reject; a fresh observation is needed. |
| Response lost from memory before commit, no retention | Exact retry is impossible from an operation ID alone. There is no server replay cache in this profile. |
| Client committed, local completion acknowledgement lost | Recover the original receipt locally from the exact retained request and operation ID; no upstream request or signing handoff is needed. |

Re-signing the same authority revision is not an exact retry: challenge, request,
issuance, expiry, or signature bytes may differ. A fresh valid observation need
not advance the high-water mark; it may be `UNCHANGED` or rejected by its temporal
or lineage checks. Operation IDs are idempotency bindings, not credentials.

Network ACKs do not establish local commitment. The harness defines no such ACK
exchange. It tests loss of the local completion acknowledgement after the SQLite
commit, then exact receipt recovery. The two SQLite databases remain separate;
there is no cross-store transaction or distributed commit coordinator.

## Retention and test scope

The harness writes a complete public `AdvancementRequest` to a test-owned file
and flushes it before selected client-process exits. This includes the signed
response, retained request, operation ID, public trust store and checkpoint.
The file is explicit fixture retention, not a production durable inbox, protected
configuration source, authenticated recovery store, or power-loss guarantee.
Tests without retained bytes start a fresh observation cycle instead.

Tests exercise exact bytes across TLS, partial reads/writes, cumulative deadlines,
sender enrollment changes, receiver-context mismatches, invalid signatures after
successful framing, before-delivery disconnects with a later fresh authority
snapshot, retained responses across pre/post-commit process exits, expiry before
commit, and offline receipt recovery. Temporary keys and certificates are test
fixtures. Application clocks are controlled; real socket timeouts and deterministic
monotonic hooks cover transport bounds without sleep-based race assumptions.
