# Signing-service IPC: test-only process boundary

This milestone implements a spawned-process loopback harness, not a Windows
signing daemon or a Unix peer-credential adapter. Existing live observation
handoffs are not serialized or replaced by generic bearer credentials.

## Authentication and bootstrap

The test parent provisions a random 32-byte per-principal secret to broker and
client through trusted multiprocessing bootstrap. Signing keys are generated
inside the broker process by `TestCustodyProvider`. Public metadata is returned
out of band using bounded test bootstrap messages. Multiprocessing's trusted
startup arguments are not an untrusted deserialization endpoint.

Each TCP connection receives a fresh random broker nonce. Requests and responses
carry HMAC-SHA256 over a direction-specific domain, nonce, principal and exact
canonical body bytes. Each connection accepts one request. Old request packets
cannot be replayed against a new challenge. The shared secret authenticates the
fixture principal; **it does not attest a PID, UID, executable or Windows token**.
Loopback is an addressing restriction, not authentication. The channel provides
message integrity/authentication, not encryption or protection from a compromised
process holding a fixture secret. Production OS peer authentication is deferred.

## Framing and limits

Frames use a four-byte big-endian length and a 32 KiB cap. The cap is checked
before payload allocation. Canonical typed JSON rejects unknown fields and
noncanonical encodings. Reads and partial writes share a total five-second
connection deadline. Admission and dispatch also intersect this connection budget;
client response decoding is followed by a final deadline check. Policy callback
exceptions deny access without escaping the authorization gate. Signed request bodies carry hex fields and JSON metadata,
so the frame cap is separate from the provider's 4096-byte raw preimage profile.
The existing pure evaluator enforces the raw preimage cap before issuing a token.
There is no prehash or alternate-mechanism fallback.

## Token and deadline semantics

ISSUE authorizes the fixture principal and validates the exact request against
broker-owned custody pins and retained observation request. The broker mints a
random ID and MAC bound to the boot instance, canonical request digest and owner.
Its registry retains the exact request and a broker-owned monotonic deadline of
at most five seconds. This establishes a **new broker admission lease**, not a
proof of a remote caller's earlier deadline. Future observation-bridge IPC must
bind a trusted remaining lease explicitly; arbitrary remote monotonic timestamps
are not accepted here. SIGN never extends an issued deadline or changes its body.

Up to 64 tokens and unique attempt IDs are retained without eviction per broker.
An authenticated owner consumes its recognized token on its first SIGN, including
denial, expiry, malformed request binding and provider faults. Authentication or
foreign-owner failures cannot burn another principal's token. Authorization denial
returns the same answer whether or not the token exists. A repeated consumed
token under current permission returns TOKEN_ALREADY_CONSUMED without dispatch.

Policy callbacks run before lookup, before provider dispatch and after return.
Response release performs another permission/deadline check. These discrete checks
are not a global lock against changes after the final check. The sequential test
broker serializes its own token registry; it does not implement service concurrency,
fair scheduling, durable policy storage or hardware driver cancellation.

## Historical recovery and uncertainty

RECOVER requires current recovery permission, exact request digest, token and
authenticated owner. It returns the saved outcome and original signed response
fields without invoking the provider. This is historical evidence, not renewed
current authorization. Recovering an unconsumed token returns NO_RECORDED_OUTCOME.

A lost network acknowledgement is unknown to the client but need not be unknown
to the broker: a retained verified result is recovered without signing again.
Provider ambiguity is recorded as OUTCOME_UNKNOWN with no signature. Late or
revoked output is discarded. A response-release denial overwrites the saved result
with a denial so a suppressed signature cannot be exposed through recovery.

The registry is in memory. Broker death loses outcomes and its secret; a new boot
rejects old tokens. This harness cannot provide durable exact recovery across
broker restart and never auto-resubmits an unknown operation. Durable broker
receipts and an authenticated recovery protocol are separate future milestones.

## Test coverage

Real spawned brokers and clients exercise signing, current permission gates,
nonce replay, forged credentials, cross-owner tokens, token tampering, frame bounds,
strict decoding, single use, expired leases, provider faults, mid-flight revocation,
client termination after result recording, historical lookup and broker death.
Fixture barriers expose precise software boundaries. They are not hardware
power-loss or production peer-attestation tests. No network command selects faults,
replaces trust configuration, alters policy or dispatches an arbitrary algorithm.
