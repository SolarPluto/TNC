# Session-bound handoff and temporary authority observation bridge

The bridge connects the real mTLS transport to the existing **temporary,
synthetic-policy authority store**. It is named `TestObservationBridge` to keep
that boundary explicit. It does not activate a production authority service.

## Handoff contract

`ObservationRequestBinding` remains serializable audit data. It cannot be passed
to the bridge as authorization. `ObservationRequestTransport.receive_handoff`
instead validates a frame and retains its exact canonical bytes and binding in
an `ObservationHandoff`.

The handoff is confined to the originating transport instance, exact connection
object, process, and thread. Its monotonic expiry is the earlier of the original
request-processing deadline and five seconds after minting. The first
consumption attempt burns it under a lock, including attempts that fail scope,
expiry, or storage checks. Copying, deep-copying, ordinary mutation, JSON export,
and pickle serialization are rejected. There is no exported token format or
deserialization route.

These are host API constraints, not a defense against hostile Python code in
the process. Private attributes and constructor sentinels cannot provide an
OS-level security boundary. The serializable audit record and unsigned output
remain reports, not bearer credentials. Discarded handoffs confer no persistent
state or recovery capability; a caller must send a fresh framed request.

## Bridge flow

1. Consume the handoff for its original host transport and connection.
2. Re-verify mTLS enrollment and current observation grants, exact request
   digest, registry/policy revisions, scope, connection identity, and time.
   No SQLite operation occurs before these host checks succeed.
3. Derive the existing synthetic authority caller context from that binding.
   The mapping is explicit test-store compatibility, not production policy
   authentication. The authority's own snapshot policy must independently grant
   observation access.
4. Call `ReadOnlyAuthorityAdapter.observe_current_snapshot`. It captures the
   observation and policy from the same validated `BEGIN` read transaction,
   using `mode=ro` and `query_only`. Historical recovery remains separate.
5. Recheck host authorization, time, and the original cumulative deadline after
   acquisition. Failures suppress the candidate. Revalidation never extends the
   original binding interval.
6. Return an immutable `UnsignedObservationCandidate` or a generic denial with
   no partial snapshot or filesystem diagnostics.

The candidate retains the exact v2 request (including principal, issuer, scope,
and challenge), its digest, live audit binding, full envelope and digest, and
the snapshot policy revision/digest. It uses aware datetime observation bounds.
It is **pre-signing data, not a complete `ObservationPayload` or signed
response**: no signing key, trust revision, or independent checkpoint is
invented. A future signer must supply and validate those host-owned inputs and
handle v2 integer-time bounds explicitly.

## Snapshot and concurrency limits

Envelope and authority policy come from one read transaction; no second policy
read is used to assemble the candidate. A concurrent authority-policy update
can legitimately leave an in-flight read reflecting its earlier snapshot.
Host enrollment/policy rechecks detect changes between checked snapshots, not
changes after the final check. No shared release-authorization lock is added.

Deadlines are cooperative for host providers and SQLite validation. Late results
are rejected, but a Python callback is not forcibly interrupted. Single-use
handoffs do not consume request challenges globally or prevent a fresh,
authorized network request from observing again.

No signing, checkpoint publication, state mutation, service launch, or persistent
credential was added. Tests use temporary certificates and authority databases,
covering real TLS binding, pre-read denials, post-read suppression, atomic
snapshot assembly, confinement, failed-read consumption, serialization refusal,
expiry, and unchanged database contents.
