# Loopback mTLS observation request binding

`ObservationRequestTransport` joins the existing `MtlsConnection` to the pure
Phase 1 binding rules. Construct it with host-owned policy/context readers and
an aware UTC clock. Pass only the connection returned by `MtlsServer.accept`.
There is deliberately no separate socket parameter: the bytes and peer identity
come from the same accepted TLS connection.

## Framing and lifetime

One frame consists of a four-byte unsigned big-endian payload length followed
by exact canonical v2 request bytes. Lengths from 1 through 16,384 are permitted;
the request must still pass canonical and structural validation. Reads accumulate
fragmented headers and bodies and stop at the declared boundary. Subsequent
frames remain for later calls, each requiring fresh checks. Use one host worker
per connection.

The configured total deadline is finite, positive, and at most 30 seconds
(default 10). It starts when `bind` is called, after the existing TLS handshake.
The new `MtlsConnection.recv_before` re-verifies enrollment, recomputes the time
remaining before the socket receive, and restores the previous socket timeout.
All framing and host-validation stages check the same monotonic deadline.
Host callbacks must themselves be bounded: these checks reject late results
but cannot forcibly interrupt a blocked Python provider. The handshake retains
the existing server timeout; this is not a combined handshake/request deadline.

## Identity and policy binding

The adapter obtains the connection's verified identity, reads a frame, snapshots
the host observation policy and context, and invokes Phase 1. Before returning,
it verifies the connection again, rejects changed credential/principal/connection
or enrollment revision, re-reads policy/context, and re-evaluates pure binding
with a fresh clock. Backward wall-clock movement and expired inputs are denied.

Every failure returns a generic `DENIED / ACCESS_DENIED` outcome without partial
identity or request data. Failed streams close, including framing errors, so
partial requests cannot desynchronize later reads. Successful calls leave the
connection available for another independently checked frame. The adapter sends
no network response; the returned binding remains host-side audit data.

## Limits

Enrollment and observation policy providers are trusted host dependencies.
Repeated checks detect changes between snapshots; they do not share an atomic
authorization lock or prevent changes after the final check. This is snapshot
audit validation, not release-time authorization. Existing TLS trust and CRL
reload limitations still apply. A challenge is bound to the request, not consumed
as a one-use token; exact repeated frames are allowed under current checks.

There is no production listener, authority-store access, observation signing,
credential provisioning, checkpoint publication, or database mutation here.
Tests use real loopback TLS and temporary certificate files. Deterministic clock
hooks exercise cumulative deadline failures; a separate real socket timeout test
checks silent-peer handling. Tests also cover fragmentation, truncated and
oversized frames, spoofed claims, enrollment and grant changes, reuse, time
bounds, and sanitized provider failures.
