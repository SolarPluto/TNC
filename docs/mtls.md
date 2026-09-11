# mTLS transport adapter

`src/tnc/provenance/mtls.py` adds a real socket/TLS boundary to the existing
enrollment contracts. It does not start a service, install certificates, expose
HTTP routes, or connect to the request journal.

## Host interface

Construct `MtlsServer` with protected host-selected certificate, private-key and
CA bundle paths plus an `AuthorizationStateReader`. Pass an accepted raw socket
to `accept()`. The server owns that socket thereafter and closes it if the TLS
handshake or current enrollment check fails. It returns an `MtlsConnection` only
after both checks succeed. A pre-wrapped SSL socket or a certificate/header blob
cannot substitute for the handshake.

The adapter uses Python/OpenSSL certificate verification with required client
certificates, TLS 1.3 only, strict X.509 verification, explicit trust files, and
disabled tickets. The client context helper requires certificate verification and
SAN hostname matching; callers must supply the intended `server_hostname`.
Certificate bytes and validity dates come from the verified socket, using public
SSL APIs. [Python SSL reference](https://docs.python.org/3.12/library/ssl.html).

SHA-256 of the peer's DER certificate selects an exact enabled enrollment in the
existing registry. Neither certificate display names nor request headers assign
principals or permissions. Each `verify()` creates fresh identity evidence and
checks current enrollment. Connection IDs are stable per connection; audit IDs are
new per verification. Certificate expiry is checked again on reused connections.

Before each future application request, call `verify()` then the authorizer for
the specific action and host-resolved resource. Connection `recv()` and `sendall()`
also check enrollment, but these transport methods do not grant application
permissions. One worker should own each connection. Stream framing, size limits,
HTTP handling and dispatch are future work.

## Revocation and lifecycle

Local enrollment disablement is always checked and does not require a CRL.
Optional `crl_file` enables issuer-signed leaf CRL verification during handshakes.
Tests demonstrate rejection for revoked clients and missing or expired CRLs, and
acceptance with a current clean CRL. No online OCSP or automatic CRL retrieval is
implemented. Without `crl_file`, this profile does not claim CA revocation checking.

CA and CRL files are loaded at construction, not reloaded for each request.
Replacing trust/CRL state requires constructing a new server and retiring old
connections. CRL expiry/revocation is not revalidated on established connections;
current enrollment disablement is the application control for those connections.
An operational CRL refresh and connection-retirement policy remains required.

The accepted socket has a finite timeout, default five seconds, with configuration
limited to at most thirty seconds. Handshake failures become generic
`AuthenticationError`; configuration errors do not trigger insecure fallbacks.
Explicit context construction avoids ambient system trust roots and environment
key logging. No TLS 1.2 downgrade or early-data handling route is exposed.

This initial file-based key profile takes protected unencrypted PEM keys and
suppresses interactive password prompts. Deployment still requires secure key
provisioning and OS ACLs; encrypted-key or Windows key-provider integration is not
implemented. No real keys or trust roots are created by the production module.

The host owns the context and Python process. Private attributes and connection
objects are not protections against hostile in-process code. Current identity
checks do not close the authorization-to-release race: final authorization must
still be coordinated transactionally with the journal and outbox.

## Tests and dependencies

`tests/test_mtls.py` performs real loopback TLS handshakes with temporary certificates
and keys. The `cryptography` package is a development-only dependency used to create
test CAs, certificates and CRLs; the production adapter uses the standard library.
Certificate construction follows the library's X.509 builder APIs.
[Cryptography X.509 tutorial](https://cryptography.io/en/latest/x509/tutorial/).

The 32 cases cover valid enrollment without implicit permission, missing/expired/
future/untrusted/wrong-purpose client certificates, server hostname/root/expiry/
purpose checks, SAN-only hostname verification, disabled/unknown/unavailable
enrollment, certificate rotation, reused-connection disablement and expiry, CRLs,
TLS 1.2 rejection, timeout handling, invalid configuration, header/blob rejection
and avoidance of environment-based TLS key logging.

Test sockets are bounded, local and closed after each case. Generated keys exist
only under pytest temporary directories; they are not installed in Windows or
committed. No service or persistent listener is installed. The historical CLI,
journal, SQLite schema and ABC review state remain unchanged.
