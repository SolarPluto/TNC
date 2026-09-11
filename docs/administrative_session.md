# Live mTLS administrative sessions

`MtlsAdministrativeSession` implements the existing administrative session contract
by wrapping a host-created `MtlsConnection` returned by `MtlsServer.accept()`.
Every `verify_identity()` delegates to the live connection's `verify()` method.
The adapter caches neither identity nor permissions and accepts no actor overrides.

Use the validated `AdministrationWriter` enrollment reader when constructing the
host's `MtlsServer`. After successful handshake and enrollment, create the session
inside the trusted host and pass it to `AdministrationWriter.append`. The writer
still checks current authority inside its own database transaction. A successful
TLS handshake or session verification alone does not authorize an append.

The host retains ownership of the connection. A closed connection or disabled
enrollment cannot supply another identity. Permission revocation can leave TLS
identity verification valid while causing the writer's action check to deny.
Policy changes between identity verification and locking require fresh verification
and, for a new append, an updated expected head.

The constructor rejects raw sockets, dictionaries, strings, byte blobs and other
objects. This is an internal type boundary, not protection against hostile Python
code with access to the service process. Neither a session nor its connection is
accepted as serialized client proof. No public request route was introduced.

## Verification

13 tests cover real TLS-to-SQLite administrative append, actual fingerprint/actor
recording, an enrolled client without host.manage, disablement on a reused connection,
permission revocation, fresh-connection exact retry, closed connections, unknown
certificates, invalid constructor inputs and a policy change between verification
and the write transaction. The ordering test uses a second real TLS connection and
writer before the first writer obtains its transaction; it uses no timing sleeps.

Certificates are generated temporarily by the existing TLS test fixture. The tests
bootstrap their temporary v4 databases through an explicitly synthetic provisioning
adapter, then use real TLS sessions for every tested administrative write. They
do not test Windows operator authentication or a real bootstrap certificate-policy
loader. No certificates are installed in Windows.

The implementation adds no service, HTTP/JSON framing, CLI activation command,
provisioning adapter or journal execution route. The seven execution guards remain
unchanged. Real ABC captures receive no approvals. Windows operator identity and
protected provisioning configuration remain the next separate implementation steps.
