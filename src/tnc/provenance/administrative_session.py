"""Live mTLS session adapter for host-owned administrative writer calls."""
from tnc.provenance.host_auth import AuthenticationError, VerifiedIdentity
from tnc.provenance.mtls import MtlsConnection


class MtlsAdministrativeSession:
    """Wrap a connection obtained from MtlsServer.accept, not client data.

    The host retains connection ownership. Every verification reads the live
    connection and current enrollment; no identity or permission is cached here.
    Python type checks are not a boundary against hostile in-process code.
    """
    __slots__ = ("_connection",)

    def __init__(self, connection: MtlsConnection):
        if type(connection) is not MtlsConnection:
            raise AuthenticationError("Authentication failed")
        self._connection = connection

    def verify_identity(self) -> VerifiedIdentity:
        return self._connection.verify()
