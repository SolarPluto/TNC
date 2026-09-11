"""Host-owned TLS 1.3 transport; no listener, HTTP routes or journal dispatch."""
from datetime import datetime, timezone
from hashlib import sha256
import math
from pathlib import Path
import socket
import ssl
from typing import Callable
from uuid import uuid4

from tnc.provenance.host_auth import (
    AuthenticationError, AuthorizationStateReader, RegistryCredentialVerifier,
    TrustedTransportEvidence, VerifiedIdentity,
)


class MtlsConfigurationError(Exception):
    pass


def _context(*, server, certificate, private_key, trusted_ca, crl_file=None):
    # Explicit contexts avoid ambient system roots and SSLKEYLOGFILE behavior.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.options |= ssl.OP_NO_TICKET
    if server:
        context.num_tickets = 0
    else:
        context.check_hostname = True
        context.hostname_checks_common_name = False
    context.load_verify_locations(cafile=str(Path(trusted_ca)))
    if crl_file is not None:
        context.load_verify_locations(cafile=str(Path(crl_file)))
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    # No interactive password prompt. Protected unencrypted PEMs are this initial
    # profile; an OS key-provider/encrypted-key integration is separate work.
    context.load_cert_chain(str(Path(certificate)), str(Path(private_key)), password="")
    return context


def create_mtls_client_context(*, certificate, private_key, trusted_ca,
                               crl_file=None) -> ssl.SSLContext:
    """Host configuration only. Caller must pass the expected server_hostname.

    Do not mutate the returned context or accept client-selected trust paths.
    """
    try:
        return _context(server=False, certificate=certificate, private_key=private_key,
                        trusted_ca=trusted_ca, crl_file=crl_file)
    except Exception:
        raise MtlsConfigurationError("Invalid TLS configuration") from None


class MtlsServer:
    """Own the context that performs the client-certificate handshake.

    Configuration is read once. Replace the server and retire old connections to
    reload CA/CRL state. Enrollment is re-read on every connection verification.
    """
    def __init__(self, state_reader: AuthorizationStateReader, *, certificate,
                 private_key, trusted_ca, crl_file=None, timeout: float = 5.0,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        try:
            if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 30:
                raise ValueError("Invalid timeout")
            self._context = _context(server=True, certificate=certificate, private_key=private_key,
                                     trusted_ca=trusted_ca, crl_file=crl_file)
            self._timeout = timeout
            self._clock = clock
            self._registry = RegistryCredentialVerifier(state_reader, clock=clock)
        except Exception:
            raise MtlsConfigurationError("Invalid TLS configuration") from None

    def accept(self, raw_socket: socket.socket) -> "MtlsConnection":
        """Take ownership of an accepted raw socket; close it on any failure.

        No client-supplied SSLSocket, context, certificate blob or attestation is
        accepted as proof. Success includes handshake and current enrollment.
        """
        secure = None
        try:
            if type(raw_socket) is not socket.socket:
                raise ValueError("Raw host socket required")
            raw_socket.settimeout(self._timeout)
            secure = self._context.wrap_socket(raw_socket, server_side=True,
                                                do_handshake_on_connect=False)
            secure.do_handshake()
            connection = MtlsConnection(secure, self._context, self._registry, self._clock)
            connection.verify()
            return connection
        except Exception:
            if secure is not None:
                secure.close()
            elif isinstance(raw_socket, socket.socket):
                raw_socket.close()
            raise AuthenticationError("Authentication failed") from None


class MtlsConnection:
    """Internal connection, created by MtlsServer.accept, never client JSON.

    Each request must call verify then authorize its action. recv/sendall check
    current enrollment too, but do not authorize application actions or provide
    atomic authorization at journal release. Use one host worker per connection.
    """
    def __init__(self, secure, context, registry, clock):
        self._socket = secure
        self._context = context
        self._registry = registry
        self._clock = clock
        self._connection_id = str(uuid4())

    def verify(self) -> VerifiedIdentity:
        try:
            if (type(self._socket) is not ssl.SSLSocket
                    or not self._socket.server_side
                    or self._socket.context is not self._context
                    or self._context.verify_mode != ssl.CERT_REQUIRED
                    or self._context.minimum_version != ssl.TLSVersion.TLSv1_3
                    or not self._context.verify_flags & ssl.VERIFY_X509_STRICT
                    or self._socket.version() != "TLSv1.3"):
                raise ValueError("Invalid TLS connection")
            der = self._socket.getpeercert(binary_form=True)
            certificate = self._socket.getpeercert()
            if not der or not certificate:
                raise ValueError("Missing verified certificate")
            evidence = TrustedTransportEvidence(
                credential_id=sha256(der).hexdigest(), connection_id=self._connection_id,
                verified_at=self._clock(),
                credential_valid_from=datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(certificate["notBefore"]), timezone.utc),
                credential_valid_until=datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc))
            return self._registry.verify(evidence)
        except Exception:
            self.close()
            raise AuthenticationError("Authentication failed") from None

    def recv(self, size: int) -> bytes:
        self.verify()
        return self._socket.recv(size)

    def sendall(self, data: bytes) -> None:
        self.verify()
        self._socket.sendall(data)

    def close(self):
        self._socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
