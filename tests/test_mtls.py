"""Real loopback TLS handshakes with temporary test-only keys and certificates."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from tnc.provenance.host_auth import (
    AuthenticationError, AuthorizationError, AuthorizationState, CredentialEnrollment,
    Action, PolicyAuthorizer, ResourceScope,
)
from tnc.provenance.mtls import (
    MtlsConfigurationError, MtlsServer, create_mtls_client_context,
)


class PKI:
    def __init__(self, path):
        self.path = path
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.ca = self.issue("root", ca=True)
        self.server = self.issue("server", san="localhost", eku=ExtendedKeyUsageOID.SERVER_AUTH)
        self.client = self.issue("client")

    def issue(self, name, *, ca=False, issuer=None, san=None,
              eku=ExtendedKeyUsageOID.CLIENT_AUTH, start=None, end=None):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        issuer = issuer or (None if ca else self.ca)
        signing_key = key if issuer is None else issuer[1]
        cert = (x509.CertificateBuilder().subject_name(subject)
                .issuer_name(subject if issuer is None else issuer[0].subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(start or self.now - timedelta(days=1))
                .not_valid_after(end or self.now + timedelta(days=2))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False))
        if not ca:
            cert = cert.add_extension(x509.ExtendedKeyUsage([eku]), False)
        if san:
            cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
        cert = cert.sign(signing_key, hashes.SHA256())
        cert_path, key_path = self.path / (name + ".pem"), self.path / (name + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert, key, cert_path, key_path

    def crl(self, *, revoked=(), expired=False):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.ca[0].subject)
                   .last_update(self.now - timedelta(days=1))
                   .next_update(self.now + timedelta(days=-0.5 if expired else 1))
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca[1].public_key()), False))
        for cert in revoked:
            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder()
                .serial_number(cert.serial_number).revocation_date(self.now - timedelta(hours=1)).build())
        path = self.path / "revocations.pem"
        path.write_bytes(builder.sign(self.ca[1], hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        return path


class Reader:
    def __init__(self, pki, cert=None):
        self.calls = 0
        cert = cert or pki.client[0]
        self.state = AuthorizationState(revision=1, credentials=(CredentialEnrollment(
            credential_id=sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
            principal_id="alice", enabled=True, valid_from=pki.now - timedelta(days=10),
            valid_until=pki.now + timedelta(days=10)),))

    def read(self):
        self.calls += 1
        return self.state


@pytest.fixture
def pki(tmp_path):
    return PKI(tmp_path)


def server(pki, reader, **kw):
    return MtlsServer(reader, certificate=pki.server[2], private_key=pki.server[3],
                      trusted_ca=pki.ca[2], **kw)


def client(pki, identity=None, **kw):
    identity = identity or pki.client
    return create_mtls_client_context(certificate=identity[2], private_key=identity[3],
                                      trusted_ca=pki.ca[2], **kw)


def exchange(host, context, *, hostname="localhost", callback=None):
    """Bounded threads and sockets; no sleeps or persistent listeners."""
    accepted = []
    def serve(listener):
        raw, _ = listener.accept()
        try:
            with host.accept(raw) as connection:
                accepted.append(connection.verify())
                if callback:
                    callback(connection)
                connection.sendall(b"ok")
            return None
        except AuthenticationError as exc:
            return exc
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        pending = executor.submit(serve, listener)
        response, client_error = None, None
        try:
            with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=hostname) as connection:
                    response = connection.recv(2)  # TLS 1.3 alerts can arrive after client handshake.
        except (ssl.SSLError, OSError) as exc:
            client_error = exc
        return accepted, response, pending.result(timeout=7), client_error


def test_real_handshake_maps_exact_fingerprint_without_granting_permission(pki):
    reader = Reader(pki)
    accepted, response, error, _ = exchange(server(pki, reader), client(pki))
    assert error is None and response == b"ok"
    identity = accepted[0]
    assert identity.principal_id == "alice"
    assert identity.credential_id == reader.state.credentials[0].credential_id
    with pytest.raises(AuthorizationError):
        PolicyAuthorizer(reader).authorize(identity, Action.SUBMIT,
            ResourceScope(corpus_id="c", document_id="d", version_id="v"))


@pytest.mark.parametrize("kind", ["expired", "future", "wrong_eku", "untrusted", "missing"])
def test_bad_client_certificate_blocks_before_registry(pki, kind):
    if kind == "expired":
        identity = pki.issue("expired", end=pki.now - timedelta(hours=1))
    elif kind == "future":
        identity = pki.issue("future", start=pki.now + timedelta(days=1))
    elif kind == "wrong_eku":
        identity = pki.issue("wrong", eku=ExtendedKeyUsageOID.SERVER_AUTH)
    elif kind == "untrusted":
        foreign = pki.issue("foreign", ca=True)
        identity = pki.issue("outsider", issuer=foreign)
    else:
        identity = pki.client
    reader = Reader(pki, identity[0])  # Enrollment cannot override a failed handshake.
    context = client(pki, identity)
    if kind == "missing":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=pki.ca[2])
    accepted, response, error, _ = exchange(server(pki, reader), context)
    assert not accepted and response != b"ok" and isinstance(error, AuthenticationError)
    assert reader.calls == 0


@pytest.mark.parametrize("kind", ["unknown", "disabled", "unavailable"])
def test_valid_chain_still_requires_current_enrollment(pki, kind):
    reader = Reader(pki)
    if kind == "unknown":
        reader.state = reader.state.model_copy(update={"credentials": ()})
    elif kind == "disabled":
        reader.state = reader.state.model_copy(update={"credentials": (
            reader.state.credentials[0].model_copy(update={"enabled": False}),)})
    else:
        def unavailable():
            raise OSError("secret host path")
        reader.read = unavailable
    accepted, response, error, _ = exchange(server(pki, reader), client(pki))
    assert not accepted and response != b"ok"
    assert str(error) == "Authentication failed"


def test_reused_connection_rechecks_disablement(pki):
    reader = Reader(pki)
    def disable(connection):
        first = connection.verify()
        second = connection.verify()
        assert first.connection_id == second.connection_id and first.audit_id != second.audit_id
        reader.state = reader.state.model_copy(update={"revision": 2, "credentials": (
            reader.state.credentials[0].model_copy(update={"enabled": False}),)})
        connection.verify()
    accepted, response, error, _ = exchange(server(pki, reader), client(pki), callback=disable)
    assert accepted and response != b"ok" and isinstance(error, AuthenticationError)


def test_reused_connection_rechecks_certificate_time(pki):
    reader = Reader(pki)
    clock = [pki.now]
    def expire(connection):
        clock[0] = pki.client[0].not_valid_after_utc
        connection.verify()
    accepted, response, error, _ = exchange(server(pki, reader, clock=lambda: clock[0]),
                                          client(pki), callback=expire)
    assert accepted and response != b"ok" and isinstance(error, AuthenticationError)


@pytest.mark.parametrize("kind", ["wrong_hostname", "wrong_root"])
def test_client_verifies_server_identity(pki, kind):
    reader = Reader(pki)
    context = client(pki)
    hostname = "wrong.example" if kind == "wrong_hostname" else "localhost"
    if kind == "wrong_root":
        foreign = pki.issue("foreign", ca=True)
        context = create_mtls_client_context(certificate=pki.client[2], private_key=pki.client[3],
                                             trusted_ca=foreign[2])
    accepted, response, _, error = exchange(server(pki, reader), context, hostname=hostname)
    assert not accepted and response != b"ok" and isinstance(error, ssl.SSLCertVerificationError)


@pytest.mark.parametrize("kind", ["revoked", "expired_crl", "missing_crl", "clean"])
def test_explicit_crl_profile(pki, kind):
    reader = Reader(pki)
    crl = pki.crl(revoked=(pki.client[0],) if kind == "revoked" else (),
                  expired=kind == "expired_crl")
    if kind == "missing_crl":
        crl = pki.ca[2]  # Valid PEM, but no issuer CRL. Handshake must fail.
    accepted, response, error, _ = exchange(server(pki, reader, crl_file=crl), client(pki))
    if kind == "clean":
        assert accepted and response == b"ok" and error is None
    else:
        assert not accepted and response != b"ok" and isinstance(error, AuthenticationError)
        assert reader.calls == 0


def test_tls12_cannot_downgrade(pki):
    reader = Reader(pki)
    context = client(pki)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    accepted, response, error, _ = exchange(server(pki, reader), context)
    assert not accepted and response != b"ok" and isinstance(error, AuthenticationError)
    assert reader.calls == 0


@pytest.mark.parametrize("timeout", [0, -1, 31, float("inf"), float("nan"), True])
def test_bounded_timeout_configuration(pki, timeout):
    with pytest.raises(MtlsConfigurationError):
        server(pki, Reader(pki), timeout=timeout)


def test_invalid_configuration_never_falls_back(pki):
    with pytest.raises(MtlsConfigurationError, match="^Invalid TLS configuration$"):
        MtlsServer(Reader(pki), certificate=pki.server[2], private_key=pki.client[3], trusted_ca=pki.ca[2])
    with pytest.raises(MtlsConfigurationError):
        create_mtls_client_context(certificate=pki.client[2], private_key=pki.client[3],
                                   trusted_ca=pki.path / "absent")


def test_header_and_certificate_inputs_rejected(pki):
    host = server(pki, Reader(pki))
    for value in ({"X-Client-Cert": "trusted"}, pki.client[0].public_bytes(serialization.Encoding.DER)):
        with pytest.raises(AuthenticationError):
            host.accept(value)


def test_key_logging_environment_is_ignored(pki, monkeypatch):
    secret_log = pki.path / "session-secrets"
    monkeypatch.setenv("SSLKEYLOGFILE", str(secret_log))
    accepted, response, error, _ = exchange(server(pki, Reader(pki)), client(pki))
    assert accepted and response == b"ok" and error is None
    assert not secret_log.exists()


def test_handshake_timeout_closes_silent_peer(pki):
    host = server(pki, Reader(pki), timeout=0.1)
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        def serve():
            raw, _ = listener.accept()
            with pytest.raises(AuthenticationError):
                host.accept(raw)
        future = executor.submit(serve)
        with socket.create_connection(listener.getsockname(), timeout=5) as raw:
            assert raw.recv(1) == b""
        future.result(timeout=5)


@pytest.mark.parametrize("kind", ["expired", "wrong_eku", "cn_only"])
def test_server_certificate_profile(pki, kind):
    if kind == "expired":
        pki.server = pki.issue("expired-server", san="localhost", eku=ExtendedKeyUsageOID.SERVER_AUTH,
                               end=pki.now - timedelta(hours=1))
    elif kind == "wrong_eku":
        pki.server = pki.issue("wrong-server", san="localhost")
    else:
        pki.server = pki.issue("localhost", eku=ExtendedKeyUsageOID.SERVER_AUTH)
    accepted, response, _, error = exchange(server(pki, Reader(pki)), client(pki))
    assert not accepted and response != b"ok" and isinstance(error, ssl.SSLCertVerificationError)


def test_real_certificate_rotation_requires_explicit_enrollment(pki):
    reader = Reader(pki)
    rotated = pki.issue("rotated")
    host = server(pki, reader)
    assert not exchange(host, client(pki, rotated))[0]
    old = reader.state.credentials[0]
    reader.state = reader.state.model_copy(update={"revision": 2, "credentials": (
        old.model_copy(update={"enabled": False}), old.model_copy(update={
            "credential_id": sha256(rotated[0].public_bytes(serialization.Encoding.DER)).hexdigest()}))})
    accepted, response, error, _ = exchange(host, client(pki, rotated))
    assert accepted[0].principal_id == "alice" and response == b"ok" and error is None
    assert not exchange(host, client(pki))[0]
