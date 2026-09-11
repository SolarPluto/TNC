"""Real TLS -> session adapter -> SQLite writer; bootstrap alone is synthetic."""
from contextlib import contextmanager
from datetime import timedelta
from hashlib import sha256
import socket

import pytest
from cryptography.hazmat.primitives import serialization

from test_mtls import pki, server, client, exchange
from tnc.provenance.administrative_session import MtlsAdministrativeSession
from tnc.provenance.authorization_models import (
    ZERO, BootstrapManifest, BootstrapTrustAnchor, CredentialEnrolled, CredentialDisabled,
    PermissionGranted, PermissionRevoked, record_digest,
)
from tnc.provenance.authorization_writer import (
    AdministrationWriter, ProvisioningAuthorization, AdministrativeAppendRequest,
)
from tnc.provenance.host_auth import (
    Action, CredentialEnrollment, PermissionGrant, AuthenticationError, AuthorizationError,
)
from tnc.provenance.sqlite_review_store import SqliteReviewStore


def enrollment(identity, principal):
    cert = identity[0]
    fingerprint = sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return CredentialEnrolled(credential=CredentialEnrollment(credential_id=fingerprint,
        principal_id=principal, enabled=True, valid_from=cert.not_valid_before_utc,
        valid_until=cert.not_valid_after_utc), enrollment_evidence_hash=fingerprint)


def grant(pki, grant_id):
    return PermissionGranted(grant_id=grant_id, permission=PermissionGrant(
        principal_id='admin', action=Action.MANAGE_HOST, corpus_id=None,
        valid_from=pki.now-timedelta(minutes=1), valid_until=pki.now+timedelta(hours=1)))


@pytest.fixture
def writer(pki):
    manifest = BootstrapManifest(request_id='fixture-bootstrap', deployment_id='fixture', service_identity='fixture-service',
        legacy_journal_sequence=0, legacy_journal_hash=ZERO, legacy_release_sequence=0, legacy_release_hash=ZERO,
        trust_configuration_hash=sha256(pki.ca[2].read_bytes()).hexdigest(), admin_policy_hash='c'*64,
        valid_from=pki.now-timedelta(minutes=1), valid_until=pki.now+timedelta(hours=1),
        initial_enrollment=enrollment(pki.client, 'admin'), initial_grant=grant(pki, 'initial-admin'))
    anchor = BootstrapTrustAnchor(deployment_id='fixture', manifest_hash=record_digest(manifest), operator_id='test-operator',
        provisioning_session_id='test-bootstrap-session', valid_from=manifest.valid_from, valid_until=manifest.valid_until)
    store = SqliteReviewStore.provision(path=pki.path/'writer.sqlite', allowed_reviewers=frozenset())
    store.migrate_to_v2()
    store.migrate_to_v3()
    store = SqliteReviewStore.open_existing(path=store._path, allowed_reviewers=frozenset(), bootstrap_anchor=anchor)
    result = AdministrationWriter(store=store)
    class SyntheticBootstrap:
        def verify_commit(self, proof, *, database_path):
            return None  # Synthetic bootstrap only; this suite tests live mTLS appends.

        def verify_activation(self, manifest):
            return ProvisioningAuthorization(operator_id=anchor.operator_id, session_id=anchor.provisioning_session_id,
                manifest_hash=anchor.manifest_hash, deployment_id=anchor.deployment_id,
                valid_from=anchor.valid_from, valid_until=anchor.valid_until)
    result.migrate_to_v4(provisioning=SyntheticBootstrap(), manifest=manifest)
    return result


def request(writer, payload, event_id='admin-event'):
    head = writer.history()[-1]
    return AdministrativeAppendRequest(event_id=event_id, expected_head_sequence=head.sequence,
        expected_head_hash=head.entry_hash, payload=payload)


def test_real_tls_identity_is_recorded_by_writer(pki, writer):
    result = []
    def append(connection):
        session = MtlsAdministrativeSession(connection)
        identity = session.verify_identity()
        receipt = writer.append(session=session, request=request(writer, grant(pki, 'second')))
        result.append((identity, receipt))
    accepted, response, error, _ = exchange(server(pki, writer), client(pki), callback=append)
    assert accepted and response == b'ok' and error is None
    identity, receipt = result[0]
    event = writer.history()[-1]
    assert event.actor.principal_id == identity.principal_id == 'admin'
    assert event.actor.credential_id == identity.credential_id
    assert event.actor.audit_id != identity.audit_id  # Writer requested fresh verification.
    assert receipt.event_hash == event.entry_hash and receipt.event_sequence == 3


def test_enrolled_tls_client_without_permission_cannot_append(pki, writer):
    bob = pki.issue('bob')
    def enroll(connection):
        writer.append(session=MtlsAdministrativeSession(connection), request=request(writer, enrollment(bob, 'bob')))
    assert exchange(server(pki, writer), client(pki), callback=enroll)[1] == b'ok'
    before = writer.history()
    def denied(connection):
        session = MtlsAdministrativeSession(connection)
        assert session.verify_identity().principal_id == 'bob'
        with pytest.raises(AuthorizationError):
            writer.append(session=session, request=request(writer, grant(pki, 'forbidden'), 'denied'))
    assert exchange(server(pki, writer), client(pki, bob), callback=denied)[1] == b'ok'
    assert writer.history() == before


def test_reused_connection_disablement_blocks_further_verification(pki, writer):
    def disable(connection):
        session = MtlsAdministrativeSession(connection)
        fingerprint = session.verify_identity().credential_id
        writer.append(session=session, request=request(writer,
            CredentialDisabled(credential_id=fingerprint, expected_enrollment_sequence=1, rationale='test disable')))
        with pytest.raises(AuthenticationError):
            session.verify_identity()
    accepted, response, error, _ = exchange(server(pki, writer), client(pki), callback=disable)
    assert accepted and response != b'ok' and isinstance(error, AuthenticationError)
    assert len(writer.history()) == 3


def test_reused_connection_permission_revocation_still_blocks_writer(pki, writer):
    def revoke(connection):
        session = MtlsAdministrativeSession(connection)
        writer.append(session=session, request=request(writer,
            PermissionRevoked(grant_id='initial-admin', expected_grant_sequence=2, rationale='test revoke')))
        assert session.verify_identity().principal_id == 'admin'
        with pytest.raises(AuthorizationError):
            writer.append(session=session, request=request(writer, grant(pki, 'forbidden'), 'denied'))
    assert exchange(server(pki, writer), client(pki), callback=revoke)[1] == b'ok'
    assert len(writer.history()) == 3


def test_fresh_tls_connection_exact_retry_preserves_original_event(pki, writer):
    candidate = request(writer, grant(pki, 'second'))
    receipts, identities = [], []
    def append(connection):
        session = MtlsAdministrativeSession(connection)
        identities.append(session.verify_identity())
        receipts.append(writer.append(session=session, request=candidate))
    host = server(pki, writer)
    assert exchange(host, client(pki), callback=append)[1] == b'ok'
    before = writer.history()
    assert exchange(host, client(pki), callback=append)[1] == b'ok'
    assert receipts[0] == receipts[1] and writer.history() == before
    assert identities[0].connection_id != identities[1].connection_id


def test_closed_connection_cannot_supply_identity(pki, writer):
    def close(connection):
        session = MtlsAdministrativeSession(connection)
        connection.close()
        with pytest.raises(AuthenticationError):
            session.verify_identity()
    before = writer.history()
    exchange(server(pki, writer), client(pki), callback=close)
    assert writer.history() == before


def test_unknown_certificate_never_reaches_writer(pki, writer):
    stranger = pki.issue('stranger')
    called = []
    before = writer.history()
    accepted, _, error, _ = exchange(server(pki, writer), client(pki, stranger), callback=lambda conn: called.append(conn))
    assert not accepted and not called and isinstance(error, AuthenticationError)
    assert writer.history() == before


@pytest.mark.parametrize('value', [None, {}, b'certificate', 'principal=admin'])
def test_caller_data_is_not_a_session(value):
    with pytest.raises(AuthenticationError):
        MtlsAdministrativeSession(value)


def test_raw_socket_is_not_a_session():
    with socket.socket() as raw:
        with pytest.raises(AuthenticationError):
            MtlsAdministrativeSession(raw)


def test_changed_policy_after_identity_verification_denied_then_reverified(pki, writer, monkeypatch):
    other = AdministrationWriter(store=SqliteReviewStore.open_existing(path=writer._store._path,
        allowed_reviewers=frozenset(), bootstrap_anchor=writer._store._bootstrap_anchor))
    original = writer._store._transaction
    changed = []
    @contextmanager
    def interleave(**kwargs):
        if kwargs.get('write') and not changed:
            changed.append(True)
            def independent(connection):
                other.append(session=MtlsAdministrativeSession(connection),
                             request=request(other, grant(pki, 'intervening'), 'intervening'))
            assert exchange(server(pki, other), client(pki), callback=independent)[1] == b'ok'
        with original(**kwargs) as values:
            yield values
    monkeypatch.setattr(writer._store, '_transaction', interleave)
    def competing(connection):
        session = MtlsAdministrativeSession(connection)
        candidate = request(writer, grant(pki, 'eventual'), 'eventual')
        with pytest.raises(AuthorizationError):
            writer.append(session=session, request=candidate)
        assert len(writer.history()) == 3
        receipt = writer.append(session=session, request=request(writer, grant(pki, 'eventual'), 'eventual'))
        assert receipt.event_sequence == 4
    assert exchange(server(pki, writer), client(pki), callback=competing)[1] == b'ok'
