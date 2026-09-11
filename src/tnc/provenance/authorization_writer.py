"""Host-only v4 writer. No default provisioning verifier, CLI or network route.

Session adapters must establish real identity outside these transaction APIs.
Synthetic sessions are appropriate only for tests. Typed claims are not proof.
"""
from datetime import datetime, timezone
from typing import Protocol

from tnc.provenance.authorization_models import (
    Model, Identifier, Digest, Nonnegative, Positive, AdminPayload, BootstrapManifest,
    BootstrapRecord, BootstrapReceipt, AuthorizationEvent, AuthorizationCheckpoint,
    AdministrativeActor, ProvisioningActor, ZERO, canonical_bytes, decode_canonical,
    record_digest, event_digest, bootstrap_receipt_digest,
)
from tnc.provenance.authorization_validator import validate_authorization_ledger
from tnc.provenance.authorization_storage import read_administration, event_values, projection_maps
from tnc.provenance.host_auth import (
    Action, AuthorizationState, VerifiedIdentity, PolicyAuthorizer, ResourceScope,
    AuthorizationError,
)
from tnc.provenance.review_store import ReviewStoreError, ReviewConflictError, ReviewIntegrityError
from tnc.provenance.sqlite_review_store import SqliteReviewStore, _apply_v4


class AdministrativeAppendRequest(Model):
    event_id: Identifier
    expected_head_sequence: Nonnegative
    expected_head_hash: Digest
    payload: AdminPayload


class AdministrativeAppendReceipt(Model):
    event_id: Identifier
    event_sequence: Positive
    event_hash: Digest
    checkpoint: AuthorizationCheckpoint


class ProvisioningAuthorization(Model):
    """Host-adapter result, NOT a client-authenticatable token."""
    operator_id: Identifier
    session_id: Identifier
    manifest_hash: Digest
    deployment_id: Identifier
    valid_from: datetime
    valid_until: datetime


class ProvisioningSession(Protocol):
    def verify_activation(self, manifest: BootstrapManifest) -> ProvisioningAuthorization: ...


class AdministrativeSession(Protocol):
    def verify_identity(self) -> VerifiedIdentity: ...


def _copy(value, kind):
    if type(value) is not kind:
        raise ValueError('Typed host value required')
    return decode_canonical(kind, canonical_bytes(value))


class AdministrationWriter:
    def __init__(self, *, store: SqliteReviewStore, clock=lambda: datetime.now(timezone.utc)):
        self._store = store
        self._clock = clock

    def _now(self):
        at = self._clock()
        if not isinstance(at, datetime) or at.utcoffset() is None:
            raise ReviewStoreError('Invalid host clock')
        return at.astimezone(timezone.utc)

    def migrate_to_v4(self, *, provisioning: ProvisioningSession,
                      manifest: BootstrapManifest) -> BootstrapReceipt:
        manifest = _copy(manifest, BootstrapManifest)
        # Authentication callback runs before locking; never inside the transaction.
        proof = _copy(provisioning.verify_activation(manifest), ProvisioningAuthorization)
        digest = record_digest(manifest)
        anchor = self._store._bootstrap_anchor
        with self._store._transaction(write=True, outbox=True) as (connection, _, _):
            now = self._now()
            if (anchor is None or proof.operator_id != anchor.operator_id
                    or proof.manifest_hash != digest or digest != anchor.manifest_hash
                    or proof.deployment_id != manifest.deployment_id
                    or manifest.deployment_id != anchor.deployment_id
                    or not proof.valid_from <= now < proof.valid_until):
                raise AuthorizationError('Access denied')
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            if version == 4:
                old, _, _ = read_administration(connection, anchor)
                if old.manifest != manifest:
                    raise ReviewConflictError('Bootstrap request conflict')
                return old.receipt
            if version != 3:
                raise ReviewStoreError('Explicit version-3 source required')
            if proof.session_id != anchor.provisioning_session_id:
                raise AuthorizationError('Access denied')
            if connection.execute('PRAGMA foreign_key_check').fetchall():
                raise ReviewIntegrityError('Invalid source foreign keys')
            _apply_v4(connection)
            actor = ProvisioningActor(operator_id=proof.operator_id, session_id=proof.session_id, manifest_hash=digest)
            events = []
            previous = ZERO
            for sequence, payload in enumerate((manifest.initial_enrollment, manifest.initial_grant), 1):
                event = AuthorizationEvent(sequence=sequence, event_id=f'bootstrap-seed-{sequence}', actor=actor,
                    expected_head_sequence=sequence-1, expected_head_hash=previous, recorded_at=now,
                    payload=payload, previous_entry_hash=previous, entry_hash=ZERO)
                event = event.model_copy(update={'entry_hash': event_digest(event)})
                connection.execute('INSERT INTO authorization_events VALUES (?,?,?,?,?,?,?,?)',
                                   event_values(event, *projection_maps(events)))
                events.append(event)
                previous = event.entry_hash
            receipt = BootstrapReceipt(manifest_hash=digest, deployment_id=manifest.deployment_id,
                operator_id=proof.operator_id, provisioning_session_id=proof.session_id, provisioned_at=now,
                first_event_hash=events[0].entry_hash, second_event_hash=events[1].entry_hash, receipt_hash=ZERO)
            receipt = receipt.model_copy(update={'receipt_hash': bootstrap_receipt_digest(receipt)})
            bootstrap = BootstrapRecord(manifest=manifest, receipt=receipt)
            connection.execute('INSERT INTO administration_bootstrap VALUES (?,?,?,?,?)',
                (1, manifest.deployment_id, digest, receipt.receipt_hash, canonical_bytes(bootstrap)))
            updated = connection.execute('UPDATE authorization_state SET sequence=2, head_hash=? '
                'WHERE singleton=1 AND sequence=0 AND head_hash=?', (previous, ZERO))
            if updated.rowcount != 1:
                raise ReviewIntegrityError('Checkpoint changed')
            self._store._load(connection, outbox=True)
            if connection.execute('PRAGMA foreign_key_check').fetchall():
                raise ReviewIntegrityError('Invalid target foreign keys')
        return receipt

    def history(self):
        with self._store._transaction() as (connection, _, _):
            return read_administration(connection, self._store._bootstrap_anchor)[1]

    def read(self) -> AuthorizationState:
        """Preliminary enrollment reader; writes independently re-read under lock."""
        with self._store._transaction() as (connection, _, _):
            _, _, state = read_administration(connection, self._store._bootstrap_anchor)
            return self._state(state)

    @staticmethod
    def _state(state):
        return AuthorizationState(revision=state.checkpoint.sequence,
            credentials=tuple(entry.credential for entry in state.credentials),
            grants=tuple(grant.permission for grant in state.grants if not grant.revoked))

    def append(self, *, session: AdministrativeSession,
               request: AdministrativeAppendRequest) -> AdministrativeAppendReceipt:
        request = _copy(request, AdministrativeAppendRequest)
        # VerifiedIdentity is a different shared Model type, revalidate explicitly.
        identity = session.verify_identity()
        if type(identity) is not VerifiedIdentity:
            raise AuthorizationError('Access denied')
        identity = VerifiedIdentity.model_validate(identity.model_dump())
        with self._store._transaction(write=True) as (connection, _, _):
            bootstrap, events, state = read_administration(connection, self._store._bootstrap_anchor)
            now = self._now()
            authority = self._state(state)
            class SnapshotReader:
                def read(self):
                    return authority
            PolicyAuthorizer(SnapshotReader(), clock=lambda: now).authorize(identity, Action.MANAGE_HOST, ResourceScope())
            prior = next((event for event in events if event.event_id == request.event_id), None)
            if prior is not None:
                if (type(prior.actor) is not AdministrativeActor
                        or prior.actor.principal_id != identity.principal_id
                        or prior.actor.credential_id != identity.credential_id
                        or prior.payload != request.payload
                        or (prior.expected_head_sequence, prior.expected_head_hash) !=
                           (request.expected_head_sequence, request.expected_head_hash)):
                    raise ReviewConflictError('Administrative request conflict')
                return self._receipt(prior)
            if (request.expected_head_sequence, request.expected_head_hash) != (
                    state.checkpoint.sequence, state.checkpoint.head_hash):
                raise ReviewConflictError('Authorization head changed')
            grants = sorted((grant for grant in state.grants if not grant.revoked
                and grant.permission.principal_id == identity.principal_id
                and grant.permission.action == Action.MANAGE_HOST
                and grant.permission.valid_from <= now < grant.permission.valid_until), key=lambda grant: grant.grant_id)
            actor = AdministrativeActor(principal_id=identity.principal_id, credential_id=identity.credential_id,
                verified_at=identity.verified_at, valid_until=identity.valid_until,
                registry_revision=identity.registry_revision, permission_grant_id=grants[0].grant_id,
                audit_id=identity.audit_id)
            event = AuthorizationEvent(sequence=state.checkpoint.sequence+1, event_id=request.event_id, actor=actor,
                expected_head_sequence=request.expected_head_sequence, expected_head_hash=request.expected_head_hash,
                recorded_at=now, payload=request.payload, previous_entry_hash=state.checkpoint.head_hash, entry_hash=ZERO)
            event = event.model_copy(update={'entry_hash': event_digest(event)})
            checkpoint = AuthorizationCheckpoint(sequence=event.sequence, head_hash=event.entry_hash)
            validate_authorization_ledger(events=events+(event,), bootstrap=bootstrap,
                trust_anchor=self._store._bootstrap_anchor, checkpoint=checkpoint)
            connection.execute('INSERT INTO authorization_events VALUES (?,?,?,?,?,?,?,?)',
                               event_values(event, *projection_maps(events)))
            updated = connection.execute('UPDATE authorization_state SET sequence=?, head_hash=? '
                'WHERE singleton=1 AND sequence=? AND head_hash=?', (event.sequence, event.entry_hash,
                    state.checkpoint.sequence, state.checkpoint.head_hash))
            if updated.rowcount != 1:
                raise ReviewIntegrityError('Authorization checkpoint changed')
            self._store._load(connection, outbox=False)
        return self._receipt(event)

    @staticmethod
    def _receipt(event):
        return AdministrativeAppendReceipt(event_id=event.event_id, event_sequence=event.sequence,
            event_hash=event.entry_hash,
            checkpoint=AuthorizationCheckpoint(sequence=event.sequence, head_hash=event.entry_hash))
