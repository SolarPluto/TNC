"""Host-only read-only update evaluation. Providers, not clients, supply trusted facts."""
from datetime import datetime, timezone
from typing import Literal, Protocol

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.provisioning_models import Interval
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.update_models import (
    UPDATE_RECORD_LIMIT, UpdateIntent, UpdateAuthorityHead, UpdateOperation, UpdateCommand,
    InstallerEvidenceClaims, PreparedUpdateEvidence, SyntheticDrainEvidence, LocatorObservation, UpdateTransitionResult,
)
from tnc.provenance.update_validation import _evaluate_checked_update_transition
from tnc.provenance.update_verification import (
    SignatureEnvelope, InstallerTrustStore, InstallerTrustCheckpoint, CommittedSignatureBinding,
    verify_update_intent_signature, verify_committed_update_signature,
)

Action = Literal['REGISTER', 'PREPARE', 'COMMIT', 'PUBLISH', 'RECOVER']
Permission = Literal['UPDATE_EVALUATE', 'UPDATE_RECOVER_OWN']


class UpdateEvaluationRequest(Model):
    action: Action
    intent: UpdateIntent
    signature: SignatureEnvelope | None = None


class UpdatePermissionSnapshot(Interval):
    principal_id: Identifier
    deployment_id: Identifier
    operation_id: Identifier
    credential_id: Digest  # Transport certificate identity, never an Ed25519 key ID.
    registry_revision: int = Field(strict=True, gt=0)
    revision: int = Field(strict=True, gt=0)
    permissions: tuple[Permission, ...] = Field(max_length=2)

    @model_validator(mode='after')
    def ordered(self):
        if self.permissions != tuple(sorted(set(self.permissions))):
            raise ValueError('Sorted unique permissions required')
        return self


class ArchivedUpdateSignature(Model):
    signature: SignatureEnvelope
    trust_store: InstallerTrustStore
    trust_checkpoint: InstallerTrustCheckpoint
    binding: CommittedSignatureBinding


class UpdateProviderSnapshot(Interval):
    revision: int = Field(strict=True, gt=0)
    deployment_id: Identifier
    operation_id: Identifier
    head: UpdateAuthorityHead
    existing: UpdateOperation | None = None
    trust_store: InstallerTrustStore
    trust_checkpoint: InstallerTrustCheckpoint
    registered_signature: SignatureEnvelope | None = None
    archive: ArchivedUpdateSignature | None = None


class SyntheticUpdateObservations(Model):
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    preparation: PreparedUpdateEvidence | None = None
    drain: SyntheticDrainEvidence | None = None
    locator: LocatorObservation | None = None


class UpdateEvaluationResult(Model):
    audit_only: bool = Field(default=True, strict=True)
    status: Literal['EVALUATED', 'REJECTED']
    reason_code: Literal['INVALID_REQUEST', 'ACCESS_DENIED', 'UNAVAILABLE', 'STALE_CONTEXT',
                         'SIGNATURE_REJECTED', 'TRANSITION_REJECTED'] | None = None
    proposal: UpdateTransitionResult | None = None
    snapshot_revision: int | None = Field(default=None, strict=True, gt=0)
    permission_revision: int | None = Field(default=None, strict=True, gt=0)
    trust_revision: int | None = Field(default=None, strict=True, gt=0)
    signature_mode: Literal['CURRENT', 'HISTORICAL'] | None = None

    @model_validator(mode='after')
    def shape(self):
        if not self.audit_only:
            raise ValueError('Only audit results are supported')
        facts = (self.proposal, self.snapshot_revision, self.permission_revision, self.trust_revision, self.signature_mode)
        if self.status == 'EVALUATED':
            if self.reason_code is not None or any(v is None for v in facts) or self.proposal.status == 'DENIED':
                raise ValueError('Incomplete evaluation')
        elif self.reason_code is None or any(v is not None for v in facts):
            raise ValueError('Rejected evaluation exposes no state')
        return self


class UpdateIdentityProvider(Protocol):
    def verify(self) -> VerifiedIdentity: ...


class UpdatePermissionProvider(Protocol):
    def resolve(self, identity: VerifiedIdentity, deployment_id: str, operation_id: str) -> UpdatePermissionSnapshot: ...
    def is_current(self, permission: UpdatePermissionSnapshot) -> bool: ...


class UpdateSnapshotProvider(Protocol):
    def read(self, deployment_id: str, operation_id: str) -> UpdateProviderSnapshot: ...
    def is_current(self, snapshot: UpdateProviderSnapshot) -> bool: ...


class UpdateObservationProvider(Protocol):
    def observe(self, intent: UpdateIntent, action: str, snapshot: UpdateProviderSnapshot) -> SyntheticUpdateObservations: ...


def _copy(value, kind, limit=UPDATE_RECORD_LIMIT):
    if type(value) is not kind:
        raise ValueError('Exact typed host record required')
    data = canonical_bytes(value)
    if len(data) > limit:
        raise ValueError('Record limit exceeded')
    return decode_canonical(kind, data)


def decode_update_evaluation_request(data):
    if type(data) is not bytes or not 0 < len(data) <= UPDATE_RECORD_LIMIT:
        raise ValueError('Invalid request')
    return decode_canonical(UpdateEvaluationRequest, data)


class _Denied(Exception):
    def __init__(self, reason): self.reason = reason


def _require(condition, reason):
    if not condition: raise _Denied(reason)


def _identity_copy(value):
    # VerifiedIdentity is a host-auth model rather than a canonical administration model.
    _require(type(value) is VerifiedIdentity, 'ACCESS_DENIED')
    return VerifiedIdentity.model_validate(value.model_dump())


class AuthenticatedUpdateEvaluator:
    def __init__(self, identity_provider: UpdateIdentityProvider, permission_provider: UpdatePermissionProvider,
                 snapshot_provider: UpdateSnapshotProvider, observation_provider: UpdateObservationProvider,
                 *, clock=None):
        self._identity, self._permissions = identity_provider, permission_provider
        self._snapshots, self._observations = snapshot_provider, observation_provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def evaluate(self, request):
        stage = 'INVALID_REQUEST'
        last = None
        def now():
            nonlocal last
            at = self._clock()
            _require(isinstance(at, datetime) and at.utcoffset() is not None and (last is None or at >= last), 'STALE_CONTEXT')
            last = at
            return at
        try:
            request = _copy(request, UpdateEvaluationRequest)
            intent = request.intent
            stage = 'ACCESS_DENIED'
            identity = _identity_copy(self._identity.verify())
            at = now()
            _require(identity.verified_at <= at < identity.valid_until and identity.principal_id == intent.publisher_id,
                     'ACCESS_DENIED')
            permission = _copy(self._permissions.resolve(identity, intent.deployment_id, intent.operation_id), UpdatePermissionSnapshot)
            required = 'UPDATE_RECOVER_OWN' if request.action == 'RECOVER' else 'UPDATE_EVALUATE'
            _require((permission.principal_id, permission.deployment_id, permission.operation_id,
                      permission.credential_id, permission.registry_revision) == (
                          identity.principal_id, intent.deployment_id, intent.operation_id,
                          identity.credential_id, identity.registry_revision)
                     and permission.valid_from <= at < permission.valid_until and required in permission.permissions,
                     'ACCESS_DENIED')
            _require(self._permissions.is_current(permission) is True, 'ACCESS_DENIED')
            stage = 'UNAVAILABLE'
            snapshot = _copy(self._snapshots.read(intent.deployment_id, intent.operation_id), UpdateProviderSnapshot,
                             limit=4 * UPDATE_RECORD_LIMIT)
            at = now()
            _require((snapshot.deployment_id, snapshot.operation_id, snapshot.head.checkpoint.deployment_id) ==
                     (intent.deployment_id, intent.operation_id, intent.deployment_id)
                     and snapshot.valid_from <= at < snapshot.valid_until, 'UNAVAILABLE')
            _require(self._snapshots.is_current(snapshot) is True, 'STALE_CONTEXT')
            store, checkpoint = snapshot.trust_store, snapshot.trust_checkpoint
            _require(store.deployment_id == checkpoint.deployment_id == intent.deployment_id
                     and store.revision == checkpoint.revision and record_digest(store) == checkpoint.trust_store_hash
                     and all(v.valid_from <= at < v.valid_until for v in (store, checkpoint)), 'UNAVAILABLE')
            existing = snapshot.existing
            if existing is not None:
                _require(existing.intent.publisher_id == identity.principal_id
                         and canonical_bytes(existing.intent) == canonical_bytes(intent), 'ACCESS_DENIED')
            elif request.action != 'REGISTER':
                raise _Denied('ACCESS_DENIED')
            historical = existing is not None and existing.receipt is not None
            if historical:
                _require('UPDATE_RECOVER_OWN' in permission.permissions, 'ACCESS_DENIED')
                _require(snapshot.archive is not None, 'UNAVAILABLE')
                archive = snapshot.archive
                _require(request.signature is None or canonical_bytes(request.signature) == canonical_bytes(archive.signature),
                         'ACCESS_DENIED')
                signature = verify_committed_update_signature(intent, archive.signature, archive.trust_store,
                    archive.trust_checkpoint, existing.receipt, trusted_binding=archive.binding)
            else:
                envelope = request.signature or snapshot.registered_signature
                _require(envelope is not None, 'SIGNATURE_REJECTED')
                signature = verify_update_intent_signature(intent, envelope, store, trusted_checkpoint=checkpoint, now=at)
            _require(signature.status == 'VERIFIED' and signature.principal_id == identity.principal_id,
                     'SIGNATURE_REJECTED')
            observations = SyntheticUpdateObservations()
            # Exact committed retries reuse recorded evidence; no fresh drain is performed.
            if historical and request.action == 'COMMIT':
                observations = SyntheticUpdateObservations(preparation=existing.preparation, drain=existing.drain)
            elif request.action in ('PREPARE', 'COMMIT', 'PUBLISH'):
                observations = _copy(self._observations.observe(intent, request.action, snapshot), SyntheticUpdateObservations)
            command = UpdateCommand(action=request.action, intent=intent, preparation=observations.preparation,
                                    drain=observations.drain, locator=observations.locator)
            at = now()
            claims = InstallerEvidenceClaims(principal_id=identity.principal_id, signer_key_hash=signature.key_id,
                deployment_id=intent.deployment_id, authenticated=True, may_publish=True,
                valid_from=at, valid_until=min(identity.valid_until, permission.valid_until, snapshot.valid_until,
                                               store.valid_until, checkpoint.valid_until))
            proposal = _evaluate_checked_update_transition(head=snapshot.head, existing=existing, command=command,
                                                         authority=claims, now=at)
            # Recheck live session and provider freshness before exposing any proposal/receipt.
            fresh = _identity_copy(self._identity.verify())
            end = now()
            _require((fresh.principal_id, fresh.credential_id, fresh.connection_id, fresh.registry_revision) ==
                     (identity.principal_id, identity.credential_id, identity.connection_id, identity.registry_revision)
                     and fresh.verified_at <= end < min(fresh.valid_until, claims.valid_until), 'STALE_CONTEXT')
            _require(self._permissions.is_current(permission) is True and self._snapshots.is_current(snapshot) is True,
                     'STALE_CONTEXT')
            if not historical:
                _require(verify_update_intent_signature(intent, envelope, store, trusted_checkpoint=checkpoint, now=end).status
                         == 'VERIFIED', 'STALE_CONTEXT')
            proposal = _evaluate_checked_update_transition(head=snapshot.head, existing=existing, command=command,
                                                         authority=claims, now=end)
            _require(proposal.status != 'DENIED', 'TRANSITION_REJECTED')
            return UpdateEvaluationResult(status='EVALUATED', proposal=proposal, snapshot_revision=snapshot.revision,
                permission_revision=permission.revision, trust_revision=store.revision, signature_mode=signature.mode)
        except _Denied as exc:
            stage = exc.reason
        except Exception:
            pass
        return UpdateEvaluationResult(status='REJECTED', reason_code=stage)
