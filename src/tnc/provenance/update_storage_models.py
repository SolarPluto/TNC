"""Bounded logical storage image for pure consistency validation, not a database."""
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.update_models import (
    UpdateAuthorityHead, UpdateIntent, PreparedUpdateEvidence, SyntheticDrainEvidence, UpdateReceipt, LocatorObservation,
)
from tnc.provenance.update_verification import SignatureEnvelope, InstallerTrustStore, InstallerTrustCheckpoint
from tnc.provenance.update_integration import UpdatePermissionSnapshot, ArchivedUpdateSignature

EVENT_LIMIT = 4 * 1024 * 1024
IMAGE_LIMIT = 16 * 1024 * 1024


class RecordedUpdateAuthority(Model):
    kind: Literal['AUTHORITY'] = 'AUTHORITY'
    trust_store: InstallerTrustStore
    trust_checkpoint: InstallerTrustCheckpoint
    identities: tuple[VerifiedIdentity, ...] = Field(max_length=64)
    permissions: tuple[UpdatePermissionSnapshot, ...] = Field(max_length=128)

    @model_validator(mode='after')
    def ordered(self):
        ids = tuple(i.credential_id for i in self.identities)
        grants = tuple((p.principal_id, p.operation_id, p.credential_id) for p in self.permissions)
        if ids != tuple(sorted(set(ids))) or grants != tuple(sorted(set(grants))):
            raise ValueError('Sorted unique authority records required')
        return self


class StoredUpdateRegistration(Model):
    kind: Literal['REGISTER'] = 'REGISTER'
    intent: UpdateIntent
    signature: SignatureEnvelope
    credential_id: Digest


class StoredUpdatePreparation(Model):
    kind: Literal['PREPARE'] = 'PREPARE'
    operation_id: Identifier
    preparation: PreparedUpdateEvidence
    credential_id: Digest


class StoredUpdateCommit(Model):
    kind: Literal['COMMIT'] = 'COMMIT'
    operation_id: Identifier
    authority_revision: int = Field(strict=True, gt=0)
    credential_id: Digest
    preparation: PreparedUpdateEvidence
    drain: SyntheticDrainEvidence
    receipt: UpdateReceipt
    head: UpdateAuthorityHead
    archive: ArchivedUpdateSignature


class StoredLocatorPublication(Model):
    kind: Literal['PUBLISH'] = 'PUBLISH'
    operation_id: Identifier
    credential_id: Digest
    locator: LocatorObservation


StoredPayload = Annotated[RecordedUpdateAuthority | StoredUpdateRegistration | StoredUpdatePreparation |
                          StoredUpdateCommit | StoredLocatorPublication, Field(discriminator='kind')]


class StoredUpdateEvent(Model):
    sequence: int = Field(strict=True, gt=0)
    recorded_at: datetime
    previous_hash: Digest
    entry_hash: Digest
    payload: StoredPayload


class UpdateStorageImage(Model):
    codec_version: Literal[1] = 1
    deployment_id: Identifier
    base_head: UpdateAuthorityHead
    events: tuple[StoredUpdateEvent, ...] = Field(max_length=256)
    head: UpdateAuthorityHead


class UpdateStorageCheckpoint(Model):
    """Independent trusted binding to the complete storage image and both heads."""
    deployment_id: Identifier
    image_hash: Digest
    event_count: int = Field(strict=True, ge=0, le=256)
    event_head_hash: Digest
    authority_head_hash: Digest


class UpdateStorageValidationResult(Model):
    status: Literal['CONSISTENT', 'INVALID']
    reason_code: Literal['INVALID_RECORD', 'CHECKPOINT_MISMATCH', 'CHAIN_INVALID', 'AUTHORITY_INVALID',
        'OPERATION_INVALID', 'COMMIT_INVALID', 'ARCHIVE_INVALID', 'PUBLICATION_INVALID', 'HEAD_MISMATCH'] | None = None
    event_count: int = Field(default=0, strict=True, ge=0, le=256)
    operation_count: int = Field(default=0, strict=True, ge=0, le=256)
    commit_count: int = Field(default=0, strict=True, ge=0, le=256)
    unpublished_operation_ids: tuple[Identifier, ...] = Field(default=(), max_length=256)

    @model_validator(mode='after')
    def shape(self):
        if self.status == 'CONSISTENT' and self.reason_code is not None:
            raise ValueError('Consistent image has no failure')
        if self.status == 'INVALID' and (self.reason_code is None or self.event_count or self.operation_count or
                                       self.commit_count or self.unpublished_operation_ids):
            raise ValueError('Invalid image exposes no validated state')
        if self.unpublished_operation_ids != tuple(sorted(set(self.unpublished_operation_ids))):
            raise ValueError('Sorted unique operation IDs required')
        return self
