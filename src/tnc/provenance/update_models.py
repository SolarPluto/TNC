"""Pure installer update contracts. Synthetic evidence is not authentication."""
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier
from tnc.provenance.provisioning_models import Interval, HostProvisioningDescriptor
from tnc.provenance.installation_models import InstallationEnvelope, ExternalInstallationAnchor, DeploymentPreflightReport, LocalPath
from tnc.provenance.trusted_boundary import TrustedInstallationPolicy, InstallationCheckpoint

UPDATE_RECORD_LIMIT = 1024 * 1024


class UpdateCandidate(Model):
    policy: TrustedInstallationPolicy
    checkpoint: InstallationCheckpoint
    anchor: ExternalInstallationAnchor
    envelope: InstallationEnvelope
    descriptor: HostProvisioningDescriptor


class UpdateIntent(Interval):
    codec_version: Literal[1] = 1
    domain: Literal['tnc-installer-update-v1'] = 'tnc-installer-update-v1'
    deployment_id: Identifier
    operation_id: Identifier
    publisher_id: Identifier
    signer_key_hash: Digest
    expected_head_sequence: int = Field(strict=True, ge=0)
    expected_checkpoint_hash: Digest
    candidate: UpdateCandidate


class UpdateAuthorityHead(Model):
    sequence: int = Field(strict=True, ge=0)
    checkpoint: InstallationCheckpoint
    generation_location: LocalPath


class InstallerEvidenceClaims(Interval):
    """Internal validator claims; records alone do not authenticate their source."""
    principal_id: Identifier
    signer_key_hash: Digest
    deployment_id: Identifier
    authenticated: bool = Field(strict=True)
    may_publish: bool = Field(strict=True)


class SyntheticInstallerEvidence(InstallerEvidenceClaims):
    """Synthetic evidence for standalone pure tests; never a live credential."""


class PreparedUpdateEvidence(Interval):
    intent_hash: Digest
    report: DeploymentPreflightReport


class SyntheticDrainEvidence(Interval):
    intent_hash: Digest
    expected_head_sequence: int = Field(strict=True, ge=0)
    expected_checkpoint_hash: Digest
    admissions_fenced: bool = Field(strict=True)
    processes_terminated: bool = Field(strict=True)
    handles_released: bool = Field(strict=True)


class UpdateReceipt(Model):
    operation_id: Identifier
    deployment_id: Identifier
    publisher_id: Identifier
    intent_hash: Digest
    checkpoint_hash: Digest
    authority_sequence: int = Field(strict=True, gt=0)
    generation: int = Field(strict=True, gt=0)
    committed_at: datetime


class LocatorObservation(Model):
    observed_at: datetime
    state: Literal['PRESENT', 'MISSING', 'UNREADABLE']
    deployment_id: Identifier | None = None
    authority_sequence: int | None = Field(default=None, strict=True, ge=0)
    checkpoint_hash: Digest | None = None
    generation_location: LocalPath | None = None
    target_state: Literal['VALID', 'INVALID', 'UNKNOWN'] | None = None

    @model_validator(mode='after')
    def shape(self):
        values = (self.deployment_id, self.authority_sequence, self.checkpoint_hash,
                  self.generation_location, self.target_state)
        if self.state == 'PRESENT' and any(v is None for v in values):
            raise ValueError('Complete locator required')
        if self.state != 'PRESENT' and any(v is not None for v in values):
            raise ValueError('Absent locator has no target facts')
        return self


class UpdateOperation(Model):
    intent: UpdateIntent
    stage: Literal['REGISTERED', 'PREPARED', 'COMMITTED', 'PUBLISHED']
    preparation: PreparedUpdateEvidence | None = None
    drain: SyntheticDrainEvidence | None = None
    receipt: UpdateReceipt | None = None
    publication: LocatorObservation | None = None

    @model_validator(mode='after')
    def shape(self):
        if (self.preparation is not None) != (self.stage != 'REGISTERED'):
            raise ValueError('Preparation/stage mismatch')
        committed = self.stage in ('COMMITTED', 'PUBLISHED')
        if (self.receipt is not None) != committed or (self.drain is not None) != committed:
            raise ValueError('Commit/stage mismatch')
        if (self.publication is not None) != (self.stage == 'PUBLISHED'):
            raise ValueError('Publication/stage mismatch')
        return self


class UpdateCommand(Model):
    action: Literal['REGISTER', 'PREPARE', 'COMMIT', 'PUBLISH', 'RECOVER']
    intent: UpdateIntent
    preparation: PreparedUpdateEvidence | None = None
    drain: SyntheticDrainEvidence | None = None
    locator: LocatorObservation | None = None

    @model_validator(mode='after')
    def shape(self):
        if (self.preparation is not None) != (self.action in ('PREPARE', 'COMMIT')):
            raise ValueError('Preparation required only for prepare/commit')
        if (self.drain is not None) != (self.action == 'COMMIT'):
            raise ValueError('Drain required only for commit')
        if (self.locator is not None) != (self.action == 'PUBLISH'):
            raise ValueError('Locator required only for publish')
        return self


UpdateReason = Literal['INVALID_RECORD', 'UNAUTHENTICATED_INSTALLER', 'PUBLISH_PERMISSION_DENIED',
    'OPERATION_CONFLICT', 'HEAD_CONFLICT', 'GENERATION_TOO_OLD', 'ANCHOR_MISMATCH',
    'DEPLOYMENT_MISMATCH', 'EXPIRED_VALIDITY_INTERVAL', 'PREFLIGHT_NOT_CONFORMING',
    'DRAIN_INCOMPLETE', 'AUTHORITY_UNAVAILABLE', 'RECOVERY_REQUIRED', 'INVALID_TRANSITION',
    'OPERATION_UNAVAILABLE', 'CANDIDATE_MISMATCH']


class UpdateTransitionResult(Model):
    status: Literal['PROPOSED', 'UNCHANGED', 'RECOVERED', 'DENIED']
    reason_code: UpdateReason | None = None
    operation: UpdateOperation | None = None
    proposed_head: UpdateAuthorityHead | None = None

    @model_validator(mode='after')
    def shape(self):
        if self.status == 'DENIED':
            if self.reason_code is None or self.operation is not None or self.proposed_head is not None:
                raise ValueError('Denied result exposes no state')
        elif self.reason_code is not None or self.operation is None:
            raise ValueError('Successful result requires operation')
        if self.proposed_head is not None and (self.status != 'PROPOSED' or self.operation.stage != 'COMMITTED'):
            raise ValueError('Only a new commit proposes a head')
        return self


class UpdateRecoveryResult(Model):
    disposition: Literal['MATCHED', 'REPAIR_REQUIRED', 'BLOCKED']
    reason_code: UpdateReason | None = None

    @model_validator(mode='after')
    def shape(self):
        if (self.disposition == 'MATCHED') != (self.reason_code is None):
            raise ValueError('Recovery reason mismatch')
        return self
