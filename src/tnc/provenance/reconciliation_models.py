"""Frozen reconciliation contracts. Synthetic evidence is not authentication."""
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Digest, Identifier, ZERO
from tnc.provenance.provisioning_models import Interval
from tnc.provenance.update_storage_models import UpdateStorageCheckpoint

RECONCILIATION_LIMIT = 64 * 1024


class ReconciliationEnvelope(Interval):
    codec_version: Literal[1] = 1
    profile: Literal['tnc-reconciliation-logical-v1'] = 'tnc-reconciliation-logical-v1'
    deployment_id: Identifier
    store_instance_id: Identifier
    authority_revision: int = Field(strict=True, gt=0)
    previous_envelope_hash: Digest
    issuer_id: Identifier
    key_id: Digest
    checkpoint: UpdateStorageCheckpoint

    @model_validator(mode='after')
    def binding(self):
        if self.deployment_id != self.checkpoint.deployment_id:
            raise ValueError('Deployment binding mismatch')
        if (self.authority_revision == 1) != (self.previous_envelope_hash == ZERO):
            raise ValueError('Invalid predecessor binding')
        return self


class SyntheticCheckpointEvidence(Interval):
    """Test assertion of current independent state, never a signature proof."""
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    deployment_id: Identifier
    store_instance_id: Identifier
    current_authority_revision: int = Field(strict=True, gt=0)
    current_envelope_hash: Digest


class ReconciliationRequest(Interval):
    codec_version: Literal[1] = 1
    request_id: Identifier
    principal_id: Identifier
    deployment_id: Identifier
    store_instance_id: Identifier
    expected_authority_revision: int = Field(strict=True, gt=0)
    expected_envelope_hash: Digest
    successor_checkpoint: UpdateStorageCheckpoint
    event_batch_hash: Digest

    @model_validator(mode='after')
    def binding(self):
        if self.successor_checkpoint.deployment_id != self.deployment_id:
            raise ValueError('Deployment binding mismatch')
        return self


class ReconciliationAcceptance(Model):
    codec_version: Literal[1] = 1
    acceptance_id: Identifier
    request_id: Identifier
    request_hash: Digest
    principal_id: Identifier
    deployment_id: Identifier
    store_instance_id: Identifier
    predecessor_revision: int = Field(strict=True, gt=0)
    predecessor_hash: Digest
    accepted_at: datetime
    successor: ReconciliationEnvelope
    event_batch_hash: Digest
    policy_revision: int = Field(strict=True, gt=0)
    independent_evidence_hash: Digest

    @model_validator(mode='after')
    def binding(self):
        if ((self.deployment_id, self.store_instance_id) !=
                (self.successor.deployment_id, self.successor.store_instance_id)
                or self.successor.authority_revision != self.predecessor_revision + 1
                or self.successor.previous_envelope_hash != self.predecessor_hash):
            raise ValueError('Invalid successor binding')
        return self


class SyntheticAcceptanceEvidence(Interval):
    """Independent archival binding plus current recovery scope, for pure tests.

    A real provider must establish both; hashing one's own record is insufficient.
    """
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    deployment_id: Identifier
    store_instance_id: Identifier
    principal_id: Identifier
    request_id: Identifier
    request_hash: Digest
    acceptance_hash: Digest
    independent_evidence_hash: Digest
    may_recover: bool = Field(strict=True)


class ReconciliationRelationship(Model):
    audit_only: bool = Field(default=True, strict=True)
    relationship: Literal['MATCHED', 'DATABASE_EXTENSION_PENDING', 'CHECKPOINT_AHEAD',
                          'FORK_OR_MISMATCH', 'INDETERMINATE']
    reason_code: Literal['EXACT_MATCH', 'INDEPENDENT_ACCEPTANCE_REQUIRED', 'DATABASE_BEHIND',
                         'IDENTITY_MISMATCH', 'PREFIX_MISMATCH', 'IMAGE_INVALID',
                         'INVALID_INPUT', 'FRESHNESS_UNAVAILABLE']
    observed_event_count: int | None = Field(default=None, strict=True, ge=0, le=256)
    observed_image_hash: Digest | None = None
    suffix_batch_hash: Digest | None = None

    @model_validator(mode='after')
    def shape(self):
        if not self.audit_only:
            raise ValueError('Audit only')
        expected = {
            'MATCHED': {'EXACT_MATCH'}, 'DATABASE_EXTENSION_PENDING': {'INDEPENDENT_ACCEPTANCE_REQUIRED'},
            'CHECKPOINT_AHEAD': {'DATABASE_BEHIND'},
            'FORK_OR_MISMATCH': {'IDENTITY_MISMATCH','PREFIX_MISMATCH','IMAGE_INVALID'},
            'INDETERMINATE': {'INVALID_INPUT','FRESHNESS_UNAVAILABLE'},
        }
        if self.reason_code not in expected[self.relationship]:
            raise ValueError('Inconsistent reason')
        known = self.relationship in ('MATCHED','DATABASE_EXTENSION_PENDING')
        if known != (self.observed_event_count is not None and self.observed_image_hash is not None):
            raise ValueError('Incomplete observations')
        if not known and any(v is not None for v in (self.observed_event_count,self.observed_image_hash,self.suffix_batch_hash)):
            raise ValueError('Blocked result exposes no observations')
        if (self.relationship == 'DATABASE_EXTENSION_PENDING') != (self.suffix_batch_hash is not None):
            raise ValueError('Invalid suffix binding')
        return self


class ReconciliationAcceptanceResult(Model):
    audit_only: bool = Field(default=True, strict=True)
    status: Literal['VALID_BINDING', 'REJECTED']
    reason_code: Literal['INVALID_INPUT','ACCESS_DENIED','BINDING_MISMATCH'] | None = None
    acceptance_hash: Digest | None = None

    @model_validator(mode='after')
    def shape(self):
        if not self.audit_only or ((self.status == 'VALID_BINDING') !=
                (self.reason_code is None and self.acceptance_hash is not None)):
            raise ValueError('Invalid result')
        if self.status == 'REJECTED' and (self.reason_code is None or self.acceptance_hash is not None):
            raise ValueError('Rejected result exposes no acceptance')
        return self
