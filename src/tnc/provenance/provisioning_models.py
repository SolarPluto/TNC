"""Pure provisioning contracts. Typed evidence is not OS or X.509 verification."""
from datetime import datetime
import re
from typing import Annotated, Literal

from pydantic import Field, AfterValidator, model_validator

from tnc.provenance.authorization_models import Model, Digest, Identifier, BootstrapTrustAnchor

JSON_LIMIT = 64 * 1024
BUNDLE_LIMIT = 4 * 1024 * 1024
TOTAL_LIMIT = 16 * 1024 * 1024


def _sid(value):
    if not re.fullmatch(r'S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}', value):
        raise ValueError('Canonical decimal SID required')
    parts = value.split('-')
    if int(parts[2]) >= 2**48 or any(int(x) >= 2**32 for x in parts[3:]):
        raise ValueError('SID component out of range')
    return value


Sid = Annotated[str, AfterValidator(_sid)]
Filename = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}\.(?:json|pem|der|crl)$')]


class Interval(Model):
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode='after')
    def interval(self):
        if self.valid_from >= self.valid_until:
            raise ValueError('Empty interval')
        return self


class CertificateProfile(Model):
    codec_version: Literal[1] = 1
    profile: Literal['offline-client-full-crl-v1'] = 'offline-client-full-crl-v1'
    # The profile fixes algorithms and rejects unsupported CRL forms; no bypass flags.
    max_crl_age_seconds: int = Field(strict=True, gt=0, le=604800)


class ArtifactBinding(Model):
    name: Filename
    kind: Literal['leaf', 'roots', 'intermediates', 'crls']
    sha256: Digest
    length: int = Field(strict=True, gt=0, le=BUNDLE_LIMIT)


class ProvisioningPolicy(Interval):
    codec_version: Literal[1] = 1
    deployment_id: Identifier
    service_sid: Sid
    operator_sids: tuple[Sid, ...] = Field(min_length=1, max_length=32)
    artifacts: tuple[ArtifactBinding, ...] = Field(min_length=3, max_length=4)
    certificate_profile: CertificateProfile
    authorization_seconds: int = Field(strict=True, gt=0, le=60)

    @model_validator(mode='after')
    def unique(self):
        if tuple(sorted(set(self.operator_sids))) != self.operator_sids:
            raise ValueError('Sorted unique operators required')
        if tuple(sorted(self.artifacts, key=lambda a: a.name)) != self.artifacts:
            raise ValueError('Sorted artifact names required')
        kinds = [a.kind for a in self.artifacts]
        if (len(set(a.name for a in self.artifacts)) != len(self.artifacts)
                or len(set(kinds)) != len(kinds)
                or not {'leaf', 'roots', 'crls'} <= set(kinds)):
            raise ValueError('Complete unique artifact bindings required')
        return self


class HostProvisioningDescriptor(Model):
    codec_version: Literal[1] = 1
    loader_profile: Literal['local-ntfs-flat-v1'] = 'local-ntfs-flat-v1'
    deployment_id: Identifier
    service_sid: Sid
    configuration_root: str
    database_path: str
    trusted_owner_sids: tuple[Sid, ...] = Field(min_length=1, max_length=32)
    trusted_writer_sids: tuple[Sid, ...] = Field(min_length=1, max_length=32)
    policy_hash: Digest
    trust_configuration_hash: Digest
    bootstrap_anchor: BootstrapTrustAnchor

    @model_validator(mode='after')
    def bindings(self):
        # Lexical restriction only. The future native loader must verify handles/ACLs.
        for path in (self.configuration_root, self.database_path):
            if not re.fullmatch(r'[A-Z]:\\[^<>:"/|?*\x00-\x1f]+', path):
                raise ValueError('Local absolute Windows path required')
            for part in path[3:].split('\\'):
                if (not part or part in ('.', '..') or part.endswith((' ', '.'))
                        or re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?', part)):
                    raise ValueError('Unsafe path component')
        for sids in (self.trusted_owner_sids, self.trusted_writer_sids):
            if tuple(sorted(set(sids))) != sids:
                raise ValueError('Sorted unique SIDs required')
        if self.bootstrap_anchor.deployment_id != self.deployment_id:
            raise ValueError('Deployment mismatch')
        return self


class ProtectedArtifactRecord(Model):
    """Future loader observations, not proof that access control was checked."""
    name: Filename
    sha256: Digest
    length: int = Field(strict=True, gt=0, le=BUNDLE_LIMIT)
    volume_id: Identifier
    file_id: Identifier
    security_descriptor_hash: Digest


class ProvisioningSnapshotRecord(Model):
    domain: Literal['tnc.provisioning.snapshot.v1'] = 'tnc.provisioning.snapshot.v1'
    descriptor_hash: Digest
    policy_hash: Digest
    manifest_hash: Digest
    artifacts: tuple[ProtectedArtifactRecord, ...] = Field(min_length=3, max_length=4)

    @model_validator(mode='after')
    def ordered(self):
        names = tuple(a.name for a in self.artifacts)
        if names != tuple(sorted(set(names))):
            raise ValueError('Sorted unique artifacts required')
        return self


class CertificateValidationEvidence(Interval):
    """Host backend result contract. Constructing this record verifies no certificate."""
    leaf_fingerprint: Digest
    chain_fingerprints: tuple[Digest, ...] = Field(min_length=2, max_length=32)
    root_fingerprint: Digest
    crl_digests: tuple[Digest, ...] = Field(min_length=1, max_length=32)
    profile_hash: Digest
    snapshot_hash: Digest
    validated_at: datetime
    # Backend computes this from supplied CRL freshness and all certificate intervals.
    @model_validator(mode='after')
    def chain(self):
        if (self.chain_fingerprints[0] != self.leaf_fingerprint
                or self.chain_fingerprints[-1] != self.root_fingerprint
                or len(set(self.chain_fingerprints)) != len(self.chain_fingerprints)
                or tuple(sorted(set(self.crl_digests))) != self.crl_digests
                or not self.valid_from <= self.validated_at < self.valid_until):
            raise ValueError('Invalid certificate evidence binding')
        return self


class ProvisioningLeaseBounds(Interval):
    """Calculated bounds only; deliberately not ProvisioningAuthorization."""
    snapshot_hash: Digest
    operator_sid: Sid
