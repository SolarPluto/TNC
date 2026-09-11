"""Pure validation. No files, Windows APIs, certificate parsing, clock reads or writes."""
from datetime import datetime, timedelta
from hashlib import sha256

from tnc.provenance.authorization_models import (
    BootstrapManifest, canonical_bytes, decode_canonical, record_digest,
)
from tnc.provenance.provisioning_models import (
    JSON_LIMIT, TOTAL_LIMIT, HostProvisioningDescriptor, ProvisioningPolicy,
    ProtectedArtifactRecord, ProvisioningSnapshotRecord, CertificateValidationEvidence,
    ProvisioningLeaseBounds,
)


def decode_provisioning_record(kind, data):
    if type(data) is not bytes or not 0 < len(data) <= JSON_LIMIT:
        raise ValueError('Invalid provisioning record size')
    if kind not in (HostProvisioningDescriptor, ProvisioningPolicy, BootstrapManifest,
                    ProvisioningSnapshotRecord, CertificateValidationEvidence):
        raise ValueError('Unsupported provisioning record')
    return decode_canonical(kind, data)


def _copy(value, kind):
    if type(value) is not kind:
        raise ValueError('Exact typed record required')
    return decode_provisioning_record(kind, canonical_bytes(value))


def validate_provisioning_snapshot(*, descriptor, policy, manifest, artifacts, observations):
    """Check supplied bytes/observations only; caller must establish their provenance."""
    descriptor = _copy(descriptor, HostProvisioningDescriptor)
    policy = _copy(policy, ProvisioningPolicy)
    manifest = _copy(manifest, BootstrapManifest)
    if (descriptor.deployment_id != policy.deployment_id
            or policy.deployment_id != manifest.deployment_id
            or descriptor.service_sid != policy.service_sid
            or policy.service_sid != manifest.service_identity
            or descriptor.policy_hash != record_digest(policy)
            or manifest.admin_policy_hash != descriptor.policy_hash
            or manifest.trust_configuration_hash != descriptor.trust_configuration_hash
            or descriptor.bootstrap_anchor.manifest_hash != record_digest(manifest)
            or descriptor.bootstrap_anchor.operator_id not in policy.operator_sids):
        raise ValueError('Provisioning binding mismatch')
    if type(artifacts) is not dict or type(observations) is not tuple:
        raise ValueError('Exact artifact collection required')
    expected = {a.name for a in policy.artifacts}
    if set(artifacts) != expected:
        raise ValueError('Artifact set mismatch')
    records = []
    for record in observations:
        if type(record) is not ProtectedArtifactRecord:
            raise ValueError('Typed artifact observation required')
        records.append(decode_canonical(ProtectedArtifactRecord, canonical_bytes(record)))
    if len(records) != len(expected) or {r.name for r in records} != expected:
        raise ValueError('Observation set mismatch')
    observed = {r.name: r for r in records}
    total = sum(len(canonical_bytes(r)) for r in (descriptor, policy, manifest))
    for binding in policy.artifacts:
        data = artifacts[binding.name]
        if type(data) is not bytes or len(data) != binding.length:
            raise ValueError('Artifact size mismatch')
        total += len(data)
        if total > TOTAL_LIMIT:
            raise ValueError('Snapshot size exceeded')
        digest = sha256(data).hexdigest()
        record = observed[binding.name]
        if digest != binding.sha256 or record.sha256 != digest or record.length != len(data):
            raise ValueError('Artifact digest mismatch')
    return ProvisioningSnapshotRecord(descriptor_hash=record_digest(descriptor),
        policy_hash=record_digest(policy), manifest_hash=record_digest(manifest),
        artifacts=tuple(sorted(records, key=lambda r: r.name)))


def calculate_provisioning_lease(*, descriptor, policy, manifest, snapshot, evidence,
                                 operator_sid, now):
    """Intersect trusted-input deadlines without issuing a writer-compatible proof."""
    descriptor = _copy(descriptor, HostProvisioningDescriptor)
    policy = _copy(policy, ProvisioningPolicy)
    manifest = _copy(manifest, BootstrapManifest)
    snapshot = _copy(snapshot, ProvisioningSnapshotRecord)
    evidence = _copy(evidence, CertificateValidationEvidence)
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError('Aware evaluation time required')
    anchor = descriptor.bootstrap_anchor
    credential = manifest.initial_enrollment.credential
    grant = manifest.initial_grant.permission
    if (snapshot.descriptor_hash != record_digest(descriptor)
            or snapshot.policy_hash != record_digest(policy)
            or snapshot.manifest_hash != record_digest(manifest)
            or descriptor.policy_hash != record_digest(policy)
            or manifest.admin_policy_hash != descriptor.policy_hash
            or anchor.manifest_hash != record_digest(manifest)
            or manifest.trust_configuration_hash != descriptor.trust_configuration_hash
            or not descriptor.deployment_id == policy.deployment_id == manifest.deployment_id
            or not descriptor.service_sid == policy.service_sid == manifest.service_identity
            or operator_sid != anchor.operator_id or operator_sid not in policy.operator_sids
            or evidence.snapshot_hash != record_digest(snapshot)
            or evidence.profile_hash != record_digest(policy.certificate_profile)
            or evidence.leaf_fingerprint != credential.credential_id
            or evidence.validated_at != now):
        raise ValueError('Lease binding mismatch')
    intervals = (policy, manifest, anchor, credential, grant, evidence)
    if any(not item.valid_from <= now < item.valid_until for item in intervals):
        raise ValueError('Provisioning interval unavailable')
    return ProvisioningLeaseBounds(valid_from=now,
        valid_until=min(now + timedelta(seconds=policy.authorization_seconds),
                        *(item.valid_until for item in intervals)),
        snapshot_hash=record_digest(snapshot), operator_sid=operator_sid)
