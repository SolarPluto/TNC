"""Synthetic evidence tests pure bindings, not filesystem or certificate security."""
from datetime import timedelta
from hashlib import sha256
import json

import pytest

from test_authorization_validation import Chain, NOW, END, ROOT
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.provisioning_models import (
    CertificateProfile, ArtifactBinding, ProvisioningPolicy, HostProvisioningDescriptor,
    ProtectedArtifactRecord, CertificateValidationEvidence, JSON_LIMIT, BUNDLE_LIMIT,
)
from tnc.provenance.provisioning_validation import (
    decode_provisioning_record, validate_provisioning_snapshot, calculate_provisioning_lease,
)

SID = 'S-1-5-21-123'
SERVICE = 'S-1-5-80-456'


@pytest.fixture
def case():
    chain = Chain()
    data = {'leaf.der': b'leaf', 'roots.pem': b'root', 'revocations.crl': b'crl'}
    kinds = {'leaf.der': 'leaf', 'roots.pem': 'roots', 'revocations.crl': 'crls'}
    policy = ProvisioningPolicy(deployment_id='deployment', service_sid=SERVICE,
        valid_from=NOW, valid_until=END, operator_sids=(SID,), authorization_seconds=60,
        certificate_profile=CertificateProfile(max_crl_age_seconds=86400),
        artifacts=tuple(ArtifactBinding(name=n, kind=kinds[n], sha256=sha256(b).hexdigest(),
            length=len(b)) for n, b in sorted(data.items())))
    manifest = chain.manifest.model_copy(update={'service_identity': SERVICE,
        'admin_policy_hash': record_digest(policy)})
    anchor = chain.anchor.model_copy(update={'operator_id': SID,
        'manifest_hash': record_digest(manifest)})
    descriptor = HostProvisioningDescriptor(deployment_id='deployment', service_sid=SERVICE,
        configuration_root=r'C:\TNC\config', database_path=r'C:\TNC\data\store.sqlite',
        trusted_owner_sids=(SID,), trusted_writer_sids=(SID,), policy_hash=record_digest(policy),
        trust_configuration_hash=manifest.trust_configuration_hash, bootstrap_anchor=anchor)
    observations = tuple(ProtectedArtifactRecord(name=n, sha256=sha256(b).hexdigest(),
        length=len(b), volume_id='volume', file_id=n, security_descriptor_hash='d'*64)
        for n, b in sorted(data.items()))
    return dict(descriptor=descriptor, policy=policy, manifest=manifest,
        artifacts=data, observations=observations)


def lease_args(case):
    snapshot = validate_provisioning_snapshot(**case)
    return {k: case[k] for k in ('descriptor', 'policy', 'manifest')} | dict(
        snapshot=snapshot, operator_sid=SID, now=NOW,
        evidence=CertificateValidationEvidence(leaf_fingerprint=ROOT,
            chain_fingerprints=(ROOT, 'b'*64), root_fingerprint='b'*64,
            crl_digests=('c'*64,), profile_hash=record_digest(case['policy'].certificate_profile),
            snapshot_hash=record_digest(snapshot), validated_at=NOW,
            valid_from=NOW, valid_until=END))


def test_valid_snapshot_and_lease(case):
    snapshot = validate_provisioning_snapshot(**case)
    assert snapshot == validate_provisioning_snapshot(**(case | {
        'observations': tuple(reversed(case['observations']))}))
    result = calculate_provisioning_lease(**lease_args(case))
    assert result.valid_until == NOW + timedelta(seconds=60)
    assert result.snapshot_hash == record_digest(snapshot)
    assert not hasattr(result, 'session_id')  # Not a writer-compatible authorization.


@pytest.mark.parametrize('mutation', [
    lambda b: b + b' ', lambda b: b.replace(b'"codec_version":1', b'"codec_version":true'),
    lambda b: b.replace(b'"codec_version":1', b'"codec_version":1,"codec_version":1'),
    lambda b: b.replace(b'.000000Z', b'Z'),
    lambda b: b[:-1]+b',"unknown":1}', lambda b: b[:-1]+b',"unknown":NaN}',
    lambda b: b'\xff', lambda b: b'', lambda b: b' '*(JSON_LIMIT+1), lambda b: bytearray(b),
])
def test_canonical_rejections(case, mutation):
    with pytest.raises(ValueError):
        decode_provisioning_record(ProvisioningPolicy, mutation(canonical_bytes(case['policy'])))


def test_canonical_roundtrip(case):
    for key in ('policy', 'descriptor', 'manifest'):
        value = case[key]
        assert decode_provisioning_record(type(value), canonical_bytes(value)) == value


@pytest.mark.parametrize('sid', ['admin', 'S-1-05-1', 'S-1-5-01', 'S-1-5-4294967296',
    'S-1-281474976710656-1', 'S-1-5' + '-1'*16, 'S-1-5'])
def test_bad_sid(case, sid):
    with pytest.raises(ValueError):
        ProvisioningPolicy.model_validate(case['policy'].model_dump() | {'operator_sids': (sid,)})


@pytest.mark.parametrize('path', [r'\\server\share', r'\\?\C:\TNC', r'C:\TNC\..\x',
    r'C:\TNC\x:stream', r'C:\TNC\NUL', r'C:\TNC\x.', 'C:\\TNC\\', r'config', r'C:/TNC'])
def test_bad_path(case, path):
    with pytest.raises(ValueError):
        HostProvisioningDescriptor.model_validate(case['descriptor'].model_dump() |
            {'configuration_root': path})


@pytest.mark.parametrize('field,value', [('authorization_seconds', 61), ('authorization_seconds', True),
    ('operator_sids', (SID, SID)), ('operator_sids', ()), ('valid_until', NOW),
    ('valid_from', NOW.replace(tzinfo=None))])
def test_policy_constraints(case, field, value):
    with pytest.raises(ValueError):
        ProvisioningPolicy.model_validate(case['policy'].model_dump() | {field: value})


@pytest.mark.parametrize('key,field,value', [
    ('descriptor', 'policy_hash', 'f'*64), ('descriptor', 'trust_configuration_hash', 'f'*64),
    ('descriptor', 'service_sid', SID), ('policy', 'deployment_id', 'other'),
    ('manifest', 'admin_policy_hash', 'f'*64), ('manifest', 'service_identity', 'other'),
])
def test_binding_mismatch(case, key, field, value):
    case[key] = case[key].model_copy(update={field: value})
    with pytest.raises(ValueError):
        validate_provisioning_snapshot(**case)


@pytest.mark.parametrize('change', ['missing', 'extra', 'changed', 'wrong_type', 'observation', 'duplicate'])
def test_artifact_failures(case, change):
    if change == 'missing':
        del case['artifacts']['leaf.der']
    elif change == 'extra':
        case['artifacts']['extra.der'] = b'x'
    elif change == 'changed':
        case['artifacts']['leaf.der'] = b'fake'
    elif change == 'wrong_type':
        case['artifacts']['leaf.der'] = bytearray(b'leaf')
    elif change == 'observation':
        case['observations'] = (case['observations'][0].model_copy(update={'sha256': 'f'*64}),) + case['observations'][1:]
    else:
        case['observations'] += (case['observations'][0],)
    with pytest.raises(ValueError):
        validate_provisioning_snapshot(**case)


@pytest.mark.parametrize('length', [0, -1, True, BUNDLE_LIMIT+1])
def test_artifact_size_limit(length):
    with pytest.raises(ValueError):
        ArtifactBinding(name='leaf.der', kind='leaf', sha256=ROOT, length=length)


@pytest.mark.parametrize('field,value', [('leaf_fingerprint', 'f'*64), ('profile_hash', 'f'*64),
    ('snapshot_hash', 'f'*64), ('validated_at', NOW-timedelta(seconds=1)),
    ('valid_until', NOW), ('chain_fingerprints', (ROOT, ROOT)), ('crl_digests', ())])
def test_evidence_rejected(case, field, value):
    args = lease_args(case)
    args['evidence'] = args['evidence'].model_copy(update={field: value})
    with pytest.raises(ValueError):
        calculate_provisioning_lease(**args)


@pytest.mark.parametrize('seconds', [1, 30, 60, 90])
def test_evidence_deadline_intersection(case, seconds):
    args = lease_args(case)
    args['evidence'] = args['evidence'].model_copy(update={'valid_until': NOW+timedelta(seconds=seconds)})
    assert calculate_provisioning_lease(**args).valid_until == NOW+timedelta(seconds=min(seconds, 60))


@pytest.mark.parametrize('field,value', [('operator_sid', SERVICE), ('now', NOW.replace(tzinfo=None)),
    ('now', NOW-timedelta(seconds=1)), ('now', END)])
def test_operator_and_clock_rejected(case, field, value):
    with pytest.raises(ValueError):
        calculate_provisioning_lease(**(lease_args(case) | {field: value}))


@pytest.mark.parametrize('target', ['policy', 'manifest', 'anchor', 'credential', 'grant'])
@pytest.mark.parametrize('seconds', [0, 10])
def test_every_deadline(case, target, seconds):
    deadline = NOW + timedelta(seconds=seconds)
    if target == 'policy':
        case['policy'] = case['policy'].model_copy(update={'valid_until': deadline})
    manifest = case['manifest']
    if target == 'manifest':
        manifest = manifest.model_copy(update={'valid_until': deadline})
    if target in ('credential', 'grant'):
        outer = 'initial_enrollment' if target == 'credential' else 'initial_grant'
        inner = 'credential' if target == 'credential' else 'permission'
        seed = getattr(manifest, outer)
        value = getattr(seed, inner).model_copy(update={'valid_until': deadline})
        manifest = manifest.model_copy(update={outer: seed.model_copy(update={inner: value})})
    if seconds == 0:
        # Invalid constructed intervals must be revalidated, not trusted.
        with pytest.raises(ValueError):
            if target == 'anchor':
                case['descriptor'] = case['descriptor'].model_copy(update={
                    'bootstrap_anchor': case['descriptor'].bootstrap_anchor.model_copy(update={'valid_until': deadline})})
            case['manifest'] = manifest
            lease_args(case)
        return
    policy_hash = record_digest(case['policy'])
    manifest = manifest.model_copy(update={'admin_policy_hash': policy_hash})
    anchor = case['descriptor'].bootstrap_anchor.model_copy(update={'manifest_hash': record_digest(manifest)} |
        ({'valid_until': deadline} if target == 'anchor' else {}))
    case['manifest'] = manifest
    case['descriptor'] = case['descriptor'].model_copy(update={'policy_hash': policy_hash, 'bootstrap_anchor': anchor})
    assert calculate_provisioning_lease(**lease_args(case)).valid_until == deadline


def test_total_size_limit(case):
    bindings, observations, data = [], [], {}
    for kind in ('leaf', 'roots', 'intermediates', 'crls'):
        name = kind + '.der'
        body = b'x' * BUNDLE_LIMIT
        digest = sha256(body).hexdigest()
        data[name] = body
        bindings.append(ArtifactBinding(name=name, kind=kind, length=len(body), sha256=digest))
        observations.append(ProtectedArtifactRecord(name=name, length=len(body), sha256=digest,
            volume_id='volume', file_id=name, security_descriptor_hash=ROOT))
    policy = case['policy'].model_copy(update={'artifacts': tuple(sorted(bindings, key=lambda x: x.name))})
    manifest = case['manifest'].model_copy(update={'admin_policy_hash': record_digest(policy)})
    anchor = case['descriptor'].bootstrap_anchor.model_copy(update={'manifest_hash': record_digest(manifest)})
    descriptor = case['descriptor'].model_copy(update={'policy_hash': record_digest(policy), 'bootstrap_anchor': anchor})
    with pytest.raises(ValueError, match='Snapshot size exceeded'):
        validate_provisioning_snapshot(descriptor=descriptor, policy=policy, manifest=manifest,
            artifacts=data, observations=tuple(observations))
