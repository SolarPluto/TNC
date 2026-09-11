"""Synthetic host anchors test ledger semantics, not OS or TLS authentication."""
from datetime import datetime, timedelta, timezone
import json

import pytest
from pydantic import ValidationError

from tnc.provenance.host_auth import Action, CredentialEnrollment, PermissionGrant
from tnc.provenance.authorization_models import (
    ZERO, AdministrativeActor, AuthorizationCheckpoint, AuthorizationEvent,
    BootstrapManifest, BootstrapReceipt, BootstrapRecord, BootstrapTrustAnchor,
    CredentialEnrolled, CredentialDisabled, PermissionGranted, PermissionRevoked,
    ProvisioningActor, canonical_bytes, decode_canonical, record_digest,
    event_digest, bootstrap_receipt_digest,
)
from tnc.provenance.authorization_validator import validate_authorization_ledger, AuthorizationValidationError


NOW = datetime(2026, 9, 11, 12, tzinfo=timezone.utc)
END = NOW + timedelta(days=1)
ROOT = 'a' * 64
OTHER = 'b' * 64


def enrollment(fingerprint=ROOT, principal='root', **changes):
    return CredentialEnrolled(credential=CredentialEnrollment(**(dict(
        credential_id=fingerprint, principal_id=principal, enabled=True,
        valid_from=NOW-timedelta(days=1), valid_until=END) | changes)), enrollment_evidence_hash='c'*64)


def grant(grant_id='admin', principal='root', action=Action.MANAGE_HOST, **changes):
    return PermissionGranted(grant_id=grant_id, permission=PermissionGrant(**(dict(
        principal_id=principal, action=action, corpus_id=None if action == Action.MANAGE_HOST else 'corpus',
        valid_from=NOW, valid_until=END) | changes)))


class Chain:
    def __init__(self):
        self.events = []
        self.manifest = BootstrapManifest(request_id='bootstrap', deployment_id='deployment',
            service_identity='service', legacy_journal_sequence=0, legacy_journal_hash=ZERO,
            legacy_release_sequence=0, legacy_release_hash=ZERO, trust_configuration_hash='d'*64,
            admin_policy_hash='e'*64, valid_from=NOW, valid_until=END,
            initial_enrollment=enrollment(), initial_grant=grant())
        self.anchor = BootstrapTrustAnchor(deployment_id='deployment', manifest_hash=record_digest(self.manifest),
            operator_id='operator', provisioning_session_id='provisioning-session', valid_from=NOW, valid_until=END)
        actor = ProvisioningActor(operator_id='operator', session_id='provisioning-session',
                                  manifest_hash=self.anchor.manifest_hash)
        self.append(self.manifest.initial_enrollment, actor=actor, at=NOW)
        self.append(self.manifest.initial_grant, actor=actor, at=NOW)
        receipt = BootstrapReceipt(manifest_hash=self.anchor.manifest_hash, deployment_id='deployment',
            operator_id='operator', provisioning_session_id='provisioning-session', provisioned_at=NOW,
            first_event_hash=self.events[0].entry_hash, second_event_hash=self.events[1].entry_hash, receipt_hash=ZERO)
        self.bootstrap = BootstrapRecord(manifest=self.manifest,
            receipt=receipt.model_copy(update={'receipt_hash': bootstrap_receipt_digest(receipt)}))

    def append(self, payload, *, actor=None, at=None, **changes):
        sequence = len(self.events)+1
        at = at or NOW+timedelta(seconds=sequence)
        actor = actor or AdministrativeActor(principal_id='root', credential_id=ROOT,
            verified_at=at, valid_until=min(at+timedelta(minutes=5), END), registry_revision=sequence-1,
            permission_grant_id='admin', audit_id=f'audit-{sequence}')
        previous = self.events[-1].entry_hash if self.events else ZERO
        event = AuthorizationEvent(**(dict(sequence=sequence, event_id=f'event-{sequence}', actor=actor,
            expected_head_sequence=sequence-1, expected_head_hash=previous, previous_entry_hash=previous,
            recorded_at=at, payload=payload, entry_hash=ZERO) | changes))
        self.events.append(event.model_copy(update={'entry_hash': event_digest(event)}))

    def validate(self, **changes):
        return validate_authorization_ledger(**(dict(events=tuple(self.events), bootstrap=self.bootstrap,
            trust_anchor=self.anchor, checkpoint=AuthorizationCheckpoint(sequence=len(self.events),
                head_hash=self.events[-1].entry_hash)) | changes))


def test_valid_bootstrap_and_canonical_roundtrip():
    chain = Chain()
    result = chain.validate()
    assert result.checkpoint.sequence == 2
    assert len(result.credentials) == len(result.grants) == 1
    assert result.grants[0].permission.action == Action.MANAGE_HOST
    data = canonical_bytes(chain.bootstrap)
    assert b'2026-09-11T12:00:00.000000Z' in data
    assert decode_canonical(BootstrapRecord, data) == chain.bootstrap
    assert data == json.dumps(json.loads(data), ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def test_independent_grant_and_self_revocation():
    chain = Chain()
    chain.append(grant('second'))
    chain.append(PermissionRevoked(grant_id='admin', expected_grant_sequence=2, rationale='retire'))
    at = NOW+timedelta(seconds=5)
    actor = AdministrativeActor(principal_id='root', credential_id=ROOT, verified_at=at,
        valid_until=at+timedelta(minutes=5), registry_revision=4, permission_grant_id='second', audit_id='new')
    chain.append(enrollment(OTHER, 'bob'), actor=actor, at=at)
    result = chain.validate()
    assert [g.grant_id for g in result.grants if not g.revoked] == ['second']
    assert len(result.credentials) == 2


def test_rotation_retains_owner_and_disabled_fingerprint():
    chain = Chain()
    chain.append(enrollment(OTHER))
    chain.append(CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='rotation'))
    at = NOW+timedelta(seconds=5)
    actor = AdministrativeActor(principal_id='root', credential_id=OTHER, verified_at=at,
        valid_until=at+timedelta(minutes=5), registry_revision=4, permission_grant_id='admin', audit_id='rotated')
    chain.append(grant('replay', action=Action.SUBMIT), actor=actor)
    result = chain.validate()
    assert result.credentials[0].credential.enabled is False
    assert result.credentials[1].credential.principal_id == 'root'


@pytest.mark.parametrize('fault', ['duplicate_grant', 'reenroll', 'rebind', 'unknown_grantee',
    'missing_credential', 'stale_enrollment', 'missing_grant', 'stale_grant'])
def test_lifecycle_failures(fault):
    chain = Chain()
    payload = {
        'duplicate_grant': grant(), 'reenroll': enrollment(), 'rebind': enrollment(ROOT, 'bob'),
        'unknown_grantee': grant('bob-grant', 'bob'),
        'missing_credential': CredentialDisabled(credential_id=OTHER, expected_enrollment_sequence=1, rationale='x'),
        'stale_enrollment': CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=2, rationale='x'),
        'missing_grant': PermissionRevoked(grant_id='missing', expected_grant_sequence=2, rationale='x'),
        'stale_grant': PermissionRevoked(grant_id='admin', expected_grant_sequence=1, rationale='x'),
    }[fault]
    chain.append(payload)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('kind', ['disabled', 'revoked', 'double_disable', 'double_revoke', 'reuse_revoked_id'])
def test_terminal_states_never_fall_back(kind):
    chain = Chain()
    if kind in ('disabled', 'double_disable'):
        chain.append(CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='x'))
        if kind == 'double_disable':
            chain.append(CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='again'))
        else:
            chain.append(enrollment(OTHER))
    else:
        chain.append(grant('second'))
        chain.append(PermissionRevoked(grant_id='second', expected_grant_sequence=3, rationale='x'))
        if kind == 'double_revoke':
            chain.append(PermissionRevoked(grant_id='second', expected_grant_sequence=3, rationale='again'))
        elif kind == 'reuse_revoked_id':
            chain.append(grant('second'))
        else:
            at = NOW+timedelta(seconds=5)
            actor = AdministrativeActor(principal_id='root', credential_id=ROOT, verified_at=at,
                valid_until=at+timedelta(minutes=5), registry_revision=4, permission_grant_id='second', audit_id='revoked')
            chain.append(enrollment(OTHER), actor=actor)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('change', [
    {'principal_id': 'bob'}, {'credential_id': OTHER}, {'registry_revision': 1},
    {'valid_until': NOW}, {'verified_at': END}, {'valid_until': END},
    {'permission_grant_id': 'unknown'},
])
def test_actor_binding_and_session_limits(change):
    chain = Chain()
    at = NOW+timedelta(seconds=3)
    actor = AdministrativeActor(principal_id='root', credential_id=ROOT, verified_at=at,
        valid_until=at+timedelta(minutes=5), registry_revision=2, permission_grant_id='admin', audit_id='a')
    chain.append(enrollment(OTHER), actor=actor.model_copy(update=change))
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('change', [
    {'sequence': 4}, {'event_id': 'event-1'}, {'expected_head_sequence': 1},
    {'expected_head_hash': ZERO}, {'previous_entry_hash': ZERO}, {'recorded_at': NOW-timedelta(seconds=1)},
])
def test_sequence_chain_and_expected_head_semantics(change):
    chain = Chain()
    chain.append(enrollment(OTHER), **change)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('change', [
    {'deployment_id': 'other'}, {'manifest_hash': ZERO}, {'operator_id': 'attacker'},
    {'provisioning_session_id': 'other'}, {'valid_until': NOW},
])
def test_independent_bootstrap_anchor_required(change):
    chain = Chain()
    with pytest.raises(AuthorizationValidationError):
        chain.validate(trust_anchor=chain.anchor.model_copy(update=change))


def test_provisioning_actor_not_allowed_after_two_seeds():
    chain = Chain()
    chain.append(enrollment(OTHER), actor=chain.events[0].actor)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('fault', ['seed_payload', 'seed_order', 'seed_time', 'receipt_hash', 'receipt_seed_hash'])
def test_exact_seed_exception(fault):
    chain = Chain()
    if fault == 'seed_payload':
        chain.events[1] = chain.events[1].model_copy(update={'payload': grant('wrong')})
    elif fault == 'seed_order':
        chain.events.reverse()
    elif fault == 'seed_time':
        chain.events[0] = chain.events[0].model_copy(update={'recorded_at': NOW+timedelta(seconds=1)})
    elif fault == 'receipt_hash':
        chain.bootstrap = chain.bootstrap.model_copy(update={'receipt': chain.bootstrap.receipt.model_copy(update={'receipt_hash': ZERO})})
    else:
        receipt = chain.bootstrap.receipt.model_copy(update={'second_event_hash': ZERO})
        receipt = receipt.model_copy(update={'receipt_hash': bootstrap_receipt_digest(receipt)})
        chain.bootstrap = chain.bootstrap.model_copy(update={'receipt': receipt})
    if fault in ('seed_payload', 'seed_time'):
        # Rehash so rejection exercises the seed semantics, not merely damage.
        previous = ZERO
        for index, event in enumerate(chain.events):
            event = event.model_copy(update={'previous_entry_hash': previous, 'expected_head_hash': previous})
            chain.events[index] = event.model_copy(update={'entry_hash': event_digest(event)})
            previous = chain.events[index].entry_hash
        receipt = chain.bootstrap.receipt.model_copy(update={
            'first_event_hash': chain.events[0].entry_hash, 'second_event_hash': chain.events[1].entry_hash})
        chain.bootstrap = chain.bootstrap.model_copy(update={'receipt': receipt.model_copy(update={
            'receipt_hash': bootstrap_receipt_digest(receipt)})})
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


def test_checkpoint_detects_tail_truncation_and_hash_corruption():
    chain = Chain()
    chain.append(enrollment(OTHER))
    checkpoint = AuthorizationCheckpoint(sequence=3, head_hash=chain.events[-1].entry_hash)
    with pytest.raises(AuthorizationValidationError):
        chain.validate(events=tuple(chain.events[:2]), checkpoint=checkpoint)
    chain.events[-1] = chain.events[-1].model_copy(update={'entry_hash': ZERO})
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('fault', ['spaces', 'timestamp_precision', 'duplicate_key', 'nan', 'invalid_utf8', 'extra_field'])
def test_noncanonical_bytes_rejected(fault):
    chain = Chain()
    data = canonical_bytes(chain.bootstrap)
    if fault == 'spaces':
        data = json.dumps(json.loads(data)).encode()
    elif fault == 'timestamp_precision':
        data = data.replace(b'.000000Z', b'Z')
    elif fault == 'duplicate_key':
        data = data.replace(b'{', b'{"manifest":{},', 1)
    elif fault == 'nan':
        data = data.replace(b'{', b'{"invalid":NaN,', 1)
    elif fault == 'invalid_utf8':
        data = b'\xff'
    else:
        data = data.replace(b'{', b'{"extra":1,', 1)
    with pytest.raises((ValueError, ValidationError)):
        decode_canonical(BootstrapRecord, data)


@pytest.mark.parametrize('fingerprint', ['A'*64, 'a'*63, 'g'*64])
def test_fingerprint_format(fingerprint):
    with pytest.raises(ValidationError):
        enrollment(fingerprint)


def test_normalized_timezone_and_frozen_nested_models():
    chain = Chain()
    original = chain.events[0]
    eastern = timezone(timedelta(hours=-4))
    changed = original.model_copy(update={'recorded_at': NOW.astimezone(eastern)})
    assert canonical_bytes(original) == canonical_bytes(changed)
    with pytest.raises(ValidationError):
        original.payload.credential.principal_id = 'other'
    with pytest.raises(ValueError):
        canonical_bytes(original.model_copy(update={'recorded_at': NOW.replace(tzinfo=None)}))


def test_current_clock_not_used_and_expired_historical_actor_rejected():
    chain = Chain()
    before = tuple(chain.events)
    assert chain.validate() == chain.validate()
    assert tuple(chain.events) == before
    chain.append(enrollment(OTHER, valid_until=END+timedelta(days=1)), at=END)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


def test_bootstrap_manifest_requires_only_host_manage():
    chain = Chain()
    with pytest.raises(ValidationError):
        BootstrapManifest.model_validate(chain.manifest.model_dump() | {'initial_grant': grant(action=Action.SUBMIT)})


def test_nonadmin_grant_cannot_authorize_admin_append():
    chain = Chain()
    chain.append(grant('replay', action=Action.SUBMIT))
    at = NOW+timedelta(seconds=4)
    actor = AdministrativeActor(principal_id='root', credential_id=ROOT, verified_at=at,
        valid_until=at+timedelta(minutes=5), registry_revision=3, permission_grant_id='replay', audit_id='wrong-role')
    chain.append(enrollment(OTHER), actor=actor)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('value', [True, 1.0, '1'])
def test_codec_version_is_strict_integer(value):
    chain = Chain()
    with pytest.raises(ValidationError):
        BootstrapManifest.model_validate(chain.manifest.model_dump() | {'codec_version': value})


def test_double_disablement_rejected_with_different_active_credential():
    chain = Chain()
    chain.append(enrollment(OTHER))
    chain.append(CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='rotate'))
    at = NOW+timedelta(seconds=5)
    actor = AdministrativeActor(principal_id='root', credential_id=OTHER, verified_at=at,
        valid_until=at+timedelta(minutes=5), registry_revision=4, permission_grant_id='admin', audit_id='a')
    chain.append(CredentialDisabled(credential_id=ROOT, expected_enrollment_sequence=1, rationale='again'), actor=actor)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


@pytest.mark.parametrize('kind', ['expired', 'future'])
def test_permission_must_be_active_at_historical_event(kind):
    chain = Chain()
    chain.append(grant('bounded', valid_from=NOW+timedelta(seconds=10) if kind == 'future' else NOW,
                       valid_until=NOW+timedelta(seconds=5) if kind == 'expired' else END))
    at = NOW+timedelta(seconds=5)
    actor = AdministrativeActor(principal_id='root', credential_id=ROOT, verified_at=at,
        valid_until=at+timedelta(minutes=5), registry_revision=3, permission_grant_id='bounded', audit_id='a')
    chain.append(enrollment(OTHER), at=at, actor=actor)
    with pytest.raises(AuthorizationValidationError):
        chain.validate()


def test_equal_recorded_times_are_ordered_by_sequence():
    chain = Chain()
    chain.append(enrollment(OTHER), at=NOW)
    chain.append(grant('new'), at=NOW)
    assert chain.validate().checkpoint.sequence == 4
