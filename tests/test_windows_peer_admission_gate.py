"""Pure fail-closed tests for native peer admission composition."""
import pytest

from tnc.provenance.windows_peer_admission_gate import evaluate_native_peer_admission
from tnc.provenance.windows_pipe_auth_bridge import NativePeerAuditResult
from tnc.provenance.windows_pipe_process_lease import ProcessLeaseAudit


def native_lease(**update):
    data = dict(status='CORRELATED', reason='AUDIT_MATCHED', source='NATIVE_PROCESS_API')
    data.update(update)
    return ProcessLeaseAudit(**data)


def fake_lease(**update):
    data = dict(status='CORRELATED', reason='AUDIT_MATCHED', source='FAKE_PROCESS_API')
    data.update(update)
    return ProcessLeaseAudit(**data)


def peer_unproven(**update):
    data = dict(status='INDETERMINATE', reason='APP_CONTAINER_EXCLUSION_UNPROVEN')
    data.update(update)
    return NativePeerAuditResult(**data)


def peer_violation(reason='TOKEN_IDENTITY_MISMATCH'):
    return NativePeerAuditResult(status='VIOLATIONS', reason=reason)


def test_matching_native_evidence_still_cannot_admit():
    result = evaluate_native_peer_admission(lease=native_lease(), peer=peer_unproven())
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'APP_CONTAINER_EXCLUSION_UNPROVEN'
    assert not result.admission_granted
    assert not result.authorization_granted
    assert not result.grants_evaluated
    assert not result.signing_evaluated


def test_fake_process_lease_cannot_be_promoted_to_native_admission():
    result = evaluate_native_peer_admission(lease=fake_lease(), peer=peer_unproven())
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'NATIVE_PROCESS_LEASE_REQUIRED'
    assert not result.admission_granted


@pytest.mark.parametrize(
    'status,reason',
    [
        ('INDETERMINATE', 'ABORTED'),
        ('INDETERMINATE', 'PROCESS_CORRELATION_FAILED'),
    ],
)
def test_noncorrelated_native_lease_is_denied(status, reason):
    result = evaluate_native_peer_admission(
        lease=native_lease(status=status, reason=reason),
        peer=peer_unproven(),
    )
    assert result.status == 'DENIED'
    assert result.reason == 'PROCESS_LEASE_NOT_CORRELATED'
    assert not result.admission_granted


@pytest.mark.parametrize(
    'reason',
    [
        'TOKEN_IDENTITY_MISMATCH',
        'PROCESS_CORRELATION_MISMATCH',
        'ENDPOINT_CORRELATION_MISMATCH',
        'DESCRIPTOR_CHANGED',
        'APP_CONTAINER_DENIED',
        'RESTRICTED_CONTEXT_DENIED',
        'INTEGRITY_LEVEL_DENIED',
        'TOKEN_PROFILE_DENIED',
    ],
)
def test_peer_policy_violation_stays_denied(reason):
    result = evaluate_native_peer_admission(
        lease=native_lease(),
        peer=peer_violation(reason),
    )
    assert result.status == 'DENIED'
    assert result.reason == reason
    assert not result.admission_granted


@pytest.mark.parametrize(
    'reason',
    [
        'NATIVE_CAPTURE_REQUIRED',
        'CAPTURE_UNAVAILABLE',
        'APP_CONTAINER_EXCLUSION_UNPROVEN',
        'INVALID_RECORD',
    ],
)
def test_indeterminate_peer_evidence_never_admits(reason):
    result = evaluate_native_peer_admission(
        lease=native_lease(),
        peer=NativePeerAuditResult(status='INDETERMINATE', reason=reason),
    )
    assert result.status == 'INDETERMINATE'
    assert result.reason == reason
    assert not result.admission_granted


def test_invalid_record_type_fails_closed():
    result = evaluate_native_peer_admission(lease={'status': 'CORRELATED'}, peer=peer_unproven())
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'INVALID_ADMISSION_EVIDENCE'
    assert not result.admission_granted


def test_output_schema_has_no_admitted_state():
    schema = type(evaluate_native_peer_admission(lease=native_lease(), peer=peer_unproven())).model_json_schema()
    status_schema = schema['properties']['status']
    assert set(status_schema['enum']) == {'DENIED', 'INDETERMINATE'}
    assert 'ADMITTED' not in status_schema['enum']
