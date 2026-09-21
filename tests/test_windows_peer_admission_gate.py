"""Pure fail-closed tests for native peer admission composition."""
import pytest
from pydantic import TypeAdapter

from tnc.provenance.windows_peer_admission_gate import (
    LEGAL_RESULT_PAIRS,
    AdmissionEvaluatorInvariantError,
    NativePeerAdmissionResult,
    evaluate_native_peer_admission,
)
from tnc.provenance.windows_pipe_auth_bridge import (
    NATIVE_PEER_AUDIT_RESULT_PAIRS,
    NativePeerAuditResult,
)
from tnc.provenance.windows_pipe_context_producer import PipePeerAdmissionEvidence
from tnc.provenance.windows_pipe_process_lease import ProcessLeaseAudit


_PIPE_CONTEXT = TypeAdapter(PipePeerAdmissionEvidence)
_BINDING = dict(
    connection_operation_id='connect-op',
    pipe_lease_id='pipe-lease',
    process_lease_operation_id='process-lease',
    process_pid=1234,
    process_creation_filetime=5678,
    capture_ordinal=1,
)
_NON_APPCONTAINER_EVIDENCE = dict(
    source='FAKE_TOKEN_API',
    token_type='IMPERSONATION',
    level='IMPERSONATION',
    token_is_app_container=False,
    app_container_sid=None,
    capability_sids=(),
)
_APPCONTAINER_EVIDENCE = dict(
    source='FAKE_TOKEN_API',
    token_type='IMPERSONATION',
    level='IMPERSONATION',
    token_is_app_container=True,
    app_container_sid='S-1-15-2-1',
    capability_sids=(),
)

PIPE_CONTEXT_CASES = (
    ('CAPTURED_APPCONTAINER', ('DENIED', 'APP_CONTAINER_DENIED')),
    ('CAPTURED_NON_APPCONTAINER', ('INDETERMINATE', 'PEER_ADMISSION_NOT_IMPLEMENTED')),
    ('CAPTURED_CLASSIFICATION_CONFLICT', ('INDETERMINATE', 'PIPE_CONTEXT_CLASSIFICATION_CONFLICT')),
    ('CAPTURED_CLASSIFICATION_UNAVAILABLE', ('INDETERMINATE', 'PEER_EVIDENCE_UNAVAILABLE')),
    ('CAPTURE_UNAVAILABLE', ('INDETERMINATE', 'PEER_EVIDENCE_UNAVAILABLE')),
)

def pipe_context(status):
    data = dict(_BINDING, status=status)
    if status == 'CAPTURED_NON_APPCONTAINER':
        data.update(classification_source='PIPE_TOKEN', evidence=_NON_APPCONTAINER_EVIDENCE)
    elif status == 'CAPTURED_APPCONTAINER':
        data.update(classification_source='PIPE_TOKEN', evidence=_APPCONTAINER_EVIDENCE)
    elif status == 'CAPTURED_CLASSIFICATION_CONFLICT':
        data.update(
            classification_source='PIPE_TOKEN',
            reason='APPCONTAINER_SIGNAL_CONFLICT',
        )
    elif status == 'CAPTURED_CLASSIFICATION_UNAVAILABLE':
        data.update(
            classification_source='PIPE_TOKEN',
            failure_scope='SERVER_CLASSIFICATION',
            information_class=29,
            failure_reason='QUERY_29_FAILED_5',
            winerror=5,
        )
    elif status == 'CAPTURE_UNAVAILABLE':
        data.update(
            failure_scope='CAPTURE',
            failed_stage='OPEN_THREAD_TOKEN',
            winerror=5,
        )
    else:
        raise AssertionError(status)
    return _PIPE_CONTEXT.validate_python(data)


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


def evaluate(*, lease=None, peer=None, status='CAPTURED_NON_APPCONTAINER'):
    return evaluate_native_peer_admission(
        lease=native_lease() if lease is None else lease,
        peer=peer_unproven() if peer is None else peer,
        pipe_context=pipe_context(status),
    )


def test_matching_native_evidence_reaches_procedural_terminal_state():
    result = evaluate()
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'PEER_ADMISSION_NOT_IMPLEMENTED'
    assert not result.admission_granted
    assert not result.authorization_granted
    assert not result.grants_evaluated
    assert not result.signing_evaluated


def test_fake_process_lease_cannot_be_promoted_to_native_admission():
    result = evaluate(lease=fake_lease())
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
    result = evaluate(lease=native_lease(status=status, reason=reason))
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
    result = evaluate(peer=peer_violation(reason))
    assert result.status == 'DENIED'
    assert result.reason == reason
    assert not result.admission_granted


@pytest.mark.parametrize(
    'reason',
    [
        'NATIVE_CAPTURE_REQUIRED',
        'INVALID_RECORD',
    ],
)
def test_indeterminate_peer_evidence_never_admits(reason):
    result = evaluate(
        peer=NativePeerAuditResult(status='INDETERMINATE', reason=reason),
    )
    assert result.status == 'INDETERMINATE'
    assert result.reason == reason
    assert not result.admission_granted


def test_bridge_capture_unavailable_maps_to_peer_evidence_unavailable():
    result = evaluate(
        peer=NativePeerAuditResult(
            status='INDETERMINATE',
            reason='CAPTURE_UNAVAILABLE',
        ),
    )
    assert (result.status, result.reason) == (
        'INDETERMINATE',
        'PEER_EVIDENCE_UNAVAILABLE',
    )


@pytest.mark.parametrize('status,reason', sorted(NATIVE_PEER_AUDIT_RESULT_PAIRS))
def test_every_bridge_result_maps_to_expected_evaluator_result(status, reason):
    result = evaluate(peer=NativePeerAuditResult(status=status, reason=reason))
    if status == 'VIOLATIONS':
        expected = ('DENIED', reason)
    elif reason == 'CAPTURE_UNAVAILABLE':
        expected = ('INDETERMINATE', 'PEER_EVIDENCE_UNAVAILABLE')
    elif reason == 'APP_CONTAINER_EXCLUSION_UNPROVEN':
        expected = ('INDETERMINATE', 'PEER_ADMISSION_NOT_IMPLEMENTED')
    else:
        expected = ('INDETERMINATE', reason)
    assert (result.status, result.reason) == expected
    assert (result.status, result.reason) in LEGAL_RESULT_PAIRS


@pytest.mark.parametrize('status,expected', PIPE_CONTEXT_CASES)
def test_every_pipe_context_variant_is_fail_closed_and_legal(status, expected):
    result = evaluate(status=status)
    assert (result.status, result.reason) == expected
    assert (result.status, result.reason) in LEGAL_RESULT_PAIRS
    assert not result.admission_granted
    assert not result.authorization_granted


def test_fail_closed_matrix_covers_every_pipe_context_variant():
    mapping = _PIPE_CONTEXT.json_schema()['discriminator']['mapping']
    assert set(mapping) == {status for status, _ in PIPE_CONTEXT_CASES}


def test_appcontainer_hard_exclusion_precedes_peer_identity_denial():
    result = evaluate(
        peer=peer_violation('TOKEN_IDENTITY_MISMATCH'),
        status='CAPTURED_APPCONTAINER',
    )
    assert (result.status, result.reason) == ('DENIED', 'APP_CONTAINER_DENIED')


def test_existing_peer_denial_precedes_capture_unavailability():
    result = evaluate(
        peer=peer_violation('TOKEN_IDENTITY_MISMATCH'),
        status='CAPTURE_UNAVAILABLE',
    )
    assert (result.status, result.reason) == ('DENIED', 'TOKEN_IDENTITY_MISMATCH')


def test_pipe_context_unavailability_replaces_old_exclusion_blocker():
    result = evaluate(status='CAPTURED_CLASSIFICATION_UNAVAILABLE')
    assert (result.status, result.reason) == ('INDETERMINATE', 'PEER_EVIDENCE_UNAVAILABLE')


def test_invalid_record_type_fails_closed():
    result = evaluate_native_peer_admission(
        lease={'status': 'CORRELATED'},
        peer=peer_unproven(),
        pipe_context=pipe_context('CAPTURED_NON_APPCONTAINER'),
    )
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'INVALID_ADMISSION_EVIDENCE'
    assert not result.admission_granted


def test_capture_unavailable_is_not_an_evaluator_reason():
    assert ('INDETERMINATE', 'CAPTURE_UNAVAILABLE') not in LEGAL_RESULT_PAIRS


def test_retired_appcontainer_unproven_pair_is_illegal():
    assert ('INDETERMINATE', 'APP_CONTAINER_EXCLUSION_UNPROVEN') not in LEGAL_RESULT_PAIRS
    with pytest.raises(ValueError, match='illegal admission result pair'):
        NativePeerAdmissionResult(
            status='INDETERMINATE',
            reason='APP_CONTAINER_EXCLUSION_UNPROVEN',
        )


def test_internal_result_validation_failure_is_not_reclassified_as_bad_evidence(monkeypatch):
    import tnc.provenance.windows_peer_admission_gate as gate

    class BrokenResult:
        def __init__(self, **kwargs):
            raise ValueError('internal result bug')

    monkeypatch.setattr(gate, 'NativePeerAdmissionResult', BrokenResult)
    with pytest.raises(AdmissionEvaluatorInvariantError, match='illegal evaluator output'):
        evaluate(status='CAPTURED_APPCONTAINER')


def test_output_schema_has_no_admitted_state():
    schema = type(evaluate()).model_json_schema()
    status_schema = schema['properties']['status']
    assert set(status_schema['enum']) == {'DENIED', 'INDETERMINATE'}
    assert 'ADMITTED' not in status_schema['enum']
