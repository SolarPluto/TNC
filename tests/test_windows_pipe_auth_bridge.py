"""Pure audit bridge tests. Native-shaped fixtures are not OS attestations."""
import pytest
from tnc.provenance.windows_pipe_auth_bridge import *
from tnc.provenance.windows_pipe_token import CapturedTokenFacts, TokenCaptureResult
from tnc.provenance.windows_custody_peer import PipeACE, CLIENT_RIGHTS, SERVICE_RIGHTS


def change(value, **updates):
    return type(value).model_validate({**value.model_dump(), **updates})


@pytest.fixture
def inputs():
    process = PeerProcess(pid=123, creation_filetime=1000, session_id=2, running=True)
    identity = WindowsPeerPolicy(deployment_id='deployment', store_instance_id='store',
        pipe_name=r'\\.\pipe\TNC-test', service_sid='S-1-5-80-100', client_sid='S-1-5-21-200',
        logon_sid='S-1-5-5-300-400', authentication_id=42,
        expected_process=process, timestamp=100, expiry=200)
    policy = NativePeerAuditPolicy(identity=identity)
    facts = CapturedTokenFacts(user_sid=identity.client_sid, logon_sid=identity.logon_sid,
        authentication_id=42, token_id=8, modified_id=9, session_id=2,
        level='IDENTIFICATION', integrity_rid=8192, has_restrictions=False,
        restricted_sids_present=False, app_container_reported=False)
    capture = TokenCaptureResult(status='CAPTURED', reason='AUDIT_CAPTURE_ONLY',
        source='NATIVE_TOKEN_API', facts=facts, operation_id='read-1', preamble_digest='a'*64)
    endpoint = PipeEndpoint(name=identity.pipe_name, server_end=True, local=True)
    security = PipeSecurityObservation(owner_sid=identity.service_sid, protected_dacl=True,
        aces=(PipeACE(sid=identity.service_sid, mask=SERVICE_RIGHTS),
              PipeACE(sid=identity.client_sid, mask=CLIENT_RIGHTS)))
    correlation = PeerCorrelationAudit(deployment_id='deployment', store_instance_id='store',
        process_before=process, process_after=process, endpoint_before=endpoint, endpoint_after=endpoint,
        security_before=security, security_after=security, observed_at=110)
    return policy, capture, correlation, PeerReadBinding(operation_id='read-1', preamble_digest='a'*64)


def evaluate(inputs, **updates):
    policy, capture, correlation, retained = inputs
    return WindowsPipeAuthBridge(updates.get('policy', policy)).evaluate_native_peer(
        updates.get('capture', capture), updates.get('correlation', correlation),
        retained_read=updates.get('retained', retained), now=updates.get('now', 120))


def test_matching_claims_preserve_uncertainty(inputs):
    result = evaluate(inputs)
    assert result.status == 'INDETERMINATE' and result.reason == 'APP_CONTAINER_EXCLUSION_UNPROVEN'
    assert result.audit_only and not result.authorization_granted and not result.grants_evaluated


@pytest.mark.parametrize('field,value,reason', [
    ('app_container_reported', True, 'APP_CONTAINER_DENIED'),
    ('has_restrictions', True, 'RESTRICTED_CONTEXT_DENIED'),
    ('restricted_sids_present', True, 'RESTRICTED_CONTEXT_DENIED'),
    ('integrity_rid', 4096, 'INTEGRITY_LEVEL_DENIED'),
    ('integrity_rid', 8191, 'INTEGRITY_LEVEL_DENIED'),
    ('level', 'IMPERSONATION', 'TOKEN_PROFILE_DENIED'),
    ('level', 'DELEGATION', 'TOKEN_PROFILE_DENIED'),
    ('user_sid', 'S-1-5-21-999', 'TOKEN_IDENTITY_MISMATCH'),
    ('logon_sid', 'S-1-5-5-1-2', 'TOKEN_IDENTITY_MISMATCH'),
    ('authentication_id', 43, 'TOKEN_IDENTITY_MISMATCH'),
    ('session_id', 3, 'TOKEN_IDENTITY_MISMATCH'),
])
def test_token_denials(inputs, field, value, reason):
    capture = change(inputs[1], facts=change(inputs[1].facts, **{field:value}))
    assert evaluate(inputs, capture=capture).reason == reason


@pytest.mark.parametrize('field,value', [('pid',124), ('creation_filetime',1001), ('session_id',3), ('running',False)])
def test_process_correlation_changes(inputs, field, value):
    correlation = change(inputs[2], process_after=change(inputs[2].process_after, **{field:value}))
    assert evaluate(inputs, correlation=correlation).reason == 'PROCESS_CORRELATION_MISMATCH'


def test_stable_wrong_process_is_not_accepted(inputs):
    process = change(inputs[2].process_after, creation_filetime=1001)
    correlation = change(inputs[2], process_before=process, process_after=process)
    assert evaluate(inputs, correlation=correlation).reason == 'PROCESS_LIFETIME_MISMATCH'


@pytest.mark.parametrize('field,value', [('local',False), ('server_end',False), ('name',r'\\.\pipe\TNC-other')])
def test_endpoint_changes(inputs, field, value):
    correlation = change(inputs[2], endpoint_after=change(inputs[2].endpoint_after, **{field:value}))
    assert evaluate(inputs, correlation=correlation).reason == 'ENDPOINT_CORRELATION_MISMATCH'


@pytest.mark.parametrize('field,value', [('owner_sid','S-1-5-21-999'), ('protected_dacl',False), ('aces',())])
def test_stable_wrong_descriptor(inputs, field, value):
    security = change(inputs[2].security_after, **{field:value})
    correlation = change(inputs[2], security_before=security, security_after=security)
    assert evaluate(inputs, correlation=correlation).reason == 'DESCRIPTOR_MISMATCH'


def test_changed_descriptor(inputs):
    correlation = change(inputs[2], security_after=change(inputs[2].security_after, protected_dacl=False))
    assert evaluate(inputs, correlation=correlation).reason == 'DESCRIPTOR_CHANGED'


@pytest.mark.parametrize('field', ['deployment_id','store_instance_id'])
def test_scope_mismatch(inputs, field):
    assert evaluate(inputs, correlation=change(inputs[2], **{field:'other'})).reason == 'SCOPE_MISMATCH'


@pytest.mark.parametrize('now', [True, -1, 1.5, 2**63])
def test_invalid_clocks(inputs, now):
    assert evaluate(inputs, now=now).reason == 'INVALID_RECORD'


@pytest.mark.parametrize('now', [109, 200, 201])
def test_time_window(inputs, now):
    assert evaluate(inputs, now=now).reason == 'TIME_MISMATCH'


@pytest.mark.parametrize('field,value', [('operation_id','other'), ('preamble_digest','b'*64)])
def test_exact_read_binding(inputs, field, value):
    assert evaluate(inputs, retained=change(inputs[3], **{field:value})).reason == 'READ_BINDING_MISMATCH'


def test_fake_source_is_not_relabelled(inputs):
    assert evaluate(inputs, capture=change(inputs[1], source='FAKE_TOKEN_API')).reason == 'NATIVE_CAPTURE_REQUIRED'


@pytest.mark.parametrize('updates', [{'facts':None}, {'status':'INDETERMINATE'}, {'reason':'OTHER'}])
def test_missing_capture(inputs, updates):
    assert evaluate(inputs, capture=change(inputs[1], **updates)).reason == 'CAPTURE_UNAVAILABLE'


def test_forged_nested_scalar_revalidated(inputs):
    facts = inputs[1].facts.model_copy(update={'integrity_rid':True})
    assert evaluate(inputs, capture=inputs[1].model_copy(update={'facts':facts})).reason == 'INVALID_RECORD'


def test_no_methods_or_username_resolution(inputs):
    class Untrusted:
        def __getattr__(self, name):
            raise AssertionError('Untrusted object invoked')
    assert evaluate(inputs, capture=Untrusted()).reason == 'INVALID_RECORD'


def test_explicit_stronger_integrity_floor(inputs):
    assert evaluate(inputs, policy=change(inputs[0], minimum_integrity_rid=12288)).reason == 'INTEGRITY_LEVEL_DENIED'
    with pytest.raises(ValueError):
        change(inputs[0], minimum_integrity_rid=4096)


def test_audit_records_frozen_and_no_side_effects(inputs, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('External side effect')
    for target in ('builtins.open','socket.socket','sqlite3.connect','time.time','ctypes.WinDLL'):
        monkeypatch.setattr(target, forbidden, raising=False)
    result = evaluate(inputs)
    assert result.status == 'INDETERMINATE'
    with pytest.raises(ValueError):
        result.authorization_granted = True
