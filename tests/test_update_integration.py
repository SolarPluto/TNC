from datetime import timedelta
from types import SimpleNamespace
import builtins
import sqlite3

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update, locator
from test_update_verification import signed
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.update_verification import CommittedSignatureBinding
from tnc.provenance.update_integration import (
    AuthenticatedUpdateEvaluator, UpdateEvaluationRequest, UpdatePermissionSnapshot,
    UpdateProviderSnapshot, ArchivedUpdateSignature, SyntheticUpdateObservations, UpdateEvaluationResult,
    decode_update_evaluation_request,
)


class Identity:
    def __init__(self):
        self.value = VerifiedIdentity(principal_id='installer', credential_id='9'*64, method='mtls',
            connection_id='connection-1', verified_at=NOW, valid_until=NOW+timedelta(hours=1),
            registry_revision=3, audit_id='audit-1')
        self.calls = 0
        self.after = None
    def verify(self):
        self.calls += 1
        if self.after and self.calls > 1: return self.after
        return self.value


class Permissions:
    def __init__(self, signed):
        self.value = UpdatePermissionSnapshot(principal_id='installer', credential_id='9'*64, registry_revision=3,
            revision=4, deployment_id=signed['intent'].deployment_id, operation_id=signed['intent'].operation_id,
            permissions=('UPDATE_EVALUATE','UPDATE_RECOVER_OWN'), valid_from=NOW, valid_until=NOW+timedelta(hours=1))
        self.calls = 0
        self.current = True
    def resolve(self, *args):
        self.calls += 1
        return self.value
    def is_current(self, value): return self.current


class Snapshots:
    def __init__(self, update, signed):
        self.value = UpdateProviderSnapshot(revision=5, deployment_id=signed['intent'].deployment_id,
            operation_id=signed['intent'].operation_id, head=update['head'], trust_store=signed['store'],
            trust_checkpoint=signed['checkpoint'], registered_signature=signed['envelope'],
            valid_from=NOW, valid_until=NOW+timedelta(hours=1))
        self.calls = 0
        self.current = True
    def read(self, *args):
        self.calls += 1
        return self.value
    def is_current(self, value): return self.current


class Observations:
    def __init__(self, update, signed):
        self.preparation = update['preparation'].model_copy(update={'intent_hash':record_digest(signed['intent'])})
        self.drain = update['drain'].model_copy(update={'intent_hash':record_digest(signed['intent'])})
        self.calls = 0
        self.hook = None
    def observe(self, intent, action, snapshot):
        self.calls += 1
        if self.hook: self.hook()
        if action=='PUBLISH': return SyntheticUpdateObservations(locator=locator(snapshot.head))
        return SyntheticUpdateObservations(preparation=self.preparation, drain=self.drain if action=='COMMIT' else None)


@pytest.fixture
def host(update, signed):
    identity, permissions = Identity(), Permissions(signed)
    snapshots, observations = Snapshots(update, signed), Observations(update, signed)
    clock = [NOW]
    evaluator = AuthenticatedUpdateEvaluator(identity, permissions, snapshots, observations, clock=lambda:clock[0])
    request = UpdateEvaluationRequest(action='REGISTER', intent=signed['intent'], signature=signed['envelope'])
    return SimpleNamespace(identity=identity, permissions=permissions, snapshots=snapshots, observations=observations,
                           evaluator=evaluator, request=request, clock=clock)


def step(host, action):
    result = host.evaluator.evaluate(host.request.model_copy(update={'action':action}))
    assert result.status=='EVALUATED', result
    return result


def prepared(host):
    registered = step(host, 'REGISTER')
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':registered.proposal.operation})
    result = step(host, 'PREPARE')
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':result.proposal.operation})
    return result


def committed(host, signed):
    prepared(host)
    result = step(host, 'COMMIT')
    receipt = result.proposal.operation.receipt
    archive = ArchivedUpdateSignature(signature=signed['envelope'], trust_store=signed['store'], trust_checkpoint=signed['checkpoint'],
        binding=CommittedSignatureBinding(deployment_id=signed['intent'].deployment_id, receipt_hash=record_digest(receipt),
            signature_envelope_hash=record_digest(signed['envelope']), trust_checkpoint_hash=record_digest(signed['checkpoint'])))
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':result.proposal.operation,
        'head':result.proposal.proposed_head, 'archive':archive})
    return result


def test_real_signature_and_separate_transport_identity(host):
    before = canonical_bytes(host.snapshots.value)
    result = step(host, 'REGISTER')
    assert result.audit_only and result.signature_mode=='CURRENT'
    assert result.proposal.operation.stage=='REGISTERED'
    assert host.identity.value.credential_id != host.request.intent.signer_key_hash
    assert host.identity.calls==2 and host.snapshots.calls==1
    assert canonical_bytes(host.snapshots.value)==before


def test_complete_read_only_proposal_flow(host, signed):
    commit = committed(host, signed)
    assert commit.proposal.operation.stage=='COMMITTED'
    assert step(host,'PUBLISH').proposal.operation.stage=='PUBLISHED'
    recovered = step(host, 'RECOVER')
    assert recovered.signature_mode=='HISTORICAL'
    assert recovered.proposal.operation.receipt==commit.proposal.operation.receipt


@pytest.mark.parametrize('field,value', [('principal_id','other'), ('valid_until',NOW), ('verified_at',NOW+timedelta(seconds=1))])
def test_live_identity_denied_before_state_read(host, field, value):
    host.identity.value = host.identity.value.model_copy(update={field:value})
    result = host.evaluator.evaluate(host.request)
    assert result.reason_code=='ACCESS_DENIED' and host.snapshots.calls==0


@pytest.mark.parametrize('field,value', [('permissions',()), ('credential_id','e'*64), ('registry_revision',2),
    ('deployment_id','other'), ('operation_id','other'), ('principal_id','other'), ('valid_until',NOW)])
def test_permission_scope_before_lookup(host, field, value):
    host.permissions.value = host.permissions.value.model_copy(update={field:value})
    assert host.evaluator.evaluate(host.request).reason_code=='ACCESS_DENIED'
    assert host.snapshots.calls==0


def test_generic_host_manage_is_not_installer_permission(host):
    host.permissions.value = host.permissions.value.model_copy(update={'permissions':('host.manage',)})
    assert host.evaluator.evaluate(host.request).reason_code=='ACCESS_DENIED'
    assert host.snapshots.calls==0


@pytest.mark.parametrize('field', ['identity','authority','head','preparation','drain','trust_checkpoint'])
def test_client_cannot_inject_host_evidence(host, field):
    with pytest.raises(ValueError):
        UpdateEvaluationRequest.model_validate(host.request.model_dump() | {field:{}})


def test_invalid_signature_no_observation_or_proposal(host):
    request = host.request.model_copy(update={'signature':host.request.signature.model_copy(update={'signature_hex':'00'*64})})
    result = host.evaluator.evaluate(request)
    assert result.reason_code=='SIGNATURE_REJECTED' and result.proposal is None and host.observations.calls==0


def test_revoked_key_blocks_new_evaluation(host):
    snapshot = host.snapshots.value
    store = snapshot.trust_store.model_copy(update={'revision':2, 'revoked_key_ids':(host.request.intent.signer_key_hash,)})
    checkpoint = snapshot.trust_checkpoint.model_copy(update={'revision':2, 'trust_store_hash':record_digest(store)})
    host.snapshots.value = snapshot.model_copy(update={'trust_store':store, 'trust_checkpoint':checkpoint})
    assert host.evaluator.evaluate(host.request).reason_code=='SIGNATURE_REJECTED'


@pytest.mark.parametrize('field,value', [('operation_id','other'), ('deployment_id','other'), ('valid_until',NOW)])
def test_invalid_provider_scope(host, field, value):
    host.snapshots.value = host.snapshots.value.model_copy(update={field:value})
    assert host.evaluator.evaluate(host.request).reason_code=='UNAVAILABLE'


def test_trust_snapshot_hash_mismatch(host):
    checkpoint = host.snapshots.value.trust_checkpoint.model_copy(update={'trust_store_hash':'f'*64})
    host.snapshots.value = host.snapshots.value.model_copy(update={'trust_checkpoint':checkpoint})
    assert host.evaluator.evaluate(host.request).reason_code=='UNAVAILABLE'


@pytest.mark.parametrize('provider', ['permissions','snapshots'])
def test_provider_change_during_observation_discards_proposal(host, provider):
    registered = step(host,'REGISTER')
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':registered.proposal.operation})
    host.observations.hook = lambda:setattr(getattr(host,provider), 'current', False)
    result = host.evaluator.evaluate(host.request.model_copy(update={'action':'PREPARE'}))
    assert result.reason_code=='STALE_CONTEXT' and result.proposal is None


def test_transport_registry_changes_before_release(host):
    host.identity.after = host.identity.value.model_copy(update={'registry_revision':4})
    assert host.evaluator.evaluate(host.request).reason_code=='STALE_CONTEXT'


def test_expiry_during_observation_discards_proposal(host):
    registered = step(host,'REGISTER')
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':registered.proposal.operation})
    host.observations.hook = lambda:host.clock.__setitem__(0, NOW+timedelta(minutes=31))
    result = host.evaluator.evaluate(host.request.model_copy(update={'action':'PREPARE'}))
    assert result.reason_code=='STALE_CONTEXT' and result.proposal is None


def test_stale_expected_authority_head_rejected(host):
    host.snapshots.value = host.snapshots.value.model_copy(update={'head':host.snapshots.value.head.model_copy(update={'sequence':99})})
    assert host.evaluator.evaluate(host.request).reason_code=='TRANSITION_REJECTED'


def test_drain_failure_never_proposes_commit(host):
    prepared(host)
    host.observations.drain = host.observations.drain.model_copy(update={'processes_terminated':False})
    result = host.evaluator.evaluate(host.request.model_copy(update={'action':'COMMIT'}))
    assert result.reason_code=='TRANSITION_REJECTED' and result.proposal is None


def test_false_freshness_value_cannot_be_coerced(host):
    host.snapshots.current = 1
    assert host.evaluator.evaluate(host.request).reason_code=='STALE_CONTEXT'


def test_backwards_clock_is_rejected(host):
    registered = step(host,'REGISTER')
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':registered.proposal.operation})
    host.observations.hook = lambda:host.clock.__setitem__(0, NOW-timedelta(seconds=1))
    assert host.evaluator.evaluate(host.request.model_copy(update={'action':'PREPARE'})).reason_code=='STALE_CONTEXT'


def test_conflicting_intent_is_generic_denial(host):
    registered = step(host,'REGISTER')
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':registered.proposal.operation})
    changed = host.request.intent.model_copy(update={'expected_head_sequence':123})
    assert host.evaluator.evaluate(host.request.model_copy(update={'intent':changed})).reason_code=='ACCESS_DENIED'


def test_foreign_operation_and_missing_operation_have_same_response(host):
    registered = step(host,'REGISTER')
    request = host.request.model_copy(update={'action':'RECOVER'})
    missing = host.evaluator.evaluate(request)
    foreign = registered.proposal.operation.model_copy(update={'intent':host.request.intent.model_copy(update={'publisher_id':'other'})})
    host.snapshots.value = host.snapshots.value.model_copy(update={'existing':foreign})
    denied = host.evaluator.evaluate(request)
    assert canonical_bytes(missing)==canonical_bytes(denied)


def test_own_recovery_permission_required_for_receipt(host, signed):
    committed(host,signed)
    host.permissions.value = host.permissions.value.model_copy(update={'permissions':('UPDATE_EVALUATE',)})
    assert host.evaluator.evaluate(host.request).reason_code=='ACCESS_DENIED'
    assert host.evaluator.evaluate(host.request.model_copy(update={'action':'RECOVER'})).reason_code=='ACCESS_DENIED'


def test_exact_commit_retry_uses_recorded_evidence(host, signed):
    original = committed(host,signed)
    calls = host.observations.calls
    retry = step(host,'COMMIT')
    assert retry.proposal.status=='RECOVERED' and retry.proposal.proposed_head is None
    assert retry.proposal.operation.receipt==original.proposal.operation.receipt
    assert host.observations.calls==calls


def test_rotated_transport_credential_recovers_archival_receipt(host, signed):
    original = committed(host,signed)
    host.identity.value = host.identity.value.model_copy(update={'credential_id':'8'*64,'registry_revision':4})
    host.permissions.value = host.permissions.value.model_copy(update={'credential_id':'8'*64,'registry_revision':4})
    store = host.snapshots.value.trust_store
    store = store.model_copy(update={'revision':2,'keys':(store.keys[0].model_copy(update={'state':'RETIRED'}),)})
    cp = host.snapshots.value.trust_checkpoint.model_copy(update={'revision':2,'trust_store_hash':record_digest(store)})
    host.snapshots.value = host.snapshots.value.model_copy(update={'trust_store':store,'trust_checkpoint':cp})
    retry = step(host,'RECOVER')
    assert retry.signature_mode=='HISTORICAL' and retry.proposal.operation.receipt==original.proposal.operation.receipt


def test_archive_binding_missing_blocks_recovery(host, signed):
    committed(host,signed)
    host.snapshots.value = host.snapshots.value.model_copy(update={'archive':None})
    assert host.evaluator.evaluate(host.request.model_copy(update={'action':'RECOVER'})).reason_code=='UNAVAILABLE'


def test_archive_binding_tampering_blocks_recovery(host, signed):
    committed(host,signed)
    archive = host.snapshots.value.archive
    archive = archive.model_copy(update={'binding':archive.binding.model_copy(update={'receipt_hash':'f'*64})})
    host.snapshots.value = host.snapshots.value.model_copy(update={'archive':archive})
    assert host.evaluator.evaluate(host.request.model_copy(update={'action':'RECOVER'})).reason_code=='SIGNATURE_REJECTED'


def test_recovery_cannot_inject_replacement_signature(host, signed):
    committed(host,signed)
    request = host.request.model_copy(update={'action':'RECOVER',
        'signature':host.request.signature.model_copy(update={'signature_hex':'00'*64})})
    assert host.evaluator.evaluate(request).reason_code=='ACCESS_DENIED'


def test_provider_exception_does_not_leak_message(host):
    def fail(*a): raise OSError('secret path and receipt')
    host.snapshots.read = fail
    result = host.evaluator.evaluate(host.request)
    assert result.reason_code=='UNAVAILABLE' and b'secret' not in canonical_bytes(result)


def test_no_file_or_sqlite_write_path(host, monkeypatch):
    def forbidden(*a, **kw): pytest.fail('Unexpected I/O')
    monkeypatch.setattr(builtins,'open',forbidden)
    monkeypatch.setattr(sqlite3,'connect',forbidden)
    step(host,'REGISTER')


def test_canonical_request_bound(host):
    data = canonical_bytes(host.request)
    assert decode_update_evaluation_request(data)==host.request
    with pytest.raises(ValueError): decode_update_evaluation_request(data+b' ')
    with pytest.raises(ValueError): decode_update_evaluation_request(b' '*(1024*1024+1))


def test_audit_only_cannot_be_disabled(host):
    result = step(host,'REGISTER')
    with pytest.raises(ValueError): UpdateEvaluationResult.model_validate(result.model_dump() | {'audit_only':False})
