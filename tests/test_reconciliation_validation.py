from datetime import timedelta
import builtins
from hashlib import sha256
import sqlite3

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update, locator
from test_update_verification import signed
from test_update_integration import host
from test_update_storage_validation import stored, image_from, checkpoint
from tnc.provenance.authorization_models import ZERO, canonical_bytes, record_digest
from tnc.provenance.update_storage_models import StoredLocatorPublication
from tnc.provenance.update_storage_validation import update_storage_event_hash
from tnc.provenance.reconciliation_models import (
    RECONCILIATION_LIMIT, ReconciliationEnvelope, SyntheticCheckpointEvidence, ReconciliationRequest,
    ReconciliationAcceptance, SyntheticAcceptanceEvidence, ReconciliationRelationship, ReconciliationAcceptanceResult,
)
from tnc.provenance.reconciliation_validation import (
    classify_checkpoint_relationship, verify_reconciliation_acceptance, decode_reconciliation_record,
    reconciliation_batch_digest,
)


def envelope(image):
    return ReconciliationEnvelope(deployment_id=image.deployment_id,store_instance_id='store-1',authority_revision=1,
        previous_envelope_hash=ZERO,issuer_id='checkpoint-authority',key_id='a'*64,checkpoint=checkpoint(image),
        valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(hours=1))


def freshness(value):
    return SyntheticCheckpointEvidence(deployment_id=value.deployment_id,store_instance_id=value.store_instance_id,
        current_authority_revision=value.authority_revision,current_envelope_hash=record_digest(value),
        valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(hours=1))


def classify(image,value,evidence=None,now=NOW,store='store-1'):
    return classify_checkpoint_relationship(image,value,observed_store_instance_id=store,
        evidence=evidence if evidence is not None else freshness(value),now=now)


@pytest.fixture
def reconciliation(stored):
    prefix=image_from(stored[0],stored[1][:1]); image=image_from(*stored)
    before=envelope(prefix)
    batch=reconciliation_batch_digest(image.events[1:])
    request=ReconciliationRequest(request_id='request-1',principal_id='reconciler',deployment_id=image.deployment_id,
        store_instance_id='store-1',expected_authority_revision=1,expected_envelope_hash=record_digest(before),
        successor_checkpoint=checkpoint(image),event_batch_hash=batch,
        valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(minutes=30))
    successor=before.model_copy(update={'authority_revision':2,'previous_envelope_hash':record_digest(before),'checkpoint':checkpoint(image)})
    acceptance=ReconciliationAcceptance(acceptance_id='acceptance-1',request_id=request.request_id,request_hash=record_digest(request),
        principal_id=request.principal_id,deployment_id=image.deployment_id,store_instance_id='store-1',
        predecessor_revision=1,predecessor_hash=record_digest(before),accepted_at=NOW,successor=successor,
        event_batch_hash=batch,policy_revision=2,independent_evidence_hash='c'*64)
    evidence=SyntheticAcceptanceEvidence(deployment_id=image.deployment_id,store_instance_id='store-1',principal_id='reconciler',
        request_id=request.request_id,request_hash=record_digest(request),acceptance_hash=record_digest(acceptance),
        independent_evidence_hash='c'*64,may_recover=True,valid_from=NOW,valid_until=NOW+timedelta(hours=2))
    return prefix,image,before,request,acceptance,evidence


def test_exact_match_is_audit_only(reconciliation):
    prefix,_,before,*_=reconciliation
    result=classify(prefix,before)
    assert result.relationship=='MATCHED' and result.audit_only
    assert result.observed_image_hash==record_digest(prefix) and result.suffix_batch_hash is None


def test_extension_is_pending_not_accepted(reconciliation):
    _,image,before,request,*_=reconciliation
    result=classify(image,before)
    assert result.relationship=='DATABASE_EXTENSION_PENDING'
    assert result.suffix_batch_hash==request.event_batch_hash
    assert result.reason_code=='INDEPENDENT_ACCEPTANCE_REQUIRED'


def test_checkpoint_ahead_has_no_observed_facts(reconciliation):
    prefix,image,*_=reconciliation
    result=classify(prefix,envelope(image))
    assert result.relationship=='CHECKPOINT_AHEAD' and result.observed_event_count is None


@pytest.mark.parametrize('count',[1,2,3,4,5])
def test_every_event_kind_requires_advancement(stored,count):
    payloads=stored[1]+[StoredLocatorPublication(operation_id=stored[1][-1].operation_id,credential_id='9'*64,
        locator=locator(stored[1][-1].head))]
    before=image_from(stored[0],payloads[:count-1]); after=image_from(stored[0],payloads[:count])
    assert classify(after,envelope(before)).relationship=='DATABASE_EXTENSION_PENDING'


@pytest.mark.parametrize('field,value',[('image_hash','f'*64),('event_head_hash','f'*64),('authority_head_hash','f'*64)])
def test_equal_sequence_hash_fork(reconciliation,field,value):
    prefix,_,before,*_=reconciliation
    before=before.model_copy(update={'checkpoint':before.checkpoint.model_copy(update={field:value})})
    assert classify(prefix,before).relationship=='FORK_OR_MISMATCH'


def test_higher_sequence_does_not_prove_prefix(reconciliation):
    _,image,before,*_=reconciliation
    before=before.model_copy(update={'checkpoint':before.checkpoint.model_copy(update={'image_hash':'f'*64})})
    assert classify(image,before).reason_code=='PREFIX_MISMATCH'


def test_corrupt_suffix_cannot_be_blessed(reconciliation):
    _,image,before,*_=reconciliation
    events=image.events[:-1]+(image.events[-1].model_copy(update={'entry_hash':'f'*64}),)
    assert classify(image.model_copy(update={'events':events}),before).reason_code=='IMAGE_INVALID'


@pytest.mark.parametrize('store',['other-store',''])
def test_store_substitution(reconciliation,store):
    prefix,_,before,*_=reconciliation
    assert classify(prefix,before,store=store).reason_code=='IDENTITY_MISMATCH'


def test_deployment_substitution(reconciliation):
    prefix,_,before,*_=reconciliation
    assert classify(prefix.model_copy(update={'deployment_id':'other'}),before).reason_code=='IDENTITY_MISMATCH'


@pytest.mark.parametrize('field,value',[('current_authority_revision',2),('current_envelope_hash','f'*64),
    ('store_instance_id','other'),('deployment_id','other')])
def test_stale_or_mismatched_freshness(reconciliation,field,value):
    prefix,_,before,*_=reconciliation
    evidence=freshness(before).model_copy(update={field:value})
    assert classify(prefix,before,evidence).reason_code=='FRESHNESS_UNAVAILABLE'


def test_missing_evidence_is_not_self_derived(reconciliation):
    prefix,_,before,*_=reconciliation
    result=classify_checkpoint_relationship(prefix,before,observed_store_instance_id='store-1',evidence=None,now=NOW)
    assert result.relationship=='INDETERMINATE'


@pytest.mark.parametrize('offset',[-120,3600])
def test_validity_boundaries(reconciliation,offset):
    prefix,_,before,*_=reconciliation
    assert classify(prefix,before,now=NOW+timedelta(seconds=offset)).reason_code=='FRESHNESS_UNAVAILABLE'


def test_replayed_old_envelope_and_database_need_current_evidence(reconciliation):
    prefix,_,before,_,acceptance,_=reconciliation
    assert classify(prefix,before,freshness(acceptance.successor)).relationship=='INDETERMINATE'


def test_acceptance_binding_and_idempotent_check(reconciliation):
    *_,request,acceptance,evidence=reconciliation
    result=verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW)
    assert result.status=='VALID_BINDING' and result.audit_only
    assert result==verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW)
    assert result.acceptance_hash==record_digest(acceptance)


@pytest.mark.parametrize('field,value',[('request_id','other'),('principal_id','other'),('store_instance_id','other'),
    ('deployment_id','other'),('may_recover',False)])
def test_current_recovery_scope(reconciliation,field,value):
    *_,request,acceptance,evidence=reconciliation
    result=verify_reconciliation_acceptance(request,acceptance,evidence=evidence.model_copy(update={field:value}),now=NOW)
    assert result.reason_code=='ACCESS_DENIED' and result.acceptance_hash is None


@pytest.mark.parametrize('field,value',[('request_hash','f'*64),('acceptance_hash','f'*64),('independent_evidence_hash','f'*64)])
def test_exact_independent_binding(reconciliation,field,value):
    *_,request,acceptance,evidence=reconciliation
    result=verify_reconciliation_acceptance(request,acceptance,evidence=evidence.model_copy(update={field:value}),now=NOW)
    assert result.reason_code=='BINDING_MISMATCH'


@pytest.mark.parametrize('field,value',[('event_batch_hash','f'*64),('expected_envelope_hash','f'*64),('expected_authority_revision',2)])
def test_conflicting_request_retry(reconciliation,field,value):
    *_,request,acceptance,evidence=reconciliation
    result=verify_reconciliation_acceptance(request.model_copy(update={field:value}),acceptance,evidence=evidence,now=NOW)
    assert result.status=='REJECTED'


def test_old_acceptance_recovery_does_not_authorize_republication(reconciliation):
    *_,request,acceptance,evidence=reconciliation
    result=verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW+timedelta(minutes=90))
    assert result.status=='VALID_BINDING' and result.audit_only
    # Request and old envelope are expired now, but valid at recorded acceptance.
    assert not hasattr(result,'publish') and not hasattr(result,'successor')


def test_expired_recovery_scope_rejected(reconciliation):
    *_,request,acceptance,evidence=reconciliation
    assert verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW+timedelta(hours=2)).reason_code=='ACCESS_DENIED'


def test_future_acceptance_rejected_even_with_rebound_test_evidence(reconciliation):
    *_,request,acceptance,evidence=reconciliation
    acceptance=acceptance.model_copy(update={'accepted_at':NOW+timedelta(seconds=1)})
    evidence=evidence.model_copy(update={'acceptance_hash':record_digest(acceptance)})
    assert verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW).reason_code=='BINDING_MISMATCH'


def test_local_receipt_and_locator_cannot_substitute_for_evidence(reconciliation,stored):
    *_,request,acceptance,_=reconciliation
    for evidence in (stored[1][-1].receipt,locator(stored[1][-1].head)):
        assert verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW).status=='REJECTED'


def test_batch_domain_lengths_and_order(reconciliation):
    events=reconciliation[1].events
    expected=b'TNC-RECONCILIATION-EVENT-BATCH\x00v1\x00'+len(events).to_bytes(4,'big')
    for event in events:
        data=canonical_bytes(event); expected+=len(data).to_bytes(8,'big')+data
    assert reconciliation_batch_digest(events)==sha256(expected).hexdigest()
    assert reconciliation_batch_digest(events)!=reconciliation_batch_digest(tuple(reversed(events)))
    for invalid in ((),list(events),events*65):
        with pytest.raises(ValueError): reconciliation_batch_digest(invalid)


@pytest.mark.parametrize('mutation',['newline','duplicate','extra','version_bool','version_string','nan','timestamp'])
def test_canonical_input_rejections(reconciliation,mutation):
    value=reconciliation[2]; data=canonical_bytes(value)
    if mutation=='newline': data+=b'\n'
    elif mutation=='duplicate': data=b'{"codec_version":1,'+data[1:]
    elif mutation=='extra': data=b'{"extra":1,'+data[1:]
    elif mutation=='version_bool': data=data.replace(b'"codec_version":1',b'"codec_version":true')
    elif mutation=='version_string': data=data.replace(b'"codec_version":1',b'"codec_version":"1"')
    elif mutation=='nan': data=data.replace(b'"authority_revision":1',b'"authority_revision":NaN')
    else: data=data.replace(b'.000000Z',b'Z')
    with pytest.raises(ValueError): decode_reconciliation_record(ReconciliationEnvelope,data)


def test_size_and_type_bounds(reconciliation):
    with pytest.raises(ValueError): decode_reconciliation_record(ReconciliationEnvelope,b'x'*(RECONCILIATION_LIMIT+1))
    with pytest.raises(ValueError): decode_reconciliation_record(dict,b'{}')
    with pytest.raises(ValueError): decode_reconciliation_record(ReconciliationEnvelope,bytearray(canonical_bytes(reconciliation[2])))


def test_result_cannot_promote_authority_or_leak_blocked_facts():
    with pytest.raises(ValueError): ReconciliationRelationship(relationship='MATCHED',reason_code='EXACT_MATCH',audit_only=False)
    with pytest.raises(ValueError): ReconciliationRelationship(relationship='CHECKPOINT_AHEAD',reason_code='DATABASE_BEHIND',observed_event_count=1)
    with pytest.raises(ValueError): ReconciliationAcceptanceResult(status='REJECTED',reason_code='ACCESS_DENIED',acceptance_hash='a'*64)


def test_no_io_and_immutable_results(reconciliation,monkeypatch):
    prefix,image,before,request,acceptance,evidence=reconciliation
    original=canonical_bytes(image)
    def forbidden(*args,**kwargs): pytest.fail('Pure layer performed I/O')
    monkeypatch.setattr(builtins,'open',forbidden); monkeypatch.setattr(sqlite3,'connect',forbidden)
    a=classify(image,before); b=classify(image,before)
    assert a==b and canonical_bytes(image)==original
    assert verify_reconciliation_acceptance(request,acceptance,evidence=evidence,now=NOW).status=='VALID_BINDING'
    with pytest.raises(ValueError): a.audit_only=False


def test_empty_prefix_and_empty_exact_match(stored):
    empty=image_from(stored[0],[])
    assert classify(empty,envelope(empty)).relationship=='MATCHED'
    assert classify(image_from(*stored),envelope(empty)).relationship=='DATABASE_EXTENSION_PENDING'


def test_future_recorded_observation_is_indeterminate(stored):
    image=image_from(stored[0],stored[1][:1])
    event=image.events[0].model_copy(update={'recorded_at':NOW+timedelta(seconds=1)})
    event=event.model_copy(update={'entry_hash':update_storage_event_hash(event)})
    image=image.model_copy(update={'events':(event,)})
    assert classify(image,envelope(image)).relationship=='INDETERMINATE'


@pytest.mark.parametrize('field,value',[('predecessor_revision',5),('predecessor_hash','f'*64),('store_instance_id','other')])
def test_invalid_acceptance_successor_shape(reconciliation,field,value):
    acceptance=reconciliation[4].model_copy(update={field:value})
    with pytest.raises(ValueError): canonical_bytes(acceptance)


def test_naive_evaluation_time_rejected(reconciliation):
    prefix,_,before,*_=reconciliation
    assert classify(prefix,before,now=NOW.replace(tzinfo=None)).reason_code=='INVALID_INPUT'


def test_unauthorized_recovery_does_not_inspect_acceptance(reconciliation):
    *_,request,_,evidence=reconciliation
    evidence=evidence.model_copy(update={'may_recover':False})
    assert verify_reconciliation_acceptance(request,None,evidence=evidence,now=NOW).reason_code=='ACCESS_DENIED'
