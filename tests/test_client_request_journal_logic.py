"""Pure journal lifecycle and synthetic high-water reconciliation evidence."""
import builtins
import json
import socket
import sqlite3
import time
from hashlib import sha256
import pytest
from test_client_high_water_logic import (
    case, inventory, config, update, signed, host, stored, reconciliation, NOW,
    vector, response, client, run, successor,
)
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.client_request_journal_logic import *
import tnc.provenance.client_request_journal_logic as journal


@pytest.fixture
def setup(client):
    a,s,r=client
    intent=ClientJournalIntent(operation_id=r.operation_id,client_anchor_digest=record_digest(a),
        principal_id=a.principal_id,request=r.retained_request,trust_store=r.trust_store,
        trusted_checkpoint=r.trusted_checkpoint,created_at=a.accepted_timestamp,expires_at=r.retained_request.expiry)
    return a,s,r,intent


def register(c,image=None,intent=None,**changes):
    args=dict(trusted_client_anchor=c[0],caller_principal=c[0].principal_id,now=c[0].accepted_timestamp)
    args.update(changes)
    return register_intent(image or ClientJournalImage(),intent or c[3],**args)


def retain(c,image=None,raw=None,**changes):
    args=dict(trusted_client_anchor=c[0],caller_principal=c[0].principal_id,now=c[0].accepted_timestamp)
    args.update(changes)
    return retain_response(image or register(c).proposed_image,c[3].operation_id,
        canonical_bytes(c[2].response) if raw is None else raw,**args)


def recover(c,image=None,evidence=None,**changes):
    args=dict(trusted_client_anchor=c[0],caller_principal=c[0].principal_id,now=c[0].accepted_timestamp)
    args.update(changes)
    return evaluate_recovery(image or retain(c).proposed_image,c[3].operation_id,
        checked_high_water_state=c[1] if evidence is None else evidence,**args)


def test_register_before_dispatch_and_exact_retry(setup):
    c=setup; image=register(c).proposed_image; before=canonical_bytes(image)
    assert image.entries[0].state=='AWAITING_RESPONSE'
    assert recover(c,image).status=='AWAITING_RESPONSE'
    assert register(c,image,now=c[3].expires_at+10).status=='UNCHANGED'
    assert canonical_bytes(image)==before


def test_complete_lifecycle_unchanged_receipt(setup,client):
    c=setup; retained=retain(c).proposed_image
    ready=recover(c,retained)
    assert ready.status=='READY_TO_APPLY' and ready.advancement_request==c[2]
    committed=run(client)
    result=recover(c,retained,committed.proposed_state)
    assert result.status=='COMMITTED' and result.receipt==committed.receipt
    assert result.receipt.status=='UNCHANGED'
    assert result.proposed_image.entries[0].local_sequence==3
    assert recover(c,result.proposed_image,evidence='unavailable',now=c[3].expires_at+100).receipt==committed.receipt


def test_receipt_first_after_expiry_and_later_advancement(setup,client,vector):
    c=setup; retained=retain(c).proposed_image; first=run(client)
    later=run(client,state=first.proposed_state,request=successor(vector,c[2],first.proposed_state))
    result=recover(c,retained,later.proposed_state,now=c[3].expires_at+1000)
    assert result.status=='COMMITTED' and result.receipt==first.receipt
    assert result.proposed_image.entries[0].receipt_binding.receipt_canonical_json.encode()==canonical_bytes(first.receipt)
    assert later.proposed_state.authority_revision==2


def test_retention_exact_retry_after_expiry_is_not_permission(setup):
    c=setup; image=retain(c).proposed_image; before=canonical_bytes(image)
    assert retain(c,image,now=c[3].expires_at).status=='UNCHANGED'
    assert recover(c,image,now=c[3].expires_at).reason_code=='RESPONSE_EXPIRED'
    assert canonical_bytes(image)==before


@pytest.mark.parametrize('delta,status',[(59,'READY_TO_APPLY'),(60,'REJECTED'),(61,'REJECTED')])
def test_expiry_boundary(setup,delta,status):
    assert recover(setup,now=setup[3].created_at+delta).status==status


def test_expired_first_retention_preserves_awaiting(setup):
    c=setup; image=register(c).proposed_image; before=canonical_bytes(image)
    assert retain(c,image,now=c[3].expires_at).reason_code=='RESPONSE_EXPIRED'
    assert canonical_bytes(image)==before


@pytest.mark.parametrize('now',[True,-1,1.5,'100'])
def test_invalid_clock_types(setup,now):
    assert register(setup,now=now).reason_code=='INVALID_INPUT'


def test_clock_regression(setup):
    c=setup; image=retain(c,now=c[3].created_at+1).proposed_image
    assert recover(c,image).reason_code=='CLOCK_REGRESSION'


@pytest.mark.parametrize('field,value',[('operation_id','different'),('expires_at',1),('created_at',True),('profile','other')])
def test_intent_tampering_or_binding_changes(setup,field,value):
    c=setup; changed=c[3].model_copy(update={field:value})
    if field=='operation_id':
        assert intent_digest(changed)!=intent_digest(c[3])
    else: assert register(c,intent=changed).status=='REJECTED'


def test_existing_operation_cannot_change_request_or_trust(setup):
    c=setup; image=register(c).proposed_image
    changed=c[3].model_copy(update={'request':c[3].request.model_copy(update={'challenge':'f'*64})})
    assert register(c,image,intent=changed).reason_code=='OPERATION_CONFLICT'
    trust=c[3].trust_store.model_copy(update={'revision':2})
    cp=c[3].trusted_checkpoint.model_copy(update={'revision':2,'trust_store_digest':record_digest(trust)})
    changed=c[3].model_copy(update={'trust_store':trust,'trusted_checkpoint':cp})
    assert register(c,image,intent=changed).reason_code=='OPERATION_CONFLICT'


@pytest.mark.parametrize('which',['principal','scope','anchor','checkpoint'])
def test_intent_scope_and_independent_anchor(setup,which):
    c=setup; i=c[3]
    if which=='principal': i=i.model_copy(update={'principal_id':'other'})
    if which=='scope': i=i.model_copy(update={'request':i.request.model_copy(update={'store_instance_id':'other'})})
    if which=='anchor': i=i.model_copy(update={'client_anchor_digest':'f'*64})
    if which=='checkpoint': i=i.model_copy(update={'trusted_checkpoint':i.trusted_checkpoint.model_copy(update={'trust_store_digest':'f'*64})})
    assert register(c,intent=i).status=='REJECTED'


def test_caller_denied_before_image_validation(setup):
    c=setup
    assert register(c,image='corrupt',caller_principal='other').reason_code=='ACCESS_DENIED'
    assert recover(c,caller_principal='other').reason_code=='ACCESS_DENIED'
    image=register(c).proposed_image
    missing=evaluate_recovery(image,'absent',trusted_client_anchor=c[0],caller_principal=c[0].principal_id,
        checked_high_water_state=c[1],now=c[3].created_at)
    assert missing.reason_code=='ACCESS_DENIED'


@pytest.mark.parametrize('kind',['signature','challenge','scope'])
def test_response_tampering_and_signed_wrong_context(setup,vector,kind):
    c=setup
    if kind=='signature': r=c[2].response.model_copy(update={'signature_hex':'0'*128})
    else:
        change={'challenge':'f'*64} if kind=='challenge' else {'store_instance_id':'other'}
        r=response(vector,vector[1].model_copy(update=change))
    assert retain(c,raw=canonical_bytes(r)).reason_code=='VERIFICATION_FAILED'


def test_replacement_response_conflict(setup,vector):
    c=setup; image=retain(c).proposed_image
    other=response(vector,vector[1].model_copy(update={'policy_revision':99}))
    assert retain(c,image,canonical_bytes(other)).reason_code=='OPERATION_CONFLICT'


@pytest.mark.parametrize('raw',[b'',b' '*32768,b' '*32769,b'\xff',b'{}',b'{"a":1,"a":1}'],
    ids=['empty','at-cap','over-cap','utf8','shape','duplicate'])
def test_response_bounds_and_invalid_encoding(setup,raw):
    assert retain(setup,raw=raw).status=='REJECTED'


def test_response_whitespace_not_normalized(setup):
    assert retain(setup,raw=b' '+canonical_bytes(setup[2].response)).status=='REJECTED'


@pytest.mark.parametrize('mutation',['extra','duplicate','padding','coercion'])
def test_canonical_intent_rejection(setup,mutation):
    raw=canonical_bytes(setup[3])
    if mutation=='extra': raw=raw[:-1]+b',"extra":true}'
    if mutation=='duplicate': raw=raw[:-1]+b',"operation_id":"op-1"}'
    if mutation=='padding': raw=b' '+raw
    if mutation=='coercion':
        value=json.loads(raw);value['created_at']=str(value['created_at']);raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    with pytest.raises(ValueError): decode_journal_record(ClientJournalIntent,raw)


def test_frozen_domain_separation_and_roundtrip(setup):
    i=setup[3]; raw=canonical_bytes(i)
    assert intent_digest(i)==sha256(b'TNC-CLIENT-JOURNAL-INTENT-v1:'+raw).hexdigest()
    assert intent_digest(i)!=record_digest(i)
    assert decode_journal_record(ClientJournalIntent,raw)==i
    with pytest.raises(ValueError): i.operation_id='changed'


@pytest.mark.parametrize('field,value',[('state','COMMITTED_RECEIPT'),('local_sequence',3),('intent_digest','f'*64),('last_event_at',0)])
def test_illegal_jumps_or_corruption(setup,field,value):
    c=setup; image=register(c).proposed_image
    image=image.model_copy(update={'entries':(image.entries[0].model_copy(update={field:value}),)})
    assert recover(c,image).status=='REJECTED'


@pytest.mark.parametrize('evidence',['missing','corrupt','wrong-anchor','forged-receipt'])
def test_unavailable_is_not_absent(setup,client,evidence):
    c=setup; state=run(client).proposed_state
    if evidence=='missing': state='missing'
    if evidence=='corrupt': state=state.model_copy(update={'local_sequence':5})
    if evidence=='wrong-anchor': state=state.model_copy(update={'anchor':state.anchor.model_copy(update={'envelope_digest':'f'*64})})
    if evidence=='forged-receipt':
        e=state.history[0]; e=e.model_copy(update={'receipt':e.receipt.model_copy(update={'response_digest':'f'*64})})
        state=state.model_copy(update={'history':(e,)})
    result=recover(c,evidence=state,now=c[3].expires_at+100)
    assert result.status=='INDETERMINATE' and result.proposed_image is None


def test_same_operation_conflicting_high_water_receipt(setup,client,vector):
    other=client[2].model_copy(update={'response':response(vector,vector[1].model_copy(update={'policy_revision':99}))})
    state=run(client,request=other).proposed_state
    assert recover(setup,evidence=state).reason_code=='OPERATION_CONFLICT'


def test_receipt_predating_retention_rejected(setup,client):
    c=setup; image=retain(c,now=c[3].created_at+1).proposed_image
    assert recover(c,image,run(client).proposed_state,now=c[3].created_at+1).reason_code=='INVALID_RECEIPT'


def test_terminal_evidence_corruption_rejected(setup,client):
    c=setup; result=recover(c,evidence=run(client).proposed_state)
    image=result.proposed_image; e=image.entries[0]; b=e.receipt_binding
    bad=b.model_copy(update={'advancement_request_digest':e.intent_digest})
    image=image.model_copy(update={'entries':(e.model_copy(update={'receipt_binding':bad}),)})
    assert recover(c,image).status=='REJECTED'


def test_model_row_bounds_and_exact_input_byte_limits(setup,monkeypatch):
    e=register(setup).proposed_image.entries[0]
    with pytest.raises(ValueError): ClientJournalImage(entries=(e,)*65)
    with pytest.raises(ValueError): ClientJournalImage(entries=(e,e))
    raw=canonical_bytes(setup[3]); monkeypatch.setattr(journal,'INTENT_LIMIT',len(raw))
    assert decode_journal_record(ClientJournalIntent,raw)==setup[3]
    monkeypatch.setattr(journal,'INTENT_LIMIT',len(raw)-1)
    with pytest.raises(ValueError): decode_journal_record(ClientJournalIntent,raw)


def test_image_output_capacity_before_publication(setup,monkeypatch):
    monkeypatch.setattr(journal,'IMAGE_LIMIT',1)
    assert register(setup).status=='REJECTED'


def test_zero_io_wall_clock_and_signing(setup,client,monkeypatch):
    high_water=run(client).proposed_state
    raw=canonical_bytes(setup[2].response)
    def fail(*a,**kw): pytest.fail('Forbidden side effect')
    for obj,name in ((builtins,'open'),(sqlite3,'connect'),(socket,'socket'),(time,'time'),(time,'monotonic')):
        monkeypatch.setattr(obj,name,fail)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    monkeypatch.setattr(Ed25519PrivateKey,'generate',fail)
    image=retain(setup,raw=raw).proposed_image
    assert recover(setup,image,high_water).status=='COMMITTED'


def fixed_intent():
    from tnc.provenance.reconciliation_verifier import ObservationKey
    scope=dict(deployment_id='deployment',store_instance_id='store',timestamp=100,expiry=200)
    public=bytes(32)
    key=ObservationKey(**scope,key_id=sha256(public).hexdigest(),public_key_hex=public.hex(),
        issuer_id='observer',envelope_issuer_id='authority',permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active')
    trust=ObservationTrustStore(**scope,revision=1,keys=(key,))
    cp=ObservationTrustCheckpoint(**scope,revision=1,trust_store_digest=record_digest(trust))
    request=ObservationRequest(**{**scope,'timestamp':120,'expiry':180},principal_id='caller',issuer_id='observer',challenge='c'*64)
    return ClientJournalIntent(operation_id='golden-1',client_anchor_digest='a'*64,principal_id='caller',
        request=request,trust_store=trust,trusted_checkpoint=cp,created_at=120,expires_at=180)


def test_fixed_canonical_intent_vector():
    intent=fixed_intent()
    assert canonical_bytes(intent.request)==(b'{"action":"OBSERVE_CURRENT","challenge":"'+b'c'*64+
        b'","deployment_id":"deployment","expiry":180,"issuer_id":"observer","principal_id":"caller",'
        b'"profile":"tnc-authority-v2","store_instance_id":"store","timestamp":120}')
    assert intent_digest(intent)=='16a0a5b7b4898903dd99eb278e043db12ab2a5670aa0319b4ce0c0b28e3cc991'


def test_64_operations_then_capacity_rejection(setup):
    c=setup
    entries=[]
    for index in range(64):
        intent=c[3].model_copy(update={'operation_id':f'op-{index:02d}'})
        entries.append(ClientJournalEntry(intent=intent,intent_digest=intent_digest(intent),local_sequence=1,
            last_event_at=intent.created_at,state='AWAITING_RESPONSE'))
    image=ClientJournalImage(entries=tuple(entries))
    assert register(c,image,intent=c[3].model_copy(update={'operation_id':'op-64'})).reason_code=='CAPACITY_EXCEEDED'


def test_exact_response_byte_cap_enforced(setup,monkeypatch):
    raw=canonical_bytes(setup[2].response)
    monkeypatch.setattr(journal,'RESPONSE_LIMIT',len(raw))
    assert retain(setup,raw=raw).status=='RETAINED'
    monkeypatch.setattr(journal,'RESPONSE_LIMIT',len(raw)-1)
    assert retain(setup,raw=raw).reason_code=='INVALID_RESPONSE'


def test_pure_outcome_cannot_be_permission():
    with pytest.raises(ValueError): JournalOutcome(status='UNCHANGED',audit_only=1)
    with pytest.raises(ValueError): JournalOutcome(status='UNCHANGED',audit_only=False)
    with pytest.raises(ValueError): JournalOutcome(status='REJECTED',reason_code='invented')


def test_output_budget_rejects_otherwise_valid_transition(setup,monkeypatch):
    image=register(setup).proposed_image
    monkeypatch.setattr(journal,'IMAGE_LIMIT',len(canonical_bytes(image)))
    assert retain(setup,image).reason_code=='CAPACITY_EXCEEDED'
