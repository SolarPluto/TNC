import builtins
import socket
import sqlite3
import pytest
from test_reconciliation_verifier import case,inventory,config,update,signed,host,stored,reconciliation,NOW,vector,response
from tnc.provenance.authorization_models import record_digest,canonical_bytes
from tnc.provenance.client_high_water_logic import *


@pytest.fixture
def client(vector):
    p=vector[1]
    anchor=ClientAnchor(deployment_id=p.deployment_id,store_instance_id=p.store_instance_id,
        principal_id=p.principal_id,authority_revision=p.authority_revision,envelope_digest=p.envelope_digest,accepted_timestamp=vector[5])
    state=ClientHighWaterState(anchor=anchor,authority_revision=anchor.authority_revision,envelope_digest=anchor.envelope_digest,
        accepted_timestamp=anchor.accepted_timestamp,local_sequence=0)
    request=AdvancementRequest(operation_id='op-1',response=response(vector),retained_request=vector[2],trust_store=vector[3],trusted_checkpoint=vector[4])
    return anchor,state,request


def run(client,**changes):
    a,s,r=client
    args=dict(state=s,request=r,trusted_initial_anchor=a,caller_principal=a.principal_id,now=a.accepted_timestamp)
    args.update(changes)
    return evaluate_client_transition(**args)


def successor(vector,request,state,revision=None,previous=None,op='advance'):
    env=vector[1].envelope.model_copy(update={'authority_revision':revision or state.authority_revision+1,
        'previous_envelope_hash':previous or state.envelope_digest})
    p=vector[1].model_copy(update={'authority_revision':env.authority_revision,'envelope_digest':record_digest(env),'envelope':env})
    return request.model_copy(update={'operation_id':op,'response':response(vector,p)})


def test_unchanged_records_evidence(client):
    before=canonical_bytes(client[1]); out=run(client)
    assert out.status=='UNCHANGED' and out.proposed_state.local_sequence==1
    assert out.proposed_state.authority_revision==client[1].authority_revision
    assert canonical_bytes(client[1])==before


def test_direct_successor(client,vector):
    request=successor(vector,client[2],client[1]); out=run(client,request=request)
    assert out.status=='VALID_ADVANCE' and out.proposed_state.authority_revision==2 and out.audit_only


@pytest.mark.parametrize('revision,previous',[(2,'f'*64),(3,None)])
def test_predecessor_and_missing_chain(client,vector,revision,previous):
    out=run(client,request=successor(vector,client[2],client[1],revision,previous))
    assert out.status=='PREDECESSOR_MISMATCH' and out.proposed_state is None


def test_stale(client,vector):
    advanced=run(client,request=successor(vector,client[2],client[1])).proposed_state
    assert run(client,state=advanced).status=='STALE'


def test_fork(client,vector):
    env=vector[1].envelope.model_copy(update={'key_id':'f'*64})
    p=vector[1].model_copy(update={'envelope':env,'envelope_digest':record_digest(env)})
    assert run(client,request=client[2].model_copy(update={'response':response(vector,p)})).status=='CONFLICT_FORK'


def test_old_retry_after_advance_and_expiry(client,vector):
    first=run(client)
    second=run(client,state=first.proposed_state,request=successor(vector,client[2],first.proposed_state))
    retry=run(client,state=second.proposed_state,now=vector[5]+1000)
    assert retry.status=='RECOVERED' and retry.receipt==first.receipt and retry.proposed_state is None


def test_conflicting_operation(client):
    first=run(client)
    changed=client[2].model_copy(update={'response':client[2].response.model_copy(update={'signature_hex':'0'*128})})
    assert run(client,state=first.proposed_state,request=changed).reason_code=='OPERATION_CONFLICT'


def test_new_expired_request_rejected(client,vector):
    assert run(client,now=vector[5]+60).reason_code=='VERIFICATION_FAILED'


def test_policy_evidence_changes_not_authority(client,vector):
    first=run(client)
    p=vector[1].model_copy(update={'policy_revision':99,'policy_digest':'f'*64})
    request=client[2].model_copy(update={'operation_id':'new-policy','response':response(vector,p)})
    out=run(client,state=first.proposed_state,request=request)
    assert out.status=='UNCHANGED' and out.proposed_state.local_sequence==2
    assert out.proposed_state.envelope_digest==client[1].envelope_digest
    assert out.proposed_state.history[-1].request.response.payload.policy_revision==99


@pytest.mark.parametrize('field,value',[('local_sequence',7),('envelope_digest','f'*64),('authority_revision',9),('signing_key_id','f'*64)])
def test_state_corruption(client,field,value):
    assert run(client,state=client[1].model_copy(update={field:value})).reason_code=='INVALID_STATE'


def test_receipt_corruption(client):
    state=run(client).proposed_state; entry=state.history[0]
    bad=entry.model_copy(update={'receipt':entry.receipt.model_copy(update={'response_digest':'f'*64})})
    assert run(client,state=state.model_copy(update={'history':(bad,)})).reason_code=='INVALID_STATE'


def test_wrong_anchor(client):
    assert run(client,trusted_initial_anchor=client[0].model_copy(update={'envelope_digest':'f'*64})).reason_code=='INVALID_STATE'


def test_caller_is_host_fixture_not_request_identity(client):
    assert run(client,caller_principal='other').reason_code=='ACCESS_DENIED'


@pytest.mark.parametrize('now',[True,1.5,'100',-1])
def test_time_types(client,now):
    assert run(client,now=now).reason_code=='INVALID_INPUT'


def test_no_io(client,monkeypatch):
    def fail(*a,**kw): pytest.fail('I/O forbidden')
    monkeypatch.setattr(builtins,'open',fail); monkeypatch.setattr(sqlite3,'connect',fail); monkeypatch.setattr(socket,'socket',fail)
    assert run(client).status=='UNCHANGED'


def test_canonical_and_frozen(client):
    state=client[1]
    assert decode_client_record(ClientHighWaterState,canonical_bytes(state))==state
    with pytest.raises(ValueError): decode_client_record(ClientHighWaterState,b' '+canonical_bytes(state))
    with pytest.raises(ValueError): state.local_sequence=99


def test_bounded_history(client):
    entry=run(client).proposed_state.history[0]
    with pytest.raises(ValueError): ClientHighWaterState(**{**client[1].model_dump(),'history':(entry,)*65})


def test_bad_signature(client):
    r=client[2].model_copy(update={'response':client[2].response.model_copy(update={'signature_hex':'0'*128})})
    assert run(client,request=r).reason_code=='VERIFICATION_FAILED'
