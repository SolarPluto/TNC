from datetime import timedelta
from hashlib import sha256
import builtins
import json
import socket
import sqlite3
import pytest
from test_reconciliation_verifier import case,inventory,config,update,signed,host,stored,reconciliation,NOW,vector
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.authorization_models import canonical_bytes,record_digest
from tnc.provenance.observation_request_binding import *


@pytest.fixture
def binding_case(vector):
    request=vector[2]
    identity=VerifiedIdentity(principal_id=request.principal_id,credential_id='e'*64,connection_id='connection',audit_id='audit',
        verified_at=NOW,valid_until=NOW+timedelta(seconds=40),registry_revision=3)
    grant=ObservationGrant(grant_id='grant',principal_id=request.principal_id,deployment_id=request.deployment_id,
        store_instance_id=request.store_instance_id,valid_from=NOW,valid_until=NOW+timedelta(seconds=50))
    policy=ObservationPolicy(revision=7,grants=(grant,),valid_from=NOW,valid_until=NOW+timedelta(seconds=50))
    context=ObservationHostContext(deployment_id=request.deployment_id,store_instance_id=request.store_instance_id,
        issuer_id=request.issuer_id,registry_revision=3,policy_revision=7,policy_digest=record_digest(policy),
        valid_from=NOW,valid_until=NOW+timedelta(seconds=50))
    return dict(request_bytes=canonical_bytes(request),identity=identity,policy=policy,host_context=context,now=NOW)


def run(c,**changes): return bind_observation_request(**{**c,**changes})


def test_bound_exact_bytes(binding_case):
    c=binding_case; before=c['request_bytes']; result=run(c)
    assert result.status=='BOUND' and result.binding.audit_only
    assert result.binding.request_digest==sha256(before).hexdigest()
    assert result.binding.credential_id=='e'*64 and result.binding.registry_revision==3
    assert result.binding.valid_until==NOW+timedelta(seconds=40) and before==c['request_bytes']


@pytest.mark.parametrize('field,value',[('principal_id','other'),('deployment_id','other'),('store_instance_id','other'),('issuer_id','other')])
def test_request_context_mismatch(binding_case,field,value):
    data=json.loads(binding_case['request_bytes']);data[field]=value
    result=run(binding_case,request_bytes=json.dumps(data,sort_keys=True,separators=(',',':')).encode())
    assert result.reason_code=='ACCESS_DENIED' and result.binding is None


@pytest.mark.parametrize('field,value',[('registry_revision',4),('policy_revision',8),('policy_digest','f'*64)])
def test_stale_host_context(binding_case,field,value):
    assert run(binding_case,host_context=binding_case['host_context'].model_copy(update={field:value})).reason_code=='ACCESS_DENIED'


def test_missing_grant(binding_case):
    p=binding_case['policy'].model_copy(update={'grants':()})
    ctx=binding_case['host_context'].model_copy(update={'policy_digest':record_digest(p)})
    assert run(binding_case,policy=p,host_context=ctx).reason_code=='ACCESS_DENIED'


@pytest.mark.parametrize('field,value',[('principal_id','other'),('store_instance_id','other'),('deployment_id','other')])
def test_grant_scope(binding_case,field,value):
    p=binding_case['policy']; p=p.model_copy(update={'grants':(p.grants[0].model_copy(update={field:value}),)})
    ctx=binding_case['host_context'].model_copy(update={'policy_digest':record_digest(p)})
    assert run(binding_case,policy=p,host_context=ctx).reason_code=='ACCESS_DENIED'


@pytest.mark.parametrize('offset',[40,60,-1])
def test_expiry_and_future_identity(binding_case,offset):
    assert run(binding_case,now=NOW+timedelta(seconds=offset)).reason_code=='ACCESS_DENIED'


@pytest.mark.parametrize('kind',['extra','duplicate','padding','oversize','action','float','missing'])
def test_canonical_shape(binding_case,kind):
    data=binding_case['request_bytes']
    if kind=='padding':data=b' '+data
    elif kind=='duplicate':data=data.replace(b'"action":',b'"action":"OBSERVE_CURRENT","action":')
    elif kind=='oversize':data=b'x'*16385
    else:
        obj=json.loads(data)
        if kind=='missing':del obj['challenge']
        else:obj[{'extra':'identity','action':'action','float':'timestamp'}[kind]]={'extra':'forged','action':'host.manage','float':1.5}[kind]
        data=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
    assert run(binding_case,request_bytes=data).reason_code=='INVALID_INPUT'


def test_identity_dict_is_not_proof(binding_case):
    assert run(binding_case,identity=binding_case['identity'].model_dump()).reason_code=='INVALID_INPUT'


def test_no_io(binding_case,monkeypatch):
    def fail(*a,**kw):pytest.fail('I/O forbidden')
    monkeypatch.setattr(builtins,'open',fail);monkeypatch.setattr(sqlite3,'connect',fail);monkeypatch.setattr(socket,'socket',fail)
    assert run(binding_case).status=='BOUND'


def test_duplicate_and_existing_action_rejected(binding_case):
    p=binding_case['policy']; g=p.grants[0]
    with pytest.raises(ValueError):ObservationPolicy(**{**p.model_dump(),'grants':(g,g)})
    with pytest.raises(ValueError):ObservationGrant(**{**g.model_dump(),'action':'replay.submit'})


def test_frozen_audit(binding_case):
    result=run(binding_case)
    with pytest.raises(ValueError):result.binding.credential_id='f'*64
    assert decode_binding_record(BindingOutcome,canonical_bytes(result))==result


def test_naive_time(binding_case):
    assert run(binding_case,now=NOW.replace(tzinfo=None)).reason_code=='INVALID_INPUT'


def test_fixture_identity_is_explicit_assumption(binding_case):
    # A structurally valid synthetic identity passes pure rules. No TLS is claimed.
    assert run(binding_case).status=='BOUND'
