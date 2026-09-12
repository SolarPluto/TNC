from hashlib import sha256
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from test_reconciliation_validation import case,inventory,config,update,signed,host,stored,reconciliation,NOW
from tnc.provenance.authorization_models import canonical_bytes,record_digest
from tnc.provenance.reconciliation_verifier import *


@pytest.fixture
def vector(reconciliation):
    env=reconciliation[2]; t=int(NOW.timestamp())
    private=Ed25519PrivateKey.generate()
    raw=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    scope=dict(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id)
    key=ObservationKey(**scope,timestamp=t-100,expiry=t+100,key_id=sha256(raw).hexdigest(),public_key_hex=raw.hex(),
        issuer_id='observer',envelope_issuer_id=env.issuer_id,permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active')
    trust=ObservationTrustStore(**scope,timestamp=t-100,expiry=t+100,revision=1,keys=(key,))
    cp=ObservationTrustCheckpoint(**scope,timestamp=t-100,expiry=t+100,revision=1,trust_store_digest=record_digest(trust))
    req=ObservationRequest(**scope,timestamp=t,expiry=t+60,principal_id='caller',issuer_id='observer',challenge='c'*64)
    payload=ObservationPayload(**req.model_dump(),request_digest=record_digest(req),signing_key_id=key.key_id,
        trust_revision=1,trust_store_digest=record_digest(trust),policy_revision=7,policy_digest='d'*64,
        authority_revision=env.authority_revision,envelope_digest=record_digest(env),envelope=env)
    return private,payload,req,trust,cp,t


def response(v,p=None,domain=None):
    p=p or v[1]
    preimage=observation_preimage(p) if domain is None else domain+canonical_bytes(p)
    return SignedObservation(payload=p,signature_hex=v[0].sign(preimage).hex())


def verify(v,r=None,**changes):
    kw=dict(expected_request=v[2],trust_store=v[3],trusted_checkpoint=v[4],now=v[5]); kw.update(changes)
    return verify_observation(r or response(v),**kw)


def test_valid_and_nonconsuming(vector):
    result=verify(vector)
    assert result.status=='VERIFIED' and result.audit_only and result.checked_payload==vector[1]
    assert result==verify(vector)


@pytest.mark.parametrize('field,value', [('challenge','f'*64),('principal_id','other'),('policy_revision',8),('policy_digest','f'*64),
    ('request_digest','f'*64),('envelope_digest','f'*64),('authority_revision',2)])
def test_tampering(vector,field,value):
    r=response(vector); r=r.model_copy(update={'payload':r.payload.model_copy(update={field:value})})
    assert verify(vector,r).reason_code=='SIGNATURE_INVALID'


@pytest.mark.parametrize('field,value', [('challenge','f'*64),('principal_id','other'),('request_digest','f'*64),
    ('deployment_id','other'),('store_instance_id','other'),('issuer_id','other')])
def test_signed_wrong_context(vector,field,value):
    assert verify(vector,response(vector,vector[1].model_copy(update={field:value}))).reason_code=='REQUEST_MISMATCH'


@pytest.mark.parametrize('domain',[b'TNC-SIGNED-OBSERVATION-v1:',b'TNC-INSTALLER-UPDATE\0v1\0',b'TNC-RECOVERY:'])
def test_wrong_domain(vector,domain):
    assert verify(vector,response(vector,domain=domain)).reason_code=='SIGNATURE_INVALID'


@pytest.mark.parametrize('delta,expected',[(0,'VERIFIED'),(59,'VERIFIED'),(60,'REJECTED'),(-1,'REJECTED')])
def test_expiry(vector,delta,expected):
    assert verify(vector,now=vector[5]+delta).status==expected


@pytest.mark.parametrize('change',[dict(status='revoked'),dict(status='retired'),dict(permissions=()),dict(issuer_id='other')])
def test_key_denied(vector,change):
    key=vector[3].keys[0].model_copy(update=change)
    trust=vector[3].model_copy(update={'keys':(key,)})
    cp=vector[4].model_copy(update={'trust_store_digest':record_digest(trust)})
    p=vector[1].model_copy(update={'trust_store_digest':record_digest(trust)})
    assert verify(vector,response(vector,p),trust_store=trust,trusted_checkpoint=cp).reason_code=='KEY_DENIED'


@pytest.mark.parametrize('when',['future','expires'])
def test_key_time(vector,when):
    t=vector[5]; key=vector[3].keys[0].model_copy(update={'timestamp':t+1} if when=='future' else {'expiry':t+30})
    trust=vector[3].model_copy(update={'keys':(key,)})
    cp=vector[4].model_copy(update={'trust_store_digest':record_digest(trust)})
    p=vector[1].model_copy(update={'trust_store_digest':record_digest(trust)})
    assert verify(vector,response(vector,p),trust_store=trust,trusted_checkpoint=cp).reason_code=='INTERVAL_INVALID'


@pytest.mark.parametrize('field,value',[('revision',2),('trust_store_digest','f'*64),('deployment_id','wrong')])
def test_checkpoint_mismatch(vector,field,value):
    assert verify(vector,trusted_checkpoint=vector[4].model_copy(update={field:value})).reason_code=='TRUST_MISMATCH'


@pytest.mark.parametrize('field,value',[('authority_revision',9),('envelope_digest','f'*64)])
def test_envelope_binding(vector,field,value):
    assert verify(vector,response(vector,vector[1].model_copy(update={field:value}))).reason_code=='ENVELOPE_MISMATCH'


def test_wrong_public_key_identifier(vector):
    key=vector[3].keys[0].model_dump(); key['key_id']='f'*64
    with pytest.raises(ValueError): ObservationKey(**key)


@pytest.mark.parametrize('mode',['padding','duplicate','extra','oversize','float'])
def test_canonical_rejections(vector,mode):
    data=canonical_bytes(vector[2])
    if mode=='padding': data=b' '+data
    elif mode=='duplicate': data=data.replace(b'"action":',b'"action":"OBSERVE_CURRENT","action":')
    elif mode=='oversize': data=b'x'*65537
    else:
        obj=json.loads(data); obj['extra' if mode=='extra' else 'timestamp']=1.5
        data=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
    with pytest.raises(ValueError): decode_v2_record(ObservationRequest,data)


def test_no_rejected_payload(vector):
    r=response(vector).model_copy(update={'signature_hex':'0'*128})
    out=verify(vector,r)
    assert out.status=='REJECTED' and out.checked_payload is None and out.response_digest is None
