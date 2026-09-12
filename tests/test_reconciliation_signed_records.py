import json
import pytest
from pydantic import ValidationError
from tnc.provenance.reconciliation_signed_records import *

# Hand-specified bytes, independent of the encoder under test.
VECTOR=(b'{"authority_revision":1,"challenge":"'+b'c'*64+
    b'","deployment_store_id":"deployment/store","envelope_digest":"'+b'e'*64+
    b'","expiry":160,"policy_digest":"'+b'd'*64+
    b'","policy_revision":2,"profile":"tnc-authority-v1","timestamp":100}')


@pytest.fixture
def records():
    key=KeyRecord(key_id='a'*64,public_key_hex='b'*64,created_at=0)
    trust=TrustStore(deployment_store_id='deployment/store',keys=(key,))
    container=SignedResponseContainer(payload_json_hex=VECTOR.hex(),signature_hex='0'*128,key_id=key.key_id)
    return container,trust


def test_exact_vector_and_preimage():
    p=ObservationPayload(deployment_store_id='deployment/store',authority_revision=1,
        envelope_digest='e'*64,policy_revision=2,policy_digest='d'*64,challenge='c'*64,timestamp=100,expiry=160)
    assert encode_signed_record(p)==VECTOR
    assert compute_preimage(VECTOR)==b'TNC-SIGNED-OBSERVATION-v1:'+VECTOR


def test_structural_only_even_fake_signature(records):
    result=validate_structural_record(*records,100,'c'*64)
    assert result.status=='STRUCTURALLY_VALID' and result.signature_verified is False and result.audit_only


@pytest.mark.parametrize('at,status',[(99,'FUTURE_TIMESTAMP'),(100,None),(159,None),(160,'OBSERVATION_EXPIRED'),(161,'OBSERVATION_EXPIRED')])
def test_time_boundary(records,at,status):
    assert validate_structural_record(*records,at,'c'*64).error_code==status


@pytest.mark.parametrize('field,value',[
    ('timestamp',True),('timestamp','100'),('timestamp',100.0),('timestamp',-1),
    ('expiry',100),('expiry',99),('authority_revision',0),('policy_revision',False),
    ('envelope_digest','A'*64),('policy_digest','f'*63),('challenge','c '*32),
    ('profile','other'),('deployment_store_id',123),('extra',1)])
def test_invalid_fields(field,value):
    data=json.loads(VECTOR); data[field]=value
    with pytest.raises(ValueError): decode_signed_record(ObservationPayload,json.dumps(data,sort_keys=True,separators=(',',':')).encode())


@pytest.mark.parametrize('data',[b' '+VECTOR,VECTOR+b'\n',VECTOR.replace(b'"timestamp":100',b'"timestamp":100,"timestamp":100'),
    VECTOR.replace(b'"timestamp":100',b'"timestamp":NaN'),b'\xff',b'[]',b'{}',b'x'*65537],ids=['padding','newline','duplicate','nan','utf8','array','missing','oversize'])
def test_bad_canonical(data):
    with pytest.raises(ValueError): compute_preimage(data)


def test_duplicate_and_unsorted_keys(records):
    key=records[1].keys[0]
    for keys in ((key,key),(key.model_copy(update={'key_id':'f'*64}),key)):
        with pytest.raises(ValueError): TrustStore(deployment_store_id='deployment/store',keys=keys)


@pytest.mark.parametrize('field,value',[('signature_hex','0'*126),('signature_hex','G'*128),('key_id','a'*63),('payload_json_hex','zz'),('profile','other')])
def test_container_shape(records,field,value):
    with pytest.raises(ValueError): SignedResponseContainer(**{**records[0].model_dump(),field:value})


@pytest.mark.parametrize('change,code',[(dict(status='retired'),'INACTIVE_SIGNING_KEY'),(dict(status='revoked'),'INACTIVE_SIGNING_KEY'),
    (dict(created_at=101),'KEY_NOT_YET_CREATED'),(dict(key_id='f'*64),'UNKNOWN_SIGNING_KEY')])
def test_key_structure(records,change,code):
    c,t=records; t=t.model_copy(update={'keys':(t.keys[0].model_copy(update=change),)})
    assert validate_structural_record(c,t,100,'c'*64).error_code==code


def test_scope_and_challenge(records):
    c,t=records
    assert validate_structural_record(c,t.model_copy(update={'deployment_store_id':'wrong'}),100,'c'*64).error_code=='WRONG_DEPLOYMENT_STORE'
    assert validate_structural_record(c,t,100,'d'*64).error_code=='MISMATCHED_CHALLENGE'


@pytest.mark.parametrize('time',[True,'100',100.0,-1])
def test_no_time_coercion(records,time):
    assert validate_structural_record(*records,time,'c'*64).error_code=='INVALID_RECORD'


def test_frozen_nested_records(records):
    with pytest.raises(ValidationError): records[1].keys[0].status='retired'
    assert type(records[1].keys) is tuple


def test_missing_fields():
    data=json.loads(VECTOR); del data['challenge']
    with pytest.raises(ValueError): decode_signed_record(ObservationPayload,json.dumps(data,sort_keys=True,separators=(',',':')).encode())


def test_no_signature_success_promotion():
    with pytest.raises(ValueError): VerificationResult(status='STRUCTURALLY_VALID',signature_verified=True)


def test_oversized_container(records):
    with pytest.raises(ValueError): records[0].model_validate({**records[0].model_dump(),'payload_json_hex':'00'*65537})
