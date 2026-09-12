"""Pure structural integer-time profile; no signing or signature verification."""
from typing import Annotated, Literal
from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical

DOMAIN_PREFIX = b'TNC-SIGNED-OBSERVATION-v1:'
MAX_RECORD_SIZE_BYTES = 65536
Timestamp = Annotated[int, Field(strict=True, ge=0)]
Revision = Annotated[int, Field(strict=True, gt=0)]


class KeyRecord(Model):
    key_id: Digest
    algorithm: Literal['Ed25519'] = 'Ed25519'
    public_key_hex: Digest
    created_at: Timestamp
    status: Literal['active','retired','revoked'] = 'active'


class TrustStore(Model):
    deployment_store_id: Identifier
    keys: tuple[KeyRecord, ...] = Field(min_length=1,max_length=64)

    @model_validator(mode='after')
    def unique_sorted(self):
        ids=tuple(k.key_id for k in self.keys)
        if ids!=tuple(sorted(set(ids))): raise ValueError('Sorted unique keys required')
        return self


class ObservationPayload(Model):
    deployment_store_id: Identifier
    authority_revision: Revision
    envelope_digest: Digest
    policy_revision: Revision
    policy_digest: Digest
    challenge: Digest
    timestamp: Timestamp
    expiry: Timestamp
    profile: Literal['tnc-authority-v1'] = 'tnc-authority-v1'

    @model_validator(mode='after')
    def interval(self):
        if self.timestamp>=self.expiry: raise ValueError('Positive interval required')
        return self


class SignedResponseContainer(Model):
    # Hex permits unambiguous bounded canonical JSON without mutable byte buffers.
    payload_json_hex: str = Field(min_length=2,max_length=MAX_RECORD_SIZE_BYTES*2,pattern=r'^(?:[0-9a-f]{2})+$')
    signature_hex: str = Field(pattern=r'^[0-9a-f]{128}$')
    key_id: Digest
    profile: Literal['tnc-authority-v1'] = 'tnc-authority-v1'


class VerificationResult(Model):
    status: Literal['STRUCTURALLY_VALID','REJECTED']
    signature_verified: Literal[False] = False
    audit_only: Literal[True] = True
    error_code: Literal['INVALID_RECORD','UNKNOWN_SIGNING_KEY','INACTIVE_SIGNING_KEY',
        'WRONG_DEPLOYMENT_STORE','OBSERVATION_EXPIRED','FUTURE_TIMESTAMP',
        'KEY_NOT_YET_CREATED','MISMATCHED_CHALLENGE'] | None = None

    @model_validator(mode='after')
    def shape(self):
        if (self.status=='REJECTED')!=(self.error_code is not None): raise ValueError('Invalid outcome')
        if type(self.signature_verified) is not bool or type(self.audit_only) is not bool:
            raise ValueError('Exact booleans required')
        return self


KINDS=(KeyRecord,TrustStore,ObservationPayload,SignedResponseContainer,VerificationResult)


def decode_signed_record(kind,data):
    limit=MAX_RECORD_SIZE_BYTES*2+1024 if kind is SignedResponseContainer else MAX_RECORD_SIZE_BYTES
    if kind not in KINDS or type(data) is not bytes or not 0<len(data)<=limit:
        raise ValueError('INVALID_RECORD')
    return decode_canonical(kind,data)


def encode_signed_record(record):
    if type(record) not in KINDS: raise ValueError('INVALID_RECORD')
    data=canonical_bytes(record)
    decode_signed_record(type(record),data)
    return data


def compute_preimage(payload_bytes):
    decode_signed_record(ObservationPayload,payload_bytes)
    return DOMAIN_PREFIX+payload_bytes


def validate_structural_record(container,trust_store,current_time,expected_challenge):
    def reject(reason): return VerificationResult(status='REJECTED',error_code=reason)
    try:
        if type(container) is not SignedResponseContainer or type(trust_store) is not TrustStore:
            raise ValueError()
        container=decode_signed_record(SignedResponseContainer,encode_signed_record(container))
        trust_store=decode_signed_record(TrustStore,encode_signed_record(trust_store))
        if type(current_time) is not int or current_time<0: raise ValueError()
        if type(expected_challenge) is not str or len(expected_challenge)!=64 or any(c not in '0123456789abcdef' for c in expected_challenge):
            raise ValueError()
        payload=decode_signed_record(ObservationPayload,bytes.fromhex(container.payload_json_hex))
        if payload.deployment_store_id!=trust_store.deployment_store_id: return reject('WRONG_DEPLOYMENT_STORE')
        key=next((k for k in trust_store.keys if k.key_id==container.key_id),None)
        if key is None: return reject('UNKNOWN_SIGNING_KEY')
        if key.status!='active': return reject('INACTIVE_SIGNING_KEY')
        if payload.timestamp<key.created_at: return reject('KEY_NOT_YET_CREATED')
        if current_time>=payload.expiry: return reject('OBSERVATION_EXPIRED')
        if payload.timestamp>current_time: return reject('FUTURE_TIMESTAMP')
        if payload.challenge!=expected_challenge: return reject('MISMATCHED_CHALLENGE')
        return VerificationResult(status='STRUCTURALLY_VALID')
    except Exception:
        return reject('INVALID_RECORD')
