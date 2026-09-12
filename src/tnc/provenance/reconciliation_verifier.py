"""V2 current observation verification. No signing, I/O, or runtime integration."""
from hashlib import sha256
from typing import Annotated, Literal
from pydantic import Field, model_validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.reconciliation_models import ReconciliationEnvelope

DOMAIN_PREFIX=b'TNC-SIGNED-OBSERVATION-v2:'
Time=Annotated[int,Field(strict=True,ge=0)]
Revision=Annotated[int,Field(strict=True,gt=0)]


class Interval(Model):
    timestamp: Time
    expiry: Time
    @model_validator(mode='after')
    def interval(self):
        if self.timestamp>=self.expiry: raise ValueError('Positive interval required')
        return self


class Scope(Interval):
    deployment_id: Identifier
    store_instance_id: Identifier


class ObservationRequest(Scope):
    profile: Literal['tnc-authority-v2']='tnc-authority-v2'
    action: Literal['OBSERVE_CURRENT']='OBSERVE_CURRENT'
    principal_id: Identifier
    issuer_id: Identifier
    challenge: Digest


class ObservationKey(Scope):
    key_id: Digest
    public_key_hex: Digest
    algorithm: Literal['Ed25519']='Ed25519'
    issuer_id: Identifier
    envelope_issuer_id: Identifier
    permissions: tuple[Literal['AUTHORITY_OBSERVE_CURRENT'], ...]=Field(max_length=1)
    status: Literal['active','retired','revoked']
    @model_validator(mode='after')
    def key_binding(self):
        if self.key_id!=sha256(bytes.fromhex(self.public_key_hex)).hexdigest(): raise ValueError('Key binding mismatch')
        return self


class ObservationTrustStore(Scope):
    revision: Revision
    keys: tuple[ObservationKey,...]=Field(min_length=1,max_length=64)
    @model_validator(mode='after')
    def inventory(self):
        ids=tuple(k.key_id for k in self.keys)
        if ids!=tuple(sorted(set(ids))): raise ValueError('Sorted unique keys required')
        if any((k.deployment_id,k.store_instance_id)!=(self.deployment_id,self.store_instance_id) for k in self.keys):
            raise ValueError('Key scope mismatch')
        return self


class ObservationTrustCheckpoint(Scope):
    revision: Revision
    trust_store_digest: Digest


class ObservationPayload(ObservationRequest):
    request_digest: Digest
    signing_key_id: Digest
    trust_revision: Revision
    trust_store_digest: Digest
    policy_revision: Revision
    policy_digest: Digest
    authority_revision: Revision
    envelope_digest: Digest
    envelope: ReconciliationEnvelope


class SignedObservation(Model):
    payload: ObservationPayload
    signature_hex: str=Field(pattern=r'^[0-9a-f]{128}$')


class ObservationVerificationResult(Model):
    status: Literal['VERIFIED','REJECTED']
    audit_only: bool=Field(default=True,strict=True)
    reason_code: Literal['INVALID_RECORD','TRUST_MISMATCH','KEY_DENIED','SIGNATURE_INVALID',
        'REQUEST_MISMATCH','INTERVAL_INVALID','ENVELOPE_MISMATCH'] | None=None
    response_digest: Digest | None=None
    checked_payload: ObservationPayload | None=None
    @model_validator(mode='after')
    def shape(self):
        ok=self.status=='VERIFIED'
        if not self.audit_only or (self.reason_code is None)!=ok or (self.checked_payload is not None)!=ok or (self.response_digest is not None)!=ok:
            raise ValueError('Invalid result')
        return self


KINDS=(ObservationRequest,ObservationKey,ObservationTrustStore,ObservationTrustCheckpoint,
    ObservationPayload,SignedObservation,ObservationVerificationResult)


def decode_v2_record(kind,data):
    limit=1048576 if kind is ObservationTrustStore else 131072 if kind in (SignedObservation,ObservationVerificationResult) else 65536
    if kind not in KINDS or type(data) is not bytes or not 0<len(data)<=limit: raise ValueError('INVALID_RECORD')
    return decode_canonical(kind,data)


def _copy(value,kind):
    if type(value) is not kind: raise ValueError('Exact type required')
    return decode_v2_record(kind,canonical_bytes(value))


def observation_preimage(payload):
    return DOMAIN_PREFIX+canonical_bytes(_copy(payload,ObservationPayload))


def verify_observation(response,*,expected_request,trust_store,trusted_checkpoint,now):
    def deny(reason): return ObservationVerificationResult(status='REJECTED',reason_code=reason)
    try:
        if type(now) is not int or now<0: return deny('INVALID_RECORD')
        response=_copy(response,SignedObservation); request=_copy(expected_request,ObservationRequest)
        trust=_copy(trust_store,ObservationTrustStore); cp=_copy(trusted_checkpoint,ObservationTrustCheckpoint)
        if sum(len(canonical_bytes(v)) for v in (response,request,trust,cp))>2097152: return deny('INVALID_RECORD')
        p=response.payload
        scope=lambda x:(x.deployment_id,x.store_instance_id)
        if (scope(cp)!=scope(trust) or scope(cp)!=scope(request) or cp.revision!=trust.revision
                or cp.trust_store_digest!=record_digest(trust) or p.trust_revision!=cp.revision
                or p.trust_store_digest!=cp.trust_store_digest): return deny('TRUST_MISMATCH')
        key=next((k for k in trust.keys if k.key_id==p.signing_key_id),None)
        if key is None or key.status!='active' or key.issuer_id!=request.issuer_id or 'AUTHORITY_OBSERVE_CURRENT' not in key.permissions:
            return deny('KEY_DENIED')
        try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(bytes.fromhex(response.signature_hex),observation_preimage(p))
        except InvalidSignature: return deny('SIGNATURE_INVALID')
        if (p.request_digest!=record_digest(request) or scope(p)!=scope(request)
                or (p.principal_id,p.issuer_id,p.challenge)!=(request.principal_id,request.issuer_id,request.challenge)):
            return deny('REQUEST_MISMATCH')
        if not (request.timestamp<=p.timestamp<=now<p.expiry<=request.expiry
                and request.expiry-request.timestamp<=60 and p.expiry-p.timestamp<=60): return deny('INTERVAL_INVALID')
        if any(not (v.timestamp<=p.timestamp and v.timestamp<=now<v.expiry and p.expiry<=v.expiry) for v in (key,trust,cp)):
            return deny('INTERVAL_INVALID')
        e=p.envelope
        if (scope(e)!=scope(p) or e.issuer_id!=key.envelope_issuer_id or record_digest(e)!=p.envelope_digest
                or e.authority_revision!=p.authority_revision
                or not e.valid_from.timestamp()<=p.timestamp<=now<e.valid_until.timestamp()
                or p.expiry>e.valid_until.timestamp()): return deny('ENVELOPE_MISMATCH')
        return ObservationVerificationResult(status='VERIFIED',response_digest=record_digest(response),checked_payload=p)
    except Exception: return deny('INVALID_RECORD')
