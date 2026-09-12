"""Pure signed caller-configuration checks. No loading, transport, or runtime grants."""
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from typing import Annotated, Literal
from pydantic import Field, model_validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.reconciliation_verifier import ObservationRequest, ObservationTrustCheckpoint, decode_v2_record

DOMAIN = b'TNC-CALLER-CONFIG-v1:'
CONFIG_LIMIT = 262144
REQUEST_LIMIT = 16384
Time = Annotated[int, Field(strict=True, ge=0, le=2**63-1)]
Revision = Annotated[int, Field(strict=True, gt=0, le=2**63-1)]


class ConfigInterval(Model):
    effective_at: Time
    expires_at: Time

    @model_validator(mode='after')
    def interval(self):
        if self.effective_at>=self.expires_at: raise ValueError('Positive interval required')
        return self


class CallerEnrollmentRecord(ConfigInterval):
    certificate_sha256: Digest
    principal_id: Identifier
    status: Literal['active','disabled']


class CallerObservationGrant(ConfigInterval):
    grant_id: Identifier
    principal_id: Identifier
    action: Literal['AUTHORITY_OBSERVE_CURRENT']='AUTHORITY_OBSERVE_CURRENT'
    deployment_id: Identifier
    store_instance_id: Identifier
    observation_issuer_id: Identifier
    observation_trust_digest: Digest
    status: Literal['active','revoked']='active'
    # Validated policy declarations only: no usage counter exists in this module.
    max_requests: int | None = Field(default=None, strict=True, ge=1, le=1000000)
    window_seconds: int | None = Field(default=None, strict=True, ge=1, le=86400)

    @model_validator(mode='after')
    def rate_shape(self):
        if (self.max_requests is None)!=(self.window_seconds is None): raise ValueError('Complete rate declaration required')
        return self


class CallerConfigPayload(ConfigInterval):
    profile: Literal['tnc-caller-config-v1']='tnc-caller-config-v1'
    configuration_id: Identifier
    issuer_id: Identifier
    signing_key_id: Digest
    revision: Revision
    registry_revision: Revision
    enrollments: tuple[CallerEnrollmentRecord,...] = Field(max_length=64)
    grants: tuple[CallerObservationGrant,...] = Field(max_length=64)

    @model_validator(mode='after')
    def inventory(self):
        fingerprints=tuple(e.certificate_sha256 for e in self.enrollments)
        grants=tuple(g.grant_id for g in self.grants)
        if fingerprints!=tuple(sorted(set(fingerprints))) or grants!=tuple(sorted(set(grants))):
            raise ValueError('Sorted unique records required')
        principals={e.principal_id for e in self.enrollments}
        if any(g.principal_id not in principals for g in self.grants): raise ValueError('Unenrolled grant principal')
        if any(not self.effective_at<=v.effective_at<v.expires_at<=self.expires_at for v in self.enrollments+self.grants):
            raise ValueError('Record outside configuration interval')
        return self


class CallerConfigDocument(Model):
    payload: CallerConfigPayload
    signature_hex: str = Field(strict=True, pattern=r'^[a-f0-9]{128}$')


class ConfigurationAuthorityKey(ConfigInterval):
    configuration_id: Identifier
    issuer_id: Identifier
    key_id: Digest
    public_key_hex: Digest
    algorithm: Literal['Ed25519']='Ed25519'
    status: Literal['active','revoked','retired']
    permissions: tuple[Literal['CALLER_CONFIG_SIGN'],...] = Field(max_length=1)

    @model_validator(mode='after')
    def key_binding(self):
        if sha256(bytes.fromhex(self.public_key_hex)).hexdigest()!=self.key_id:
            raise ValueError('Public key binding mismatch')
        return self


class CallerConfigCheckpoint(ConfigInterval):
    """Independent host input; never taken from the presented configuration."""
    configuration_id: Identifier
    issuer_id: Identifier
    signing_key_id: Digest
    revision: Revision
    configuration_digest: Digest


class CallerConfigHead(Model):
    configuration_id: Identifier
    revision: Revision
    configuration_digest: Digest
    accepted_at: Time


Reason = Literal['INVALID_INPUT','CONFIG_TRUST_MISMATCH','CONFIG_SIGNATURE_INVALID','CONFIG_KEY_DENIED',
    'CONFIG_EXPIRED','CONFIG_NOT_YET_VALID','CONFIG_ROLLBACK','CONFIG_FORK','CLOCK_REGRESSION',
    'IDENTITY_INVALID','REGISTRY_REVISION_MISMATCH','CREDENTIAL_INVALID','PRINCIPAL_MISMATCH',
    'GRANT_SCOPE_MISMATCH','GRANT_REVOKED','REQUEST_EXPIRED','OBSERVATION_TRUST_MISMATCH']


class ConfigRevisionDecision(Model):
    status: Literal['INITIAL','UNCHANGED','ADVANCE','REJECTED']
    audit_only: bool = Field(default=True,strict=True)
    reason_code: Reason | None = None
    proposed_head: CallerConfigHead | None = None

    @model_validator(mode='after')
    def shape(self):
        if (not self.audit_only or (self.reason_code is not None)!=(self.status=='REJECTED')
                or (self.proposed_head is not None)!=(self.status in ('INITIAL','ADVANCE'))):
            raise ValueError('Invalid decision')
        return self


class CallerConfigAuditBinding(ConfigInterval):
    audit_only: bool = Field(default=True,strict=True)
    signature_verified: bool = Field(default=True,strict=True)
    rate_limit_enforced: bool = Field(default=False,strict=True)
    configuration_id: Identifier
    configuration_revision: Revision
    configuration_digest: Digest
    configuration_key_id: Digest
    registry_revision: Revision
    principal_id: Identifier
    certificate_sha256: Digest
    connection_id: str = Field(strict=True,min_length=1,max_length=128)
    identity_audit_id: str = Field(strict=True,min_length=1,max_length=128)
    request_digest: Digest
    deployment_id: Identifier
    store_instance_id: Identifier
    observation_issuer_id: Identifier
    observation_trust_revision: Revision
    observation_trust_digest: Digest
    grant_id: Identifier
    max_requests: int | None = Field(default=None,strict=True,ge=1,le=1000000)
    window_seconds: int | None = Field(default=None,strict=True,ge=1,le=86400)

    @model_validator(mode='after')
    def audit(self):
        if (not self.audit_only or not self.signature_verified or self.rate_limit_enforced
                or (self.max_requests is None)!=(self.window_seconds is None)):
            raise ValueError('Audit evidence only')
        return self


class CallerAccessDecision(Model):
    status: Literal['MATCHED','DENIED']
    reason_code: Reason | None = None
    binding: CallerConfigAuditBinding | None = None

    @model_validator(mode='after')
    def shape(self):
        if (self.binding is not None)!=(self.status=='MATCHED') or (self.reason_code is not None)!=(self.status=='DENIED'):
            raise ValueError('Invalid access decision')
        return self


KINDS=(CallerEnrollmentRecord,CallerObservationGrant,CallerConfigPayload,CallerConfigDocument,
       ConfigurationAuthorityKey,CallerConfigCheckpoint,CallerConfigHead,ConfigRevisionDecision,
       CallerConfigAuditBinding,CallerAccessDecision)


def decode_caller_config(kind,raw):
    limit=CONFIG_LIMIT if kind in (CallerConfigPayload,CallerConfigDocument) else 16384
    if kind not in KINDS or type(raw) is not bytes or not 0<len(raw)<=limit:
        raise ValueError('Invalid record bound')
    return decode_canonical(kind,raw)


def _copy(value,kind):
    if type(value) is not kind: raise ValueError('Exact record required')
    return decode_caller_config(kind,canonical_bytes(value))


def caller_config_preimage(payload):
    return DOMAIN+canonical_bytes(_copy(payload,CallerConfigPayload))


class _Denied(ValueError): pass


def _require(condition,reason):
    if not condition: raise _Denied(reason)


def _time(now):
    _require(type(now) is int and 0<=now<=2**63-1,'INVALID_INPUT')


def _authenticate(document,key,checkpoint,now):
    _time(now)
    document=_copy(document,CallerConfigDocument)
    key=_copy(key,ConfigurationAuthorityKey); checkpoint=_copy(checkpoint,CallerConfigCheckpoint)
    p=document.payload
    _require((p.configuration_id,p.issuer_id,p.signing_key_id)==
        (key.configuration_id,key.issuer_id,key.key_id)==
        (checkpoint.configuration_id,checkpoint.issuer_id,checkpoint.signing_key_id)
        and p.revision==checkpoint.revision and record_digest(p)==checkpoint.configuration_digest,'CONFIG_TRUST_MISMATCH')
    _require(key.status=='active' and key.permissions==('CALLER_CONFIG_SIGN',)
        and key.effective_at<=p.effective_at<p.expires_at<=key.expires_at
        and key.effective_at<=now<key.expires_at,'CONFIG_KEY_DENIED')
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(bytes.fromhex(document.signature_hex),caller_config_preimage(p))
    except InvalidSignature: raise _Denied('CONFIG_SIGNATURE_INVALID') from None
    _require(now>=p.effective_at and now>=checkpoint.effective_at,'CONFIG_NOT_YET_VALID')
    _require(now<p.expires_at and now<checkpoint.expires_at,'CONFIG_EXPIRED')
    return document,key,checkpoint


def _revision(payload,head,now):
    digest=record_digest(payload)
    if head is None: status='INITIAL'
    else:
        head=_copy(head,CallerConfigHead)
        _require(head.configuration_id==payload.configuration_id,'CONFIG_TRUST_MISMATCH')
        _require(head.accepted_at<=now,'CLOCK_REGRESSION')
        _require(payload.revision>=head.revision,'CONFIG_ROLLBACK')
        if payload.revision==head.revision:
            _require(digest==head.configuration_digest,'CONFIG_FORK')
            return ConfigRevisionDecision(status='UNCHANGED')
        status='ADVANCE'
    return ConfigRevisionDecision(status=status,proposed_head=CallerConfigHead(configuration_id=payload.configuration_id,
        revision=payload.revision,configuration_digest=digest,accepted_at=now))


def evaluate_config_revision(document,*,trusted_key,trusted_checkpoint,retained_head,now):
    """Verify a complete snapshot and propose a head; no durable high-water update."""
    try:
        document,_,_=_authenticate(document,trusted_key,trusted_checkpoint,now)
        return _revision(document.payload,retained_head,now)
    except Exception as exc:
        return ConfigRevisionDecision(status='REJECTED',reason_code=str(exc) if isinstance(exc,_Denied) else 'INVALID_INPUT')


def validate_caller_request(document,request_bytes,*,identity,trusted_key,trusted_checkpoint,
                            observation_checkpoint,retained_head,now):
    """Validate host-supplied identity and configuration at one instant.

    A VerifiedIdentity object is not self-authenticating. Real TLS, enrollment
    acquisition, rate enforcement and release-time checks remain host duties.
    """
    try:
        document,key,checkpoint=_authenticate(document,trusted_key,trusted_checkpoint,now)
        p=document.payload;_revision(p,retained_head,now)
        _require(type(request_bytes) is bytes and 0<len(request_bytes)<=REQUEST_LIMIT,'INVALID_INPUT')
        request=decode_v2_record(ObservationRequest,request_bytes)
        _require(type(identity) is VerifiedIdentity,'IDENTITY_INVALID')
        _require(all(type(v) is str and 0<len(v)<=128 for v in
            (identity.principal_id,identity.connection_id,identity.audit_id)),'IDENTITY_INVALID')
        identity=VerifiedIdentity.model_validate(identity.model_dump())
        instant=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(seconds=now)
        _require(identity.verified_at<=instant<identity.valid_until,'IDENTITY_INVALID')
        _require(identity.registry_revision==p.registry_revision,'REGISTRY_REVISION_MISMATCH')
        enrollment=next((e for e in p.enrollments if e.certificate_sha256==identity.credential_id),None)
        _require(enrollment is not None and enrollment.status=='active'
            and enrollment.effective_at<=now<enrollment.expires_at,'CREDENTIAL_INVALID')
        _require(enrollment.principal_id==identity.principal_id==request.principal_id,'PRINCIPAL_MISMATCH')
        _require(request.timestamp<=now<request.expiry and request.expiry-request.timestamp<=60,'REQUEST_EXPIRED')
        _require(type(observation_checkpoint) is ObservationTrustCheckpoint,'INVALID_INPUT')
        oc=decode_v2_record(ObservationTrustCheckpoint,canonical_bytes(observation_checkpoint))
        _require((request.deployment_id,request.store_instance_id)==(oc.deployment_id,oc.store_instance_id)
            and oc.timestamp<=now<oc.expiry,'OBSERVATION_TRUST_MISMATCH')
        grants=[g for g in p.grants if g.principal_id==identity.principal_id
            and g.effective_at<=now<g.expires_at
            and (g.deployment_id,g.store_instance_id,g.observation_issuer_id,g.observation_trust_digest)==
                (request.deployment_id,request.store_instance_id,request.issuer_id,oc.trust_store_digest)]
        if grants and not any(g.status=='active' for g in grants): raise _Denied('GRANT_REVOKED')
        grants=[g for g in grants if g.status=='active']
        _require(bool(grants),'GRANT_SCOPE_MISMATCH')
        # Explicit deterministic matching; rate declarations are carried, not consumed.
        grant=sorted(grants,key=lambda g:(g.expires_at*-1,g.grant_id))[0]
        delta=identity.valid_until.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
        identity_upper=delta.days*86400+delta.seconds  # Floor; never widen fractional validity.
        upper=min(p.expires_at,key.expires_at,checkpoint.expires_at,enrollment.expires_at,
                  grant.expires_at,request.expiry,oc.expiry,identity_upper)
        _require(now<upper,'IDENTITY_INVALID')
        binding=CallerConfigAuditBinding(effective_at=now,expires_at=upper,
            configuration_id=p.configuration_id,configuration_revision=p.revision,
            configuration_digest=record_digest(p),configuration_key_id=p.signing_key_id,
            registry_revision=p.registry_revision,principal_id=identity.principal_id,
            certificate_sha256=identity.credential_id,connection_id=identity.connection_id,
            identity_audit_id=identity.audit_id,request_digest=sha256(request_bytes).hexdigest(),
            deployment_id=request.deployment_id,store_instance_id=request.store_instance_id,
            observation_issuer_id=request.issuer_id,observation_trust_revision=oc.revision,
            observation_trust_digest=oc.trust_store_digest,grant_id=grant.grant_id,
            max_requests=grant.max_requests,window_seconds=grant.window_seconds)
        return CallerAccessDecision(status='MATCHED',binding=_copy(binding,CallerConfigAuditBinding))
    except Exception as exc:
        return CallerAccessDecision(status='DENIED',reason_code=str(exc) if isinstance(exc,_Denied) else 'INVALID_INPUT')
