"""Pure request binding contracts. Host identity inputs are not authentication proof."""
from datetime import datetime,timezone
from hashlib import sha256
from typing import Literal
from pydantic import Field,model_validator
from tnc.provenance.authorization_models import Model,Digest,Identifier,canonical_bytes,decode_canonical,record_digest
from tnc.provenance.host_auth import VerifiedIdentity
from tnc.provenance.provisioning_models import Interval
from tnc.provenance.reconciliation_verifier import ObservationRequest,decode_v2_record

REQUEST_LIMIT=16384


class ObservationGrant(Interval):
    grant_id: Identifier
    principal_id: Identifier
    deployment_id: Identifier
    store_instance_id: Identifier
    action: Literal['AUTHORITY_OBSERVE_CURRENT']='AUTHORITY_OBSERVE_CURRENT'


class ObservationPolicy(Interval):
    revision: int=Field(strict=True,gt=0)
    grants: tuple[ObservationGrant,...]=Field(max_length=64)
    @model_validator(mode='after')
    def inventory(self):
        ids=tuple(g.grant_id for g in self.grants)
        if ids!=tuple(sorted(set(ids))): raise ValueError('Sorted unique grants required')
        return self


class ObservationHostContext(Interval):
    deployment_id: Identifier
    store_instance_id: Identifier
    issuer_id: Identifier
    registry_revision: int=Field(strict=True,gt=0)
    policy_revision: int=Field(strict=True,gt=0)
    policy_digest: Digest


class ObservationRequestBinding(Interval):
    request_digest: Digest
    principal_id: Identifier
    credential_id: Digest
    connection_id: str=Field(min_length=1,max_length=128)
    identity_audit_id: str=Field(min_length=1,max_length=128)
    identity_verified_at: datetime
    registry_revision: int=Field(strict=True,gt=0)
    deployment_id: Identifier
    store_instance_id: Identifier
    issuer_id: Identifier
    policy_revision: int=Field(strict=True,gt=0)
    policy_digest: Digest
    grant_id: Identifier
    audit_only: bool=Field(default=True,strict=True)
    @model_validator(mode='after')
    def audit(self):
        if not self.audit_only or self.identity_verified_at>self.valid_from: raise ValueError('Invalid audit record')
        return self


class BindingOutcome(Model):
    status: Literal['BOUND','DENIED']
    reason_code: Literal['INVALID_INPUT','ACCESS_DENIED'] | None=None
    binding: ObservationRequestBinding | None=None
    @model_validator(mode='after')
    def shape(self):
        if (self.status=='BOUND')!=(self.binding is not None) or (self.status=='DENIED')!=(self.reason_code is not None):
            raise ValueError('Invalid outcome')
        return self


KINDS=(ObservationGrant,ObservationPolicy,ObservationHostContext,ObservationRequestBinding,BindingOutcome)


def decode_binding_record(kind,data):
    if kind not in KINDS or type(data) is not bytes or not 0<len(data)<=65536: raise ValueError('Invalid record')
    return decode_canonical(kind,data)


def _copy(value,kind):
    if type(value) is not kind: raise ValueError('Exact record required')
    return decode_binding_record(kind,canonical_bytes(value))


def bind_observation_request(request_bytes,*,identity,policy,host_context,now):
    """Phase 1 only: trusted host supplies identity/context; no socket or lookup."""
    def denied(reason='ACCESS_DENIED'): return BindingOutcome(status='DENIED',reason_code=reason)
    try:
        if type(request_bytes) is not bytes or not 0<len(request_bytes)<=REQUEST_LIMIT: return denied('INVALID_INPUT')
        if type(now) is not datetime or now.utcoffset() is None: return denied('INVALID_INPUT')
        if type(identity) is not VerifiedIdentity: return denied('INVALID_INPUT')
        # Bound host identity strings before copying the identity fixture.
        if any(type(v) is not str or not 0<len(v)<=128 for v in (identity.principal_id,identity.connection_id,identity.audit_id)):
            return denied('INVALID_INPUT')
        identity=VerifiedIdentity.model_validate(identity.model_dump())
        policy=_copy(policy,ObservationPolicy); context=_copy(host_context,ObservationHostContext)
        request=decode_v2_record(ObservationRequest,request_bytes)
        active=lambda v:v.valid_from<=now<v.valid_until
        if not (identity.verified_at<=now<identity.valid_until and identity.registry_revision==context.registry_revision
                and active(policy) and active(context) and policy.revision==context.policy_revision
                and record_digest(policy)==context.policy_digest): return denied()
        if (request.principal_id!=identity.principal_id or request.deployment_id!=context.deployment_id
                or request.store_instance_id!=context.store_instance_id or request.issuer_id!=context.issuer_id): return denied()
        start=datetime.fromtimestamp(request.timestamp,timezone.utc); end=datetime.fromtimestamp(request.expiry,timezone.utc)
        if not start<=now<end or request.expiry-request.timestamp>60: return denied()
        matches=[g for g in policy.grants if active(g) and g.principal_id==identity.principal_id
            and g.deployment_id==context.deployment_id and g.store_instance_id==context.store_instance_id]
        if not matches: return denied()
        # Pick the longest applicable grant, then stable grant ID for auditability.
        grant=sorted(matches,key=lambda g:(-g.valid_until.timestamp(),g.grant_id))[0]
        bound=ObservationRequestBinding(request_digest=sha256(request_bytes).hexdigest(),principal_id=identity.principal_id,
            credential_id=identity.credential_id,connection_id=identity.connection_id,identity_audit_id=identity.audit_id,
            identity_verified_at=identity.verified_at,registry_revision=identity.registry_revision,
            deployment_id=context.deployment_id,store_instance_id=context.store_instance_id,issuer_id=context.issuer_id,
            policy_revision=policy.revision,policy_digest=context.policy_digest,grant_id=grant.grant_id,
            valid_from=now,valid_until=min(end,identity.valid_until,policy.valid_until,context.valid_until,grant.valid_until))
        return BindingOutcome(status='BOUND',binding=bound)
    except Exception: return denied('INVALID_INPUT')
