"""Pure synthetic authority simulation. No locks, signing, storage, or I/O."""
from datetime import datetime
from hashlib import sha256
from typing import Literal

from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.provisioning_models import Interval
from tnc.provenance.update_storage_models import UpdateStorageImage, IMAGE_LIMIT
from tnc.provenance.update_storage_validation import decode_update_storage_record, validate_update_storage_image
from tnc.provenance.reconciliation_models import (
    RECONCILIATION_LIMIT, ReconciliationEnvelope, ReconciliationRequest, ReconciliationAcceptance,
    SyntheticCheckpointEvidence,
)
from tnc.provenance.reconciliation_validation import classify_checkpoint_relationship, _checkpoint

STATE_LIMIT = 32 * 1024 * 1024
INPUT_LIMIT = 48 * 1024 * 1024
Action = Literal['SUBMIT','RECOVER','OBSERVE_CURRENT']


class SimulationGrant(Interval):
    principal_id: Identifier
    actions: tuple[Action, ...] = Field(max_length=3)

    @model_validator(mode='after')
    def ordered(self):
        if self.actions != tuple(sorted(set(self.actions))): raise ValueError('Sorted unique actions required')
        return self


class SyntheticAuthorityPolicy(Interval):
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    deployment_id: Identifier
    store_instance_id: Identifier
    revision: int = Field(strict=True, gt=0)
    grants: tuple[SimulationGrant, ...] = Field(max_length=64)

    @model_validator(mode='after')
    def ordered(self):
        ids=tuple(g.principal_id for g in self.grants)
        if ids != tuple(sorted(set(ids))): raise ValueError('Sorted unique principals required')
        return self


class SyntheticAuthorityCaller(Interval):
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    principal_id: Identifier
    deployment_id: Identifier
    store_instance_id: Identifier


class SyntheticBatchAuthorization(Interval):
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    evidence_id: Identifier
    principal_id: Identifier
    deployment_id: Identifier
    store_instance_id: Identifier
    request_hash: Digest
    predecessor_revision: int = Field(strict=True, gt=0)
    predecessor_hash: Digest
    successor_checkpoint_hash: Digest
    event_batch_hash: Digest
    policy_revision: int = Field(strict=True, gt=0)
    approved: bool = Field(strict=True)


class SimulationAcceptanceEntry(Model):
    policy: SyntheticAuthorityPolicy
    authorization: SyntheticBatchAuthorization
    request: ReconciliationRequest
    acceptance: ReconciliationAcceptance


class AuthoritySimulationState(Model):
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    initial_envelope: ReconciliationEnvelope
    current_envelope: ReconciliationEnvelope
    accepted_image: UpdateStorageImage
    policy: SyntheticAuthorityPolicy
    history: tuple[SimulationAcceptanceEntry, ...] = Field(default=(),max_length=64)


class AuthoritySimulationCommand(Model):
    action: Action
    request: ReconciliationRequest | None = None
    candidate_image: UpdateStorageImage | None = None
    challenge: Digest | None = None

    @model_validator(mode='after')
    def shape(self):
        if self.action=='OBSERVE_CURRENT':
            if self.request is not None or self.candidate_image is not None or self.challenge is None:
                raise ValueError('Observation requires only a challenge')
        elif self.request is None or self.challenge is not None or (self.action=='RECOVER' and self.candidate_image is not None):
            raise ValueError('Invalid request command')
        return self


class SyntheticCurrentObservation(Interval):
    source: Literal['SYNTHETIC'] = 'SYNTHETIC'
    principal_id: Identifier
    challenge: Digest
    envelope: ReconciliationEnvelope


class AuthoritySimulationResult(Model):
    synthetic: bool = Field(default=True,strict=True)
    audit_only: bool = Field(default=True,strict=True)
    status: Literal['ACCEPTED','RECOVERED','CURRENT','DENIED']
    reason_code: Literal['INVALID_INPUT','INVALID_STATE','ACCESS_DENIED','REQUEST_CONFLICT','CAS_CONFLICT',
                         'BATCH_DENIED','INVALID_BATCH','CAPACITY_EXCEEDED','FRESHNESS_UNAVAILABLE'] | None = None
    proposed_state: AuthoritySimulationState | None = None
    acceptance: ReconciliationAcceptance | None = None
    observation: SyntheticCurrentObservation | None = None

    @model_validator(mode='after')
    def shape(self):
        actual=(self.proposed_state is not None,self.acceptance is not None,self.observation is not None)
        expected={'ACCEPTED':(True,True,False),'RECOVERED':(False,True,False),'CURRENT':(False,False,True),'DENIED':(False,False,False)}
        if not self.synthetic or not self.audit_only or actual!=expected[self.status] or ((self.status=='DENIED') != (self.reason_code is not None)):
            raise ValueError('Invalid outcome')
        return self


class ClientCheckpointMark(Model):
    deployment_id: Identifier
    store_instance_id: Identifier
    authority_revision: int = Field(strict=True,gt=0)
    envelope_hash: Digest


class ClientObservationResult(Model):
    audit_only: bool = Field(default=True,strict=True)
    status: Literal['UNCHANGED','ADVANCE_PROPOSED','STALE_HISTORICAL','FORK','INDETERMINATE']
    proposed_mark: ClientCheckpointMark | None = None

    @model_validator(mode='after')
    def shape(self):
        if not self.audit_only or ((self.status=='ADVANCE_PROPOSED') != (self.proposed_mark is not None)):
            raise ValueError('No promotion from blocked observations')
        return self


_SMALL=(SimulationGrant,SyntheticAuthorityPolicy,SyntheticAuthorityCaller,SyntheticBatchAuthorization,
        SimulationAcceptanceEntry,SyntheticCurrentObservation,ClientCheckpointMark,ClientObservationResult,
        ReconciliationEnvelope,ReconciliationRequest)


def decode_simulation_record(kind,data):
    limit = STATE_LIMIT if kind in (AuthoritySimulationState,AuthoritySimulationResult) else IMAGE_LIMIT+RECONCILIATION_LIMIT if kind is AuthoritySimulationCommand else RECONCILIATION_LIMIT
    if kind not in _SMALL+(AuthoritySimulationState,AuthoritySimulationResult,AuthoritySimulationCommand) or type(data) is not bytes or not 0<len(data)<=limit:
        raise ValueError('Invalid bounded simulation record')
    return decode_canonical(kind,data)


def _copy(value,kind):
    if type(value) is not kind: raise ValueError('Exact typed record required')
    return decode_simulation_record(kind,canonical_bytes(value))


class _Denied(ValueError):
    def __init__(self,reason): self.reason=reason


def _require(condition,reason):
    if not condition: raise _Denied(reason)


def _active(value,at): return value.valid_from<=at<value.valid_until


def _scope(value): return value.deployment_id,value.store_instance_id


def _permission(policy,principal,action,at):
    return _active(policy,at) and any(g.principal_id==principal and action in g.actions and _active(g,at) for g in policy.grants)


def _prefix(image,count):
    _require(count<=len(image.events),'INVALID_STATE')
    events=image.events[:count]; head=image.base_head
    for event in events:
        if event.payload.kind=='COMMIT': head=event.payload.head
    return image.model_copy(update={'events':events,'head':head})


def _freshness(envelope):
    # Explicit simulation-derived evidence; never used outside this pure harness.
    return SyntheticCheckpointEvidence(deployment_id=envelope.deployment_id,store_instance_id=envelope.store_instance_id,
        current_authority_revision=envelope.authority_revision,current_envelope_hash=record_digest(envelope),
        valid_from=envelope.valid_from,valid_until=envelope.valid_until)


def _make_acceptance(previous,request,image,policy,authorization,at):
    _require(_scope(request)==_scope(previous) and request.expected_authority_revision==previous.authority_revision
        and request.expected_envelope_hash==record_digest(previous),'CAS_CONFLICT')
    _require(_scope(policy)==_scope(previous) and _permission(policy,request.principal_id,'SUBMIT',at),'ACCESS_DENIED')
    _require(_active(request,at) and _active(authorization,at) and authorization.approved
        and _scope(authorization)==_scope(request) and authorization.principal_id==request.principal_id
        and authorization.request_hash==record_digest(request)
        and authorization.predecessor_revision==request.expected_authority_revision
        and authorization.predecessor_hash==request.expected_envelope_hash
        and authorization.successor_checkpoint_hash==record_digest(request.successor_checkpoint)
        and authorization.event_batch_hash==request.event_batch_hash and authorization.policy_revision==policy.revision,'BATCH_DENIED')
    comparison=classify_checkpoint_relationship(image,previous,observed_store_instance_id=previous.store_instance_id,
        evidence=_freshness(previous),now=at)
    _require(comparison.relationship=='DATABASE_EXTENSION_PENDING' and comparison.suffix_batch_hash==request.event_batch_hash
        and canonical_bytes(_checkpoint(image))==canonical_bytes(request.successor_checkpoint),'INVALID_BATCH')
    expiry=min(request.valid_until,authorization.valid_until,policy.valid_until,
        next(g.valid_until for g in policy.grants if g.principal_id==request.principal_id))
    successor=ReconciliationEnvelope(deployment_id=previous.deployment_id,store_instance_id=previous.store_instance_id,
        authority_revision=previous.authority_revision+1,previous_envelope_hash=record_digest(previous),
        issuer_id=previous.issuer_id,key_id=previous.key_id,checkpoint=request.successor_checkpoint,valid_from=at,valid_until=expiry)
    assigned_id=sha256(b'TNC-SIM-ACCEPTANCE\x00v1\x00'+record_digest(previous).encode('ascii')+b'\x00'+str(successor.authority_revision).encode('ascii')).hexdigest()
    return ReconciliationAcceptance(acceptance_id='sim-'+assigned_id,request_id=request.request_id,request_hash=record_digest(request),
        principal_id=request.principal_id,deployment_id=request.deployment_id,store_instance_id=request.store_instance_id,
        predecessor_revision=previous.authority_revision,predecessor_hash=record_digest(previous),accepted_at=at,
        successor=successor,event_batch_hash=request.event_batch_hash,policy_revision=policy.revision,
        independent_evidence_hash=record_digest(authorization))


def _validate_state(state,anchor,now):
    _require(canonical_bytes(state.initial_envelope)==canonical_bytes(anchor) and anchor.authority_revision==1,'INVALID_STATE')
    image=decode_update_storage_record(UpdateStorageImage,canonical_bytes(state.accepted_image))
    _require(validate_update_storage_image(image,trusted_checkpoint=state.current_envelope.checkpoint).status=='CONSISTENT'
        and not any(e.recorded_at>now for e in image.events),'INVALID_STATE')
    _require(canonical_bytes(_checkpoint(_prefix(image,anchor.checkpoint.event_count)))==canonical_bytes(anchor.checkpoint),'INVALID_STATE')
    previous=anchor; prior_policy=None; last_time=None; ids=set(); acceptance_ids=set()
    for entry in state.history:
        _copy(entry,SimulationAcceptanceEntry)
        _require(entry.request.request_id not in ids and entry.acceptance.acceptance_id not in acceptance_ids,'INVALID_STATE')
        _require(entry.acceptance.accepted_at<=now and (last_time is None or last_time<=entry.acceptance.accepted_at),'INVALID_STATE')
        if prior_policy is not None:
            _require(entry.policy.revision>=prior_policy.revision and
                (entry.policy.revision>prior_policy.revision or canonical_bytes(entry.policy)==canonical_bytes(prior_policy)),'INVALID_STATE')
        candidate=_prefix(image,entry.acceptance.successor.checkpoint.event_count)
        try: expected=_make_acceptance(previous,entry.request,candidate,entry.policy,entry.authorization,entry.acceptance.accepted_at)
        except Exception: raise _Denied('INVALID_STATE') from None
        _require(canonical_bytes(expected)==canonical_bytes(entry.acceptance),'INVALID_STATE')
        ids.add(entry.request.request_id); acceptance_ids.add(entry.acceptance.acceptance_id)
        previous=entry.acceptance.successor; prior_policy=entry.policy; last_time=entry.acceptance.accepted_at
    _require(canonical_bytes(previous)==canonical_bytes(state.current_envelope) and _scope(state.policy)==_scope(anchor),'INVALID_STATE')
    if prior_policy is not None:
        _require(state.policy.revision>=prior_policy.revision and
            (state.policy.revision>prior_policy.revision or canonical_bytes(state.policy)==canonical_bytes(prior_policy)),'INVALID_STATE')


def simulate_authority(state,command,*,caller,batch_authorization=None,trusted_initial_envelope,now):
    """Return proposed immutable state; the test driver selects when to apply it."""
    try:
        _require(type(now) is datetime and now.utcoffset() is not None,'INVALID_INPUT')
        state=_copy(state,AuthoritySimulationState); command=_copy(command,AuthoritySimulationCommand)
        caller=_copy(caller,SyntheticAuthorityCaller); anchor=_copy(trusted_initial_envelope,ReconciliationEnvelope)
        total=sum(len(canonical_bytes(v)) for v in (state,command,caller,anchor))
        if batch_authorization is not None: total+=len(canonical_bytes(batch_authorization))
        _require(total<=INPUT_LIMIT,'CAPACITY_EXCEEDED')
        _validate_state(state,anchor,now)
        _require(_scope(caller)==_scope(anchor) and _active(caller,now),'ACCESS_DENIED')
        if command.action=='OBSERVE_CURRENT':
            _require(_permission(state.policy,caller.principal_id,'OBSERVE_CURRENT',now),'ACCESS_DENIED')
            _require(_active(state.current_envelope,now),'FRESHNESS_UNAVAILABLE')
            expiry=min(caller.valid_until,state.policy.valid_until,state.current_envelope.valid_until,
                next(g.valid_until for g in state.policy.grants if g.principal_id==caller.principal_id))
            observation=SyntheticCurrentObservation(principal_id=caller.principal_id,challenge=command.challenge,
                envelope=state.current_envelope,valid_from=now,valid_until=expiry)
            return AuthoritySimulationResult(status='CURRENT',observation=observation)
        request=_copy(command.request,ReconciliationRequest)
        _require(_scope(request)==_scope(caller) and request.principal_id==caller.principal_id,'ACCESS_DENIED')
        # Before lookup, require at least one applicable right. Existing requests
        # additionally require recovery; new requests require submit.
        rights=any(_permission(state.policy,caller.principal_id,a,now) for a in ('SUBMIT','RECOVER'))
        _require(rights,'ACCESS_DENIED')
        existing=next((e for e in state.history if e.request.request_id==request.request_id),None)
        if existing is not None:
            _require(existing.request.principal_id==caller.principal_id and
                _permission(state.policy,caller.principal_id,'RECOVER',now),'ACCESS_DENIED')
            _require(canonical_bytes(existing.request)==canonical_bytes(request),'REQUEST_CONFLICT')
            return AuthoritySimulationResult(status='RECOVERED',acceptance=existing.acceptance)
        _require(command.action=='SUBMIT' and _permission(state.policy,caller.principal_id,'SUBMIT',now),'ACCESS_DENIED')
        _require(len(state.history)<64,'CAPACITY_EXCEEDED')
        _require(command.candidate_image is not None,'INVALID_BATCH')
        authorization=_copy(batch_authorization,SyntheticBatchAuthorization)
        image=decode_update_storage_record(UpdateStorageImage,canonical_bytes(command.candidate_image))
        acceptance=_make_acceptance(state.current_envelope,request,image,state.policy,authorization,now)
        entry=SimulationAcceptanceEntry(policy=state.policy,authorization=authorization,request=request,acceptance=acceptance)
        proposed=_copy(state.model_copy(update={'current_envelope':acceptance.successor,'accepted_image':image,
            'history':state.history+(entry,)}),AuthoritySimulationState)
        _validate_state(proposed,anchor,now)
        result=AuthoritySimulationResult(status='ACCEPTED',proposed_state=proposed,acceptance=acceptance)
        _require(len(canonical_bytes(result))<=STATE_LIMIT,'CAPACITY_EXCEEDED')
        return result
    except _Denied as exc: reason=exc.reason
    except Exception: reason='INVALID_INPUT'
    return AuthoritySimulationResult(status='DENIED',reason_code=reason)


def evaluate_client_observation(mark,observation,*,expected_challenge,principal_id,chain=(),now):
    """Pure high-water comparison using a synthetic fresh observation."""
    def result(status,proposed=None): return ClientObservationResult(status=status,proposed_mark=proposed)
    try:
        if type(now) is not datetime or now.utcoffset() is None: raise ValueError('Aware time required')
        mark=_copy(mark,ClientCheckpointMark); observation=_copy(observation,SyntheticCurrentObservation)
        current=observation.envelope
        if (observation.challenge!=expected_challenge or observation.principal_id!=principal_id or
                not _active(observation,now) or not _active(current,now)):
            return result('INDETERMINATE')
        if _scope(mark)!=_scope(current): return result('FORK')
        if current.authority_revision<mark.authority_revision: return result('STALE_HISTORICAL')
        if current.authority_revision==mark.authority_revision:
            return result('UNCHANGED' if record_digest(current)==mark.envelope_hash else 'FORK')
        if type(chain) is not tuple or not 0<len(chain)<=64: return result('INDETERMINATE')
        revision,digest=mark.authority_revision,mark.envelope_hash
        for link in chain:
            link=_copy(link,ReconciliationEnvelope)
            if link.authority_revision>revision+1: return result('INDETERMINATE')
            if (_scope(link)!=_scope(mark) or link.authority_revision!=revision+1 or link.previous_envelope_hash!=digest
                    or link.issuer_id!=current.issuer_id or link.key_id!=current.key_id):
                return result('FORK')
            revision,digest=link.authority_revision,record_digest(link)
        if revision!=current.authority_revision or digest!=record_digest(current): return result('INDETERMINATE')
        return result('ADVANCE_PROPOSED',ClientCheckpointMark(deployment_id=current.deployment_id,
            store_instance_id=current.store_instance_id,authority_revision=revision,envelope_hash=digest))
    except Exception: return result('INDETERMINATE')


def validate_simulation_state(state, *, trusted_initial_envelope, now):
    """Return a bounded validated copy, without authentication or freshness claims."""
    try:
        if type(now) is not datetime or now.utcoffset() is None:
            raise ValueError('Aware time required')
        state = _copy(state, AuthoritySimulationState)
        anchor = _copy(trusted_initial_envelope, ReconciliationEnvelope)
        _validate_state(state, anchor, now)
        return state
    except Exception:
        raise ValueError('INVALID_SIMULATION_STATE') from None
