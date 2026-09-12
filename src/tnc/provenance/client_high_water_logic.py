"""Pure client high-water simulation. Host trust inputs are synthetic fixtures."""
from typing import Literal
from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.reconciliation_verifier import (
    Time, Revision, SignedObservation, ObservationRequest, ObservationTrustStore,
    ObservationTrustCheckpoint, verify_observation, decode_v2_record,
)

STATE_LIMIT=16*1024*1024
REQUEST_LIMIT=2*1024*1024


class ClientAnchor(Model):
    deployment_id: Identifier
    store_instance_id: Identifier
    principal_id: Identifier
    authority_revision: Revision
    envelope_digest: Digest
    accepted_timestamp: Time


class AdvancementRequest(Model):
    operation_id: Identifier
    response: SignedObservation
    retained_request: ObservationRequest
    trust_store: ObservationTrustStore
    trusted_checkpoint: ObservationTrustCheckpoint


class ClientReceipt(Model):
    operation_id: Identifier
    request_digest: Digest
    response_digest: Digest
    local_sequence: int=Field(strict=True,gt=0)
    accepted_timestamp: Time
    authority_revision: Revision
    envelope_digest: Digest
    signing_key_id: Digest
    status: Literal['UNCHANGED','VALID_ADVANCE']


class ClientHistoryEntry(Model):
    request: AdvancementRequest
    receipt: ClientReceipt


class ClientHighWaterState(Model):
    source: Literal['SYNTHETIC']='SYNTHETIC'
    anchor: ClientAnchor
    authority_revision: Revision
    envelope_digest: Digest
    accepted_timestamp: Time
    signing_key_id: Digest | None=None
    local_sequence: int=Field(strict=True,ge=0)
    history: tuple[ClientHistoryEntry,...]=Field(default=(),max_length=64)


class TransitionOutcome(Model):
    audit_only: bool=Field(default=True,strict=True)
    status: Literal['UNCHANGED','VALID_ADVANCE','RECOVERED','STALE','CONFLICT_FORK','PREDECESSOR_MISMATCH','ERROR']
    reason_code: Literal['INVALID_INPUT','INVALID_STATE','ACCESS_DENIED','OPERATION_CONFLICT','VERIFICATION_FAILED','CAPACITY_EXCEEDED'] | None=None
    proposed_state: ClientHighWaterState | None=None
    receipt: ClientReceipt | None=None
    @model_validator(mode='after')
    def shape(self):
        accepted=self.status in ('UNCHANGED','VALID_ADVANCE')
        if (not self.audit_only or (self.proposed_state is not None)!=accepted
                or (self.receipt is not None)!=(accepted or self.status=='RECOVERED')
                or (self.reason_code is not None)!=(self.status=='ERROR')): raise ValueError('Invalid outcome')
        return self


KINDS=(ClientAnchor,AdvancementRequest,ClientReceipt,ClientHistoryEntry,ClientHighWaterState,TransitionOutcome)


def decode_client_record(kind,data):
    limit=STATE_LIMIT if kind in (ClientHighWaterState,TransitionOutcome) else REQUEST_LIMIT+65536 if kind is ClientHistoryEntry else REQUEST_LIMIT if kind is AdvancementRequest else 65536
    if kind not in KINDS or type(data) is not bytes or not 0<len(data)<=limit: raise ValueError('Invalid record')
    return decode_canonical(kind,data)


def _copy(value,kind):
    if type(value) is not kind: raise ValueError('Exact record required')
    return decode_client_record(kind,canonical_bytes(value))


def _scope(value): return value.deployment_id,value.store_instance_id


def _candidate(anchor,revision,digest,request,sequence,now):
    r=request.retained_request
    if _scope(r)!=_scope(anchor) or r.principal_id!=anchor.principal_id: return 'ERROR',None
    result=verify_observation(request.response,expected_request=r,trust_store=request.trust_store,
        trusted_checkpoint=request.trusted_checkpoint,now=now)
    if result.status!='VERIFIED': return 'ERROR',None
    p=result.checked_payload
    if p.authority_revision<revision: return 'STALE',None
    if p.authority_revision==revision:
        if p.envelope_digest!=digest: return 'CONFLICT_FORK',None
        status='UNCHANGED'
    else:
        if p.authority_revision!=revision+1 or p.envelope.previous_envelope_hash!=digest:
            return 'PREDECESSOR_MISMATCH',None
        status='VALID_ADVANCE'
    receipt=ClientReceipt(operation_id=request.operation_id,request_digest=record_digest(request),
        response_digest=record_digest(request.response),local_sequence=sequence,accepted_timestamp=now,
        authority_revision=p.authority_revision,envelope_digest=p.envelope_digest,signing_key_id=p.signing_key_id,status=status)
    return status,receipt


def _validate(state,anchor,now):
    if canonical_bytes(state.anchor)!=canonical_bytes(anchor): raise ValueError()
    revision,digest,at,key=anchor.authority_revision,anchor.envelope_digest,anchor.accepted_timestamp,None
    ids=set()
    if at>now: raise ValueError()
    for sequence,entry in enumerate(state.history,1):
        _copy(entry,ClientHistoryEntry)
        if entry.request.operation_id in ids or not at<=entry.receipt.accepted_timestamp<=now: raise ValueError()
        status,receipt=_candidate(anchor,revision,digest,entry.request,sequence,entry.receipt.accepted_timestamp)
        if receipt is None or canonical_bytes(receipt)!=canonical_bytes(entry.receipt): raise ValueError()
        revision,digest,at,key=receipt.authority_revision,receipt.envelope_digest,receipt.accepted_timestamp,receipt.signing_key_id
        ids.add(entry.request.operation_id)
    if (state.authority_revision,state.envelope_digest,state.accepted_timestamp,state.signing_key_id,state.local_sequence)!=(revision,digest,at,key,len(state.history)):
        raise ValueError()


def evaluate_client_transition(state,request,*,trusted_initial_anchor,caller_principal,now):
    """Propose immutable state only. Caller and trust snapshots are host-fixture inputs."""
    def error(reason): return TransitionOutcome(status='ERROR',reason_code=reason)
    try:
        if type(now) is not int or now<0: return error('INVALID_INPUT')
        anchor=_copy(trusted_initial_anchor,ClientAnchor)
        if type(caller_principal) is not str or caller_principal!=anchor.principal_id: return error('ACCESS_DENIED')
        state=_copy(state,ClientHighWaterState); request=_copy(request,AdvancementRequest)
        try: _validate(state,anchor,now)
        except Exception: return error('INVALID_STATE')
        if _scope(request.retained_request)!=_scope(anchor) or request.retained_request.principal_id!=caller_principal:
            return error('ACCESS_DENIED')
        existing=next((e for e in state.history if e.request.operation_id==request.operation_id),None)
        if existing is not None:
            if canonical_bytes(existing.request)!=canonical_bytes(request): return error('OPERATION_CONFLICT')
            return TransitionOutcome(status='RECOVERED',receipt=existing.receipt)
        status,receipt=_candidate(anchor,state.authority_revision,state.envelope_digest,request,state.local_sequence+1,now)
        if status=='ERROR': return error('VERIFICATION_FAILED')
        if receipt is None: return TransitionOutcome(status=status)
        if len(state.history)>=64: return error('CAPACITY_EXCEEDED')
        proposed=state.model_copy(update={'authority_revision':receipt.authority_revision,'envelope_digest':receipt.envelope_digest,
            'accepted_timestamp':now,'signing_key_id':receipt.signing_key_id,'local_sequence':receipt.local_sequence,
            'history':state.history+(ClientHistoryEntry(request=request,receipt=receipt),)})
        proposed=_copy(proposed,ClientHighWaterState)
        _validate(proposed,anchor,now)
        result=TransitionOutcome(status=status,proposed_state=proposed,receipt=receipt)
        if len(canonical_bytes(result))>STATE_LIMIT: return error('CAPACITY_EXCEEDED')
        return result
    except Exception: return error('INVALID_INPUT')
