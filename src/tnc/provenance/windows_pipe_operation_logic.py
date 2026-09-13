"""Pure fake overlapped-operation ledger. No native I/O or resource release."""
from typing import Literal
from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Identifier, canonical_bytes, decode_canonical

MAX_EVENTS=64
MAX_RECORD_BYTES=65536


class PipeOperationPlan(Model):
    profile: Literal['tnc-pipe-operation-test-v1']='tnc-pipe-operation-test-v1'
    operation_id: Identifier
    kind: Literal['CONNECT','READ','WRITE']
    pipe_lease_id: Identifier
    event_id: Identifier
    overlapped_id: Identifier
    buffer_id: Identifier
    buffer_size: int=Field(strict=True,ge=0,le=65536)
    created_tick: int=Field(strict=True,ge=0,le=2**63-1)
    request_deadline: int=Field(strict=True,ge=0,le=2**63-1)
    cleanup_deadline: int=Field(strict=True,ge=0,le=2**63-1)

    @model_validator(mode='after')
    def bindings(self):
        resources=(self.pipe_lease_id,self.event_id,self.overlapped_id,self.buffer_id)
        if len(set(resources))!=4 or self.operation_id in resources:
            raise ValueError('Distinct fixture identities required')
        if not self.created_tick<self.request_deadline<self.cleanup_deadline:
            raise ValueError('Ordered deadlines required')
        if self.request_deadline-self.created_tick>5000 or self.cleanup_deadline-self.request_deadline>1000:
            raise ValueError('Bounded millisecond budgets required')
        if (self.kind=='CONNECT')!=(self.buffer_size==0):
            raise ValueError('Connect has no data buffer; read/write require capacity')
        return self


class PipeOperationEvent(Model):
    sequence: int=Field(strict=True,ge=1,le=MAX_EVENTS)
    operation_id: Identifier
    overlapped_id: Identifier
    tick: int=Field(strict=True,ge=0,le=2**63-1)
    action: Literal['SUBMIT','POLL','CANCEL','EXPIRE','REVERT_FAILED','DISPOSE']
    outcome: Literal['NONE','PENDING','INCOMPLETE','SUCCESS','ABORTED','ERROR',
                     'CANCEL_ACCEPTED','NOT_FOUND','CANCEL_FAILED']='NONE'
    transferred: int=Field(strict=True,ge=0,le=65536,default=0)


class PipeOperationLedger(Model):
    source: Literal['FAKE_COMPLETION_LEDGER']='FAKE_COMPLETION_LEDGER'
    plan: PipeOperationPlan
    events: tuple[PipeOperationEvent,...]=Field(default=(),max_length=MAX_EVENTS)


class PipeOperationState(Model):
    stage: Literal['CREATED','PENDING','TERMINAL','DISPOSED']
    terminal: Literal['NONE','SUCCESS','ABORTED','ERROR','NOT_SUBMITTED']='NONE'
    transferred: int=Field(strict=True,ge=0,le=65536,default=0)
    cancel_requested: bool=Field(strict=True,default=False)
    response_suppressed: bool=Field(strict=True,default=False)
    shutdown_required: bool=Field(strict=True,default=False)
    quarantined: bool=Field(strict=True,default=False)
    held_resources: tuple[Identifier,...]=Field(max_length=4)
    audit_only: Literal[True]=True

    @property
    def result_available(self):
        return (self.stage=='TERMINAL' and self.terminal=='SUCCESS'
                and not self.response_suppressed and not self.shutdown_required)


class PipeTransitionResult(Model):
    status: Literal['PROPOSED','REJECTED']
    reason: Identifier
    proposed_ledger: PipeOperationLedger | None=None
    state: PipeOperationState | None=None
    audit_only: Literal[True]=True


def decode_pipe_record(kind,raw):
    if (kind not in (PipeOperationPlan,PipeOperationEvent,PipeOperationLedger)
            or type(raw) is not bytes or not 0<len(raw)<=MAX_RECORD_BYTES):
        raise ValueError('Bounded canonical fixture record required')
    return decode_canonical(kind,raw)


def _copy(kind,value):
    if type(value) is not kind:raise ValueError('Exact fixture record required')
    return decode_pipe_record(kind,canonical_bytes(value))


def _step(plan,state,event):
    if (event.operation_id,event.overlapped_id)!=(plan.operation_id,plan.overlapped_id):
        raise ValueError('OPERATION_MISMATCH')
    if state.stage=='DISPOSED':raise ValueError('ALREADY_DISPOSED')
    if event.transferred and (event.outcome!='SUCCESS' or event.action not in ('SUBMIT','POLL')):
        raise ValueError('INVALID_TRANSFER_COUNT')
    if event.transferred>plan.buffer_size:raise ValueError('INVALID_TRANSFER_COUNT')
    values=state.model_dump()
    if event.tick>=plan.request_deadline:values['response_suppressed']=True
    if state.stage=='PENDING' and event.tick>=plan.cleanup_deadline:
        values.update(quarantined=True,shutdown_required=True,response_suppressed=True)
    action,outcome=event.action,event.outcome
    if action=='SUBMIT':
        if state.stage!='CREATED' or state.shutdown_required:raise ValueError('INVALID_TRANSITION')
        if event.tick>=plan.request_deadline:raise ValueError('DEADLINE_EXCEEDED')
        if outcome=='PENDING':values['stage']='PENDING'
        elif outcome in ('SUCCESS','ERROR'):
            values.update(stage='TERMINAL',terminal=outcome,transferred=event.transferred)
        else:raise ValueError('INVALID_SUBMISSION_RESULT')
    elif action=='POLL':
        if state.stage!='PENDING':raise ValueError('INVALID_TRANSITION')
        if outcome=='INCOMPLETE':pass
        elif outcome in ('SUCCESS','ABORTED','ERROR'):
            values.update(stage='TERMINAL',terminal=outcome,transferred=event.transferred)
        else:raise ValueError('INVALID_COMPLETION_RESULT')
    elif action=='CANCEL':
        if state.stage!='PENDING' or outcome not in ('CANCEL_ACCEPTED','NOT_FOUND','CANCEL_FAILED'):
            raise ValueError('INVALID_CANCELLATION')
        values.update(cancel_requested=True,response_suppressed=True)
    elif action=='EXPIRE':
        if outcome!='NONE' or event.tick<plan.request_deadline:raise ValueError('INVALID_EXPIRATION')
        if state.stage=='CREATED':values.update(stage='TERMINAL',terminal='NOT_SUBMITTED')
    elif action=='REVERT_FAILED':
        if outcome!='NONE':raise ValueError('INVALID_TRANSITION')
        values.update(shutdown_required=True,response_suppressed=True)
        if state.stage=='PENDING':values['quarantined']=True
        if state.stage=='CREATED':values.update(stage='TERMINAL',terminal='NOT_SUBMITTED')
    elif action=='DISPOSE':
        if state.stage!='TERMINAL' or outcome!='NONE':raise ValueError('COMPLETION_UNCONFIRMED')
        values.update(stage='DISPOSED',held_resources=())
    return PipeOperationState.model_validate(values)


def replay_pipe_ledger(ledger):
    """Validate every transition; no externally supplied state projection is trusted."""
    ledger=_copy(PipeOperationLedger,ledger)
    plan=ledger.plan
    state=PipeOperationState(stage='CREATED',held_resources=(plan.pipe_lease_id,plan.event_id,plan.overlapped_id,plan.buffer_id))
    tick=plan.created_tick
    for sequence,event in enumerate(ledger.events,1):
        if event.sequence!=sequence:raise ValueError('SEQUENCE_MISMATCH')
        if event.tick<tick:raise ValueError('CLOCK_REGRESSION')
        state=_step(plan,state,event);tick=event.tick
    return state


def propose_pipe_event(ledger,event):
    """Return an immutable proposal. Applying it does not perform native disposal."""
    try:
        ledger=_copy(PipeOperationLedger,ledger);event=_copy(PipeOperationEvent,event)
        replay_pipe_ledger(ledger)
        if len(ledger.events)>=MAX_EVENTS:return PipeTransitionResult(status='REJECTED',reason='CAPACITY_EXCEEDED')
        proposed=PipeOperationLedger(plan=ledger.plan,events=ledger.events+(event,))
        state=replay_pipe_ledger(proposed)
        return PipeTransitionResult(status='PROPOSED',reason='VALID_TRANSITION',proposed_ledger=proposed,state=state)
    except (ValueError,TypeError,AttributeError):
        return PipeTransitionResult(status='REJECTED',reason='INVALID_LEDGER_OR_EVENT')


def validate_pipe_ownership(ledgers):
    """Bounded fake allocation inventory, with IDs never recycled in this image."""
    if type(ledgers) is not tuple or not 1<=len(ledgers)<=16:
        raise ValueError('Bounded tuple of operation ledgers required')
    seen=set();states=[]
    for ledger in ledgers:
        ledger=_copy(PipeOperationLedger,ledger)
        plan=ledger.plan
        identities=(plan.operation_id,plan.pipe_lease_id,plan.event_id,plan.overlapped_id,plan.buffer_id)
        if seen.intersection(identities):raise ValueError('Resource identity reused')
        seen.update(identities)
        states.append(replay_pipe_ledger(ledger))
    return tuple(states)
