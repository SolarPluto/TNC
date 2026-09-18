"""Deterministic operation histories and fake resource ownership, without I/O."""
import pytest
from tnc.provenance.windows_pipe_operation_logic import *


@pytest.fixture
def ledger():
    return PipeOperationLedger(plan=PipeOperationPlan(operation_id='operation',kind='READ',pipe_lease_id='pipe',
        event_id='event',overlapped_id='overlapped',buffer_id='buffer',buffer_size=128,
        created_tick=10,request_deadline=20,cleanup_deadline=30))


def event(ledger,action,outcome='NONE',tick=11,**kw):
    return PipeOperationEvent(sequence=len(ledger.events)+1,operation_id=ledger.plan.operation_id,
        overlapped_id=ledger.plan.overlapped_id,tick=tick,action=action,outcome=outcome,**kw)


def step(ledger,action,outcome='NONE',tick=11,**kw):
    result=propose_pipe_event(ledger,event(ledger,action,outcome,tick,**kw))
    assert result.status=='PROPOSED'
    assert result.audit_only and result.state==replay_pipe_ledger(result.proposed_ledger)
    return result.proposed_ledger


def test_initial_ownership_and_immutable_proposals(ledger):
    state=replay_pipe_ledger(ledger)
    assert state.stage=='CREATED' and len(state.held_resources)==4 and not state.result_available
    proposal=propose_pipe_event(ledger,event(ledger,'SUBMIT','PENDING'))
    assert proposal.state.stage=='PENDING' and not ledger.events
    with pytest.raises(ValueError):ledger.plan.buffer_size=1


@pytest.mark.parametrize('outcome',['SUCCESS','ERROR'])
def test_immediate_terminal_then_dispose(ledger,outcome):
    terminal=step(ledger,'SUBMIT',outcome,transferred=16 if outcome=='SUCCESS' else 0)
    state=replay_pipe_ledger(terminal)
    assert state.stage=='TERMINAL' and len(state.held_resources)==4
    assert state.result_available==(outcome=='SUCCESS')
    disposed=step(terminal,'DISPOSE',tick=12)
    assert replay_pipe_ledger(disposed).held_resources==()
    assert propose_pipe_event(disposed,event(disposed,'DISPOSE',tick=13)).status=='REJECTED'


def test_pending_then_success(ledger):
    current=step(ledger,'SUBMIT','PENDING')
    current=step(current,'POLL','INCOMPLETE',tick=12)
    assert replay_pipe_ledger(current).held_resources==replay_pipe_ledger(ledger).held_resources
    current=step(current,'POLL','SUCCESS',tick=13,transferred=128)
    assert replay_pipe_ledger(current).result_available


@pytest.mark.parametrize('cancel',['CANCEL_ACCEPTED','NOT_FOUND','CANCEL_FAILED'])
@pytest.mark.parametrize('completion',['SUCCESS','ABORTED','ERROR'])
def test_cancel_results_never_prove_completion(ledger,cancel,completion):
    current=step(ledger,'SUBMIT','PENDING')
    current=step(current,'CANCEL',cancel,tick=12)
    state=replay_pipe_ledger(current)
    assert state.stage=='PENDING' and state.cancel_requested and len(state.held_resources)==4
    assert propose_pipe_event(current,event(current,'DISPOSE',tick=13)).status=='REJECTED'
    current=step(current,'POLL',completion,tick=14)
    assert not replay_pipe_ledger(current).result_available
    assert replay_pipe_ledger(step(current,'DISPOSE',tick=15)).held_resources==()


@pytest.mark.parametrize('tick',[20,21,29])
def test_late_success_suppressed_without_freeing_resources(ledger,tick):
    current=step(ledger,'SUBMIT','PENDING')
    current=step(current,'POLL','SUCCESS',tick=tick)
    state=replay_pipe_ledger(current)
    assert state.stage=='TERMINAL' and not state.result_available and len(state.held_resources)==4


def test_cleanup_deadline_quarantines_unconfirmed_operation(ledger):
    current=step(ledger,'SUBMIT','PENDING')
    current=step(current,'EXPIRE',tick=30)
    state=replay_pipe_ledger(current)
    assert state.stage=='PENDING' and state.quarantined and state.shutdown_required
    assert len(state.held_resources)==4
    assert propose_pipe_event(current,event(current,'DISPOSE',tick=31)).status=='REJECTED'
    current=step(current,'POLL','SUCCESS',tick=32)
    assert not replay_pipe_ledger(current).result_available
    assert replay_pipe_ledger(current).shutdown_required
    assert replay_pipe_ledger(step(current,'DISPOSE',tick=33)).held_resources==()


def test_deadline_before_submission_no_kernel_assumption(ledger):
    assert propose_pipe_event(ledger,event(ledger,'SUBMIT','PENDING',tick=20)).status=='REJECTED'
    current=step(ledger,'EXPIRE',tick=20)
    assert replay_pipe_ledger(current).terminal=='NOT_SUBMITTED'
    assert replay_pipe_ledger(step(current,'DISPOSE',tick=21)).held_resources==()


@pytest.mark.parametrize('pending',[False,True])
def test_revert_failure_requires_shutdown_and_blocks_submission(ledger,pending):
    current=step(ledger,'SUBMIT','PENDING') if pending else ledger
    current=step(current,'REVERT_FAILED',tick=12)
    state=replay_pipe_ledger(current)
    assert state.shutdown_required and not state.result_available
    assert propose_pipe_event(current,event(current,'SUBMIT','SUCCESS',tick=13)).status=='REJECTED'
    if pending:assert propose_pipe_event(current,event(current,'DISPOSE',tick=13)).status=='REJECTED'


@pytest.mark.parametrize('action,outcome',[('POLL','PENDING'),('SUBMIT','INCOMPLETE'),('CANCEL','SUCCESS'),
    ('DISPOSE','SUCCESS'),('EXPIRE','SUCCESS'),('REVERT_FAILED','ERROR')])
def test_submission_and_completion_codes_not_interchangeable(ledger,action,outcome):
    current=step(ledger,'SUBMIT','PENDING') if action in ('POLL','CANCEL') else ledger
    assert propose_pipe_event(current,event(current,action,outcome,tick=12)).status=='REJECTED'


@pytest.mark.parametrize('field,value',[('operation_id','other'),('overlapped_id','other'),('sequence',2),('tick',9)])
def test_wrong_operation_or_order_rejected(ledger,field,value):
    bad=event(ledger,'SUBMIT','PENDING').model_copy(update={field:value})
    result=propose_pipe_event(ledger,bad)
    assert result.status=='REJECTED' and result.proposed_ledger is None


@pytest.mark.parametrize('value',[True,-1,2**63,1.5])
def test_strict_clock_types(ledger,value):
    bad=event(ledger,'SUBMIT','PENDING').model_copy(update={'tick':value})
    if isinstance(value,float):
        # Serializing a float into a strict int field makes Pydantic warn before
        # validation rejects it. Pin the warning so behavior changes stay legible.
        with pytest.warns(UserWarning,match='Pydantic serializer warnings'):
            result=propose_pipe_event(ledger,bad)
    else:
        result=propose_pipe_event(ledger,bad)
    assert result.status=='REJECTED'


@pytest.mark.parametrize('outcome,count',[('PENDING',1),('ERROR',1),('SUCCESS',129)])
def test_transfer_count_bounds(ledger,outcome,count):
    assert propose_pipe_event(ledger,event(ledger,'SUBMIT',outcome,transferred=count)).status=='REJECTED'


def test_connect_count_is_normalized_not_read_as_defined(ledger):
    plan=ledger.plan.model_copy(update={'kind':'CONNECT','buffer_size':0})
    current=PipeOperationLedger(plan=plan)
    assert propose_pipe_event(current,event(current,'SUBMIT','SUCCESS',transferred=1)).status=='REJECTED'
    assert replay_pipe_ledger(step(current,'SUBMIT','SUCCESS')).terminal=='SUCCESS'


def test_completed_result_expires_before_disposal(ledger):
    current=step(ledger,'SUBMIT','SUCCESS')
    current=step(current,'EXPIRE',tick=20)
    assert not replay_pipe_ledger(current).result_available


def test_full_history_replay_rejects_silent_disposal(ledger):
    pending=step(ledger,'SUBMIT','PENDING')
    forged=PipeOperationLedger(plan=ledger.plan,events=pending.events+(event(pending,'DISPOSE',tick=12),))
    with pytest.raises(ValueError):replay_pipe_ledger(forged)
    assert propose_pipe_event(forged,event(forged,'EXPIRE',tick=20)).status=='REJECTED'


def test_canonical_vectors_and_bounds(ledger):
    raw=canonical_bytes(ledger)
    assert decode_pipe_record(PipeOperationLedger,raw)==ledger
    for invalid in (b' '+raw,raw.replace(b'"events":[]',b'"events":[],"events":[]'),b'x'*(MAX_RECORD_BYTES+1)):
        with pytest.raises(ValueError):decode_pipe_record(PipeOperationLedger,invalid)


def test_capacity_retains_pending_ownership(ledger):
    current=step(ledger,'SUBMIT','PENDING')
    for _ in range(MAX_EVENTS-1):current=step(current,'POLL','INCOMPLETE')
    assert len(replay_pipe_ledger(current).held_resources)==4
    completion=PipeOperationEvent(sequence=64,operation_id=current.plan.operation_id,
        overlapped_id=current.plan.overlapped_id,tick=12,action='POLL',outcome='SUCCESS')
    result=propose_pipe_event(current,completion)
    assert result.status=='REJECTED' and result.reason=='CAPACITY_EXCEEDED'


@pytest.mark.parametrize('field',['pipe_lease_id','event_id','overlapped_id','buffer_id','operation_id'])
def test_shared_resource_inventory_rejected(ledger,field):
    updates={name:getattr(ledger.plan,name)+'-2' for name in ('pipe_lease_id','event_id','overlapped_id','buffer_id','operation_id')}
    updates[field]=getattr(ledger.plan,field)
    second=PipeOperationLedger(plan=ledger.plan.model_copy(update=updates))
    with pytest.raises(ValueError):validate_pipe_ownership((ledger,second))


def test_distinct_resource_inventory(ledger):
    updates={name:getattr(ledger.plan,name)+'-2' for name in ('pipe_lease_id','event_id','overlapped_id','buffer_id','operation_id')}
    second=PipeOperationLedger(plan=ledger.plan.model_copy(update=updates))
    assert len(validate_pipe_ownership((ledger,second)))==2


def test_pure_side_effect_guards(ledger,monkeypatch):
    def forbidden(*args,**kw):raise AssertionError('Unexpected side effect')
    for target in ('builtins.open','socket.socket','sqlite3.connect','time.time','time.monotonic','ctypes.WinDLL'):
        monkeypatch.setattr(target,forbidden)
    current=step(ledger,'SUBMIT','PENDING')
    current=step(current,'CANCEL','NOT_FOUND')
    assert len(validate_pipe_ownership((current,))[0].held_resources)==4
