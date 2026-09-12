from datetime import timedelta
import builtins
import sqlite3
import socket

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update, locator
from test_update_verification import signed
from test_update_integration import host
from test_update_storage_validation import stored, image_from, checkpoint
from test_reconciliation_validation import reconciliation
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.update_storage_models import StoredLocatorPublication
from tnc.provenance.reconciliation_models import ReconciliationRequest
from tnc.provenance.reconciliation_validation import reconciliation_batch_digest
from tnc.provenance.reconciliation_simulation import (
    SimulationGrant,SyntheticAuthorityPolicy,SyntheticAuthorityCaller,SyntheticBatchAuthorization,
    AuthoritySimulationState,AuthoritySimulationCommand,AuthoritySimulationResult,
    ClientCheckpointMark,ClientObservationResult,SyntheticCurrentObservation,
    simulate_authority,evaluate_client_observation,decode_simulation_record,STATE_LIMIT,
)


@pytest.fixture
def sim(reconciliation):
    prefix,image,anchor,request,*_=reconciliation
    grant=SimulationGrant(principal_id=request.principal_id,actions=('OBSERVE_CURRENT','RECOVER','SUBMIT'),
        valid_from=NOW,valid_until=NOW+timedelta(hours=2))
    policy=SyntheticAuthorityPolicy(deployment_id=anchor.deployment_id,store_instance_id=anchor.store_instance_id,
        revision=1,grants=(grant,),valid_from=NOW,valid_until=NOW+timedelta(hours=2))
    caller=SyntheticAuthorityCaller(principal_id=request.principal_id,deployment_id=anchor.deployment_id,
        store_instance_id=anchor.store_instance_id,valid_from=NOW,valid_until=NOW+timedelta(hours=2))
    state=AuthoritySimulationState(initial_envelope=anchor,current_envelope=anchor,accepted_image=prefix,policy=policy)
    command=AuthoritySimulationCommand(action='SUBMIT',request=request,candidate_image=image)
    authorization=auth(request)
    return state,command,caller,authorization,anchor


def auth(request,policy_revision=1):
    return SyntheticBatchAuthorization(evidence_id='batch-evidence',principal_id=request.principal_id,
        deployment_id=request.deployment_id,store_instance_id=request.store_instance_id,request_hash=record_digest(request),
        predecessor_revision=request.expected_authority_revision,predecessor_hash=request.expected_envelope_hash,
        successor_checkpoint_hash=record_digest(request.successor_checkpoint),event_batch_hash=request.event_batch_hash,
        policy_revision=policy_revision,approved=True,valid_from=NOW,valid_until=NOW+timedelta(hours=1))


def run(sim,**changes):
    state,command,caller,authorization,anchor=sim
    values=dict(state=state,command=command,caller=caller,batch_authorization=authorization,trusted_initial_envelope=anchor,now=NOW)
    values.update(changes)
    return simulate_authority(**values)


def accepted(sim):
    result=run(sim)
    assert result.status=='ACCEPTED',result
    return result


def next_command(state,image,request_id='request-2'):
    previous=state.current_envelope
    request=ReconciliationRequest(request_id=request_id,principal_id=state.policy.grants[0].principal_id,
        deployment_id=previous.deployment_id,store_instance_id=previous.store_instance_id,
        expected_authority_revision=previous.authority_revision,expected_envelope_hash=record_digest(previous),
        successor_checkpoint=checkpoint(image),event_batch_hash=reconciliation_batch_digest(image.events[previous.checkpoint.event_count:]),
        valid_from=NOW,valid_until=NOW+timedelta(minutes=30))
    return AuthoritySimulationCommand(action='SUBMIT',request=request,candidate_image=image)


def test_acceptance_atomic_proposal_and_determinism(sim):
    before=canonical_bytes(sim[0]); first=accepted(sim); second=accepted(sim)
    assert first==second and canonical_bytes(sim[0])==before
    assert first.synthetic and first.audit_only and len(first.proposed_state.history)==1
    assert first.proposed_state.current_envelope.authority_revision==2
    assert first.proposed_state.accepted_image==sim[1].candidate_image
    assert first.acceptance==first.proposed_state.history[0].acceptance


def test_lost_ack_exact_retry_no_new_state(sim):
    first=accepted(sim)
    retry=run(sim,state=first.proposed_state,batch_authorization=None,
        command=sim[1].model_copy(update={'candidate_image':None}))
    assert retry.status=='RECOVERED' and retry.proposed_state is None
    assert canonical_bytes(retry.acceptance)==canonical_bytes(first.acceptance)


def test_two_stale_proposals_must_be_rechecked(sim):
    first=accepted(sim)
    request=sim[1].request.model_copy(update={'request_id':'competitor'})
    command=sim[1].model_copy(update={'request':request})
    # Pure evaluation alone cannot choose a winner from two copies of old state.
    assert run(sim,command=command,batch_authorization=auth(request)).status=='ACCEPTED'
    loser=run(sim,state=first.proposed_state,command=command,batch_authorization=auth(request))
    assert loser.reason_code=='CAS_CONFLICT' and loser.proposed_state is None


@pytest.mark.parametrize('field,value',[('expected_authority_revision',2),('expected_envelope_hash','f'*64),('store_instance_id','other')])
def test_cas_scope_revision_and_digest(sim,field,value):
    request=sim[1].request.model_copy(update={field:value})
    result=run(sim,command=sim[1].model_copy(update={'request':request}),batch_authorization=auth(request))
    assert result.status=='DENIED' and result.acceptance is None


@pytest.mark.parametrize('field,value',[('approved',False),('request_hash','f'*64),('predecessor_revision',5),
    ('predecessor_hash','f'*64),('successor_checkpoint_hash','f'*64),('event_batch_hash','f'*64),
    ('policy_revision',2),('principal_id','other'),('deployment_id','other'),('store_instance_id','other')])
def test_independent_batch_binding_required(sim,field,value):
    result=run(sim,batch_authorization=sim[3].model_copy(update={field:value}))
    assert result.reason_code=='BATCH_DENIED' and result.proposed_state is None


def test_missing_batch_and_local_receipt_cannot_authorize(sim,stored):
    for evidence in (None,stored[1][-1].receipt):
        assert run(sim,batch_authorization=evidence).status=='DENIED'


def test_invalid_suffix_not_authorized_by_matching_request_hash(sim):
    image=sim[1].candidate_image
    events=image.events[:-1]+(image.events[-1].model_copy(update={'entry_hash':'f'*64}),)
    image=image.model_copy(update={'events':events})
    request=sim[1].request.model_copy(update={'successor_checkpoint':checkpoint(image),
        'event_batch_hash':reconciliation_batch_digest(image.events[1:])})
    assert run(sim,command=AuthoritySimulationCommand(action='SUBMIT',request=request,candidate_image=image),
        batch_authorization=auth(request)).reason_code=='INVALID_BATCH'


def test_noop_advance_is_denied(sim):
    request=sim[1].request.model_copy(update={'successor_checkpoint':sim[0].current_envelope.checkpoint})
    command=AuthoritySimulationCommand(action='SUBMIT',request=request,candidate_image=sim[0].accepted_image)
    assert run(sim,command=command,batch_authorization=auth(request)).reason_code=='INVALID_BATCH'


def test_conflicting_retry(sim):
    first=accepted(sim)
    request=sim[1].request.model_copy(update={'event_batch_hash':'f'*64})
    assert run(sim,state=first.proposed_state,command=AuthoritySimulationCommand(action='RECOVER',request=request)).reason_code=='REQUEST_CONFLICT'


def test_old_recovery_after_later_advancement(sim,stored):
    first=accepted(sim)
    publication=StoredLocatorPublication(operation_id=stored[1][-1].operation_id,credential_id='9'*64,locator=locator(stored[1][-1].head))
    image=image_from(stored[0],stored[1]+[publication])
    command=next_command(first.proposed_state,image)
    second=run(sim,state=first.proposed_state,command=command,batch_authorization=auth(command.request))
    assert second.status=='ACCEPTED'
    before=canonical_bytes(second.proposed_state)
    recovery=run(sim,state=second.proposed_state,command=AuthoritySimulationCommand(action='RECOVER',request=sim[1].request),batch_authorization=None)
    assert recovery.status=='RECOVERED' and recovery.acceptance==first.acceptance
    assert recovery.observation is None and recovery.proposed_state is None
    assert canonical_bytes(second.proposed_state)==before


def test_expired_historical_request_can_be_recovered(sim):
    first=accepted(sim)
    assert run(sim,state=first.proposed_state,command=AuthoritySimulationCommand(action='RECOVER',request=sim[1].request),
        batch_authorization=None,now=NOW+timedelta(minutes=90)).status=='RECOVERED'


def test_permission_removed_before_submit_or_recovery(sim):
    first=accepted(sim)
    for state,command in ((sim[0],sim[1]),(first.proposed_state,AuthoritySimulationCommand(action='RECOVER',request=sim[1].request))):
        policy=state.policy.model_copy(update={'revision':2,'grants':()})
        result=run(sim,state=state.model_copy(update={'policy':policy}),command=command)
        assert result.reason_code=='ACCESS_DENIED' and result.acceptance is None


def test_submit_right_does_not_imply_recovery(sim):
    first=accepted(sim); state=first.proposed_state
    grant=state.policy.grants[0].model_copy(update={'actions':('SUBMIT',)})
    state=state.model_copy(update={'policy':state.policy.model_copy(update={'revision':2,'grants':(grant,)})})
    assert run(sim,state=state).reason_code=='ACCESS_DENIED'


def test_foreign_request_and_absent_request_uniform_denial(sim):
    first=accepted(sim)
    foreign=sim[2].model_copy(update={'principal_id':'foreign'})
    for request in (sim[1].request,sim[1].request.model_copy(update={'request_id':'absent'})):
        result=run(sim,state=first.proposed_state,caller=foreign,command=AuthoritySimulationCommand(action='RECOVER',request=request))
        assert result.reason_code=='ACCESS_DENIED' and result.proposed_state is None


@pytest.mark.parametrize('field',['current_envelope','history','policy'])
def test_corrupt_retained_state_is_rejected(sim,field):
    first=accepted(sim); state=first.proposed_state
    if field=='history': value=state.history+state.history
    elif field=='current_envelope': value=sim[0].initial_envelope
    else: value=state.policy.model_copy(update={'grants':()})
    assert run(sim,state=state.model_copy(update={field:value})).reason_code=='INVALID_STATE'


def test_different_external_initial_anchor_rejected(sim):
    anchor=sim[4].model_copy(update={'issuer_id':'other'})
    assert run(sim,trusted_initial_envelope=anchor).reason_code=='INVALID_STATE'


@pytest.mark.parametrize('count',[1,2,3,4,5])
def test_every_event_kind_can_be_independently_authorized(sim,stored,count):
    payloads=stored[1]+[StoredLocatorPublication(operation_id=stored[1][-1].operation_id,credential_id='9'*64,locator=locator(stored[1][-1].head))]
    before=image_from(stored[0],payloads[:count-1]); after=image_from(stored[0],payloads[:count])
    anchor=sim[4].model_copy(update={'checkpoint':checkpoint(before)})
    state=sim[0].model_copy(update={'initial_envelope':anchor,'current_envelope':anchor,'accepted_image':before})
    command=next_command(state,after)
    result=run(sim,state=state,command=command,batch_authorization=auth(command.request),trusted_initial_envelope=anchor)
    assert result.status=='ACCEPTED',result


def observe(sim,state=None):
    result=run(sim,state=state or sim[0],command=AuthoritySimulationCommand(action='OBSERVE_CURRENT',challenge='d'*64),batch_authorization=None)
    assert result.status=='CURRENT',result
    return result.observation


def mark(envelope):
    return ClientCheckpointMark(deployment_id=envelope.deployment_id,store_instance_id=envelope.store_instance_id,
        authority_revision=envelope.authority_revision,envelope_hash=record_digest(envelope))


def client(mark_value,response,**changes):
    params=dict(expected_challenge='d'*64,principal_id=response.principal_id,now=NOW)
    params.update(changes)
    return evaluate_client_observation(mark_value,response,**params)


def test_equal_highwater_is_unchanged(sim):
    assert client(mark(sim[4]),observe(sim)).status=='UNCHANGED'


def test_same_revision_different_digest_is_fork(sim):
    high=mark(sim[4]).model_copy(update={'envelope_hash':'f'*64})
    assert client(high,observe(sim)).status=='FORK'


def test_lower_observation_is_historical_only(sim):
    first=accepted(sim)
    assert client(mark(first.proposed_state.current_envelope),observe(sim)).status=='STALE_HISTORICAL'


def test_advancement_requires_chain(sim):
    first=accepted(sim); response=observe(sim,first.proposed_state)
    assert client(mark(sim[4]),response).status=='INDETERMINATE'
    result=client(mark(sim[4]),response,chain=(response.envelope,))
    assert result.status=='ADVANCE_PROPOSED' and result.proposed_mark==mark(response.envelope)


@pytest.mark.parametrize('field,value',[('challenge','f'*64),('principal_id','other')])
def test_observation_scope_and_challenge(sim,field,value):
    response=observe(sim)
    values={'expected_challenge':'d'*64,'principal_id':sim[2].principal_id,'now':NOW}
    result=evaluate_client_observation(mark(sim[4]),response.model_copy(update={field:value}),**values)
    assert result.status=='INDETERMINATE'


def test_expired_observation_or_envelope_is_not_current(sim):
    response=observe(sim)
    assert client(mark(sim[4]),response,now=response.valid_until).status=='INDETERMINATE'
    assert run(sim,command=AuthoritySimulationCommand(action='OBSERVE_CURRENT',challenge='d'*64),now=NOW+timedelta(minutes=90)).reason_code=='FRESHNESS_UNAVAILABLE'


def test_denied_results_cannot_expose_or_promote_state(sim):
    with pytest.raises(ValueError): AuthoritySimulationResult(status='DENIED',reason_code='ACCESS_DENIED',proposed_state=sim[0])
    with pytest.raises(ValueError): ClientObservationResult(status='FORK',proposed_mark=mark(sim[4]))
    with pytest.raises(ValueError): AuthoritySimulationResult(status='DENIED',reason_code='ACCESS_DENIED',audit_only=False)


@pytest.mark.parametrize('data',[b'{}\n',b'{"action":"RECOVER","action":"SUBMIT"}',b'NaN'])
def test_noncanonical_commands_rejected(data):
    with pytest.raises(ValueError): decode_simulation_record(AuthoritySimulationCommand,data)


def test_record_bounds_and_history_limit(sim):
    with pytest.raises(ValueError): decode_simulation_record(AuthoritySimulationState,b'x'*(STATE_LIMIT+1))
    first=accepted(sim)
    with pytest.raises(ValueError): canonical_bytes(first.proposed_state.model_copy(update={'history':first.proposed_state.history*65}))


def test_pure_and_frozen(sim,monkeypatch):
    def forbidden(*args,**kwargs): pytest.fail('Simulation performed I/O')
    monkeypatch.setattr(builtins,'open',forbidden); monkeypatch.setattr(sqlite3,'connect',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden)
    result=accepted(sim)
    assert result==accepted(sim)
    with pytest.raises(ValueError): result.proposed_state.policy.revision=99


def test_skipped_revision_needs_complete_retained_chain(sim,stored):
    first=accepted(sim)
    p=StoredLocatorPublication(operation_id=stored[1][-1].operation_id,credential_id='9'*64,locator=locator(stored[1][-1].head))
    command=next_command(first.proposed_state,image_from(stored[0],stored[1]+[p]))
    second=run(sim,state=first.proposed_state,command=command,batch_authorization=auth(command.request))
    assert second.status=='ACCEPTED'
    response=observe(sim,second.proposed_state)
    assert client(mark(sim[4]),response,chain=(response.envelope,)).status=='INDETERMINATE'
    chain=(first.proposed_state.current_envelope,response.envelope)
    assert client(mark(sim[4]),response,chain=chain).status=='ADVANCE_PROPOSED'
    bad=chain[0].model_copy(update={'previous_envelope_hash':'f'*64})
    assert client(mark(sim[4]),response,chain=(bad,chain[1])).status=='FORK'


def test_new_policy_requires_new_batch_authorization(sim):
    state=sim[0].model_copy(update={'policy':sim[0].policy.model_copy(update={'revision':2})})
    assert run(sim,state=state).reason_code=='BATCH_DENIED'
    assert run(sim,state=state,batch_authorization=auth(sim[1].request,2)).status=='ACCEPTED'


@pytest.mark.parametrize('field,value',[('independent_evidence_hash','f'*64),('request_hash','f'*64),('accepted_at',NOW+timedelta(seconds=1))])
def test_altered_historical_acceptance_is_invalid(sim,field,value):
    first=accepted(sim); state=first.proposed_state
    entry=state.history[0].model_copy(update={'acceptance':state.history[0].acceptance.model_copy(update={field:value})})
    assert run(sim,state=state.model_copy(update={'history':(entry,)})).reason_code=='INVALID_STATE'


def test_expired_batch_authorization_does_not_advance(sim):
    evidence=sim[3].model_copy(update={'valid_from':NOW-timedelta(minutes=1),'valid_until':NOW})
    assert run(sim,batch_authorization=evidence).reason_code=='BATCH_DENIED'


def test_naive_clock_denied(sim):
    assert run(sim,now=NOW.replace(tzinfo=None)).reason_code=='INVALID_INPUT'


def test_bad_command_shapes():
    with pytest.raises(ValueError): AuthoritySimulationCommand(action='OBSERVE_CURRENT')
    with pytest.raises(ValueError): AuthoritySimulationCommand(action='RECOVER')


def test_result_limit_includes_duplicate_acceptance(sim,monkeypatch):
    result=accepted(sim)
    # The state alone fits, but the result also carries the original acceptance.
    bound=len(canonical_bytes(result.proposed_state))+1
    assert len(canonical_bytes(result))>bound
    monkeypatch.setattr('tnc.provenance.reconciliation_simulation.STATE_LIMIT',bound)
    denied=run(sim)
    assert denied.reason_code=='CAPACITY_EXCEEDED' and denied.proposed_state is None
