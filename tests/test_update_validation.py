from datetime import timedelta
import builtins
import sqlite3

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.deployment_validation import evaluate_deployment_observations
from tnc.provenance.update_models import (
    UPDATE_RECORD_LIMIT, UpdateCandidate, UpdateIntent, UpdateAuthorityHead, SyntheticInstallerEvidence,
    PreparedUpdateEvidence, SyntheticDrainEvidence, LocatorObservation, UpdateCommand, UpdateTransitionResult,
)
from tnc.provenance.update_validation import evaluate_update_transition, evaluate_update_recovery, decode_update_record


@pytest.fixture
def update(config, inventory):
    policy, old_checkpoint, _ = config
    envelope = inventory['envelope'].model_copy(update={'generation':2})
    anchor = inventory['external_anchor'].model_copy(update={'envelope_hash':record_digest(envelope), 'minimum_generation':2})
    checkpoint = old_checkpoint.model_copy(update={'anchor_hash':record_digest(anchor), 'high_water_generation':2})
    candidate = UpdateCandidate(policy=policy, checkpoint=checkpoint, anchor=anchor,
                                envelope=envelope, descriptor=inventory['descriptor'])
    head = UpdateAuthorityHead(sequence=7, checkpoint=old_checkpoint, generation_location=r'C:\generation-001')
    intent = UpdateIntent(deployment_id=policy.deployment_id, operation_id='update-002', publisher_id='installer',
        signer_key_hash='a'*64, expected_head_sequence=7, expected_checkpoint_hash=record_digest(old_checkpoint),
        candidate=candidate, valid_from=NOW, valid_until=NOW+timedelta(hours=1))
    authority = SyntheticInstallerEvidence(principal_id='installer', signer_key_hash='a'*64,
        deployment_id=policy.deployment_id, authenticated=True, may_publish=True,
        valid_from=NOW, valid_until=NOW+timedelta(days=2))
    report = evaluate_deployment_observations(**(inventory | {'envelope':envelope, 'external_anchor':anchor}))
    preparation = PreparedUpdateEvidence(intent_hash=record_digest(intent), report=report,
        valid_from=NOW, valid_until=NOW+timedelta(hours=1))
    drain = SyntheticDrainEvidence(intent_hash=record_digest(intent), expected_head_sequence=7,
        expected_checkpoint_hash=record_digest(old_checkpoint), admissions_fenced=True,
        processes_terminated=True, handles_released=True, valid_from=NOW, valid_until=NOW+timedelta(hours=1))
    return dict(head=head, intent=intent, authority=authority, preparation=preparation, drain=drain)


def transition(u, action, existing=None, **changes):
    kwargs = {'action':action, 'intent':u['intent']}
    if action in ('PREPARE','COMMIT'): kwargs['preparation'] = u['preparation']
    if action=='COMMIT': kwargs['drain'] = u['drain']
    if action=='PUBLISH': kwargs['locator'] = locator(u['head'])
    return evaluate_update_transition(head=u['head'], existing=existing,
        command=UpdateCommand(**kwargs), authority=u['authority'], now=NOW, **changes)


def commit(u):
    registered = transition(u, 'REGISTER')
    assert registered.status=='PROPOSED'
    prepared = transition(u, 'PREPARE', registered.operation)
    assert prepared.status=='PROPOSED'
    committed = transition(u, 'COMMIT', prepared.operation)
    assert committed.status=='PROPOSED'
    return committed


def locator(head, **updates):
    return LocatorObservation(observed_at=NOW, state='PRESENT', deployment_id=head.checkpoint.deployment_id,
        authority_sequence=head.sequence, checkpoint_hash=record_digest(head.checkpoint),
        generation_location=head.generation_location, target_state='VALID').model_copy(update=updates)


def test_complete_lifecycle_and_publication_separation(update):
    before = canonical_bytes(update['head'])
    result = commit(update)
    assert result.proposed_head.sequence==8 and result.operation.publication is None
    assert canonical_bytes(update['head'])==before
    latest = update | {'head':result.proposed_head}
    published = transition(latest, 'PUBLISH', result.operation)
    assert published.operation.stage=='PUBLISHED' and published.proposed_head is None
    assert transition(latest, 'PUBLISH', published.operation).status=='UNCHANGED'


@pytest.mark.parametrize('action', ['REGISTER','RECOVER','COMMIT'])
def test_exact_committed_retry_preserves_receipt(update, action):
    committed = commit(update)
    result = transition(update | {'head':committed.proposed_head}, action, committed.operation)
    assert result.status=='RECOVERED' and result.proposed_head is None
    assert canonical_bytes(result.operation.receipt)==canonical_bytes(committed.operation.receipt)


def test_receipt_recovery_after_expiry_and_key_rotation(update):
    committed = commit(update)
    authority = update['authority'].model_copy(update={'signer_key_hash':'b'*64})
    result = evaluate_update_transition(head=committed.proposed_head, existing=committed.operation,
        command=UpdateCommand(action='RECOVER', intent=update['intent']), authority=authority,
        now=NOW+timedelta(hours=2))
    assert result.status=='RECOVERED'


def test_recovery_of_older_receipt_does_not_regress_head(update):
    committed = commit(update)
    later_checkpoint = committed.proposed_head.checkpoint.model_copy(update={'high_water_generation':3})
    later = committed.proposed_head.model_copy(update={'sequence':9, 'checkpoint':later_checkpoint,
                                                     'generation_location':r'C:\generation-003'})
    result = transition(update | {'head':later}, 'RECOVER', committed.operation)
    assert result.status=='RECOVERED' and result.proposed_head is None
    assert transition(update | {'head':later}, 'PUBLISH', committed.operation).reason_code=='HEAD_CONFLICT'


def test_changed_intent_same_operation_conflicts(update):
    registered = transition(update, 'REGISTER').operation
    changed = update['intent'].model_copy(update={'valid_until':NOW+timedelta(minutes=30)})
    result = transition(update | {'intent':changed}, 'REGISTER', registered)
    assert result.reason_code=='OPERATION_CONFLICT' and result.operation is None


def test_competing_prepared_updates_cannot_commit_from_same_head(update):
    first = commit(update)
    intent = update['intent'].model_copy(update={'operation_id':'competing-update'})
    other = update | {'intent':intent,
        'preparation':update['preparation'].model_copy(update={'intent_hash':record_digest(intent)}),
        'drain':update['drain'].model_copy(update={'intent_hash':record_digest(intent)})}
    registered = transition(other, 'REGISTER').operation
    prepared = transition(other, 'PREPARE', registered).operation
    result = transition(other | {'head':first.proposed_head}, 'COMMIT', prepared)
    assert result.reason_code=='HEAD_CONFLICT'


@pytest.mark.parametrize('field,value,reason', [('authenticated',False,'UNAUTHENTICATED_INSTALLER'),
    ('may_publish',False,'PUBLISH_PERMISSION_DENIED'), ('principal_id','service','PUBLISH_PERMISSION_DENIED'),
    ('deployment_id','other','PUBLISH_PERMISSION_DENIED'), ('signer_key_hash','f'*64,'PUBLISH_PERMISSION_DENIED')])
def test_authority_denials(update, field, value, reason):
    result = transition(update | {'authority':update['authority'].model_copy(update={field:value})}, 'REGISTER')
    assert result.reason_code==reason and result.operation is None


def test_unauthenticated_recovery_does_not_expose_receipt(update):
    committed = commit(update)
    result = transition(update | {'head':committed.proposed_head,
        'authority':update['authority'].model_copy(update={'authenticated':False})}, 'RECOVER', committed.operation)
    assert result.status=='DENIED' and result.operation is None


@pytest.mark.parametrize('field,value', [('expected_head_sequence',6), ('expected_checkpoint_hash','e'*64)])
def test_head_conflicts(update, field, value):
    assert transition(update | {'intent':update['intent'].model_copy(update={field:value})}, 'REGISTER').reason_code=='HEAD_CONFLICT'


def test_new_equal_generation_update_rejected(update):
    old = update['head'].checkpoint.model_copy(update={'high_water_generation':2})
    head = update['head'].model_copy(update={'checkpoint':old})
    intent = update['intent'].model_copy(update={'expected_checkpoint_hash':record_digest(old)})
    assert transition(update | {'head':head, 'intent':intent}, 'REGISTER').reason_code=='GENERATION_TOO_OLD'


@pytest.mark.parametrize('field', ['admissions_fenced','processes_terminated','handles_released'])
def test_incomplete_drain_blocks_commit(update, field):
    prepared = transition(update, 'PREPARE', transition(update, 'REGISTER').operation).operation
    bad = update | {'drain':update['drain'].model_copy(update={field:False})}
    assert transition(bad, 'COMMIT', prepared).reason_code=='DRAIN_INCOMPLETE'


@pytest.mark.parametrize('field,value', [('intent_hash','e'*64), ('expected_head_sequence',6), ('expected_checkpoint_hash','e'*64)])
def test_drain_bound_to_intent_and_head(update, field, value):
    prepared = transition(update, 'PREPARE', transition(update, 'REGISTER').operation).operation
    assert transition(update | {'drain':update['drain'].model_copy(update={field:value})}, 'COMMIT', prepared).reason_code=='DRAIN_INCOMPLETE'


@pytest.mark.parametrize('field,value', [('envelope_hash','e'*64), ('inspected_object_ids',()), ('generation',3)])
def test_mismatched_preflight(update, field, value):
    registered = transition(update, 'REGISTER').operation
    preparation = update['preparation'].model_copy(update={'report':update['preparation'].report.model_copy(update={field:value})})
    assert transition(update | {'preparation':preparation}, 'PREPARE', registered).reason_code=='PREFLIGHT_NOT_CONFORMING'


def test_unprepared_commit_rejected(update):
    assert transition(update, 'COMMIT', transition(update, 'REGISTER').operation).reason_code=='INVALID_TRANSITION'


@pytest.mark.parametrize('part', ['intent','authority','preparation','drain'])
def test_expired_evidence_or_intent_blocks_new_work(update, part):
    prepared = transition(update, 'PREPARE', transition(update, 'REGISTER').operation).operation
    command = UpdateCommand(action='COMMIT', intent=update['intent'], preparation=update['preparation'], drain=update['drain'])
    if part=='authority':
        authority = update['authority'].model_copy(update={'valid_from':NOW-timedelta(hours=1), 'valid_until':NOW})
    else:
        authority = update['authority']
        changed = update[part].model_copy(update={'valid_from':NOW-timedelta(hours=1), 'valid_until':NOW})
        command = command.model_copy(update={part:changed})
    result = evaluate_update_transition(head=update['head'], existing=prepared, command=command, authority=authority, now=NOW)
    assert result.status=='DENIED'
    assert result.reason_code==('OPERATION_CONFLICT' if part=='intent' else 'EXPIRED_VALIDITY_INTERVAL')


@pytest.mark.parametrize('part,field,value', [('checkpoint','policy_hash','f'*64), ('checkpoint','anchor_hash','f'*64),
    ('anchor','minimum_generation',1), ('envelope','generation',3)])
def test_candidate_binding_mismatches(update, part, field, value):
    candidate = update['intent'].candidate
    candidate = candidate.model_copy(update={part:getattr(candidate, part).model_copy(update={field:value})})
    intent = update['intent'].model_copy(update={'candidate':candidate})
    assert transition(update | {'intent':intent}, 'REGISTER').status=='DENIED'


def test_violation_report_cannot_prepare(update):
    from tnc.provenance.installation_models import PreflightFinding
    registered = transition(update, 'REGISTER').operation
    report = update['preparation'].report.model_copy(update={'status':'VIOLATIONS',
        'findings':(PreflightFinding(object_id='code', reason_code='OWNER_DENIED'),)})
    preparation = update['preparation'].model_copy(update={'report':report})
    assert transition(update | {'preparation':preparation}, 'PREPARE', registered).reason_code=='PREFLIGHT_NOT_CONFORMING'


def test_publication_after_intent_expiry_with_rotated_authorized_key(update):
    committed = commit(update)
    now = NOW+timedelta(hours=2)
    command = UpdateCommand(action='PUBLISH', intent=update['intent'],
        locator=locator(committed.proposed_head, observed_at=now))
    result = evaluate_update_transition(head=committed.proposed_head, existing=committed.operation, command=command,
        authority=update['authority'].model_copy(update={'signer_key_hash':'b'*64}), now=now)
    assert result.status=='PROPOSED' and result.operation.stage=='PUBLISHED'


@pytest.mark.parametrize('field,value', [('authority_sequence',9), ('checkpoint_hash','f'*64),
    ('intent_hash','f'*64), ('generation',999), ('publisher_id','other')])
def test_inconsistent_receipt_is_not_recovered(update, field, value):
    committed = commit(update)
    forged = committed.operation.model_copy(update={'receipt':committed.operation.receipt.model_copy(update={field:value})})
    assert transition(update | {'head':committed.proposed_head}, 'RECOVER', forged).status=='DENIED'


@pytest.mark.parametrize('mutation', [lambda b:b+b' ', lambda b:b'{}', lambda b:b'\xff',
    lambda b:b.replace(b'"codec_version":1',b'"codec_version":true'),
    lambda b:b.replace(b'"domain":',b'"extra":1,"domain":'),
    lambda b:b.replace(b'"operation_id":',b'"operation_id":"dup","operation_id":'),
    lambda b:b.replace(b'.000000Z',b'Z'), lambda b:bytearray(b), lambda b:b' '*(UPDATE_RECORD_LIMIT+1)])
def test_canonical_rejection(update, mutation):
    with pytest.raises(ValueError): decode_update_record(UpdateIntent, mutation(canonical_bytes(update['intent'])))


def test_canonical_roundtrip_and_immutability(update):
    assert decode_update_record(UpdateIntent, canonical_bytes(update['intent']))==update['intent']
    with pytest.raises(ValueError): update['intent'].operation_id='changed'


@pytest.mark.parametrize('state,updates,disposition', [
    ('MISSING',{},'REPAIR_REQUIRED'), ('UNREADABLE',{},'BLOCKED'),
    ('PRESENT',{},'MATCHED'), ('PRESENT',{'authority_sequence':6},'REPAIR_REQUIRED'),
    ('PRESENT',{'authority_sequence':8},'BLOCKED'), ('PRESENT',{'checkpoint_hash':'f'*64},'BLOCKED'),
    ('PRESENT',{'target_state':'INVALID'},'BLOCKED'), ('PRESENT',{'target_state':'UNKNOWN'},'BLOCKED'),
    ('PRESENT',{'deployment_id':'other'},'BLOCKED'), ('PRESENT',{'generation_location':r'C:\other'},'BLOCKED'),
])
def test_crash_recovery_matrix(update, state, updates, disposition):
    observation = locator(update['head'], **updates) if state=='PRESENT' else LocatorObservation(state=state, observed_at=NOW)
    result = evaluate_update_recovery(head=update['head'], locator=observation, now=NOW)
    assert result.disposition==disposition


def test_missing_authority_never_uses_locator(update):
    assert evaluate_update_recovery(head=None, locator=locator(update['head']), now=NOW).reason_code=='AUTHORITY_UNAVAILABLE'


def test_expired_head_blocks_recovery_not_old_generation_fallback(update):
    result = evaluate_update_recovery(head=update['head'], locator=locator(update['head']), now=NOW+timedelta(days=2))
    assert result.disposition=='BLOCKED' and result.reason_code=='EXPIRED_VALIDITY_INTERVAL'


def test_no_file_or_database_io(update, monkeypatch):
    def forbidden(*a, **k): pytest.fail('Pure validator attempted I/O')
    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    commit(update)


def test_denial_cannot_carry_operation(update):
    with pytest.raises(ValueError):
        UpdateTransitionResult(status='DENIED', reason_code='HEAD_CONFLICT', operation=transition(update,'REGISTER').operation)
