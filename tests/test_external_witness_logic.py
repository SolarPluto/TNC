"""Synthetic external witness checks: no signing, persistence or network."""
from dataclasses import dataclass
from hashlib import sha256

import pytest
from pydantic import ValidationError

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical
from tnc.provenance.external_witness_logic import *


def change(record, **values):
    return type(record).model_validate({**record.model_dump(), **values})


@dataclass
class Harness:
    initial: WitnessStateRecord
    policy: SyntheticWitnessPolicy

    def caller(self, request, policy=None, **values):
        return SyntheticCallerEvidence(context=request.context, principal_id=request.principal_id,
            request_digest=witness_digest(request), policy_digest=witness_digest(policy or self.policy),
            issued_at=10, expires_at=300, **values)

    def request(self, image=None, **values):
        image = image or WitnessImage(initial=self.initial, receipts=())
        head = validate_witness_image(image, trusted_initial=self.initial)
        target = change(head.head, local_sequence=head.head.local_sequence+1,
                        history_digest=sha256(str(head.witness_sequence+1).encode()).hexdigest(),
                        policy_revision=head.head.policy_revision+1, policy_digest='b'*64)
        return WitnessAdvanceRequest(context=head.context, principal_id='alice',
            request_id=values.pop('request_id', f'request-{head.witness_sequence+1}'),
            predecessor_witness_sequence=head.witness_sequence, predecessor_state_digest=witness_digest(head),
            target_witness_sequence=head.witness_sequence+1, target_head=target,
            issued_at=10, expires_at=200, **values)

    def proof(self, request):
        return SyntheticLineageEvidence(request_digest=witness_digest(request),
            predecessor_state_digest=request.predecessor_state_digest,
            target_head_digest=witness_digest(request.target_head), root_transition_authorized=False,
            issued_at=10, expires_at=200)

    def submit(self, image=None, request=None, **values):
        image = image or WitnessImage(initial=self.initial, receipts=())
        request = request or self.request(image)
        return evaluate_witness_advance(image, request, trusted_initial=self.initial,
            caller=values.pop('caller', self.caller(request)), policy=values.pop('policy', self.policy),
            evidence=values.pop('evidence', self.proof(request)), now=values.pop('now', 20), **values)

    def observation(self, image=None):
        image = image or WitnessImage(initial=self.initial, receipts=())
        request = WitnessObservationRequest(context=self.initial.context, principal_id='alice', challenge='c'*64,
                                            issued_at=10, expires_at=200)
        result = observe_witness_current(image, request, trusted_initial=self.initial,
            caller=self.caller(request), policy=self.policy, now=30)
        observation = result.observation
        evidence = SyntheticObservationEvidence(context=request.context, request_digest=witness_digest(request),
            observation_digest=witness_digest(observation), issued_at=30, expires_at=100)
        return request, observation, evidence


@pytest.fixture
def h():
    context = WitnessStoreContext(deployment_id='deployment', store_instance_id='store',
                                  local_store_id='local', bootstrap_anchor_digest='a'*64)
    head = WitnessLocalHead(local_sequence=0, history_digest='0'*64, checkpoint_revision=1,
        checkpoint_digest='1'*64, epoch_counter=1, epoch_id='epoch-1', trust_store_revision=1,
        trust_store_digest='2'*64, policy_revision=1, policy_digest='3'*64)
    return Harness(WitnessStateRecord(context=context, witness_sequence=0, head=head, last_updated_at=10),
        SyntheticWitnessPolicy(context=context, revision=1, issued_at=10, expires_at=300,
            advance_principals=('alice',), recovery_principals=('alice',), observation_principals=('alice',)))


def test_success_is_only_proposal(h):
    original = WitnessImage(initial=h.initial, receipts=())
    before = canonical_bytes(original)
    result = h.submit(original)
    assert result.status == 'SUCCESS' and result.signature_verified is False and result.audit_only
    assert canonical_bytes(original) == before
    assert result.receipt.resulting_state.witness_sequence == 1
    assert result.receipt.resulting_state.head.checkpoint_revision == 1


def test_exact_retry_after_advance_and_expiry(h):
    request = h.request()
    first = h.submit(request=request)
    second = h.submit(first.proposed_image, now=21)
    retry = h.submit(second.proposed_image, request, now=210, evidence=None)
    assert retry.status == 'HISTORICAL_RECEIPT'
    assert canonical_bytes(retry.receipt) == canonical_bytes(first.receipt)
    assert retry.proposed_image is None


def test_concurrent_proposals_require_cas_application(h):
    a, b = h.request(), change(h.request(), request_id='competitor')
    assert h.submit(request=a).status == h.submit(request=b).status == 'SUCCESS'
    first = h.submit(request=a)
    assert h.submit(first.proposed_image, b).status == 'CAS_MISMATCH'


def test_same_request_id_conflict(h):
    first = h.submit()
    assert h.submit(first.proposed_image, change(h.request(), expires_at=199)).status == 'OPERATION_CONFLICT'


@pytest.mark.parametrize('permission', ['advance_principals', 'recovery_principals', 'observation_principals'])
def test_permission_boundaries(h, permission):
    policy = change(h.policy, revision=2, **{permission: ()})
    request = h.request()
    if permission == 'advance_principals':
        result = h.submit(request=request, policy=policy, caller=h.caller(request, policy))
    elif permission == 'recovery_principals':
        first = h.submit()
        result = h.submit(first.proposed_image, request, policy=policy, caller=h.caller(request, policy))
    else:
        req, _, _ = h.observation()
        result = observe_witness_current(WitnessImage(initial=h.initial, receipts=()), req,
            trusted_initial=h.initial, caller=h.caller(req, policy), policy=policy, now=30)
    assert result.status == 'UNAUTHORIZED_CLIENT' and result.receipt is None and result.observation is None


@pytest.mark.parametrize('field,value', [('principal_id','mallory'), ('request_digest','f'*64), ('policy_digest','f'*64)])
def test_caller_tampering(h, field, value):
    request = h.request()
    assert h.submit(request=request, caller=change(h.caller(request), **{field:value})).status == 'UNAUTHORIZED_CLIENT'


@pytest.mark.parametrize('field', ['deployment_id', 'store_instance_id', 'local_store_id', 'bootstrap_anchor_digest'])
def test_all_context_bindings(h, field):
    request = h.request()
    context = change(request.context, **{field: 'f'*64 if field.endswith('digest') else 'other'})
    assert h.submit(request=change(request, context=context)).status == 'UNAUTHORIZED_CLIENT'


@pytest.mark.parametrize('field,value', [('local_sequence',3), ('history_digest','0'*64),
    ('checkpoint_revision',3), ('checkpoint_digest','f'*64), ('trust_store_digest','f'*64),
    ('policy_revision',1), ('epoch_id','other'), ('epoch_counter',3)])
def test_invalid_lineages(h, field, value):
    request = h.request()
    request = change(request, target_head=change(request.target_head, **{field:value}))
    assert h.submit(request=request).status == 'INVALID_LINEAGE'


def test_rotation_requires_root_fixture_and_never_resets(h):
    req = h.request()
    req = change(req, target_head=change(req.target_head, epoch_counter=2, epoch_id='epoch-2',
                  checkpoint_revision=2, checkpoint_digest='d'*64))
    assert h.submit(request=req).status == 'INVALID_LINEAGE'
    assert h.submit(request=req, evidence=change(h.proof(req), root_transition_authorized=True)).status == 'SUCCESS'


@pytest.mark.parametrize('field', ['request_digest','predecessor_state_digest','target_head_digest'])
def test_lineage_evidence_exact_bindings(h, field):
    req = h.request()
    assert h.submit(request=req, evidence=change(h.proof(req), **{field:'f'*64})).status == 'INVALID_LINEAGE'


@pytest.mark.parametrize('now,status', [(9,'UNAUTHORIZED_CLIENT'), (200,'INDETERMINATE'), (300,'UNAUTHORIZED_CLIENT')])
def test_time_bounds(h, now, status):
    assert h.submit(now=now).status == status


@pytest.mark.parametrize('now', [True, -1, 1.5, '20', 2**63])
def test_strict_now(h, now):
    with pytest.raises(ValueError): h.submit(now=now)


def test_fork_and_clock_regression(h):
    assert h.submit(request=change(h.request(), predecessor_state_digest='f'*64)).status == 'STATE_FORK'
    first = h.submit()
    assert h.submit(first.proposed_image, now=19).status == 'INDETERMINATE'


def test_unwitnessed_rollback_is_undetectable(h):
    req, obs, proof = h.observation()
    pending = change(h.initial, head=h.request().target_head)
    assert compare_witness_observation(pending, req, obs, evidence=proof, now=31).status == 'LOCAL_EXTENSION_PENDING'
    assert compare_witness_observation(h.initial, req, obs, evidence=proof, now=31).status == 'MATCHED'
    # Both never-advanced and rolled-back local state have identical observable bytes.
    assert canonical_bytes(h.initial) == canonical_bytes(decode_canonical(WitnessStateRecord, canonical_bytes(h.initial)))


def test_witnessed_rollback_detected(h):
    first = h.submit()
    req, obs, proof = h.observation(first.proposed_image)
    assert compare_witness_observation(h.initial, req, obs, evidence=proof, now=31).status == 'ROLLBACK_OR_STATE_LOSS'


def test_equal_sequence_fork_and_ahead_indeterminate(h):
    req, obs, proof = h.observation()
    fork = change(h.initial, head=change(h.initial.head, history_digest='f'*64))
    assert compare_witness_observation(fork, req, obs, evidence=proof, now=31).status == 'STATE_FORK'
    assert compare_witness_observation(change(h.initial, witness_sequence=1), req, obs, evidence=proof, now=31).status == 'INDETERMINATE'


@pytest.mark.parametrize('case', ['timeout','missing_evidence','challenge','principal','expired','historical','tamper'])
def test_fresh_observation_guards(h, case):
    req, obs, proof = h.observation()
    now = 31
    if case == 'timeout': obs = None
    if case == 'missing_evidence': proof = None
    if case == 'challenge': req = change(req, challenge='f'*64)
    if case == 'principal': req = change(req, principal_id='other')
    if case == 'expired': now = 100
    if case == 'historical': obs = h.submit().receipt
    if case == 'tamper': obs = change(obs, state=change(h.initial, witness_sequence=9))
    assert compare_witness_observation(h.initial, req, obs, evidence=proof, now=now).status == 'INDETERMINATE'


def test_historical_chain_tampering(h):
    result = h.submit()
    bad = change(result.receipt, resulting_state=change(result.receipt.resulting_state, witness_sequence=4))
    with pytest.raises(ValueError):
        validate_witness_image(WitnessImage(initial=h.initial, receipts=(bad,)), trusted_initial=h.initial)
    with pytest.raises(ValueError):
        validate_witness_image(result.proposed_image, trusted_initial=change(h.initial, last_updated_at=9))


def test_canonical_domain_and_frozen(h):
    req = h.request()
    data = canonical_bytes(req)
    assert witness_digest(req) == sha256(b'TNC-WITNESS-BINDING-v1:' + data).hexdigest()
    assert decode_canonical(WitnessAdvanceRequest, data) == req
    with pytest.raises(ValidationError): req.request_id = 'mutated'
    for invalid in (data+b' ', b'{"request_id":"a","request_id":"b"}', b'{"x":NaN}'):
        with pytest.raises(ValueError): decode_canonical(WitnessAdvanceRequest, invalid)


@pytest.mark.parametrize('field,value', [('target_witness_sequence',True), ('target_witness_sequence',3),
    ('issued_at',-1), ('expires_at',10), ('expires_at',1000), ('predecessor_state_digest','A'*64)])
def test_record_bounds(h, field, value):
    with pytest.raises(ValueError): change(h.request(), **{field:value})


def test_capacity_and_exact_recovery(h):
    image = WitnessImage(initial=h.initial, receipts=())
    original = h.request()
    for _ in range(HISTORY_LIMIT): image = h.submit(image).proposed_image
    assert h.submit(image).status == 'CAPACITY_EXCEEDED'
    assert h.submit(image, original, evidence=None).status == 'HISTORICAL_RECEIPT'


def test_no_io_or_wall_clock(h, monkeypatch):
    import builtins
    import socket
    import sqlite3
    import time
    def denied(*args, **kwargs): raise AssertionError('Forbidden side effect')
    for obj, name in ((builtins,'open'), (socket,'socket'), (sqlite3,'connect'), (time,'time'), (time,'monotonic')):
        monkeypatch.setattr(obj, name, denied)
    assert h.submit().status == 'SUCCESS'


def test_archived_authority_and_lineage_replayed(h):
    first = h.submit()
    for field, value in (('caller', change(first.receipt.caller, request_digest='f'*64)),
                         ('evidence', change(first.receipt.evidence, target_head_digest='f'*64)),
                         ('policy', change(first.receipt.policy, advance_principals=()))):
        image = change(first.proposed_image, receipts=(change(first.receipt, **{field:value}),))
        with pytest.raises(ValueError): validate_witness_image(image, trusted_initial=h.initial)


def test_policy_regression_and_fork(h):
    request = h.request()
    policy = change(h.policy, revision=2)
    first = h.submit(request=request, policy=policy, caller=h.caller(request, policy))
    assert h.submit(first.proposed_image).status == 'INDETERMINATE'
    fork = change(policy, observation_principals=())
    req = h.request(first.proposed_image)
    assert h.submit(first.proposed_image, req, policy=fork, caller=h.caller(req, fork)).status == 'INDETERMINATE'


def test_other_principal_cannot_recover_receipt(h):
    first = h.submit()
    req = change(h.request(), principal_id='bob')
    policy = change(h.policy, revision=2, recovery_principals=('alice','bob'))
    result = h.submit(first.proposed_image, req, policy=policy, caller=h.caller(req, policy))
    assert result.status == 'UNAUTHORIZED_CLIENT' and result.receipt is None
