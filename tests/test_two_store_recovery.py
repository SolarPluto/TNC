"""Two independent temporary databases; orchestration and evidence are fixtures only."""
from contextlib import closing
from datetime import timedelta
import multiprocessing
import os
import sqlite3

import pytest

from test_update_durable_writer import (
    case, inventory, config, update, signed, host, stored, setup, NOW,
    read, commit, revoke, Writer as RuntimeWriter, LocalCheckpointForTesting, clock,
)
from test_reconciliation_validation import envelope, classify
from test_reconciliation_simulation import auth, next_command
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.reconciliation_simulation import (
    AuthoritySimulationState, SimulationGrant, SyntheticAuthorityPolicy, SyntheticAuthorityCaller,
)
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore
from tnc.provenance.reconciliation_durable_writer import TestCheckpointAuthorityWriter, AuthorityWriteError


class TwoStoreRecoveryHarness:
    def __init__(self, runtime, authority, caller):
        self.runtime, self.authority, self.caller = runtime, authority, caller

    def execute_runtime_commit(self):
        # Exercise the real test writer's REGISTER, PREPARE and COMMIT APIs.
        return commit(self.runtime)

    def retained_command(self, request_id='handoff-1'):
        return next_command(self.authority.load(now=NOW), read(self.runtime), request_id)

    def submit(self, command, authorization):
        return self.authority.submit(command, caller=self.caller,
            batch_authorization=authorization, now=NOW)

    def retry(self, command):
        return self.submit(command.model_copy(update={'candidate_image':None}), None)


@pytest.fixture
def harness(setup, tmp_path):
    initial = read(setup)
    anchor = envelope(initial)
    grant = SimulationGrant(principal_id='reconciler', actions=('OBSERVE_CURRENT','RECOVER','SUBMIT'),
        valid_from=NOW, valid_until=NOW+timedelta(hours=2))
    policy = SyntheticAuthorityPolicy(deployment_id=anchor.deployment_id, store_instance_id=anchor.store_instance_id,
        revision=1, grants=(grant,), valid_from=NOW, valid_until=grant.valid_until)
    state = AuthoritySimulationState(initial_envelope=anchor,current_envelope=anchor,accepted_image=initial,policy=policy)
    path = tmp_path/'independent-authority.sqlite'
    TestCheckpointAuthorityStore.create_for_testing(path,state,trusted_initial_envelope=anchor,now=NOW)
    authority = TestCheckpointAuthorityWriter(path,trusted_initial_envelope=anchor)
    caller = SyntheticAuthorityCaller(principal_id='reconciler',deployment_id=anchor.deployment_id,
        store_instance_id=anchor.store_instance_id,valid_from=NOW,valid_until=grant.valid_until)
    assert setup.writer.path != path
    return TwoStoreRecoveryHarness(setup,authority,caller)


def crash_runtime(path, identity, admin, observations, intent, signature):
    writer = RuntimeWriter(path, identity_provider=identity, administration_provider=admin,
        observation_provider=observations,checkpoint_provider=LocalCheckpointForTesting(),clock=clock)
    writer.register(intent,signature); writer.prepare(intent,signature); writer.commit(intent,signature)
    os._exit(73)


def crash_authority(path, anchor, caller, command, authorization, point):
    writer = TestCheckpointAuthorityWriter(path,trusted_initial_envelope=anchor)
    def hook(where):
        if where == point: os._exit(73)
    writer._hook = hook
    writer.submit(command,caller=caller,batch_authorization=authorization,now=NOW)


def run_crash(target, args):
    process = multiprocessing.get_context('spawn').Process(target=target,args=args)
    try:
        process.start(); process.join(25)
        assert process.exitcode == 73
    finally:
        if process.is_alive(): process.terminate(); process.join(5)


def test_runtime_commit_crash_gap_and_recovery(harness):
    h=harness; s=h.runtime
    before=h.authority.load(now=NOW)
    run_crash(crash_runtime,(str(s.writer.path),s.host.identity,s.admin,s.host.observations,s.intent,s.signature))
    image=read(s)
    assert [e.payload.kind for e in image.events] == ['AUTHORITY','REGISTER','PREPARE','COMMIT']
    assert h.authority.load(now=NOW)==before
    assert classify(image,before.current_envelope).relationship=='DATABASE_EXTENSION_PENDING'
    # The surviving fixture host reconstructs exact committed bytes after reopening.
    command=h.retained_command(); evidence=auth(command.request)
    accepted=h.submit(command,evidence)
    assert accepted.status=='ACCEPTED'
    assert classify(image,h.authority.load(now=NOW).current_envelope).relationship=='MATCHED'
    assert h.retry(command).acceptance_bytes==accepted.acceptance_bytes
    assert read(s)==image


@pytest.mark.parametrize('point,committed',[('before_commit',False),('after_commit',True)])
def test_authority_crash_preserves_runtime_and_recovers(harness,point,committed):
    h=harness; h.execute_runtime_commit()
    image=read(h.runtime); command=h.retained_command(); evidence=auth(command.request)
    before=h.authority.load(now=NOW)
    run_crash(crash_authority,(str(h.authority.path),before.initial_envelope,h.caller,command,evidence,point))
    persisted=h.authority.load(now=NOW)
    assert len(persisted.history)==int(committed)
    result=h.submit(command,evidence)
    assert result.status==('RECOVERED' if committed else 'ACCEPTED')
    if committed: assert result.acceptance_bytes==canonical_bytes(persisted.history[0].acceptance)
    assert len(h.authority.load(now=NOW).history)==1
    assert read(h.runtime)==image


def test_old_receipt_after_later_runtime_authority_event(harness):
    h=harness; h.execute_runtime_commit(); first=h.retained_command()
    receipt=h.submit(first,auth(first.request))
    revoke(h.runtime); h.runtime.writer.record_authority(expected_revision=1)
    image=read(h.runtime)
    assert image.events[-1].payload.kind=='AUTHORITY'
    second=h.retained_command('handoff-2'); h.submit(second,auth(second.request))
    head=h.authority.load(now=NOW)
    assert h.retry(first).acceptance_bytes==receipt.acceptance_bytes
    assert h.authority.load(now=NOW)==head and read(h.runtime)==image
    assert head.current_envelope.authority_revision==3


def test_runtime_retry_does_not_duplicate_handoff(harness):
    h=harness; runtime_receipt=h.execute_runtime_commit()
    command=h.retained_command(); authority_receipt=h.submit(command,auth(command.request))
    image=read(h.runtime); state=h.authority.load(now=NOW)
    assert h.runtime.writer.commit(h.runtime.intent,h.runtime.signature).receipt_bytes==runtime_receipt.receipt_bytes
    assert h.retry(command).acceptance_bytes==authority_receipt.acceptance_bytes
    assert read(h.runtime)==image and h.authority.load(now=NOW)==state


@pytest.mark.parametrize('same_id',[True,False])
def test_conflicting_or_competing_retained_requests(harness,same_id):
    h=harness; h.execute_runtime_commit(); command=h.retained_command()
    request=command.request.model_copy(update=({'event_batch_hash':'0'*64} if same_id else {'request_id':'competitor'}))
    other=command.model_copy(update={'request':request})
    h.submit(command,auth(command.request)); state=h.authority.load(now=NOW); image=read(h.runtime)
    with pytest.raises(AuthorityWriteError,match='REQUEST_CONFLICT' if same_id else 'CAS_CONFLICT'):
        h.submit(other,auth(request))
    assert h.authority.load(now=NOW)==state and read(h.runtime)==image


@pytest.mark.parametrize('accepted',[False,True])
def test_permission_removed_in_gap_or_before_retry(harness,accepted):
    h=harness; h.execute_runtime_commit(); command=h.retained_command()
    if accepted: h.submit(command,auth(command.request))
    state=h.authority.load(now=NOW); prior=state.policy
    h.authority.replace_policy_for_testing(prior.model_copy(update={'revision':2,'grants':()}),
        expected_policy_revision=1,expected_policy_digest=record_digest(prior),now=NOW)
    image=read(h.runtime)
    with pytest.raises(AuthorityWriteError,match='ACCESS_DENIED'): h.submit(command,auth(command.request))
    assert len(h.authority.load(now=NOW).history)==int(accepted) and read(h.runtime)==image


@pytest.mark.parametrize('missing',[True,False])
def test_local_commit_is_not_independent_authorization(harness,missing):
    h=harness; h.execute_runtime_commit(); command=h.retained_command()
    evidence=None if missing else auth(command.request).model_copy(update={'approved':False})
    with pytest.raises(AuthorityWriteError): h.submit(command,evidence)
    assert not h.authority.load(now=NOW).history
    assert classify(read(h.runtime),h.authority.load(now=NOW).current_envelope).relationship=='DATABASE_EXTENSION_PENDING'


def test_distinct_schemas_no_checkpoint_or_locator_publication(harness):
    h=harness; h.execute_runtime_commit()
    with closing(sqlite3.connect(h.runtime.writer.path)) as c:
        runtime_checkpoint=c.execute('SELECT checkpoint FROM store_state').fetchone()[0]
        runtime_id=c.execute('PRAGMA application_id').fetchone()[0]
    command=h.retained_command(); h.submit(command,auth(command.request))
    with closing(sqlite3.connect(h.runtime.writer.path)) as c:
        assert c.execute('SELECT checkpoint FROM store_state').fetchone()[0]==runtime_checkpoint
        assert c.execute('SELECT count(*) FROM publications').fetchone()==(0,)
    with closing(sqlite3.connect(h.authority.path)) as c:
        assert c.execute('PRAGMA application_id').fetchone()[0]!=runtime_id
        assert len(c.execute('PRAGMA database_list').fetchall())==1
