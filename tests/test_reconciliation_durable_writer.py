from contextlib import closing
from datetime import timedelta
import multiprocessing
import os
import sqlite3

import pytest

from test_reconciliation_durable_store import (
    case, inventory, config, update, signed, host, stored, reconciliation, sim, db, NOW,
)
from test_reconciliation_simulation import auth, next_command
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.reconciliation_durable_writer import TestCheckpointAuthorityWriter as Writer, AuthorityWriteError


@pytest.fixture
def writer(db, sim):
    return Writer(db.path, trusted_initial_envelope=sim[4], busy_timeout=5)


def submit(writer, sim, **kw):
    values = dict(command=sim[1], caller=sim[2], batch_authorization=sim[3], now=NOW)
    values.update(kw)
    return writer.submit(**values)


def policy(writer, sim, value=None):
    prior = writer.load(now=NOW).policy
    value = value or prior.model_copy(update={'revision': prior.revision+1, 'grants': ()})
    return writer.replace_policy_for_testing(value, expected_policy_revision=prior.revision,
        expected_policy_digest=record_digest(prior), now=NOW)


def test_commit_and_exact_retry(writer, sim):
    first = submit(writer, sim)
    before = writer.load(now=NOW)
    retry = submit(writer, sim, batch_authorization=None,
        command=sim[1].model_copy(update={'candidate_image': None}))
    assert (first.status, retry.status) == ('ACCEPTED','RECOVERED')
    assert first.acceptance_bytes == retry.acceptance_bytes == canonical_bytes(before.history[0].acceptance)
    assert writer.load(now=NOW) == before


def test_recover_command_after_expiration(writer, sim):
    first = submit(writer, sim)
    retry = submit(writer, sim, command=sim[1].model_copy(update={'action':'RECOVER','candidate_image':None}),
        batch_authorization=None, now=NOW+timedelta(minutes=90))
    assert retry.acceptance_bytes == first.acceptance_bytes


def test_historical_recovery_after_advancement(writer, sim):
    from tnc.provenance.reconciliation_simulation import _prefix
    image = sim[1].candidate_image
    initial = next_command(sim[0], _prefix(image,len(image.events)-1), 'first-prefix')
    first = submit(writer, sim, command=initial, batch_authorization=auth(initial.request))
    second = next_command(writer.load(now=NOW), image)
    submit(writer, sim, command=second, batch_authorization=auth(second.request))
    before = writer.load(now=NOW)
    retry = submit(writer, sim, command=initial.model_copy(update={'candidate_image':None}), batch_authorization=None)
    assert retry.acceptance_bytes == first.acceptance_bytes
    assert writer.load(now=NOW) == before


@pytest.mark.parametrize('field,value', [('expected_authority_revision', 9), ('expected_envelope_hash','0'*64)])
def test_cas(writer, sim, field, value):
    request = sim[1].request.model_copy(update={field:value})
    with pytest.raises(AuthorityWriteError, match='CAS_CONFLICT'):
        submit(writer, sim, command=sim[1].model_copy(update={'request':request}), batch_authorization=auth(request))
    assert writer.load(now=NOW) == sim[0]


@pytest.mark.parametrize('point', ['locked','acceptance_inserted','state_updated','before_commit'])
def test_rollback(writer, sim, point):
    def hook(where):
        if where == point: raise RuntimeError('sensitive path')
    writer._hook = hook
    with pytest.raises(AuthorityWriteError, match='^STORE_UNAVAILABLE$'):
        submit(writer, sim)
    assert writer.load(now=NOW) == sim[0]


def test_lost_ack(writer, sim):
    def hook(where):
        if where == 'after_commit': raise RuntimeError('lost acknowledgement')
    writer._hook = hook
    with pytest.raises(AuthorityWriteError, match='OUTCOME_UNKNOWN'):
        submit(writer, sim)
    writer._hook = lambda _: None
    assert submit(writer, sim).status == 'RECOVERED'


def test_policy_preserves_history(writer, sim):
    submit(writer, sim)
    before = writer.load(now=NOW)
    assert policy(writer, sim).status == 'POLICY_REPLACED'
    after = writer.load(now=NOW)
    assert after.history == before.history and after.current_envelope == before.current_envelope
    with pytest.raises(AuthorityWriteError, match='ACCESS_DENIED'):
        submit(writer, sim)


def test_policy_before_submission_denies(writer, sim):
    policy(writer, sim)
    with pytest.raises(AuthorityWriteError, match='ACCESS_DENIED'):
        submit(writer, sim)
    assert not writer.load(now=NOW).history


def test_policy_cas_and_identical_current(writer, sim):
    old = sim[0].policy
    policy(writer, sim)
    current = writer.load(now=NOW).policy
    with pytest.raises(AuthorityWriteError, match='POLICY_CONFLICT'):
        writer.replace_policy_for_testing(current, expected_policy_revision=old.revision,
            expected_policy_digest=record_digest(old), now=NOW)
    assert policy(writer, sim, current).status == 'UNCHANGED'


@pytest.mark.parametrize('change', [dict(revision=1), dict(store_instance_id='wrong'),
    dict(deployment_id='wrong'), dict(valid_until=NOW)])
def test_invalid_policy(writer, sim, change):
    candidate = sim[0].policy.model_copy(update={'revision':2,'grants':(), **change})
    with pytest.raises(AuthorityWriteError):
        policy(writer, sim, candidate)
    assert writer.load(now=NOW) == sim[0]


@pytest.mark.parametrize('point', ['state_updated','before_commit'])
def test_policy_rollback(writer, sim, point):
    def hook(where):
        if where == point: raise RuntimeError()
    writer._hook = hook
    with pytest.raises(AuthorityWriteError): policy(writer, sim)
    assert writer.load(now=NOW) == sim[0]


def test_foreign_and_absent_are_denied(writer, sim):
    submit(writer, sim)
    caller = sim[2].model_copy(update={'principal_id':'outsider'})
    for request_id in (sim[1].request.request_id, 'absent'):
        request = sim[1].request.model_copy(update={'request_id':request_id,'principal_id':'outsider'})
        with pytest.raises(AuthorityWriteError, match='^ACCESS_DENIED$'):
            submit(writer, sim, caller=caller, command=sim[1].model_copy(update={'request':request}))


def test_conflicting_retry(writer, sim):
    submit(writer, sim)
    request = sim[1].request.model_copy(update={'event_batch_hash':'0'*64})
    with pytest.raises(AuthorityWriteError, match='REQUEST_CONFLICT'):
        submit(writer, sim, command=sim[1].model_copy(update={'request':request}))


def test_submit_permission_does_not_grant_recovery(writer, sim):
    submit(writer, sim)
    old = sim[0].policy
    policy(writer, sim, old.model_copy(update={'revision':2, 'grants':(old.grants[0].model_copy(update={'actions':('SUBMIT',)}),)}))
    with pytest.raises(AuthorityWriteError, match='ACCESS_DENIED'): submit(writer, sim)


def test_busy_timeout(writer, sim):
    writer.busy_timeout = 0
    with closing(sqlite3.connect(writer.path, isolation_level=None)) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            with pytest.raises(AuthorityWriteError, match='STORE_BUSY'): submit(writer, sim)
        finally: connection.execute('ROLLBACK')


def test_missing_not_created(tmp_path, sim):
    path = tmp_path/'missing.db'
    writer = Writer(path, trusted_initial_envelope=sim[4])
    with pytest.raises(AuthorityWriteError): submit(writer, sim)
    assert not path.exists()


def test_corruption_blocks_writer(writer, sim):
    with closing(sqlite3.connect(writer.path)) as connection:
        connection.execute("UPDATE authority_state SET digest=?", ('0'*64,)); connection.commit()
    with pytest.raises(AuthorityWriteError, match='STORE_UNAVAILABLE'): submit(writer, sim)


@pytest.mark.parametrize('change', [dict(approved=False), dict(policy_revision=2), dict(event_batch_hash='0'*64)])
def test_bad_batch_never_writes(writer, sim, change):
    with pytest.raises(AuthorityWriteError, match='BATCH_DENIED'):
        submit(writer, sim, batch_authorization=sim[3].model_copy(update=change))
    assert writer.load(now=NOW) == sim[0]


def test_final_capacity_validation_rolls_back(writer, sim, monkeypatch):
    from tnc.provenance import reconciliation_durable_store as loader
    original = loader.STORED_LIMIT
    def hook(point):
        if point == 'state_updated': monkeypatch.setattr(loader, 'STORED_LIMIT', 1)
    writer._hook = hook
    with pytest.raises(AuthorityWriteError): submit(writer, sim)
    monkeypatch.setattr(loader, 'STORED_LIMIT', original)
    assert writer.load(now=NOW) == sim[0]


@pytest.mark.parametrize('value', [True, -1, 6, float('nan')])
def test_timeout_bounds(db, sim, value):
    with pytest.raises(ValueError): Writer(db.path, trusted_initial_envelope=sim[4], busy_timeout=value)


def child(path, sim, action, start, reached, release, queue, point=None):
    writer = Writer(path, trusted_initial_envelope=sim[4], busy_timeout=5)
    def hook(where):
        if point == 'crash:'+where: os._exit(73)
        if point == where:
            reached.set()
            if not release.wait(15): raise RuntimeError('barrier timeout')
    writer._hook = hook
    try:
        if not start.wait(15): raise RuntimeError('start timeout')
        result = policy(writer, sim) if action == 'policy' else submit(writer, sim)
        queue.put((result.status, result.acceptance_bytes))
    except Exception as exc: queue.put(('error', str(exc)))


def cleanup(processes):
    for p in processes:
        p.join(15)
        if p.is_alive(): p.terminate(); p.join(5)


@pytest.mark.parametrize('distinct', [False, True])
def test_competing_processes(writer, sim, distinct):
    ctx = multiprocessing.get_context('spawn')
    start, reached, release, q = ctx.Event(), ctx.Event(), ctx.Event(), ctx.Queue()
    other = sim
    if distinct:
        request = sim[1].request.model_copy(update={'request_id':'competing'})
        other = (sim[0],sim[1].model_copy(update={'request':request}),sim[2],auth(request),sim[4])
    processes = [ctx.Process(target=child,args=(str(writer.path),s,'submit',start,reached,release,q)) for s in (sim,other)]
    try:
        for p in processes: p.start()
        start.set()
        results = [q.get(timeout=25) for _ in processes]
        assert sorted(r[0] for r in results) == (['ACCEPTED','error'] if distinct else ['ACCEPTED','RECOVERED'])
        if distinct: assert ('error','CAS_CONFLICT') in results
        else: assert results[0][1] == results[1][1]
        assert len(writer.load(now=NOW).history) == 1
    finally: cleanup(processes)


@pytest.mark.parametrize('point,committed', [('before_commit',False),('after_commit',True)])
def test_process_crash(writer, sim, point, committed):
    ctx = multiprocessing.get_context('spawn')
    start, reached, release, q = ctx.Event(), ctx.Event(), ctx.Event(), ctx.Queue()
    p = ctx.Process(target=child,args=(str(writer.path),sim,'submit',start,reached,release,q,'crash:'+point))
    try:
        p.start(); start.set(); p.join(20)
        assert p.exitcode == 73
        assert len(writer.load(now=NOW).history) == int(committed)
        assert submit(writer, sim).status == ('RECOVERED' if committed else 'ACCEPTED')
    finally: cleanup([p])


@pytest.mark.parametrize('point,committed', [('before_commit',False),('after_commit',True)])
def test_policy_process_crash(writer, sim, point, committed):
    ctx = multiprocessing.get_context('spawn')
    start, reached, release, q = ctx.Event(), ctx.Event(), ctx.Event(), ctx.Queue()
    p = ctx.Process(target=child,args=(str(writer.path),sim,'policy',start,reached,release,q,'crash:'+point))
    try:
        p.start(); start.set(); p.join(20)
        assert p.exitcode == 73
        current = writer.load(now=NOW)
        assert current.policy.revision == (2 if committed else 1)
        assert current.history == sim[0].history and current.current_envelope == sim[0].current_envelope
    finally: cleanup([p])


@pytest.mark.parametrize('policy_first', [True,False])
def test_serialized_policy_race(writer, sim, policy_first):
    ctx = multiprocessing.get_context('spawn')
    start, reached, release, q = ctx.Event(), ctx.Event(), ctx.Event(), ctx.Queue()
    first = ctx.Process(target=child,args=(str(writer.path),sim,'policy' if policy_first else 'submit',start,reached,release,q,'before_commit'))
    second = ctx.Process(target=child,args=(str(writer.path),sim,'submit' if policy_first else 'policy',start,ctx.Event(),ctx.Event(),q))
    processes = [first]
    try:
        first.start(); start.set(); assert reached.wait(20)
        second.start(); processes.append(second); release.set()
        results = [q.get(timeout=25) for _ in processes]
        assert ('POLICY_REPLACED',None) in results
        if policy_first: assert ('error','ACCESS_DENIED') in results
        else: assert any(r[0]=='ACCEPTED' for r in results)
        assert len(writer.load(now=NOW).history) == int(not policy_first)
    finally: release.set(); cleanup(processes)
