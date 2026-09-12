from contextlib import closing
from datetime import timedelta
import sqlite3

import pytest

from test_reconciliation_durable_writer import (
    case,inventory,config,update,signed,host,stored,reconciliation,sim,db,writer,NOW,submit,policy,
)
from tnc.provenance.authorization_models import record_digest
from tnc.provenance.reconciliation_simulation import ClientCheckpointMark
from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter, AuthorityReadError

CHALLENGE='c'*64


@pytest.fixture
def reader(db,sim):
    return ReadOnlyAuthorityAdapter(db.path,trusted_initial_envelope=sim[4])


def observe(reader,sim):
    return reader.observe_current(CHALLENGE,caller=sim[2],now=NOW)


def mark(envelope):
    return ClientCheckpointMark(deployment_id=envelope.deployment_id,store_instance_id=envelope.store_instance_id,
        authority_revision=envelope.authority_revision,envelope_hash=record_digest(envelope))


def compare(reader,sim,observation,high,**changes):
    kw=dict(expected_challenge=CHALLENGE,principal_id=sim[2].principal_id,now=NOW)
    kw.update(changes)
    return reader.evaluate_client_observation(observation,high,**kw)


def test_original_bytes_after_expiry(reader,writer,sim):
    saved=submit(writer,sim).acceptance_bytes
    assert reader.recover_historical(sim[1].request,caller=sim[2],now=NOW+timedelta(minutes=90))==saved


def test_current_observation_binding(reader,sim):
    result=observe(reader,sim)
    assert result.source=='SYNTHETIC' and result.challenge==CHALLENGE
    assert result.principal_id==sim[2].principal_id and result.envelope==sim[4]
    assert result.valid_until<=min(sim[2].valid_until,sim[0].policy.valid_until,sim[4].valid_until)


@pytest.mark.parametrize('change',[dict(principal_id='other'),dict(store_instance_id='other'),dict(valid_from=NOW-timedelta(hours=1),valid_until=NOW)])
def test_denied_identity(reader,writer,sim,change):
    submit(writer,sim)
    caller=sim[2].model_copy(update=change)
    for request in (sim[1].request,sim[1].request.model_copy(update={'request_id':'missing'})):
        with pytest.raises(AuthorityReadError,match='^ACCESS_DENIED$'):
            reader.recover_historical(request,caller=caller,now=NOW)


def test_current_policy_removal(reader,writer,sim):
    submit(writer,sim); policy(writer,sim)
    with pytest.raises(AuthorityReadError,match='ACCESS_DENIED'): observe(reader,sim)
    with pytest.raises(AuthorityReadError,match='ACCESS_DENIED'):
        reader.recover_historical(sim[1].request,caller=sim[2],now=NOW)


def test_request_id_alone_rejected(reader,sim):
    with pytest.raises(AuthorityReadError,match='INVALID_INPUT'):
        reader.recover_historical(sim[1].request.request_id,caller=sim[2],now=NOW)


def test_conflicting_request(reader,writer,sim):
    submit(writer,sim)
    with pytest.raises(AuthorityReadError,match='REQUEST_CONFLICT'):
        reader.recover_historical(sim[1].request.model_copy(update={'event_batch_hash':'0'*64}),caller=sim[2],now=NOW)


@pytest.mark.parametrize('challenge',['bad','C'*64,None])
def test_invalid_challenge(reader,sim,challenge):
    with pytest.raises(AuthorityReadError,match='INVALID_INPUT'):
        reader.observe_current(challenge,caller=sim[2],now=NOW)


def test_unchanged_and_fork(reader,sim):
    result=observe(reader,sim); high=mark(sim[4])
    assert compare(reader,sim,result,high).status=='UNCHANGED'
    assert compare(reader,sim,result,high.model_copy(update={'envelope_hash':'0'*64})).status=='FORK'


def test_advance_needs_chain(reader,writer,sim):
    submit(writer,sim); result=observe(reader,sim); high=mark(sim[4])
    assert compare(reader,sim,result,high).status=='INDETERMINATE'
    proposal=compare(reader,sim,result,high,chain=(result.envelope,))
    assert proposal.status=='ADVANCE_PROPOSED' and proposal.audit_only
    assert high==mark(sim[4])


def test_stale_observation(reader,writer,sim):
    old=observe(reader,sim); submit(writer,sim); current=observe(reader,sim)
    assert compare(reader,sim,old,mark(current.envelope)).status=='STALE_HISTORICAL'


@pytest.mark.parametrize('changes',[dict(expected_challenge='a'*64),dict(principal_id='other'),dict(now=NOW+timedelta(hours=3))])
def test_comparison_binding(reader,sim,changes):
    assert compare(reader,sim,observe(reader,sim),mark(sim[4]),**changes).status=='INDETERMINATE'


def test_missing_file(tmp_path,sim):
    path=tmp_path/'absent.sqlite'
    with pytest.raises(AuthorityReadError,match='AUTHORITY_UNAVAILABLE'):
        observe(ReadOnlyAuthorityAdapter(path,trusted_initial_envelope=sim[4]),sim)
    assert not path.exists()


def test_corrupt_projection(reader,writer,sim):
    submit(writer,sim)
    with closing(sqlite3.connect(writer.path)) as c:
        c.execute("UPDATE authority_state SET digest=?",('0'*64,)); c.commit()
    with pytest.raises(AuthorityReadError,match='AUTHORITY_UNAVAILABLE'): observe(reader,sim)


def test_read_while_writer_locked_and_no_table_changes(reader,writer,sim):
    submit(writer,sim)
    with closing(sqlite3.connect(writer.path,isolation_level=None)) as c:
        before=list(c.iterdump()); c.execute('BEGIN IMMEDIATE')
        try:
            observe(reader,sim)
            reader.recover_historical(sim[1].request,caller=sim[2],now=NOW)
        finally: c.execute('ROLLBACK')
        assert list(c.iterdump())==before


def test_uncommitted_policy_not_visible(reader,writer,sim):
    # An uncommitted invalid projection must not contaminate the reader's snapshot.
    with closing(sqlite3.connect(writer.path,isolation_level=None)) as c:
        c.execute('BEGIN IMMEDIATE'); c.execute('UPDATE authority_state SET policy_revision=99')
        try: assert observe(reader,sim).envelope==sim[4]
        finally: c.execute('ROLLBACK')


def test_anchor_mismatch(db,sim):
    reader=ReadOnlyAuthorityAdapter(db.path,trusted_initial_envelope=sim[4].model_copy(update={'issuer_id':'other'}))
    with pytest.raises(AuthorityReadError,match='AUTHORITY_UNAVAILABLE'): observe(reader,sim)


def test_old_receipt_after_advancement(reader,writer,sim):
    from test_reconciliation_simulation import next_command, auth
    from tnc.provenance.reconciliation_simulation import _prefix
    image=sim[1].candidate_image
    first=next_command(sim[0],_prefix(image,len(image.events)-1),'early')
    receipt=submit(writer,sim,command=first,batch_authorization=auth(first.request))
    second=next_command(writer.load(now=NOW),image,'later')
    submit(writer,sim,command=second,batch_authorization=auth(second.request))
    before=writer.load(now=NOW)
    assert reader.recover_historical(first.request,caller=sim[2],now=NOW)==receipt.acceptance_bytes
    assert observe(reader,sim).envelope==before.current_envelope
    assert writer.load(now=NOW)==before


def test_snapshot_then_policy_change(reader,writer,sim,monkeypatch):
    from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore
    original=TestCheckpointAuthorityStore._load
    active=False
    def load(store,connection,*,now):
        nonlocal active
        state=original(store,connection,now=now)
        if not active:
            active=True
            policy(writer,sim)
        return state
    monkeypatch.setattr(TestCheckpointAuthorityStore,'_load',load)
    assert observe(reader,sim).envelope==sim[4]
    with pytest.raises(AuthorityReadError,match='ACCESS_DENIED'): observe(reader,sim)
