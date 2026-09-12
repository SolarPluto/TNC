from contextlib import closing
import multiprocessing
import os
import sqlite3
import pytest
from test_client_high_water_logic import case,inventory,config,update,signed,host,stored,reconciliation,NOW,vector,client,successor
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.client_high_water_store import TestClientHighWaterStore,ClientStoreError


@pytest.fixture
def store(tmp_path,client):
    result=TestClientHighWaterStore.create_for_testing(tmp_path/'client.db',trusted_initial_anchor=client[0],now=client[0].accepted_timestamp)
    result.clock=lambda:client[0].accepted_timestamp
    return result


def apply(store,client,request=None): return store.apply(request or client[2],caller_principal=client[0].principal_id)
def load(store,client): return store.load(now=client[0].accepted_timestamp)


def test_creation_and_retry(store,client):
    assert load(store,client)==client[1]
    first=apply(store,client); before=load(store,client)
    assert first.status=='UNCHANGED' and before.local_sequence==1
    assert first.receipt_bytes==canonical_bytes(before.history[0].receipt)
    assert apply(store,client).receipt_bytes==first.receipt_bytes
    assert load(store,client)==before


def test_historical_retry_after_advance(store,client,vector):
    first=apply(store,client)
    advance=successor(vector,client[2],load(store,client))
    assert apply(store,client,advance).status=='VALID_ADVANCE'
    store.clock=lambda:client[0].accepted_timestamp+1000
    result=apply(store,client)
    assert result.status=='RECOVERED' and result.receipt_bytes==first.receipt_bytes
    assert load(store,client).authority_revision==2


@pytest.mark.parametrize('action',['load','apply'])
def test_missing_no_creation(tmp_path,client,action):
    path=tmp_path/'missing.db'; s=TestClientHighWaterStore(path,trusted_initial_anchor=client[0])
    with pytest.raises(ClientStoreError): load(s,client) if action=='load' else apply(s,client)
    assert not path.exists()


def test_no_overwrite(store,client):
    before=store.path.read_bytes()
    with pytest.raises(ClientStoreError): TestClientHighWaterStore.create_for_testing(store.path,trusted_initial_anchor=client[0],now=client[0].accepted_timestamp)
    assert store.path.read_bytes()==before


@pytest.mark.parametrize('sql',[
    'PRAGMA user_version=9','PRAGMA application_id=0','CREATE TABLE extra(x INTEGER)',
    'DELETE FROM client_state','UPDATE client_state SET local_sequence=4',
    "UPDATE client_state SET digest='"+'f'*64+"'",'DROP TRIGGER client_receipts_no_update'])
def test_corrupt_store(store,client,sql):
    with closing(sqlite3.connect(store.path)) as c: c.execute(sql); c.commit()
    with pytest.raises(ClientStoreError): load(store,client)
    with pytest.raises(ClientStoreError): apply(store,client)


@pytest.mark.parametrize('point',['locked','receipt_inserted','state_updated','before_commit'])
def test_rollback(store,client,point):
    def hook(where):
        if where==point: raise RuntimeError('injected')
    store._hook=hook
    with pytest.raises(ClientStoreError): apply(store,client)
    assert load(store,client)==client[1]


def test_lost_ack(store,client):
    def hook(where):
        if where=='after_commit': raise RuntimeError('lost response')
    store._hook=hook
    with pytest.raises(ClientStoreError,match='OUTCOME_UNKNOWN'): apply(store,client)
    store._hook=lambda _:None
    assert apply(store,client).status=='RECOVERED'


def test_expiry_after_lock(store,client):
    store.clock=lambda:client[0].accepted_timestamp+60
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'): apply(store,client)
    assert load(store,client)==client[1]


def test_expiry_before_commit_rolls_back(store,client):
    def hook(where):
        if where=='before_recheck': store.clock=lambda:client[0].accepted_timestamp+60
    store._hook=hook
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'): apply(store,client)
    assert load(store,client)==client[1]


def test_wrong_anchor(store,client):
    other=TestClientHighWaterStore(store.path,trusted_initial_anchor=client[0].model_copy(update={'envelope_digest':'f'*64}))
    with pytest.raises(ClientStoreError): load(other,client)


def test_busy(store,client):
    store.timeout=0
    with closing(sqlite3.connect(store.path,isolation_level=None)) as c:
        c.execute('BEGIN IMMEDIATE')
        try:
            with pytest.raises(ClientStoreError,match='STORE_BUSY'): apply(store,client)
            assert load(store,client)==client[1]
        finally: c.execute('ROLLBACK')


def test_creation_rollback(tmp_path,client,monkeypatch):
    import tnc.provenance.client_high_water_store as module
    path=tmp_path/'failed.db'
    monkeypatch.setattr(module,'DDL',module.DDL[:1]+('INVALID SQL',))
    with pytest.raises(ClientStoreError): TestClientHighWaterStore.create_for_testing(path,trusted_initial_anchor=client[0],now=client[0].accepted_timestamp)
    with closing(sqlite3.connect(path)) as c: assert c.execute('SELECT name FROM sqlite_schema').fetchall()==[]


def worker(path,anchor,request,start,q,point=None):
    s=TestClientHighWaterStore(path,trusted_initial_anchor=anchor,clock=lambda:anchor.accepted_timestamp,busy_timeout=5)
    def hook(where):
        if where==point: os._exit(73)
    s._hook=hook
    try:
        if not start.wait(15): raise RuntimeError('timeout')
        result=s.apply(request,caller_principal=anchor.principal_id)
        q.put((result.status,result.receipt_bytes))
    except Exception as exc: q.put(('error',str(exc)))


def cleanup(ps):
    for p in ps:
        p.join(20)
        if p.is_alive(): p.terminate(); p.join(5)


@pytest.mark.parametrize('point,committed',[('before_commit',False),('after_commit',True)])
def test_process_exit(store,client,point,committed):
    ctx=multiprocessing.get_context('spawn'); start=ctx.Event(); q=ctx.Queue()
    p=ctx.Process(target=worker,args=(str(store.path),client[0],client[2],start,q,point))
    try:
        p.start(); start.set(); p.join(20); assert p.exitcode==73
        assert load(store,client).local_sequence==int(committed)
        assert apply(store,client).status==('RECOVERED' if committed else 'UNCHANGED')
    finally: cleanup([p])


@pytest.mark.parametrize('distinct',[False,True])
def test_competing_processes(store,client,vector,distinct):
    ctx=multiprocessing.get_context('spawn'); start=ctx.Event(); q=ctx.Queue()
    first=successor(vector,client[2],client[1])
    other=first
    if distinct:
        other=successor(vector,client[2],client[1],previous='f'*64,op='competitor')
        # Both must be valid successors before racing; change logical envelope key.
        from test_reconciliation_verifier import response
        env=first.response.payload.envelope.model_copy(update={'key_id':'f'*64})
        from tnc.provenance.authorization_models import record_digest
        payload=first.response.payload.model_copy(update={'envelope':env,'envelope_digest':record_digest(env)})
        other=first.model_copy(update={'operation_id':'competitor','response':response(vector,payload)})
    ps=[ctx.Process(target=worker,args=(str(store.path),client[0],r,start,q)) for r in (first,other)]
    try:
        for p in ps: p.start()
        start.set(); results=[q.get(timeout=25) for _ in ps]
        assert sorted(r[0] for r in results)==(['CONFLICT_FORK','VALID_ADVANCE'] if distinct else ['RECOVERED','VALID_ADVANCE'])
        assert load(store,client).local_sequence==1
        if not distinct: assert results[0][1]==results[1][1]
    finally: cleanup(ps)
