"""Temporary isolated stores, real process exits, and explicit two-store gaps."""
from contextlib import closing
import multiprocessing
import os
import sqlite3
import pytest
from test_client_request_journal_logic import (
    case,inventory,config,update,signed,host,stored,reconciliation,NOW,
    vector,response,client,setup,
)
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.client_high_water_store import TestClientHighWaterStore
from tnc.provenance.client_request_journal_store import TestClientRequestJournalStore, ClientJournalStoreError
import tnc.provenance.client_request_journal_store as module


@pytest.fixture
def store(tmp_path,setup):
    anchor,_,_,_=setup; now=anchor.accepted_timestamp
    high=TestClientHighWaterStore.create_for_testing(tmp_path/'high_water.db',trusted_initial_anchor=anchor,now=now)
    high.clock=lambda:now
    j=TestClientRequestJournalStore.create_for_testing(tmp_path/'request_journal.db',trusted_client_anchor=anchor,now=now)
    j.clock=lambda:now; j.high_water_store=high
    return j


def register(j,c,intent=None): return j.register_intent(intent or c[3],caller_principal=c[0].principal_id)
def retain(j,c,raw=None): return j.retain_response(c[3].operation_id,canonical_bytes(c[2].response) if raw is None else raw,caller_principal=c[0].principal_id)
def recover(j,c): return j.recover(c[3].operation_id,caller_principal=c[0].principal_id)
def load(j,c): return j.load(caller_principal=c[0].principal_id,now=j.clock())
def apply_high(j,c): return j.high_water_store.apply(c[2],caller_principal=c[0].principal_id)


def dump(path):
    with closing(sqlite3.connect(path)) as c: return tuple(c.iterdump())


def prepare(j,c,action):
    if action!='register': assert register(j,c).status=='REGISTERED'
    if action=='recover':
        assert retain(j,c).status=='RETAINED'
        apply_high(j,c)


def perform(j,c,action):
    return {'register':register,'retain':retain,'recover':recover}[action](j,c)


def test_full_lifecycle_no_automatic_high_water_apply(store,setup):
    j=store; c=setup; high_before=dump(j.high_water_store.path)
    assert load(j,c).entries==()
    assert register(j,c).status=='REGISTERED'
    assert recover(j,c).status=='AWAITING_RESPONSE'
    assert retain(j,c).status=='RETAINED'
    before=dump(j.path)
    proposal=recover(j,c)
    assert proposal.status=='READY_TO_APPLY' and proposal.audit_only and proposal.advancement_request==c[2]
    assert dump(j.path)==before and dump(j.high_water_store.path)==high_before
    receipt=apply_high(j,c)
    assert recover(j,c).receipt_bytes==receipt.receipt_bytes
    assert load(j,c).entries[0].state=='COMMITTED_RECEIPT'


def test_exact_retries_and_byte_preservation(store,setup):
    j=store; c=setup
    register(j,c); before=dump(j.path)
    assert register(j,c).status=='UNCHANGED' and dump(j.path)==before
    raw=canonical_bytes(c[2].response);retain(j,c,raw);before=dump(j.path)
    assert retain(j,c).status=='UNCHANGED' and dump(j.path)==before
    with closing(sqlite3.connect(j.path)) as db:
        assert db.execute('SELECT response_bytes FROM journal_responses').fetchone()==(raw,)
    saved=apply_high(j,c).receipt_bytes; assert recover(j,c).receipt_bytes==saved
    before=dump(j.path);j.clock=lambda:c[3].expires_at+1000
    assert recover(j,c).receipt_bytes==saved and dump(j.path)==before


def test_terminal_recovery_never_reads_high_water(store,setup,monkeypatch):
    j=store;c=setup;prepare(j,c,'recover');saved=recover(j,c).receipt_bytes
    def fail(*args,**kw): pytest.fail('High-water access forbidden')
    monkeypatch.setattr(j.high_water_store,'load',fail)
    j.clock=lambda:c[3].expires_at+1000
    assert recover(j,c).status=='RECOVERED' and recover(j,c).receipt_bytes==saved
    reopened=TestClientRequestJournalStore(j.path,trusted_client_anchor=c[0],clock=j.clock)
    assert recover(reopened,c).receipt_bytes==saved


def test_high_water_commit_before_journal_ack_after_expiry(store,setup):
    j=store;c=setup;register(j,c);retain(j,c)
    saved=apply_high(j,c).receipt_bytes;j.clock=lambda:c[3].expires_at+1000
    result=recover(j,c)
    assert result.status=='COMMITTED' and result.receipt_bytes==saved


def test_expired_uncommitted_response_preserved(store,setup):
    j=store;c=setup;register(j,c);retain(j,c);before=dump(j.path)
    j.clock=lambda:c[3].expires_at
    result=recover(j,c)
    assert result.status=='REJECTED' and result.reason_code=='RESPONSE_EXPIRED'
    assert dump(j.path)==before


@pytest.mark.parametrize('fault',['none','missing','corrupt'])
def test_high_water_unavailable_not_absent(store,setup,fault):
    j=store;c=setup;register(j,c);retain(j,c);j.clock=lambda:c[3].expires_at+1
    if fault=='none': j.high_water_store=None
    if fault=='missing':
        j.high_water_store=TestClientHighWaterStore(j.path.parent/'absent.db',trusted_initial_anchor=c[0])
    if fault=='corrupt':
        with closing(sqlite3.connect(j.high_water_store.path)) as db: db.execute('PRAGMA user_version=99')
    before=dump(j.path)
    assert recover(j,c).status=='INDETERMINATE' and dump(j.path)==before


@pytest.mark.parametrize('action',['load','register','retain','recover'])
def test_missing_never_creates(store,setup,action):
    j=TestClientRequestJournalStore(store.path.parent/'missing.db',trusted_client_anchor=setup[0],clock=store.clock)
    with pytest.raises(ClientJournalStoreError): load(j,setup) if action=='load' else perform(j,setup,action)
    assert not j.path.exists()


def test_exclusive_creation_never_overwrites(store,setup):
    before=dump(store.path)
    with pytest.raises(ClientJournalStoreError,match='CREATION_FAILED'):
        TestClientRequestJournalStore.create_for_testing(store.path,trusted_client_anchor=setup[0],now=store.clock())
    assert dump(store.path)==before


def test_separate_store_schema_and_foreign_database_rejection(store,setup):
    c=setup
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute('PRAGMA application_id').fetchone()==(module.APPLICATION_ID,)
        assert db.execute('PRAGMA journal_mode').fetchone()==('wal',)
        assert db.execute('PRAGMA user_version').fetchone()==(1,)
    wrong=TestClientRequestJournalStore(store.high_water_store.path,trusted_client_anchor=c[0],clock=store.clock)
    with pytest.raises(ClientJournalStoreError): load(wrong,c)
    with pytest.raises(ClientJournalStoreError,match='STORE_ISOLATION_REQUIRED'):
        TestClientRequestJournalStore(store.high_water_store.path,trusted_client_anchor=c[0],high_water_store=store.high_water_store)


@pytest.mark.parametrize('sql',[
    'PRAGMA application_id=0','PRAGMA user_version=7','CREATE TABLE extra(x INTEGER)',
    'DROP INDEX journal_heads_state','DROP TRIGGER journal_responses_no_update',
    "UPDATE journal_image SET digest='"+'f'*64+"'",
    'UPDATE journal_image SET operation_count=1',
    "UPDATE journal_image SET canonical=CAST(' '||CAST(canonical AS TEXT) AS BLOB)",
])
def test_fail_closed_schema_or_projection_corruption(store,setup,sql):
    with closing(sqlite3.connect(store.path)) as c: c.execute(sql);c.commit()
    before=dump(store.path)
    with pytest.raises(ClientJournalStoreError): load(store,setup)
    with pytest.raises(ClientJournalStoreError): register(store,setup)
    assert dump(store.path)==before


def test_corrupt_canonical_image_rehashed_still_rejected(store,setup):
    register(store,setup);image=load(store,setup);e=image.entries[0]
    bad=image.model_copy(update={'entries':(e.model_copy(update={'intent_digest':'f'*64}),)})
    with closing(sqlite3.connect(store.path)) as c:
        c.execute('UPDATE journal_image SET canonical=?,digest=?',(canonical_bytes(bad),record_digest(bad)));c.commit()
    with pytest.raises(ClientJournalStoreError): load(store,setup)


def test_immutable_rows_and_phase_guards(store,setup):
    j=store;c=setup;register(j,c)
    with closing(sqlite3.connect(j.path)) as db:
        for sql in ("UPDATE journal_intents SET intent_digest='"+'f'*64+"'",'DELETE FROM journal_intents',
                    "UPDATE journal_heads SET state='COMMITTED_RECEIPT',local_sequence=3",'DELETE FROM journal_heads'):
            with pytest.raises(sqlite3.IntegrityError): db.execute(sql)
    retain(j,c);apply_high(j,c);recover(j,c)
    with closing(sqlite3.connect(j.path)) as db:
        for table in ('journal_responses','journal_receipts'):
            with pytest.raises(sqlite3.IntegrityError): db.execute(f'DELETE FROM {table}')
            with pytest.raises(sqlite3.IntegrityError): db.execute(f'UPDATE {table} SET canonical=canonical')


@pytest.mark.parametrize('point',['locked','intent_inserted','head_updated','image_updated','before_recheck','before_commit'])
def test_registration_rollback_at_each_write_boundary(store,setup,point):
    before=dump(store.path)
    def hook(where):
        if where==point: raise RuntimeError('injected')
    store._hook=hook
    with pytest.raises(ClientJournalStoreError): register(store,setup)
    assert dump(store.path)==before and load(store,setup).entries==()


@pytest.mark.parametrize('action,point',[('retain','response_inserted'),('recover','receipt_inserted')])
def test_retention_and_receipt_rollback(store,setup,action,point):
    prepare(store,setup,action);before=dump(store.path)
    def hook(where):
        if where==point: raise RuntimeError('injected')
    store._hook=hook
    with pytest.raises(ClientJournalStoreError): perform(store,setup,action)
    assert dump(store.path)==before


@pytest.mark.parametrize('action',['register','retain','recover'])
def test_lost_completion_returns_original_on_retry(store,setup,action):
    j=store;c=setup;prepare(j,c,action)
    def hook(where):
        if where=='after_commit': raise RuntimeError('lost acknowledgement')
    j._hook=hook
    with pytest.raises(ClientJournalStoreError,match='OUTCOME_UNKNOWN'): perform(j,c,action)
    j._hook=lambda _:None;before=dump(j.path)
    out=perform(j,c,action)
    assert out.status==('RECOVERED' if action=='recover' else 'UNCHANGED')
    assert dump(j.path)==before


@pytest.mark.parametrize('point',['locked','before_recheck','before_commit'])
def test_expiry_checked_after_lock_and_before_commit(store,setup,point):
    j=store;c=setup;register(j,c);before=dump(j.path)
    def hook(where):
        if where==point: j.clock=lambda:c[3].expires_at
    j._hook=hook
    if point=='locked': assert retain(j,c).reason_code=='RESPONSE_EXPIRED'
    else:
        with pytest.raises(ClientJournalStoreError,match='VALIDITY_CHANGED'): retain(j,c)
    assert dump(j.path)==before


def test_clock_regression_rolls_back(store,setup):
    j=store;c=setup;register(j,c);now=c[3].created_at+1;j.clock=lambda:now;before=dump(j.path)
    def hook(where):
        if where=='before_recheck': j.clock=lambda:now-1
    j._hook=hook
    with pytest.raises(ClientJournalStoreError,match='CLOCK_REGRESSION'): retain(j,c)
    assert dump(j.path)==before


def test_permission_checked_before_database_open(store,setup,monkeypatch):
    def fail(*a,**kw): pytest.fail('Database opened before authorization')
    monkeypatch.setattr(sqlite3,'connect',fail)
    with pytest.raises(ClientJournalStoreError,match='ACCESS_DENIED'): store.recover('absent',caller_principal='other')
    with pytest.raises(ClientJournalStoreError,match='ACCESS_DENIED'): store.load(caller_principal='other',now=store.clock())


def test_invalid_response_and_conflicting_intent_no_mutation(store,setup):
    j=store;c=setup;register(j,c);before=dump(j.path)
    bad=c[3].model_copy(update={'request':c[3].request.model_copy(update={'challenge':'f'*64})})
    assert register(j,c,bad).reason_code=='OPERATION_CONFLICT'
    raw=canonical_bytes(c[2].response.model_copy(update={'signature_hex':'0'*128}))
    assert retain(j,c,raw).reason_code=='VERIFICATION_FAILED'
    assert dump(j.path)==before


def test_read_only_snapshot_while_writer_locked(store,setup):
    with closing(sqlite3.connect(store.path,isolation_level=None)) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            assert load(store,setup).entries==()
            store.timeout=0
            with pytest.raises(ClientJournalStoreError,match='STORE_BUSY'): register(store,setup)
        finally: db.execute('ROLLBACK')


def test_creation_ddl_rollback(tmp_path,setup,monkeypatch):
    path=tmp_path/'failed.db'
    monkeypatch.setattr(module,'DDL',module.DDL[:2]+('INVALID SQL',))
    with pytest.raises(ClientJournalStoreError,match='CREATION_FAILED'):
        TestClientRequestJournalStore.create_for_testing(path,trusted_client_anchor=setup[0],now=setup[0].accepted_timestamp)
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('SELECT name FROM sqlite_schema').fetchall()==[]
        assert c.execute('PRAGMA user_version').fetchone()==(0,)


def worker(path,high_path,c,action,point,barrier=None,queue=None,hold=None,release=None):
    high=TestClientHighWaterStore(high_path,trusted_initial_anchor=c[0],clock=lambda:c[3].created_at)
    j=TestClientRequestJournalStore(path,trusted_client_anchor=c[0],high_water_store=high,clock=lambda:c[3].created_at,busy_timeout=5)
    def hook(where):
        if where==point: os._exit(73)
        if where=='head_updated' and hold is not None:
            hold.set()
            if not release.wait(20): raise RuntimeError('barrier timeout')
    j._hook=hook
    try:
        if barrier is not None: barrier.wait(20)
        result=perform(j,c,action)
        if queue is not None: queue.put((result.status,result.reason_code,result.receipt_bytes))
    except Exception as exc:
        if queue is not None: queue.put(('ERROR',str(exc),None))
        else: raise


def cleanup(processes):
    for p in processes:
        p.join(20)
        if p.is_alive(): p.terminate();p.join(5)


@pytest.mark.parametrize('action',['register','retain','recover'])
@pytest.mark.parametrize('point,committed',[('before_commit',False),('after_commit',True)])
def test_process_death_at_journal_commit(store,setup,action,point,committed):
    j=store;c=setup;prepare(j,c,action);before=dump(j.path)
    ctx=multiprocessing.get_context('spawn')
    p=ctx.Process(target=worker,args=(str(j.path),str(j.high_water_store.path),c,action,point))
    try:
        p.start();p.join(20);assert p.exitcode==73
        assert (dump(j.path)!=before)==committed
        if action=='recover': j.clock=lambda:c[3].expires_at+1000
        out=perform(j,c,action)
        assert out.status==({'register':'UNCHANGED','retain':'UNCHANGED','recover':'RECOVERED'}[action] if committed
                           else {'register':'REGISTERED','retain':'RETAINED','recover':'COMMITTED'}[action])
    finally: cleanup([p])


@pytest.mark.parametrize('conflict',[False,True])
def test_competing_process_retention(store,setup,vector,conflict):
    j=store;c=setup;register(j,c)
    other=c
    if conflict:
        changed=c[2].model_copy(update={'response':response(vector,vector[1].model_copy(update={'policy_revision':99}))})
        other=(c[0],c[1],changed,c[3])
    ctx=multiprocessing.get_context('spawn');barrier=ctx.Barrier(3);q=ctx.Queue()
    ps=[ctx.Process(target=worker,args=(str(j.path),str(j.high_water_store.path),value,'retain',None,barrier,q)) for value in (c,other)]
    try:
        for p in ps: p.start()
        barrier.wait(20);out=[q.get(timeout=25) for _ in ps]
        assert sorted(x[0] for x in out)==(['REJECTED','RETAINED'] if conflict else ['RETAINED','UNCHANGED'])
        if conflict: assert next(x[1] for x in out if x[0]=='REJECTED')=='OPERATION_CONFLICT'
        assert load(j,c).entries[0].local_sequence==2
    finally: cleanup(ps);q.close();q.join_thread()


def high_water_crash(path,c):
    h=TestClientHighWaterStore(path,trusted_initial_anchor=c[0],clock=lambda:c[3].created_at)
    def hook(point):
        if point=='after_commit': os._exit(74)
    h._hook=hook;h.apply(c[2],caller_principal=c[0].principal_id)


def test_real_two_store_crash_gap(store,setup):
    j=store;c=setup;register(j,c);retain(j,c);before=dump(j.path)
    ctx=multiprocessing.get_context('spawn');p=ctx.Process(target=high_water_crash,args=(str(j.high_water_store.path),c))
    try:
        p.start();p.join(20);assert p.exitcode==74 and dump(j.path)==before
        saved=j.high_water_store.load(now=j.clock()).history[0].receipt
        j.clock=lambda:c[3].expires_at+1000
        assert recover(j,c).receipt_bytes==canonical_bytes(saved)
    finally: cleanup([p])


def test_reader_sees_previous_image_during_uncommitted_write(store,setup):
    j=store;c=setup;ctx=multiprocessing.get_context('spawn');hold=ctx.Event();release=ctx.Event()
    p=ctx.Process(target=worker,args=(str(j.path),str(j.high_water_store.path),c,'register',None,None,None,hold,release))
    try:
        p.start();assert hold.wait(20)
        assert load(j,c).entries==()
        j.timeout=0
        with pytest.raises(ClientJournalStoreError,match='STORE_BUSY'): register(j,c)
        release.set();p.join(20);assert p.exitcode==0
        assert load(j,c).entries[0].state=='AWAITING_RESPONSE'
    finally: release.set();cleanup([p])


@pytest.mark.parametrize('table,column',[
    ('journal_intents','canonical'),('journal_responses','response_bytes'),
    ('journal_responses','canonical'),('journal_receipts','receipt_bytes'),('journal_receipts','canonical'),
])
def test_rejects_projection_tampering_even_with_schema_restored(store,setup,table,column):
    j=store;c=setup;prepare(j,c,'recover');recover(j,c)
    trigger=f'{table}_no_update'
    definition=next(sql for sql in module.DDL if sql.startswith(f'CREATE TRIGGER {trigger} '))
    with closing(sqlite3.connect(j.path)) as db:
        db.execute(f'DROP TRIGGER {trigger}')
        db.execute(f'UPDATE {table} SET {column}=?',(b'{}',))
        db.execute(definition);db.commit()
    with pytest.raises(ClientJournalStoreError): load(j,c)
    with pytest.raises(ClientJournalStoreError): recover(j,c)


def test_ready_to_apply_rechecks_expiry_during_finalization(store,setup):
    j=store;c=setup;register(j,c);retain(j,c);before=dump(j.path)
    def hook(where):
        if where=='before_commit': j.clock=lambda:c[3].expires_at
    j._hook=hook
    with pytest.raises(ClientJournalStoreError,match='VALIDITY_CHANGED'): recover(j,c)
    assert dump(j.path)==before


def test_storage_byte_budget_checked_before_blob_fetch(store,setup,monkeypatch):
    before=dump(store.path)
    monkeypatch.setattr(module,'TOTAL_LIMIT',1)
    with pytest.raises(ClientJournalStoreError): load(store,setup)
    with pytest.raises(ClientJournalStoreError): register(store,setup)
    assert dump(store.path)==before


def creation_worker(path,anchor,point):
    def hook(self,where):
        if where==point: os._exit(75)
    TestClientRequestJournalStore._hook=hook
    TestClientRequestJournalStore.create_for_testing(path,trusted_client_anchor=anchor,now=anchor.accepted_timestamp)


@pytest.mark.parametrize('point,committed',[('schema_created',False),('after_commit',True)])
def test_process_death_during_explicit_creation(tmp_path,setup,point,committed):
    path=tmp_path/'creation.db';ctx=multiprocessing.get_context('spawn')
    p=ctx.Process(target=creation_worker,args=(str(path),setup[0],point))
    try:
        p.start();p.join(20);assert p.exitcode==75
        j=TestClientRequestJournalStore(path,trusted_client_anchor=setup[0],clock=lambda:setup[3].created_at)
        if committed: assert load(j,setup).entries==()
        else:
            with pytest.raises(ClientJournalStoreError): load(j,setup)
            with closing(sqlite3.connect(path)) as db:
                assert db.execute('SELECT name FROM sqlite_schema').fetchall()==[]
                assert db.execute('PRAGMA user_version').fetchone()==(0,)
    finally: cleanup([p])
