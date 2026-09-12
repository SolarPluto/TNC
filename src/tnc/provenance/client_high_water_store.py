"""Isolated test-only SQLite persistence; not independent rollback protection."""
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import math
import sqlite3
import time
from tnc.provenance.authorization_models import canonical_bytes,record_digest
from tnc.provenance.client_high_water_logic import (
    ClientAnchor,ClientHighWaterState,AdvancementRequest,decode_client_record,
    evaluate_client_transition,_validate,STATE_LIMIT,
)
from tnc.provenance.reconciliation_verifier import verify_observation

APPLICATION_ID=0x544E4348
TABLES={
    'client_anchor':'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 65536), digest TEXT NOT NULL',
    'client_state':'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16777216), digest TEXT NOT NULL, local_sequence INTEGER NOT NULL CHECK(local_sequence BETWEEN 0 AND 64), authority_revision INTEGER NOT NULL CHECK(authority_revision>0), envelope_digest TEXT NOT NULL',
    'client_receipts':'operation_id TEXT PRIMARY KEY, local_sequence INTEGER NOT NULL UNIQUE CHECK(local_sequence BETWEEN 1 AND 64), request_digest TEXT NOT NULL, canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 65536)',
}
DDL=tuple(f'CREATE TABLE {n} ({c}) STRICT' for n,c in TABLES.items())+tuple(
    f"CREATE TRIGGER {n}_no_{a.lower()} BEFORE {a} ON {n} BEGIN SELECT RAISE(ABORT,'Immutable'); END"
    for n in ('client_anchor','client_receipts') for a in ('UPDATE','DELETE'))


class ClientStoreError(ValueError): pass


@dataclass(frozen=True)
class ClientStoreResult:
    status: str
    receipt_bytes: bytes | None=None
    audit_only: bool=True


def _require(ok):
    if not ok: raise ClientStoreError('INVALID_STORE')


def _schema(c): return c.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()


def _expected_schema():
    with closing(sqlite3.connect(':memory:')) as c:
        for sql in DDL: c.execute(sql)
        return _schema(c)


def _rows(state):
    return {'client_anchor':[(1,canonical_bytes(state.anchor),record_digest(state.anchor))],
        'client_state':[(1,canonical_bytes(state),record_digest(state),state.local_sequence,state.authority_revision,state.envelope_digest)],
        'client_receipts':[(e.receipt.operation_id,e.receipt.local_sequence,e.receipt.request_digest,canonical_bytes(e.receipt)) for e in state.history]}


class TestClientHighWaterStore:
    __test__=False
    def __init__(self,path,*,trusted_initial_anchor,clock=None,busy_timeout=1):
        self.path=Path(path).absolute()
        _require(type(trusted_initial_anchor) is ClientAnchor)
        self.anchor=decode_client_record(ClientAnchor,canonical_bytes(trusted_initial_anchor))
        _require(type(busy_timeout) in (int,float) and math.isfinite(busy_timeout) and 0<=busy_timeout<=5)
        self.timeout=busy_timeout
        self.clock=clock if clock is not None else lambda:int(time.time())

    def _hook(self,point): pass

    @classmethod
    def create_for_testing(cls,path,*,trusted_initial_anchor,now):
        try:
            store=cls(path,trusted_initial_anchor=trusted_initial_anchor)
            a=store.anchor
            state=ClientHighWaterState(anchor=a,authority_revision=a.authority_revision,envelope_digest=a.envelope_digest,
                accepted_timestamp=a.accepted_timestamp,local_sequence=0)
            _require(type(now) is int and now>=0); _validate(state,a,now)
            with store.path.open('xb'): pass
            with closing(sqlite3.connect(store.path,isolation_level=None)) as c:
                _require(c.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',))
                c.execute('PRAGMA synchronous=FULL'); c.execute('PRAGMA trusted_schema=OFF')
                c.execute('BEGIN IMMEDIATE')
                try:
                    for sql in DDL: c.execute(sql)
                    c.execute(f'PRAGMA application_id={APPLICATION_ID}'); c.execute('PRAGMA user_version=1')
                    for name,rows in _rows(state).items():
                        for row in rows: c.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})",row)
                    store._load(c,now); c.execute('COMMIT')
                except BaseException:
                    if c.in_transaction: c.execute('ROLLBACK')
                    raise
            return store
        except Exception: raise ClientStoreError('CREATION_FAILED') from None

    def _load(self,c,now):
        _require(type(now) is int and now>=0)
        _require(c.execute('PRAGMA application_id').fetchone()==(APPLICATION_ID,))
        _require(c.execute('PRAGMA user_version').fetchone()==(1,))
        _require(c.execute('PRAGMA journal_mode').fetchone()==('wal',))
        size,count=c.execute('SELECT coalesce(sum(length(CAST(sql AS BLOB))),0),count(*) FROM sqlite_schema').fetchone()
        _require(size<=65536 and count<=64); _require(_schema(c)==_expected_schema())
        total=0
        for name in TABLES:
            count=c.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
            _require(count<=64 if name=='client_receipts' else count==1)
            for col in [r[1] for r in c.execute(f'PRAGMA table_info({name})')]:
                maximum,amount=c.execute(f'SELECT coalesce(max(length(CAST({col} AS BLOB))),0),coalesce(sum(length(CAST({col} AS BLOB))),0) FROM {name}').fetchone()
                _require(maximum<=(STATE_LIMIT if (name,col)==('client_state','canonical') else 65536))
                total+=amount; _require(total<=32*1024*1024)
        state=decode_client_record(ClientHighWaterState,c.execute('SELECT canonical FROM client_state').fetchone()[0])
        _validate(state,self.anchor,now)
        for name,rows in _rows(state).items(): _require(sorted(c.execute(f'SELECT * FROM {name}').fetchall())==sorted(rows))
        _require(c.execute('PRAGMA quick_check(1)').fetchone()==('ok',))
        return state

    def load(self,*,now):
        try:
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,isolation_level=None,timeout=self.timeout)) as c:
                c.execute('PRAGMA query_only=ON'); c.execute('PRAGMA trusted_schema=OFF'); c.execute('BEGIN')
                try: return self._load(c,now)
                finally: c.execute('ROLLBACK')
        except Exception: raise ClientStoreError('INVALID_STORE') from None

    def apply(self,request,*,caller_principal):
        attempted=False
        try:
            _require(type(request) is AdvancementRequest)
            request=decode_client_record(AdvancementRequest,canonical_bytes(request))
            if type(caller_principal) is not str or caller_principal!=self.anchor.principal_id:
                raise ClientStoreError('ACCESS_DENIED')
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=self.timeout)) as c:
                c.execute('PRAGMA trusted_schema=OFF'); c.execute('PRAGMA synchronous=FULL')
                _require(c.execute('PRAGMA synchronous').fetchone()==(2,))
                c.execute('BEGIN IMMEDIATE')
                try:
                    self._hook('locked'); now=self.clock(); state=self._load(c,now)
                    out=evaluate_client_transition(state,request,trusted_initial_anchor=self.anchor,caller_principal=caller_principal,now=now)
                    if out.status=='ERROR': raise ClientStoreError(out.reason_code)
                    if out.proposed_state is not None:
                        rows=_rows(out.proposed_state)
                        c.execute('INSERT INTO client_receipts VALUES (?,?,?,?)',rows['client_receipts'][-1]); self._hook('receipt_inserted')
                        row=rows['client_state'][0]
                        c.execute('UPDATE client_state SET canonical=?,digest=?,local_sequence=?,authority_revision=?,envelope_digest=? WHERE id=?',row[1:]+(1,))
                        self._hook('state_updated')
                    self._hook('before_recheck'); final_now=self.clock()
                    _require(type(final_now) is int and final_now>=now)
                    final=self._load(c,final_now)
                    _require(canonical_bytes(final)==canonical_bytes(out.proposed_state or state))
                    if out.proposed_state is not None:
                        check=verify_observation(request.response,expected_request=request.retained_request,trust_store=request.trust_store,
                            trusted_checkpoint=request.trusted_checkpoint,now=final_now)
                        if check.status!='VERIFIED': raise ClientStoreError('VERIFICATION_FAILED')
                    raw=None
                    if out.receipt is not None:
                        raw=c.execute('SELECT canonical FROM client_receipts WHERE operation_id=?',(request.operation_id,)).fetchone()[0]
                        _require(raw==canonical_bytes(out.receipt))
                    self._hook('before_commit'); attempted=True; c.execute('COMMIT'); self._hook('after_commit')
                    return ClientStoreResult(out.status,raw)
                except BaseException:
                    if c.in_transaction: c.execute('ROLLBACK')
                    raise
        except Exception as exc:
            if attempted: raise ClientStoreError('OUTCOME_UNKNOWN') from None
            if isinstance(exc,ClientStoreError): raise
            if isinstance(exc,sqlite3.OperationalError) and (getattr(exc,'sqlite_errorcode',0)&255) in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                raise ClientStoreError('STORE_BUSY') from None
            raise ClientStoreError('INVALID_STORE') from None
