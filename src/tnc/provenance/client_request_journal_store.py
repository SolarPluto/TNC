"""Isolated test-only SQLite journal. Never applies high-water updates or signs."""
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import math
import sqlite3
import time

from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.client_high_water_logic import ClientAnchor, AdvancementRequest, decode_client_record
from tnc.provenance.client_high_water_store import TestClientHighWaterStore
from tnc.provenance.client_request_journal_logic import (
    ClientJournalIntent, ClientJournalImage, decode_journal_record,
    register_intent, retain_response, evaluate_recovery, IMAGE_LIMIT, INTENT_LIMIT,
    RESPONSE_LIMIT, _validate,
)

APPLICATION_ID = 0x544E434A
TOTAL_LIMIT = 48 * 1024 * 1024
TABLES = {
    'journal_anchor': 'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 65536), digest TEXT NOT NULL CHECK(length(digest)=64)',
    'journal_image': 'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16777216), digest TEXT NOT NULL CHECK(length(digest)=64), operation_count INTEGER NOT NULL CHECK(operation_count BETWEEN 0 AND 64)',
    'journal_intents': 'operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128), intent_digest TEXT NOT NULL UNIQUE CHECK(length(intent_digest)=64), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 2097152), created_at INTEGER NOT NULL CHECK(created_at>=0), expires_at INTEGER NOT NULL CHECK(expires_at>created_at)',
    'journal_responses': 'operation_id TEXT PRIMARY KEY NOT NULL REFERENCES journal_intents(operation_id), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 131072), response_bytes BLOB NOT NULL CHECK(length(response_bytes) BETWEEN 1 AND 32768), response_digest TEXT NOT NULL CHECK(length(response_digest)=64), retained_at INTEGER NOT NULL CHECK(retained_at>=0)',
    'journal_receipts': 'operation_id TEXT PRIMARY KEY NOT NULL REFERENCES journal_responses(operation_id), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16777216), receipt_bytes BLOB NOT NULL CHECK(length(receipt_bytes) BETWEEN 1 AND 65536), reconciled_at INTEGER NOT NULL CHECK(reconciled_at>=0)',
    'journal_heads': "operation_id TEXT PRIMARY KEY NOT NULL REFERENCES journal_intents(operation_id), state TEXT NOT NULL CHECK(state IN ('AWAITING_RESPONSE','RETAINED_RESPONSE','COMMITTED_RECEIPT')), local_sequence INTEGER NOT NULL CHECK(local_sequence BETWEEN 1 AND 3), last_event_at INTEGER NOT NULL CHECK(last_event_at>=0), CHECK((state='AWAITING_RESPONSE' AND local_sequence=1) OR (state='RETAINED_RESPONSE' AND local_sequence=2) OR (state='COMMITTED_RECEIPT' AND local_sequence=3))",
}
DDL = tuple(f'CREATE TABLE {name} ({columns}) STRICT' for name,columns in TABLES.items()) + (
    'CREATE INDEX journal_heads_state ON journal_heads(state)',
    'CREATE INDEX journal_intents_expiry ON journal_intents(expires_at)',
) + tuple(
    f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT,'Immutable'); END"
    for name in ('journal_anchor','journal_intents','journal_responses','journal_receipts')
    for action in ('UPDATE','DELETE')
) + (
    "CREATE TRIGGER journal_heads_no_delete BEFORE DELETE ON journal_heads BEGIN SELECT RAISE(ABORT,'Immutable'); END",
    "CREATE TRIGGER journal_image_no_delete BEFORE DELETE ON journal_image BEGIN SELECT RAISE(ABORT,'Immutable'); END",
    "CREATE TRIGGER journal_heads_initial BEFORE INSERT ON journal_heads WHEN NEW.local_sequence<>1 OR NEW.last_event_at<>(SELECT created_at FROM journal_intents WHERE operation_id=NEW.operation_id) BEGIN SELECT RAISE(ABORT,'Invalid phase'); END",
    "CREATE TRIGGER journal_response_phase BEFORE INSERT ON journal_responses WHEN NOT EXISTS(SELECT 1 FROM journal_heads WHERE operation_id=NEW.operation_id AND local_sequence=1 AND last_event_at<=NEW.retained_at) BEGIN SELECT RAISE(ABORT,'Invalid phase'); END",
    "CREATE TRIGGER journal_receipt_phase BEFORE INSERT ON journal_receipts WHEN NOT EXISTS(SELECT 1 FROM journal_heads WHERE operation_id=NEW.operation_id AND local_sequence=2 AND last_event_at<=NEW.reconciled_at) BEGIN SELECT RAISE(ABORT,'Invalid phase'); END",
    "CREATE TRIGGER journal_heads_advance BEFORE UPDATE ON journal_heads WHEN NEW.operation_id<>OLD.operation_id OR NEW.local_sequence<>OLD.local_sequence+1 OR NEW.last_event_at<OLD.last_event_at OR (NEW.local_sequence=2 AND NOT EXISTS(SELECT 1 FROM journal_responses WHERE operation_id=NEW.operation_id AND retained_at=NEW.last_event_at)) OR (NEW.local_sequence=3 AND NOT EXISTS(SELECT 1 FROM journal_receipts WHERE operation_id=NEW.operation_id AND reconciled_at=NEW.last_event_at)) BEGIN SELECT RAISE(ABORT,'Invalid phase'); END",
)


class ClientJournalStoreError(ValueError): pass


@dataclass(frozen=True)
class ClientJournalStoreResult:
    status: str
    reason_code: str | None = None
    advancement_request: AdvancementRequest | None = None
    receipt_bytes: bytes | None = None
    audit_only: bool = True


def _require(condition, reason='INVALID_STORE'):
    if not condition: raise ClientJournalStoreError(reason)


def _schema(c):
    return c.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()


def _expected_schema():
    with closing(sqlite3.connect(':memory:')) as c:
        for sql in DDL: c.execute(sql)
        return _schema(c)


def _rows(anchor, image):
    result = {
        'journal_anchor': [(1,canonical_bytes(anchor),record_digest(anchor))],
        'journal_image': [(1,canonical_bytes(image),record_digest(image),len(image.entries))],
        'journal_intents': [], 'journal_responses': [], 'journal_receipts': [], 'journal_heads': [],
    }
    for e in image.entries:
        i=e.intent; r=e.retained_response; b=e.receipt_binding
        result['journal_intents'].append((i.operation_id,e.intent_digest,canonical_bytes(i),i.created_at,i.expires_at))
        result['journal_heads'].append((i.operation_id,e.state,e.local_sequence,e.last_event_at))
        if r is not None:
            result['journal_responses'].append((i.operation_id,canonical_bytes(r),r.response_canonical_json.encode('utf-8'),r.response_digest,r.retained_at))
        if b is not None:
            result['journal_receipts'].append((i.operation_id,canonical_bytes(b),b.receipt_canonical_json.encode('utf-8'),b.reconciled_at))
    return result


class TestClientRequestJournalStore:
    """Host-owned test adapter. Caller strings and trust anchors are not credentials."""
    __test__ = False

    def __init__(self, path, *, trusted_client_anchor, high_water_store=None, clock=None, busy_timeout=1):
        self.path=Path(path).absolute()
        _require(type(trusted_client_anchor) is ClientAnchor,'INVALID_INPUT')
        self.anchor=decode_client_record(ClientAnchor,canonical_bytes(trusted_client_anchor))
        _require(type(busy_timeout) in (int,float) and math.isfinite(busy_timeout) and 0<=busy_timeout<=5,'INVALID_INPUT')
        self.timeout=busy_timeout
        self.clock=clock if clock is not None else lambda:int(time.time())
        self.high_water_store=high_water_store
        if high_water_store is not None: self._check_high_water()

    def _check_high_water(self):
        h=self.high_water_store
        _require(type(h) is TestClientHighWaterStore,'INVALID_HIGH_WATER_STORE')
        _require(canonical_bytes(h.anchor)==canonical_bytes(self.anchor),'INVALID_HIGH_WATER_STORE')
        _require(h.path.resolve()!=self.path.resolve(),'STORE_ISOLATION_REQUIRED')
        if h.path.exists() and self.path.exists():
            _require(not h.path.samefile(self.path),'STORE_ISOLATION_REQUIRED')
        return h

    def _hook(self, point): pass

    def _authorize(self, principal):
        _require(type(principal) is str and principal==self.anchor.principal_id,'ACCESS_DENIED')

    def _now(self):
        now=self.clock()
        _require(type(now) is int and now>=self.anchor.accepted_timestamp,'INVALID_CLOCK')
        return now

    @classmethod
    def create_for_testing(cls, path, *, trusted_client_anchor, now):
        try:
            store=cls(path,trusted_client_anchor=trusted_client_anchor,clock=lambda:now)
            store._now()
            image=ClientJournalImage()
            with store.path.open('xb'): pass
            with closing(sqlite3.connect(store.path,isolation_level=None)) as c:
                _require(c.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',))
                store._configure(c)
                c.execute('BEGIN IMMEDIATE')
                try:
                    for sql in DDL: c.execute(sql)
                    store._hook('schema_created')
                    c.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    c.execute('PRAGMA user_version=1')
                    for name,rows in _rows(store.anchor,image).items():
                        for row in rows:
                            c.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})",row)
                    store._hook('initialized'); store._load(c,now)
                    store._hook('before_commit'); c.execute('COMMIT'); store._hook('after_commit')
                except BaseException:
                    if c.in_transaction: c.execute('ROLLBACK')
                    raise
            return store
        except Exception: raise ClientJournalStoreError('CREATION_FAILED') from None

    def _configure(self,c):
        c.execute('PRAGMA trusted_schema=OFF'); c.execute('PRAGMA foreign_keys=ON')
        c.execute('PRAGMA synchronous=FULL')
        _require(c.execute('PRAGMA synchronous').fetchone()==(2,))
        _require(c.execute('PRAGMA foreign_keys').fetchone()==(1,))

    def _load(self,c,now):
        _require(type(now) is int and now>=self.anchor.accepted_timestamp,'INVALID_CLOCK')
        _require(c.execute('PRAGMA application_id').fetchone()==(APPLICATION_ID,))
        _require(c.execute('PRAGMA user_version').fetchone()==(1,))
        _require(c.execute('PRAGMA journal_mode').fetchone()==('wal',))
        size,count=c.execute('SELECT coalesce(sum(length(CAST(sql AS BLOB))),0),count(*) FROM sqlite_schema').fetchone()
        _require(size<=65536 and count<=64); _require(_schema(c)==_expected_schema())
        total=0
        for name in TABLES:
            count=c.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
            _require(count==1 if name in ('journal_anchor','journal_image') else count<=64)
            for column in [r[1] for r in c.execute(f'PRAGMA table_info({name})')]:
                maximum,amount=c.execute(f'SELECT coalesce(max(length(CAST({column} AS BLOB))),0),coalesce(sum(length(CAST({column} AS BLOB))),0) FROM {name}').fetchone()
                limit=IMAGE_LIMIT if (name,column) in (('journal_image','canonical'),('journal_receipts','canonical')) else INTENT_LIMIT if (name,column)==('journal_intents','canonical') else 131072 if (name,column)==('journal_responses','canonical') else RESPONSE_LIMIT if column=='response_bytes' else 65536
                _require(maximum<=limit); total+=amount; _require(total<=TOTAL_LIMIT)
        image=decode_journal_record(ClientJournalImage,c.execute('SELECT canonical FROM journal_image').fetchone()[0])
        _validate(image,self.anchor,now)
        for name,rows in _rows(self.anchor,image).items():
            _require(c.execute(f'SELECT * FROM {name} ORDER BY 1').fetchall()==sorted(rows))
        _require(c.execute('PRAGMA foreign_key_check').fetchall()==[])
        _require(c.execute('PRAGMA quick_check(1)').fetchone()==('ok',))
        return image

    def load(self, *, caller_principal, now):
        self._authorize(caller_principal)
        try:
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,isolation_level=None,timeout=self.timeout)) as c:
                c.execute('PRAGMA query_only=ON'); c.execute('PRAGMA trusted_schema=OFF'); c.execute('BEGIN')
                try: return self._load(c,now)
                finally: c.execute('ROLLBACK')
        except Exception: raise ClientJournalStoreError('INVALID_STORE') from None

    def _persist(self,c,before,after):
        old={e.intent.operation_id:e for e in before.entries}
        changed=[e for e in after.entries if old.get(e.intent.operation_id)!=e]
        _require(len(changed)==1)
        e=changed[0]; op=e.intent.operation_id; rows=_rows(self.anchor,after)
        if op not in old:
            _require(e.state=='AWAITING_RESPONSE')
            c.execute('INSERT INTO journal_intents VALUES (?,?,?,?,?)',next(r for r in rows['journal_intents'] if r[0]==op))
            self._hook('intent_inserted')
            c.execute('INSERT INTO journal_heads VALUES (?,?,?,?)',next(r for r in rows['journal_heads'] if r[0]==op))
        else:
            _require(e.local_sequence==old[op].local_sequence+1)
            name='journal_responses' if e.state=='RETAINED_RESPONSE' else 'journal_receipts'
            row=next(r for r in rows[name] if r[0]==op)
            c.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})",row)
            self._hook('response_inserted' if name=='journal_responses' else 'receipt_inserted')
            c.execute('UPDATE journal_heads SET state=?,local_sequence=?,last_event_at=? WHERE operation_id=?',
                (e.state,e.local_sequence,e.last_event_at,op))
        self._hook('head_updated')
        row=rows['journal_image'][0]
        c.execute('UPDATE journal_image SET canonical=?,digest=?,operation_count=? WHERE id=?',row[1:]+(1,))
        self._hook('image_updated')

    def _transaction(self, action, value, raw, caller_principal):
        self._authorize(caller_principal)
        attempted=False
        try:
            if action=='register':
                _require(type(value) is ClientJournalIntent,'INVALID_INPUT')
                value=decode_journal_record(ClientJournalIntent,canonical_bytes(value))
            else: _require(type(value) is str and 0<len(value)<=128,'INVALID_INPUT')
            if action=='retain': _require(type(raw) is bytes and 0<len(raw)<=RESPONSE_LIMIT,'INVALID_INPUT')
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=self.timeout)) as c:
                self._configure(c); c.execute('BEGIN IMMEDIATE')
                try:
                    self._hook('locked'); now=self._now(); image=self._load(c,now)
                    evidence=None
                    if action=='recover':
                        entry=next((e for e in image.entries if e.intent.operation_id==value),None)
                        if entry is not None and entry.state=='RETAINED_RESPONSE' and self.high_water_store is not None:
                            try: evidence=self._check_high_water().load(now=now)
                            except Exception: evidence=None
                            self._hook('evidence_read')
                    def evaluate(at):
                        kw=dict(trusted_client_anchor=self.anchor,caller_principal=caller_principal,now=at)
                        if action=='register': return register_intent(image,value,**kw)
                        if action=='retain': return retain_response(image,value,raw,**kw)
                        return evaluate_recovery(image,value,checked_high_water_state=evidence,**kw)
                    out=evaluate(now)
                    if out.proposed_image is not None: self._persist(c,image,out.proposed_image)
                    self._hook('before_recheck'); self._hook('before_commit'); final_now=self._now()
                    _require(final_now>=now,'CLOCK_REGRESSION')
                    final=self._load(c,final_now)
                    _require(canonical_bytes(final)==canonical_bytes(out.proposed_image or image))
                    if out.status=='REGISTERED':
                        _require(final_now<value.expires_at,'INTENT_EXPIRED')
                    else:
                        check=evaluate(final_now)
                        _require((check.status,check.reason_code)==(out.status,out.reason_code),'VALIDITY_CHANGED')
                    receipt_bytes=None
                    if out.receipt is not None:
                        receipt_bytes=c.execute('SELECT receipt_bytes FROM journal_receipts WHERE operation_id=?',(value,)).fetchone()[0]
                        _require(receipt_bytes==canonical_bytes(out.receipt))
                    attempted=True; c.execute('COMMIT'); self._hook('after_commit')
                    return ClientJournalStoreResult(out.status,out.reason_code,out.advancement_request,receipt_bytes)
                except BaseException:
                    if c.in_transaction: c.execute('ROLLBACK')
                    raise
        except Exception as exc:
            if attempted: raise ClientJournalStoreError('OUTCOME_UNKNOWN') from None
            if isinstance(exc,ClientJournalStoreError): raise
            if isinstance(exc,sqlite3.OperationalError) and (getattr(exc,'sqlite_errorcode',0)&255) in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                raise ClientJournalStoreError('STORE_BUSY') from None
            raise ClientJournalStoreError('INVALID_STORE') from None

    def register_intent(self,intent,*,caller_principal):
        return self._transaction('register',intent,None,caller_principal)

    def retain_response(self,operation_id,response_bytes,*,caller_principal):
        return self._transaction('retain',operation_id,response_bytes,caller_principal)

    def recover(self,operation_id,*,caller_principal):
        return self._transaction('recover',operation_id,None,caller_principal)
