"""Isolated test-provider SQLite distribution heads and historical verification.

No production policy acquisition, filesystem protection, or runtime publication.
Local persistence is crash-consistent, not independently rollback-proof.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import math
from pathlib import Path
import sqlite3
import threading
import time
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Identifier, Digest, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.protected_trust_distribution import (
    DistributionPolicy, DistributionPolicyCheckpoint, DistributionHead, DistributionResult,
    TrustDistributionBundle, Time, verify_trust_distribution, decode_distribution,
)

APPLICATION_ID = 0x544E4344
HISTORY_LIMIT = 64
IMAGE_LIMIT = 16*1024*1024
REQUEST_LIMIT = 512*1024


class DistributionPolicyInputs(Model):
    policy: DistributionPolicy
    checkpoint: DistributionPolicyCheckpoint

    @model_validator(mode='after')
    def binding(self):
        p, c = self.policy, self.checkpoint
        if (c.deployment_id,c.store_instance_id,c.policy_revision,c.policy_digest) != (
                p.deployment_id,p.store_instance_id,p.revision,record_digest(p)):
            raise ValueError('Independent policy pin mismatch')
        return self


class DistributionStoreAnchor(Model):
    profile: Literal['tnc-distribution-store-v1'] = 'tnc-distribution-store-v1'
    local_store_id: Identifier
    initial_inputs: DistributionPolicyInputs
    created_at: Time


class DistributionIngestion(Model):
    bundle: TrustDistributionBundle
    inputs: DistributionPolicyInputs


class DistributionReceipt(Model):
    local_sequence: int = Field(strict=True, ge=1, le=HISTORY_LIMIT)
    request_digest: Digest
    result_digest: Digest
    checkpoint_revision: int = Field(strict=True, gt=0, le=2**63-1)
    checkpoint_digest: Digest
    accepted_at: Time
    status: Literal['INITIAL','ADVANCE','UNCHANGED']


class DistributionHistoryEntry(Model):
    request: DistributionIngestion
    receipt: DistributionReceipt


class DistributionStoreImage(Model):
    audit_only: bool = Field(default=True, strict=True)
    anchor: DistributionStoreAnchor
    history: tuple[DistributionHistoryEntry,...] = Field(max_length=HISTORY_LIMIT)
    head: DistributionHead | None = None

    @model_validator(mode='after')
    def shape(self):
        if not self.audit_only or bool(self.history) != (self.head is not None):
            raise ValueError('Invalid audit image')
        return self


class DistributionStoreError(ValueError): pass


def _require(ok, reason='INVALID_STORE'):
    if not ok: raise DistributionStoreError(reason)


def _copy(kind, value, limit=REQUEST_LIMIT):
    _require(type(value) is kind, 'INVALID_INPUT')
    raw = canonical_bytes(value)
    _require(0 < len(raw) <= limit, 'CAPACITY_EXCEEDED')
    return decode_canonical(kind, raw)


def _time(now):
    _require(type(now) is int and 0 <= now <= 2**63-1, 'CLOCK_INVALID')
    return now


def _anchor_inputs(anchor, inputs):
    original, p = anchor.initial_inputs.policy, inputs.policy
    fixed = lambda x: (x.deployment_id,x.store_instance_id,x.issuer_id,
        x.bootstrap_checkpoint_revision,x.bootstrap_epoch,x.bootstrap_epoch_id,x.bootstrap_signing_key_id)
    _require(fixed(original) == fixed(p), 'ANCHOR_MISMATCH')
    _require(p.revision >= original.revision, 'POLICY_REGRESSION')
    _require(p.revision != original.revision or record_digest(p) == record_digest(original), 'POLICY_FORK')


class TestDistributionPolicyProvider:
    """In-process test serialization only; not authenticated distribution.

    All replacements on this instance share the same gate held by store.apply.
    Different processes do not share this in-memory policy authority.
    """
    __test__ = False

    def __init__(self, inputs):
        self._inputs = _copy(DistributionPolicyInputs, inputs)
        self._lock, self._generation = threading.RLock(), 0

    def snapshot_for_testing(self):
        with self._lock: return _copy(DistributionPolicyInputs, self._inputs)

    def replace_for_testing(self, inputs, *, expected_inputs_digest):
        replacement = _copy(DistributionPolicyInputs, inputs)
        with self._lock:
            _require(record_digest(self._inputs) == expected_inputs_digest, 'POLICY_CONFLICT')
            _require(replacement.policy.revision >= self._inputs.policy.revision, 'POLICY_REGRESSION')
            _require(replacement.policy.revision != self._inputs.policy.revision or
                     canonical_bytes(replacement.policy) == canonical_bytes(self._inputs.policy), 'POLICY_FORK')
            self._inputs = replacement
            self._generation += 1

    @contextmanager
    def _lease(self):
        with self._lock:
            inputs, generation = _copy(DistributionPolicyInputs, self._inputs), self._generation
            def check():
                _require(generation == self._generation and canonical_bytes(inputs) == canonical_bytes(self._inputs), 'POLICY_CHANGED')
            yield inputs, check


@dataclass(frozen=True)
class DistributionStoreResult:
    status: str
    receipt_bytes: bytes
    verification: DistributionResult
    audit_only: bool = True


def _verify(request, head, now):
    result = verify_trust_distribution(request.bundle,policy=request.inputs.policy,
        trusted_policy_checkpoint=request.inputs.checkpoint,retained_head=head,now=now)
    _require(result.status != 'REJECTED', result.reason_code or 'VERIFICATION_FAILED')
    return result


def _receipt(request, result, sequence, now):
    return DistributionReceipt(local_sequence=sequence,request_digest=record_digest(request),
        result_digest=record_digest(result),checkpoint_revision=result.proposed_head.checkpoint_revision,
        checkpoint_digest=result.proposed_head.checkpoint_digest,accepted_at=now,status=result.status)


def _validate(image, anchor, now):
    _time(now)
    _require(canonical_bytes(image.anchor) == canonical_bytes(anchor), 'ANCHOR_MISMATCH')
    _require(anchor.created_at <= now, 'CLOCK_REGRESSION')
    initial = anchor.initial_inputs
    _require(all(v.issued_at <= anchor.created_at < v.expires_at for v in (initial.policy,initial.checkpoint)))
    head, seen = None, set()
    for index, entry in enumerate(image.history, 1):
        request, receipt = entry.request, entry.receipt
        _require(len(canonical_bytes(request)) <= REQUEST_LIMIT, 'CAPACITY_EXCEEDED')
        _anchor_inputs(anchor,request.inputs)
        _require(anchor.created_at <= receipt.accepted_at <= now, 'CLOCK_REGRESSION')
        result = _verify(request, head, receipt.accepted_at)
        expected = _receipt(request,result,index,receipt.accepted_at)
        _require(canonical_bytes(expected) == canonical_bytes(receipt))
        _require(receipt.request_digest not in seen)
        seen.add(receipt.request_digest)
        head = result.proposed_head
    if head is not None:
        _require(head.checked_at <= image.head.checked_at <= now, 'CLOCK_REGRESSION')
        current = _verify(image.history[-1].request, head, image.head.checked_at)
        _require(canonical_bytes(current.proposed_head) == canonical_bytes(image.head))
    return image


TABLES = {
    'distribution_anchor': 'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 524288), digest TEXT NOT NULL CHECK(length(digest)=64)',
    'distribution_image': 'id INTEGER PRIMARY KEY CHECK(id=1), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16777216), digest TEXT NOT NULL CHECK(length(digest)=64), local_sequence INTEGER NOT NULL CHECK(local_sequence BETWEEN 0 AND 64)',
    'distribution_receipts': 'local_sequence INTEGER PRIMARY KEY CHECK(local_sequence BETWEEN 1 AND 64), request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64), request BLOB NOT NULL CHECK(length(request) BETWEEN 1 AND 524288), receipt BLOB NOT NULL CHECK(length(receipt) BETWEEN 1 AND 4096)',
    'distribution_head': 'id INTEGER PRIMARY KEY CHECK(id=1), local_sequence INTEGER NOT NULL REFERENCES distribution_receipts(local_sequence), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16384), authority_key BLOB NOT NULL CHECK(length(authority_key) BETWEEN 1 AND 16384)',
}
DDL = tuple(f'CREATE TABLE {name} ({columns}) STRICT' for name,columns in TABLES.items()) + tuple(
    f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT,'Immutable'); END"
    for name in ('distribution_anchor','distribution_receipts') for action in ('UPDATE','DELETE')) + tuple(
    f"CREATE TRIGGER {name}_no_delete BEFORE DELETE ON {name} BEGIN SELECT RAISE(ABORT,'Immutable'); END"
    for name in ('distribution_image','distribution_head'))


def _schema(db):
    return db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()


def _expected_schema():
    with closing(sqlite3.connect(':memory:')) as db:
        for statement in DDL: db.execute(statement)
        return _schema(db)


def _rows(image):
    head_rows = []
    if image.head is not None:
        key = next(k for k in image.history[-1].request.inputs.policy.keys if k.key_id == image.head.signing_key_id)
        head_rows = [(1,len(image.history),canonical_bytes(image.head),canonical_bytes(key))]
    return {
        'distribution_anchor': [(1,canonical_bytes(image.anchor),record_digest(image.anchor))],
        'distribution_image': [(1,canonical_bytes(image),record_digest(image),len(image.history))],
        'distribution_receipts': [(e.receipt.local_sequence,e.receipt.request_digest,canonical_bytes(e.request),canonical_bytes(e.receipt)) for e in image.history],
        'distribution_head': head_rows,
    }


class TestProtectedTrustDistributionStore:
    __test__ = False

    def __init__(self, path, *, trusted_anchor, clock=None, busy_timeout=1):
        self.path = Path(path).absolute()
        self.anchor = _copy(DistributionStoreAnchor,trusted_anchor)
        _require(type(busy_timeout) in (int,float) and math.isfinite(busy_timeout) and 0 <= busy_timeout <= 5, 'INVALID_INPUT')
        self.timeout = busy_timeout
        self.clock = clock if clock is not None else lambda: time.time_ns()//1000000000

    def _hook(self, point): pass

    @classmethod
    def create_for_testing(cls, path, *, trusted_anchor, now):
        try:
            store = cls(path,trusted_anchor=trusted_anchor)
            image = DistributionStoreImage(anchor=store.anchor,history=())
            _validate(image,store.anchor,now)
            _require(not any(Path(str(store.path)+suffix).exists() for suffix in ('-wal','-shm','-journal')), 'CREATION_FAILED')
            with store.path.open('xb'): pass
            with closing(sqlite3.connect(store.path,isolation_level=None)) as db:
                _require(db.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',))
                db.execute('PRAGMA synchronous=FULL'); db.execute('PRAGMA trusted_schema=OFF'); db.execute('PRAGMA foreign_keys=ON')
                db.execute('BEGIN IMMEDIATE')
                try:
                    for sql in DDL: db.execute(sql)
                    store._hook('schema_created')
                    db.execute(f'PRAGMA application_id={APPLICATION_ID}'); db.execute('PRAGMA user_version=1')
                    for name,rows in _rows(image).items():
                        for row in rows: db.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in row)})",row)
                    store._load(db,now); store._hook('creation_before_commit')
                    db.execute('COMMIT'); store._hook('creation_after_commit')
                except BaseException:
                    if db.in_transaction: db.execute('ROLLBACK')
                    raise
            return store
        except Exception: raise DistributionStoreError('CREATION_FAILED') from None

    def _load(self, db, now):
        _time(now)
        _require(db.execute('PRAGMA application_id').fetchone() == (APPLICATION_ID,)
                 and db.execute('PRAGMA user_version').fetchone() == (1,)
                 and db.execute('PRAGMA journal_mode').fetchone() == ('wal',))
        amount,count = db.execute('SELECT coalesce(sum(length(CAST(sql AS BLOB))),0),count(*) FROM sqlite_schema').fetchone()
        _require(amount <= 65536 and count <= 64 and _schema(db) == _expected_schema())
        total = 0
        for name in TABLES:
            count = db.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
            _require(count <= HISTORY_LIMIT if name == 'distribution_receipts' else count <= 1 if name == 'distribution_head' else count == 1)
            for column in (r[1] for r in db.execute(f'PRAGMA table_info({name})')):
                maximum,amount = db.execute(f'SELECT coalesce(max(length(CAST({column} AS BLOB))),0),coalesce(sum(length(CAST({column} AS BLOB))),0) FROM {name}').fetchone()
                limit = IMAGE_LIMIT if (name,column) == ('distribution_image','canonical') else REQUEST_LIMIT
                _require(maximum <= limit)
                total += amount
                _require(total <= 40*1024*1024, 'CAPACITY_EXCEEDED')
        image = decode_canonical(DistributionStoreImage,db.execute('SELECT canonical FROM distribution_image').fetchone()[0])
        _validate(image,self.anchor,now)
        for name,rows in _rows(image).items():
            _require(db.execute(f'SELECT * FROM {name} ORDER BY 1').fetchall() == rows)
        _require(db.execute('PRAGMA foreign_key_check').fetchall() == [])
        _require(db.execute('PRAGMA quick_check(1)').fetchone() == ('ok',))
        return image

    def load_audit(self, *, now):
        """Historical replay at recorded verification times; never current permission."""
        try:
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,isolation_level=None,timeout=self.timeout)) as db:
                db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF'); db.execute('BEGIN')
                try: return self._load(db,now)
                finally: db.execute('ROLLBACK')
        except Exception: raise DistributionStoreError('INVALID_STORE') from None

    def _write_image(self, db, image):
        raw = canonical_bytes(image)
        _require(len(raw) <= IMAGE_LIMIT, 'CAPACITY_EXCEEDED')
        rows = _rows(image)
        db.execute('UPDATE distribution_image SET canonical=?,digest=?,local_sequence=? WHERE id=?',rows['distribution_image'][0][1:]+(1,))
        if rows['distribution_head']:
            db.execute('INSERT INTO distribution_head VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET local_sequence=excluded.local_sequence,canonical=excluded.canonical,authority_key=excluded.authority_key',rows['distribution_head'][0])

    def apply(self, bundle, *, provider):
        attempted = False
        try:
            _require(type(bundle) is TrustDistributionBundle and type(provider) is TestDistributionPolicyProvider, 'INVALID_INPUT')
            bundle = decode_distribution(TrustDistributionBundle,canonical_bytes(bundle))
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=self.timeout)) as db:
                db.execute('PRAGMA trusted_schema=OFF'); db.execute('PRAGMA synchronous=FULL'); db.execute('PRAGMA foreign_keys=ON')
                _require(db.execute('PRAGMA synchronous').fetchone() == (2,))
                db.execute('BEGIN IMMEDIATE')
                try:
                    self._hook('locked')
                    with provider._lease() as (inputs, check_policy):
                        now = _time(self.clock()); state = self._load(db,now)
                        _anchor_inputs(self.anchor,inputs)
                        request = _copy(DistributionIngestion,DistributionIngestion(bundle=bundle,inputs=inputs))
                        result = _verify(request,state.head,now)
                        repeated = bool(state.history) and canonical_bytes(state.history[-1].request) == canonical_bytes(request)
                        history = state.history
                        if repeated:
                            _require(result.status == 'UNCHANGED')
                            receipt = history[-1].receipt
                        else:
                            _require(len(history) < HISTORY_LIMIT, 'CAPACITY_EXCEEDED')
                            receipt = _receipt(request,result,len(history)+1,now)
                            history += (DistributionHistoryEntry(request=request,receipt=receipt),)
                            db.execute('INSERT INTO distribution_receipts VALUES(?,?,?,?)',(
                                receipt.local_sequence,receipt.request_digest,canonical_bytes(request),canonical_bytes(receipt)))
                            self._hook('receipt_inserted')
                        candidate = DistributionStoreImage(anchor=self.anchor,history=history,head=result.proposed_head)
                        self._write_image(db,candidate); self._hook('image_written')
                        self._hook('before_recheck')
                        final_now = _time(self.clock()); _require(final_now >= now,'CLOCK_REGRESSION')
                        check_policy()
                        current = _verify(request,candidate.head,final_now)
                        candidate = candidate.model_copy(update={'head':current.proposed_head})
                        self._write_image(db,candidate)
                        self._hook('before_commit')
                        final_check = _time(self.clock()); _require(final_check >= final_now,'CLOCK_REGRESSION')
                        _require(canonical_bytes(self._load(db,final_check)) == canonical_bytes(candidate))
                        _verify(request,candidate.head,final_check); check_policy()
                        raw = db.execute('SELECT receipt FROM distribution_receipts WHERE local_sequence=?',(receipt.local_sequence,)).fetchone()[0]
                        _require(raw == canonical_bytes(receipt))
                        attempted = True; db.execute('COMMIT'); self._hook('after_commit')
                        post_now = _time(self.clock()); _require(post_now >= final_check,'CLOCK_REGRESSION')
                        check_policy(); _verify(request,candidate.head,post_now)
                        # Return the exact verification head persisted in this
                        # transaction; the post-commit guard is not another write.
                        return DistributionStoreResult(result.status,raw,current)
                except BaseException:
                    if db.in_transaction: db.execute('ROLLBACK')
                    raise
        except Exception as exc:
            if attempted: raise DistributionStoreError('OUTCOME_UNKNOWN') from None
            if isinstance(exc,DistributionStoreError): raise
            if isinstance(exc,sqlite3.OperationalError) and (getattr(exc,'sqlite_errorcode',0)&255) in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                raise DistributionStoreError('STORE_BUSY') from None
            raise DistributionStoreError('INVALID_STORE') from None
