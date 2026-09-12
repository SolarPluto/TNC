"""Protected Windows caller-config ingestion and local crash-consistent heads.

Host-only inputs are not a trust-discovery protocol. Returned snapshots are audit
data, not execution tickets. No bridge, signer or journal routes are installed.
"""
from contextlib import contextmanager
import math
import ntpath
from pathlib import Path
import sqlite3
import struct
import threading
import time
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.authenticated_caller_config import (
    CallerConfigDocument, CallerConfigHead, ConfigurationAuthorityKey, CallerConfigCheckpoint,
    Time, evaluate_config_revision, decode_caller_config,
)
from tnc.provenance.installation_models import LocalPath, VolumeExpectation
from tnc.provenance.provisioning_models import Sid
from tnc.provenance.windows_deployment_inspection import _InspectionAPI, _Missing
from tnc.provenance.windows_protected_files import parse_security

FILE_LIMIT = 65536
STATE_LIMIT = 131072
APP_ID = 0x544E4346
DDL = (
    'CREATE TABLE anchor (id INTEGER PRIMARY KEY CHECK(id=1), policy BLOB NOT NULL CHECK(length(policy) BETWEEN 1 AND 16384)) STRICT',
    'CREATE TABLE head (id INTEGER PRIMARY KEY CHECK(id=1), snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 131072)) STRICT',
    "CREATE TRIGGER anchor_update BEFORE UPDATE ON anchor BEGIN SELECT RAISE(ABORT,'immutable'); END",
    "CREATE TRIGGER anchor_delete BEFORE DELETE ON anchor BEGIN SELECT RAISE(ABORT,'immutable'); END",
    "CREATE TRIGGER head_delete BEFORE DELETE ON head BEGIN SELECT RAISE(ABORT,'immutable'); END",
)


class CallerConfigLoadPolicy(Model):
    profile: Literal['tnc-caller-config-loader-v1'] = 'tnc-caller-config-loader-v1'
    configuration_id: Identifier
    configuration_root: LocalPath
    configuration_path: LocalPath
    state_root: LocalPath
    state_path: LocalPath
    volume: VolumeExpectation
    installer_sids: tuple[Sid, ...] = Field(min_length=1, max_length=64)
    state_writer_sids: tuple[Sid, ...] = Field(min_length=1, max_length=64)
    timeout_seconds: int = Field(default=5, strict=True, ge=1, le=10)

    @model_validator(mode='after')
    def layout(self):
        roots = (self.configuration_root, self.state_root)
        for root, path in zip(roots, (self.configuration_path, self.state_path)):
            if len(root) == 3 or root[:3] != self.volume.root or ntpath.dirname(path).lower() != root.lower():
                raise ValueError('Dedicated directories and direct children required')
        a, b = (ntpath.normcase(v) for v in roots)
        if a == b or a.startswith(b+'\\') or b.startswith(a+'\\'):
            raise ValueError('Separate configuration and state roots required')
        for sids in (self.installer_sids, self.state_writer_sids):
            if sids != tuple(sorted(set(sids))): raise ValueError('Sorted unique SIDs required')
        return self


class LoadedCallerConfiguration(Model):
    audit_only: Literal[True] = True
    document: CallerConfigDocument
    trusted_key: ConfigurationAuthorityKey
    trusted_checkpoint: CallerConfigCheckpoint
    accepted_at: Time
    checked_at: Time
    local_sequence: int = Field(strict=True, ge=1, le=2**63-1)


class CallerConfigLoadError(Exception):
    def __init__(self, reason_code='CONFIGURATION_UNAVAILABLE'):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _require(condition, reason):
    if not condition: raise CallerConfigLoadError(reason)


def _copy(kind, value):
    _require(type(value) is kind, 'INVALID_HOST_INPUT')
    return decode_canonical(kind, canonical_bytes(value))


class _Budget:
    def __init__(self, owner):
        self.owner, self.start, self.last_tick, self.last_utc = owner, None, None, None

    def check(self):
        now, tick = self.owner._clock(), self.owner._monotonic()
        _require(type(now) is int and 0 <= now <= 2**63-1 and type(tick) in (int, float)
                 and math.isfinite(tick), 'CLOCK_INVALID')
        _require((self.last_tick is None or tick >= self.last_tick)
                 and (self.last_utc is None or now >= self.last_utc), 'CLOCK_REGRESSION')
        if self.start is None: self.start = tick
        self.last_tick, self.last_utc = tick, now
        _require(tick-self.start < self.owner._policy.timeout_seconds, 'BUDGET_EXCEEDED')
        return now


class _PinnedFiles:
    """Hold ancestor handles through the SQLite transaction; never read DB bytes."""
    def __init__(self, api, policy, budget):
        self.api, self.policy, self.budget = api, policy, budget
        self.handles, self.checks = [], []

    def facts(self, handle, path, directory, mutable=False):
        self.budget.check()
        f = self.api.facts(handle)
        _require(f.directory == directory and not f.attributes & 0x400
                 and (directory or f.links == 1) and f.volume == self.policy.volume.serial,
                 'UNSAFE_FILE_OBJECT')
        if mutable and not directory:
            _require(0 <= f.size <= 8*1024*1024, 'STATE_FILE_SIZE_LIMIT')
        if path == path[:3]:
            _require(self.api.volume(handle) == (self.policy.volume.guid, 'NTFS'), 'VOLUME_MISMATCH')
        owner, entries = parse_security(f.security)
        is_state = path.lower() == self.policy.state_root.lower() or path.lower().startswith(self.policy.state_root.lower()+'\\')
        writers = set(self.policy.installer_sids) | (set(self.policy.state_writer_sids) if is_state else set())
        _require(owner in writers, 'OWNER_DENIED')
        # Newly created SQLite files inherit the protected state directory's ACL.
        # Validate every effective/future write grant; do not require an ACL edit
        # merely to set the child's protected bit after exclusive creation.
        protected = (is_state and directory) or path.lower() == self.policy.configuration_root.lower() or path.lower().startswith(self.policy.configuration_root.lower()+'\\')
        _require(not protected or struct.unpack_from('<H', f.security, 2)[0] & 0x1000, 'DACL_UNPROTECTED')
        for kind, flags, mask, sid in entries:
            _require(not mask & ~0xf31f01ff, 'UNSUPPORTED_DACL')
            _require(not (kind == 0 and mask & (0x52000000 | 0x000d0156) and sid not in writers), 'WRITE_GRANT_DENIED')
        return f

    def open(self, path, *, directory=False, content=False, mutable=False, missing=False):
        parent = None
        parts = (path[:3], *path[3:].split('\\'))
        current = ''
        for i, part in enumerate(parts):
            self.budget.check()
            _require(len(self.handles) < 128, 'HANDLE_LIMIT')
            final = i == len(parts)-1
            current = part if i == 0 else ntpath.join(current, part)
            try:
                # _InspectionAPI's directory selector controls sharing, not type:
                # for the main DB select READ|WRITE but deny DELETE, pinning its name.
                h = self.api.open_root(part) if i == 0 else self.api.open_child(
                    parent, part, not final or directory or mutable, content if final else False)
            except _Missing:
                if final and missing: return None
                raise
            self.handles.append(h)
            f = self.facts(h, current, not final or directory, mutable if final else False)
            self.checks.append((h, current, not final or directory, mutable if final else False, f))
            parent = h
        return h, f

    def read_config(self):
        h, f = self.open(self.policy.configuration_path, content=True)
        _require(0 < f.size <= FILE_LIMIT, 'CONFIG_SIZE_LIMIT')
        raw = self.api.read(h, f.size)
        _require(type(raw) is bytes and len(raw) == f.size, 'CONFIG_READ_INCOMPLETE')
        self.verify()
        return raw

    def verify(self):
        for h, path, directory, mutable, before in self.checks:
            after = self.facts(h, path, directory, mutable)
            if mutable:
                _require((after.file_id, after.security) == (before.file_id, before.security), 'FILE_CHANGED')
            else:
                # Directory sizes may change as SQLite creates sidecars.
                _require(after == before or directory and (after.file_id, after.security) ==
                         (before.file_id, before.security), 'FILE_CHANGED')

    def close(self):
        failed = False
        for h in reversed(self.handles):
            try: self.api.close(h)
            except Exception: failed = True
        self.handles.clear()
        _require(not failed, 'HANDLE_CLEANUP_FAILED')


def _schema(db):
    return tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name"))


def _expected_schema():
    db = sqlite3.connect(':memory:')
    try:
        for statement in DDL: db.execute(statement)
        return _schema(db)
    finally:
        db.close()


class SecureConfigLoader:
    """Serialized host loader. Ordinary loads require an explicitly created store.

    Trusted key/checkpoint arguments must come from the host's independent current
    authority. Neither file bytes nor a retained audit snapshot supply that trust.
    """
    def __init__(self, policy):
        self._policy = _copy(CallerConfigLoadPolicy, policy)
        _require(len(canonical_bytes(self._policy)) <= 16384, 'INVALID_HOST_INPUT')
        self._lock, self._active = threading.RLock(), None
        self._clock = lambda: time.time_ns() // 1000000000
        self._monotonic, self._api_factory = time.monotonic, _InspectionAPI
        self._test_hook = lambda stage: None

    @contextmanager
    def _guard(self):
        with self._lock:
            budget = _Budget(self)
            budget.check()
            pins = _PinnedFiles(self._api_factory(), self._policy, budget)
            try:
                yield pins, budget
            finally:
                pins.close()

    def _connect(self):
        db = sqlite3.connect(Path(self._policy.state_path).as_uri()+'?mode=rw', uri=True, timeout=0.25,
                             isolation_level=None)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA foreign_keys=ON')
        except BaseException:
            db.close()
            raise
        return db

    def provision_state(self):
        """Explicit host provisioning only; never create directories or adjust ACLs."""
        try:
            with self._guard() as (pins, budget):
                pins.open(self._policy.state_root, directory=True)
                # Reject pre-existing sidecars before exclusive main-file creation.
                for suffix in ('', '-wal', '-shm', '-journal'):
                    _require(pins.open(self._policy.state_path+suffix, mutable=True, missing=True) is None,
                             'STATE_ALREADY_EXISTS')
                with open(self._policy.state_path, 'xb'): pass
                pins.open(self._policy.state_path, mutable=True)
                db = self._connect()
                try:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('BEGIN IMMEDIATE')
                    for statement in DDL: db.execute(statement)
                    db.execute('INSERT INTO anchor VALUES(1,?)', (canonical_bytes(self._policy),))
                    db.execute(f'PRAGMA application_id={APP_ID}')
                    db.execute('PRAGMA user_version=1')
                    self._test_hook('provision_before_commit')
                    budget.check(); pins.verify()
                    self._read(db)
                    db.commit()
                finally:
                    db.close()
        except Exception as exc:
            self._active = None
            raise self._error(exc) from None

    def _read(self, db):
        _require(db.execute('PRAGMA application_id').fetchone() == (APP_ID,)
                 and db.execute('PRAGMA user_version').fetchone() == (1,)
                 and db.execute('PRAGMA journal_mode').fetchone() == ('wal',)
                 and _schema(db) == _expected_schema(), 'STATE_SCHEMA_INVALID')
        _require(db.execute('SELECT id,length(policy) FROM anchor').fetchall() == [(1, len(canonical_bytes(self._policy)))], 'STATE_ANCHOR_INVALID')
        _require(db.execute('SELECT policy FROM anchor').fetchone()[0] == canonical_bytes(self._policy), 'STATE_ANCHOR_INVALID')
        rows = db.execute('SELECT id,length(snapshot) FROM head').fetchall()
        _require(len(rows) <= 1 and (not rows or rows[0][0] == 1 and 0 < rows[0][1] <= STATE_LIMIT), 'STATE_CORRUPT')
        _require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'STATE_CORRUPT')
        if not rows: return None
        raw = db.execute('SELECT snapshot FROM head WHERE id=1').fetchone()[0]
        state = decode_canonical(LoadedCallerConfiguration, raw)
        p = state.document.payload
        _require(p.configuration_id == self._policy.configuration_id and state.accepted_at <= state.checked_at, 'STATE_CORRUPT')
        decision = evaluate_config_revision(state.document, trusted_key=state.trusted_key,
            trusted_checkpoint=state.trusted_checkpoint, retained_head=None, now=state.checked_at)
        _require(decision.status == 'INITIAL', 'STATE_CORRUPT')
        return state

    @staticmethod
    def _error(exc):
        if isinstance(exc, CallerConfigLoadError): return exc
        if isinstance(exc, sqlite3.OperationalError) and ('locked' in str(exc) or 'busy' in str(exc)):
            return CallerConfigLoadError('STATE_BUSY')
        return CallerConfigLoadError()

    def load(self, *, trusted_key, trusted_checkpoint):
        """Read/reverify on every call; no stale-cache fallback after any failure."""
        attempted_commit = False
        try:
            key = _copy(ConfigurationAuthorityKey, trusted_key)
            checkpoint = _copy(CallerConfigCheckpoint, trusted_checkpoint)
            with self._guard() as (pins, budget):
                pins.open(self._policy.state_path, mutable=True)
                for suffix in ('-wal', '-shm', '-journal'):
                    pins.open(self._policy.state_path+suffix, mutable=True, missing=True)
                db = self._connect()
                try:
                    db.execute('BEGIN IMMEDIATE')
                    self._test_hook('locked')
                    now = budget.check()
                    old = self._read(db)
                    if old: _require(now >= old.checked_at, 'CLOCK_REGRESSION')
                    document = decode_caller_config(CallerConfigDocument, pins.read_config())
                    p = document.payload
                    _require(p.configuration_id == self._policy.configuration_id, 'CONFIG_TRUST_MISMATCH')
                    head = None if old is None else CallerConfigHead(configuration_id=p.configuration_id,
                        revision=old.document.payload.revision, configuration_digest=record_digest(old.document.payload),
                        accepted_at=old.checked_at)
                    decision = evaluate_config_revision(document, trusted_key=key, trusted_checkpoint=checkpoint,
                                                        retained_head=head, now=budget.check())
                    _require(decision.status != 'REJECTED', decision.reason_code or 'CONFIGURATION_UNAVAILABLE')
                    if old:
                        previous = old.document.payload
                        _require(p.registry_revision >= previous.registry_revision, 'REGISTRY_REGRESSION')
                        _require(p.registry_revision != previous.registry_revision or p.enrollments == previous.enrollments,
                                 'REGISTRY_REVISION_CONFLICT')
                    changed = old is None or any(canonical_bytes(a) != canonical_bytes(b) for a, b in zip(
                        (document, key, checkpoint), (old.document, old.trusted_key, old.trusted_checkpoint)))
                    self._test_hook('before_commit')
                    checked_at = budget.check()
                    final = evaluate_config_revision(document, trusted_key=key, trusted_checkpoint=checkpoint,
                                                     retained_head=head, now=checked_at)
                    _require(final.status != 'REJECTED', final.reason_code or 'CONFIGURATION_UNAVAILABLE')
                    candidate = LoadedCallerConfiguration(document=document, trusted_key=key, trusted_checkpoint=checkpoint,
                        accepted_at=checked_at if changed else old.accepted_at, checked_at=checked_at,
                        local_sequence=(old.local_sequence+1 if changed else old.local_sequence) if old else 1)
                    raw = canonical_bytes(candidate)
                    _require(len(raw) <= STATE_LIMIT, 'STATE_SIZE_LIMIT')
                    db.execute('INSERT INTO head VALUES(1,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot', (raw,))
                    _require(self._read(db) == candidate, 'STATE_CORRUPT')
                    pins.verify(); budget.check()
                    # The clock may have crossed an expiry during final file checks.
                    final = evaluate_config_revision(document, trusted_key=key, trusted_checkpoint=checkpoint,
                                                     retained_head=head, now=budget.check())
                    _require(final.status != 'REJECTED', final.reason_code or 'CONFIGURATION_UNAVAILABLE')
                    attempted_commit = True
                    db.commit()
                    self._test_hook('after_commit')
                    after = evaluate_config_revision(document, trusted_key=key, trusted_checkpoint=checkpoint,
                        retained_head=head, now=budget.check())
                    _require(after.status != 'REJECTED', after.reason_code or 'CONFIGURATION_UNAVAILABLE')
                finally:
                    db.close()
                # Publish only the whole frozen snapshot, after persistence succeeds.
                self._active = candidate
            return candidate
        except Exception as exc:
            self._active = None
            if attempted_commit: raise CallerConfigLoadError('OUTCOME_UNKNOWN') from None
            raise self._error(exc) from None
