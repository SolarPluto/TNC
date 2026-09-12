"""Protected acquisition doubles, real SQLite ordering, and native denial checks."""
from dataclasses import replace
import multiprocessing as mp
import ntpath
import os
from pathlib import Path
import sqlite3
import struct
import sys
import threading

import pytest
from test_authenticated_caller_config import case, update, sign
from test_protected_provisioning import sd
from tnc.provenance.authorization_models import canonical_bytes, decode_canonical
from tnc.provenance.authenticated_caller_config import CallerConfigCheckpoint, ConfigurationAuthorityKey
from tnc.provenance.authenticated_caller_config_loader import (
    CallerConfigLoadPolicy, SecureConfigLoader, CallerConfigLoadError, FILE_LIMIT, APP_ID,
)
from tnc.provenance.installation_models import VolumeExpectation
from tnc.provenance.windows_deployment_inspection import _InspectionAPI, _Missing
from tnc.provenance.windows_protected_files import FileFacts

SID = 'S-1-5-21-12345'
OTHER = 'S-1-5-21-99999'
GUID = '\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\'


def security(owner=SID, writer=SID, protected=True):
    raw = bytearray(sd(owner, ((0, 0, 0x1f01ff, writer),)))
    struct.pack_into('<H', raw, 2, 0x9004 if protected else 0x8004)
    return bytes(raw)


class Files:
    """Only native metadata is synthetic; all configuration/SQLite files are real."""
    def __init__(self, policy):
        self.policy, self.handles, self.closed, self.reads = policy, {}, [], []
        self.bad, self.fail_close, self.after_read = None, False, None

    def open_root(self, path): return self._open(path)

    def _open(self, path):
        if not Path(path).exists(): raise _Missing('missing')
        handle = len(self.handles)+1
        self.handles[handle] = path
        return handle

    def open_child(self, parent, name, directory, content=False):
        assert parent not in self.closed
        return self._open(ntpath.join(self.handles[parent], name))

    def volume(self, handle): return self.policy.volume.guid, 'NTFS'

    def facts(self, handle):
        path = Path(self.handles[handle])
        stat = path.stat()
        result = FileFacts(path.is_dir(), 0x10 if path.is_dir() else 0, stat.st_nlink,
            0 if path.is_dir() else stat.st_size, self.policy.volume.serial, stat.st_ino, security())
        return self.bad(result, str(path)) if self.bad else result

    def read(self, handle, size):
        path = self.handles[handle]
        assert path == self.policy.configuration_path  # Never read database/key content via this API.
        self.reads.append(path)
        raw = Path(path).read_bytes()
        if self.after_read: self.after_read()
        return raw

    def close(self, handle):
        assert handle not in self.closed
        self.closed.append(handle)
        if self.fail_close: raise OSError('secret path must not leak')


def loader(policy, now):
    result = SecureConfigLoader(policy)
    result._clock, result._monotonic = lambda: now, lambda: 1.0
    result.apis = []
    def factory():
        api = Files(policy); result.apis.append(api); return api
    result._api_factory = factory
    return result


@pytest.fixture
def setup(tmp_path, case):
    config, state = tmp_path/'config', tmp_path/'state'
    config.mkdir(); state.mkdir()
    policy = CallerConfigLoadPolicy(configuration_id=case.payload.configuration_id,
        configuration_root=str(config), configuration_path=str(config/'caller.json'),
        state_root=str(state), state_path=str(state/'head.sqlite'),
        volume=VolumeExpectation(volume_id='local', root=str(tmp_path)[:3], guid=GUID, serial=123),
        installer_sids=(SID,), state_writer_sids=(SID,))
    Path(policy.configuration_path).write_bytes(canonical_bytes(case.doc))
    result = loader(policy, case.t)
    result.provision_state()
    return result, case


def load(setup, doc=None, cp=None):
    obj, c = setup
    if doc is not None: Path(obj._policy.configuration_path).write_bytes(canonical_bytes(doc))
    return obj.load(trusted_key=c.key, trusted_checkpoint=cp or c.cp)


def image(obj):
    db = sqlite3.connect(obj._policy.state_path)
    try: return db.execute('SELECT snapshot FROM head').fetchall()
    finally: db.close()


def assert_closed(obj):
    for api in obj.apis: assert sorted(api.closed) == sorted(api.handles)


def test_load_restart_and_unchanged_snapshot(setup):
    obj, c = setup
    first = load(setup)
    assert first.document == c.doc and first.audit_only and first.local_sequence == 1
    assert load(setup) == first
    restarted = loader(obj._policy, c.t+1)
    again = load((restarted, c))
    assert again.accepted_at == first.accepted_at and again.checked_at == c.t+1
    assert again.local_sequence == 1
    with pytest.raises(ValueError): first.checked_at = c.t+1
    assert_closed(obj); assert_closed(restarted)


def test_new_configuration_persisted_and_old_audit_unchanged(setup):
    obj, c = setup; old = load(setup)
    enrollment = c.payload.enrollments[0].model_copy(update={'status':'disabled'})
    doc, cp = update(c, enrollments=(enrollment,), registry_revision=4)
    current = load(setup, doc, cp)
    assert current.local_sequence == 2 and current.document.payload.registry_revision == 4
    assert old.document.payload.enrollments[0].status == 'active'
    before = image(obj)
    with pytest.raises(CallerConfigLoadError, match='CONFIG_ROLLBACK'): load(setup, c.doc)
    assert image(obj) == before and obj._active is None


@pytest.mark.parametrize('kind', ['registry_lower', 'registry_same_changed', 'same_revision_fork'])
def test_registry_and_revision_conflicts(setup, kind):
    obj, c = setup; load(setup); before = image(obj)
    changes = {'registry_revision':2} if kind == 'registry_lower' else {
        'enrollments':(c.payload.enrollments[0].model_copy(update={'status':'disabled'}),)}
    if kind == 'same_revision_fork': changes['revision'] = c.payload.revision
    doc, cp = update(c, **changes)
    reason = {'registry_lower':'REGISTRY_REGRESSION','registry_same_changed':'REGISTRY_REVISION_CONFLICT',
              'same_revision_fork':'CONFIG_FORK'}[kind]
    with pytest.raises(CallerConfigLoadError, match=reason): load(setup, doc, cp)
    assert image(obj) == before


def test_grant_only_change_keeps_registry_revision(setup):
    obj, c = setup; load(setup)
    doc, cp = update(c, grants=())
    result = load(setup, doc, cp)
    assert result.document.payload.registry_revision == 3 and result.local_sequence == 2


@pytest.mark.parametrize('kind', ['expired', 'checkpoint_expired', 'bad_signature', 'old_checkpoint', 'scope'])
def test_invalid_refresh_never_falls_back(setup, kind):
    obj, c = setup; load(setup); before = image(obj)
    doc, cp = c.doc, c.cp
    if kind == 'expired': obj._clock = lambda: c.t+60
    elif kind == 'checkpoint_expired': cp = cp.model_copy(update={'expires_at':c.t})
    elif kind == 'bad_signature': doc = doc.model_copy(update={'signature_hex':'0'*128})
    elif kind == 'scope': doc, cp = update(c, configuration_id='other')
    else: doc, _ = update(c, grants=())
    with pytest.raises(CallerConfigLoadError): load(setup, doc, cp)
    assert obj._active is None and image(obj) == before
    assert_closed(obj)


@pytest.mark.parametrize('kind', ['padding', 'duplicate', 'extra', 'oversize', 'empty'])
def test_raw_parsing_bounds(setup, kind):
    obj, c = setup
    raw = canonical_bytes(c.doc)
    raw = {'padding':raw+b' ', 'duplicate':b'{"payload":{},"payload":{}}',
           'extra':raw[:-1]+b',"extra":1}', 'oversize':b'x'*(FILE_LIMIT+1), 'empty':b''}[kind]
    Path(obj._policy.configuration_path).write_bytes(raw)
    with pytest.raises(CallerConfigLoadError): load(setup)
    assert image(obj) == []
    if kind in ('oversize','empty'): assert obj.apis[-1].reads == []
    assert_closed(obj)


@pytest.mark.parametrize('kind', ['owner','writer','dacl','reparse','links','volume','identity_change'])
def test_protected_metadata_rejects_before_use(setup, kind):
    obj, c = setup
    api = Files(obj._policy); obj.apis.append(api); obj._api_factory = lambda: api
    count = [0]
    def bad(f, path):
        if path != obj._policy.configuration_path: return f
        count[0] += 1
        return {'owner':lambda:replace(f,security=security(owner=OTHER)),
            'writer':lambda:replace(f,security=security(writer=OTHER)),
            'dacl':lambda:replace(f,security=security(protected=False)),
            'reparse':lambda:replace(f,attributes=0x400), 'links':lambda:replace(f,links=2),
            'volume':lambda:replace(f,volume=999),
            'identity_change':lambda:replace(f,file_id=f.file_id+(count[0]>1))}[kind]()
    api.bad = bad
    with pytest.raises(CallerConfigLoadError): load(setup)
    assert not image(obj)
    if kind != 'identity_change': assert not api.reads
    assert_closed(obj)


def test_cleanup_error_sanitized_without_cached_fallback(setup):
    obj, c = setup
    api = Files(obj._policy); api.fail_close = True
    obj.apis.append(api); obj._api_factory = lambda: api
    with pytest.raises(CallerConfigLoadError, match='OUTCOME_UNKNOWN'): load(setup)
    assert obj._active is None
    assert_closed(obj)
    assert load((loader(obj._policy,c.t),c)).local_sequence == 1


@pytest.mark.parametrize('stage', ['locked','before_commit','after_commit'])
def test_failure_atomicity(setup, stage):
    obj, c = setup
    def fail(at):
        if at == stage: raise RuntimeError('private internal detail')
    obj._test_hook = fail
    with pytest.raises(CallerConfigLoadError) as e: load(setup)
    assert 'private' not in str(e.value)
    assert bool(image(obj)) == (stage == 'after_commit')
    assert obj._active is None
    assert_closed(obj)


@pytest.mark.parametrize('kind', ['clock_regression','expiry_under_lock','deadline'])
def test_final_clock_rechecks(setup, kind):
    obj, c = setup
    def change(stage):
        if stage == 'before_commit':
            if kind == 'deadline': obj._monotonic = lambda: 20.
            else: obj._clock = lambda: c.t-1 if kind == 'clock_regression' else c.t+60
    obj._test_hook = change
    with pytest.raises(CallerConfigLoadError): load(setup)
    assert not image(obj)


def test_clock_regression_across_restart(setup):
    obj, c = setup; load(setup)
    with pytest.raises(CallerConfigLoadError, match='CLOCK_REGRESSION'):
        load((loader(obj._policy,c.t-1),c))


@pytest.mark.parametrize('kind', ['missing','schema','anchor','noncanonical','extra_table'])
def test_state_fail_closed(setup, kind):
    obj, c = setup
    if kind == 'missing': Path(obj._policy.state_path).unlink()
    else:
        load(setup)
        db = sqlite3.connect(obj._policy.state_path)
        if kind == 'schema': db.execute('PRAGMA user_version=2')
        elif kind == 'anchor': db.execute('DROP TRIGGER anchor_update')
        elif kind == 'extra_table': db.execute('CREATE TABLE sqliteExtra(value TEXT)')
        else:
            raw = image(obj)[0][0]
            db.execute('UPDATE head SET snapshot=?',(raw+b' ',))
        db.commit(); db.close()
    with pytest.raises(CallerConfigLoadError): load(setup)
    if kind == 'missing': assert not Path(obj._policy.state_path).exists()


def test_explicit_creation_failure_cannot_autorepair(setup):
    obj, c = setup
    with pytest.raises(CallerConfigLoadError, match='STATE_ALREADY_EXISTS'): obj.provision_state()
    Path(obj._policy.state_path).unlink()
    def fail(stage): raise RuntimeError('fail')
    obj._test_hook = fail
    with pytest.raises(CallerConfigLoadError): obj.provision_state()
    obj._test_hook = lambda stage: None
    with pytest.raises(CallerConfigLoadError): load(setup)
    assert Path(obj._policy.state_path).exists()


@pytest.mark.parametrize('path', ['relative.json', r'\\host\share\config.json', r'C:\a\..\config.json', r'C:\a\file:stream'])
def test_path_rejection(setup,path):
    obj,_ = setup
    with pytest.raises(ValueError): SecureConfigLoader(obj._policy.model_copy(update={'configuration_path':path}))


def test_atomic_memory_publication_under_concurrent_refresh(setup):
    obj,c = setup; old = load(setup)
    doc,cp = update(c,grants=())
    Path(obj._policy.configuration_path).write_bytes(canonical_bytes(doc))
    entered, resume = threading.Event(), threading.Event()
    def hook(stage):
        if stage == 'before_commit': entered.set(); assert resume.wait(10)
    obj._test_hook = hook
    results=[]
    thread=threading.Thread(target=lambda:results.append(load(setup,cp=cp)))
    thread.start()
    try:
        assert entered.wait(10)
        assert obj._active == old and old.document.payload.grants
    finally:
        resume.set(); thread.join(10)
    assert not thread.is_alive() and len(results)==1
    assert obj._active == results[0] and not results[0].document.payload.grants


def _process(policy_raw,key_raw,cp_raw,now,stage,entered=None,resume=None):
    obj=loader(decode_canonical(CallerConfigLoadPolicy,policy_raw),now)
    if stage=='after_write':
        original_read=obj._read
        reads=[0]
        def exit_after_write(db):
            result=original_read(db)
            reads[0]+=1
            if reads[0]==2:os._exit(81)  # SQL head inserted, transaction not committed.
            return result
        obj._read=exit_after_write
    def hook(at):
        if at==stage:
            if entered is not None:
                entered.set()
                if not resume.wait(15): os._exit(92)
            else: os._exit(81)
    obj._test_hook=hook
    obj.load(trusted_key=decode_canonical(ConfigurationAuthorityKey,key_raw),
             trusted_checkpoint=decode_canonical(CallerConfigCheckpoint,cp_raw))


@pytest.mark.parametrize('stage',['before_commit','after_write','after_commit'])
def test_spawned_process_exit(setup,stage):
    obj,c=setup
    p=mp.get_context('spawn').Process(target=_process,args=(canonical_bytes(obj._policy),canonical_bytes(c.key),
        canonical_bytes(c.cp),c.t,stage))
    p.start();p.join(20)
    if p.is_alive():p.terminate();p.join();pytest.fail('Child timed out')
    assert p.exitcode==81
    assert bool(image(obj))==(stage=='after_commit')
    assert load((loader(obj._policy,c.t),c)).local_sequence==1


def test_competing_process_lock_and_restart(setup):
    obj,c=setup;ctx=mp.get_context('spawn');entered,resume=ctx.Event(),ctx.Event()
    p=ctx.Process(target=_process,args=(canonical_bytes(obj._policy),canonical_bytes(c.key),canonical_bytes(c.cp),
                                      c.t,'locked',entered,resume))
    p.start()
    try:
        assert entered.wait(10)
        with pytest.raises(CallerConfigLoadError,match='STATE_BUSY'):load(setup)
    finally:
        resume.set();p.join(20)
        if p.is_alive():p.terminate();p.join()
    assert p.exitcode==0 and load(setup).local_sequence==1


def test_old_consistent_checkpoint_cannot_detect_whole_state_restore(setup):
    obj,c=setup;load(setup)
    saved=image(obj)[0][0]
    doc,cp=update(c,grants=());load(setup,doc,cp)
    # Explicit limitation: simulate privileged whole-state restore to signed old state.
    db=sqlite3.connect(obj._policy.state_path)
    db.execute('UPDATE head SET snapshot=?',(saved,));db.commit();db.close()
    assert load(setup,c.doc).document==c.doc
    with pytest.raises(CallerConfigLoadError,match='CONFIG_TRUST_MISMATCH'):load(setup,cp=cp)


def test_postcommit_expiry_is_uncertain_not_cached_success(setup):
    obj,c=setup
    def expire(stage):
        if stage=='after_commit':obj._clock=lambda:c.t+60
    obj._test_hook=expire
    with pytest.raises(CallerConfigLoadError,match='OUTCOME_UNKNOWN'):load(setup)
    assert image(obj) and obj._active is None
    with pytest.raises(CallerConfigLoadError,match='CONFIG_EXPIRED'):
        load((loader(obj._policy,c.t+60),c))


def test_state_file_can_inherit_safe_protected_parent_acl(setup):
    obj,c=setup
    api=Files(obj._policy);obj.apis.append(api);obj._api_factory=lambda:api
    api.bad=lambda f,path:replace(f,security=security(protected=False)) if path==obj._policy.state_path else f
    assert load(setup).local_sequence==1
    assert_closed(obj)


@pytest.mark.parametrize('kind',['state_size','sidecar_link','sidecar_reparse'])
def test_state_metadata_bounds_before_sqlite(setup,kind,monkeypatch):
    obj,c=setup
    suffix='-wal' if kind!='state_size' else ''
    if suffix:Path(obj._policy.state_path+suffix).write_bytes(b'fake')
    api=Files(obj._policy);obj.apis.append(api);obj._api_factory=lambda:api
    def bad(f,path):
        if path!=obj._policy.state_path+suffix:return f
        return replace(f,**({'size':8*1024*1024+1} if kind=='state_size' else
                           {'links':2} if kind=='sidecar_link' else {'attributes':0x400}))
    api.bad=bad
    monkeypatch.setattr(obj,'_connect',lambda:pytest.fail('Unsafe state must be rejected before SQLite'))
    with pytest.raises(CallerConfigLoadError):load(setup)
    assert_closed(obj)


def test_later_writer_cannot_regress_after_lock_wait(setup):
    obj,c=setup;load(setup)
    newer,newcp=update(c,grants=());load(setup,newer,newcp)
    restarted=loader(obj._policy,c.t)
    with pytest.raises(CallerConfigLoadError,match='CONFIG_ROLLBACK'):load((restarted,c),c.doc)
    assert len(image(obj))==1


@pytest.mark.skipif(sys.platform!='win32',reason='Native Windows metadata')
def test_native_untrusted_tree_denies_before_content_read(setup):
    obj,c=setup
    api=_InspectionAPI();h=api.open_root(obj._policy.volume.root)
    try: guid,_=api.volume(h);serial=api.facts(h).volume
    finally:api.close(h)
    policy=obj._policy.model_copy(update={'volume':obj._policy.volume.model_copy(update={'guid':guid,'serial':serial}),
        'installer_sids':(OTHER,), 'state_writer_sids':(OTHER,)})
    native=SecureConfigLoader(policy);native._clock=lambda:c.t
    api.read=lambda *args:pytest.fail('Unauthorized metadata must prevent content reads')
    native._api_factory=lambda:api
    before=Path(obj._policy.configuration_path).read_bytes()
    with pytest.raises(CallerConfigLoadError,match='OWNER_DENIED'):load((native,c))
    assert Path(obj._policy.configuration_path).read_bytes()==before
