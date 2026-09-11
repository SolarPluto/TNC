"""Fake acquisition tests and real Windows metadata-only interoperability."""
from dataclasses import replace
import ctypes as c
from ctypes import wintypes as w
import ntpath
import sqlite3
import sys
from datetime import datetime,timedelta,timezone
from hashlib import sha256
from types import SimpleNamespace

import pytest

from test_deployment_validation import inventory,GUID,NOW,MAINT
from test_provisioning_validation import case
from test_protected_provisioning import sd
from tnc.provenance.windows_protected_files import FileFacts,ProtectedFileError,_Attributes
from tnc.provenance.windows_deployment_inspection import _inspect,_InspectionAPI,_Missing,DeploymentInspectionError
from tnc.provenance.authorization_models import canonical_bytes,record_digest
from tnc.provenance.installation_models import ObjectExpectation,VolumeExpectation


class Fake:
    def __init__(self,inventory):
        self.objects={o.path:o for o in inventory['envelope'].objects}
        self.opened,self.closed,self.paths,self.reads=[],[],{},[]
        self.missing=set()
        self.denied=set()
        self.changed=set()
        self.reparse=set()
        self.fail_close=None
        self.visits={}
    def open_root(self,path):return self.open_child(None,path,True)
    def volume(self,handle):return GUID,'NTFS'
    def open_child(self,parent,name,directory,content=False):
        path=ntpath.join(self.paths[parent],name) if parent else name
        if path in self.missing:raise _Missing()
        if path in self.denied:raise ProtectedFileError()
        handle=len(self.opened)+1
        self.opened.append(handle)
        self.paths[handle]=path
        return handle
    def facts(self,handle):
        path=self.paths[handle]
        self.visits[path]=self.visits.get(path,0)+1
        obj=self.objects[path]
        return FileFacts(obj.kind=='directory',0x400 if path in self.reparse else 0,1,1,123,
            list(self.objects).index(path)+(100 if path in self.changed and self.visits[path]>1 else 0),
            sd(owner=MAINT,entries=((0,0,0x1f01ff,MAINT),)))
    def read(self,handle,size):
        self.reads.append(self.objects[self.paths[handle]].role)
        return b'x'
    def close(self,handle):
        self.closed.append(handle)
        if handle==self.fail_close:raise ProtectedFileError()


def run(inventory,api,mono=lambda:1.):
    return _inspect(inventory['envelope'],inventory['external_anchor'],inventory['descriptor'],api,lambda:NOW,mono)


def test_complete_observations_and_metadata_roles(inventory):
    api=Fake(inventory)
    report=run(inventory,api)
    assert report.status=='VIOLATIONS'  # Synthetic file bytes intentionally mismatch expected hashes.
    assert set(api.reads)=={'code','descriptor','anchor'}
    assert sorted(api.closed)==sorted(api.opened)
    assert len(report.inspected_object_ids)==len(inventory['envelope'].objects)


@pytest.mark.parametrize('role',['code','state','database','wal','shm','private_key'])
def test_access_denied_never_becomes_absent(inventory,role):
    api=Fake(inventory)
    obj=next(o for o in inventory['envelope'].objects if o.role==role)
    api.denied.add(obj.path)
    report=run(inventory,api)
    assert report.status=='INDETERMINATE'
    assert any(f.object_id==obj.object_id and f.reason_code=='INSPECTION_UNAVAILABLE' for f in report.findings)
    assert sorted(api.closed)==sorted(api.opened)


@pytest.mark.parametrize('role',['database','wal','shm'])
def test_recognized_missing_objects(inventory,role):
    api=Fake(inventory)
    obj=next(o for o in inventory['envelope'].objects if o.role==role)
    api.missing.add(obj.path)
    report=run(inventory,api)
    reasons={f.reason_code for f in report.findings if f.object_id==obj.object_id}
    assert reasons==({'REQUIRED_OBJECT_MISSING'} if obj.required else set())


def test_reparse_parent_is_not_traversed(inventory):
    api=Fake(inventory)
    obj=next(o for o in inventory['envelope'].objects if o.role=='state')
    api.reparse.add(obj.path)
    report=run(inventory,api)
    assert any(f.reason_code=='REPARSE_POINT' for f in report.findings)
    assert not any(path.startswith(obj.path+'\\') for path in api.paths.values())


def test_shared_object_replacement_detected(inventory):
    api=Fake(inventory)
    obj=next(o for o in inventory['envelope'].objects if o.role=='database')
    api.changed.add(obj.path)
    report=run(inventory,api)
    assert report.status=='INDETERMINATE'
    assert any(f.object_id==obj.object_id and f.reason_code=='OBJECT_CHANGED' for f in report.findings)


def test_cleanup_error_prevents_report(inventory):
    api=Fake(inventory)
    api.fail_close=1
    with pytest.raises(DeploymentInspectionError,match='cleanup'):run(inventory,api)
    assert sorted(api.opened)==sorted(api.closed)


def test_bad_anchor_before_opens(inventory):
    api=Fake(inventory)
    inventory['external_anchor']=inventory['external_anchor'].model_copy(update={'envelope_hash':'f'*64})
    with pytest.raises(ValueError):run(inventory,api)
    assert not api.opened


def test_timeout_closes_handles(inventory):
    api=Fake(inventory)
    ticks=iter((0,0,0,0,11))
    with pytest.raises(DeploymentInspectionError):run(inventory,api,lambda:next(ticks,11))
    assert sorted(api.opened)==sorted(api.closed)


native=pytest.mark.skipif(sys.platform!='win32',reason='Windows native inspection')


def open_dirs(api,path):
    handles=[]
    try:
        handles.append(api.open_root(path.anchor))
        for part in path.parts[1:]:handles.append(api.open_child(handles[-1],part,True))
        return handles
    except BaseException:
        for handle in reversed(handles):api.close(handle)
        raise


@native
def test_native_guid_serial_and_live_sqlite(tmp_path):
    api=_InspectionAPI()
    handles=open_dirs(api,tmp_path)
    path=tmp_path/'state.db'
    try:
        guid,filesystem=api.volume(handles[0])
        assert guid.startswith('\\\\?\\Volume{') and filesystem=='NTFS'
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE example (value INTEGER)')
            db.commit()
            opened=[]
            try:
                for name in ('state.db','state.db-wal','state.db-shm'):
                    opened.append(api.open_child(handles[-1],name,False,False))
                    assert api.facts(opened[-1]).volume==api.facts(handles[0]).volume
                db.execute('INSERT INTO example VALUES (1)')
                db.commit()
                assert db.execute('SELECT value FROM example').fetchall()==[(1,)]
            finally:
                for handle in reversed(opened):api.close(handle)
    finally:
        for handle in reversed(handles):api.close(handle)


@native
@pytest.mark.parametrize('directory,content,share',[(False,False,7),(False,True,1),(True,False,3)])
def test_metadata_access_flags(directory,content,share):
    api=object.__new__(_InspectionAPI)
    def create(result,access,attrs,status,allocation,attributes,sharing,disposition,options,ea,length):
        assert access==0x120080|(1 if content else 0)
        assert sharing==share and disposition==1 and options==0x200020
        assert c.cast(attrs,c.POINTER(_Attributes)).contents.root==123
        c.cast(result,c.POINTER(w.HANDLE)).contents.value=456
        return 0
    api.nt=SimpleNamespace(NtCreateFile=create)
    assert api.open_child(123,'entry',directory,content)==456


@native
@pytest.mark.parametrize('status,missing',[(0xc0000034,True),(0xc000003a,True),(0xc0000022,False),(0xc0000043,False)])
def test_precise_native_missing_status(status,missing):
    api=object.__new__(_InspectionAPI)
    api.nt=SimpleNamespace(NtCreateFile=lambda *args:c.c_long(status).value)
    with pytest.raises(_Missing if missing else ProtectedFileError) as error:api.open_child(123,'entry',False)
    assert isinstance(error.value,_Missing)==missing


@native
def test_native_full_inventory_reads_no_key_or_database_contents(tmp_path,inventory,monkeypatch):
    (tmp_path/'config').mkdir()
    (tmp_path/'state').mkdir()
    path=tmp_path/'state'/'store.db'
    descriptor=inventory['descriptor'].model_copy(update={'configuration_root':str(tmp_path/'config'),
        'database_path':str(path)})
    public={'app.py':b'public code','host.json':canonical_bytes(descriptor),
        'anchor.json':canonical_bytes(descriptor.bootstrap_anchor)}
    for name,body in public.items():(tmp_path/name).write_bytes(body)
    secret=b'TEST PRIVATE KEY SENTINEL - never read by adapter'
    (tmp_path/'server.key').write_bytes(secret)
    api=_InspectionAPI()
    root=api.open_root(tmp_path.anchor)
    try:
        guid,fs=api.volume(root)
        serial=api.facts(root).volume
    finally:api.close(root)
    objects=[]
    for obj in inventory['envelope'].objects:
        if obj.role=='ancestor':continue
        relative=ntpath.relpath(obj.path,r'C:\TNC')
        target=tmp_path/relative
        digest=sha256(public[target.name]).hexdigest() if target.name in public else None
        objects.append(obj.model_copy(update={'path':str(target),'content_hash':digest}))
    for index,parent in enumerate((*reversed(tmp_path.parents),tmp_path)):
        objects.append(ObjectExpectation(object_id=f'ancestor{index:02}',path=str(parent),role='ancestor',kind='directory',
            volume_id='volume',allowed_owners=(MAINT,),allowed_writers=(MAINT,),protected_dacl=False))
    now=datetime.now(timezone.utc)
    envelope=inventory['envelope'].model_copy(update={'descriptor_hash':record_digest(descriptor),
        'valid_from':now-timedelta(minutes=1),'valid_until':now+timedelta(minutes=2),
        'objects':tuple(sorted(objects,key=lambda o:o.object_id)),
        'volumes':(VolumeExpectation(volume_id='volume',root=tmp_path.anchor,guid=guid,serial=serial),)})
    anchor=inventory['external_anchor'].model_copy(update={'envelope_hash':record_digest(envelope),
        'valid_from':envelope.valid_from,'valid_until':envelope.valid_until})
    read_roles=[]
    role_by_handle={}
    original_open=api.open_child
    original_read=api.read
    def opening(parent,name,directory,content=False):
        handle=original_open(parent,name,directory,content)
        role_by_handle[handle]=name
        if name in ('server.key','store.db','store.db-wal','store.db-shm'):assert not content
        return handle
    def reading(handle,size):
        name=role_by_handle[handle]
        assert name in public
        read_roles.append(name)
        return original_read(handle,size)
    api.open_child,api.read=opening,reading
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE sample (n INTEGER)')
        db.commit()
        def no_sql(*args,**kwargs):raise AssertionError('Adapter opened SQLite')
        monkeypatch.setattr(sqlite3,'connect',no_sql)
        report=_inspect(envelope,anchor,descriptor,api,lambda:datetime.now(timezone.utc),__import__('time').monotonic)
        # Actual temp-directory ACLs are audited, not trusted or repaired to force a pass.
        assert report.status=='VIOLATIONS'
        assert 'VOLUME_MISMATCH' not in {f.reason_code for f in report.findings}
        assert 'INSPECTION_UNAVAILABLE' not in {f.reason_code for f in report.findings}
        assert set(read_roles)==set(public)
        assert 'TEST PRIVATE KEY' not in canonical_bytes(report).decode()
        db.execute('INSERT INTO sample VALUES (1)')
        db.commit()
    assert (tmp_path/'server.key').read_bytes()==secret
    assert all((tmp_path/name).read_bytes()==body for name,body in public.items())


def test_second_open_replacement_is_detected(inventory):
    class Replaced(Fake):
        def facts(self,handle):
            value=super().facts(handle)
            path=self.paths[handle]
            if path.endswith('store.db') and sum(p==path for p in self.paths.values())>1:
                return replace(value,file_id=999)
            return value
    report=run(inventory,Replaced(inventory))
    assert any(f.object_id=='database' and f.reason_code=='OBJECT_CHANGED' for f in report.findings)


def test_malformed_security_is_incomplete(inventory):
    class BadACL(Fake):
        def facts(self,handle):
            value=super().facts(handle)
            return replace(value,security=b'bad') if self.paths[handle].endswith('server.key') else value
    report=run(inventory,BadACL(inventory))
    assert report.status=='INDETERMINATE'


@pytest.mark.parametrize('kind',['read','facts','volume'])
def test_native_failure_closes_all_retained_handles(inventory,kind):
    api=Fake(inventory)
    def fail(*args):raise ProtectedFileError('unavailable')
    setattr(api,kind,fail)
    report=run(inventory,api)
    assert report.status=='INDETERMINATE'
    assert sorted(api.closed)==sorted(api.opened)


def test_oversize_content_stops_without_read(inventory):
    class Oversize(Fake):
        def facts(self,handle):
            value=super().facts(handle)
            return replace(value,size=4*1024*1024+1) if self.paths[handle].endswith('app.py') else value
    api=Oversize(inventory)
    with pytest.raises(DeploymentInspectionError):run(inventory,api)
    assert 'code' not in api.reads
    assert sorted(api.closed)==sorted(api.opened)
