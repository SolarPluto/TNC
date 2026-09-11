"""Bounded native deployment observations. No SQLite connection or host mutation."""
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime, timezone
from hashlib import sha256
import math
import ntpath
import re
import struct
import time

from tnc.provenance.windows_protected_files import (
    _WindowsFileAPI,_Unicode,_Attributes,_IoStatus,ProtectedFileError,parse_security,
)
from tnc.provenance.installation_models import (
    InstallationEnvelope,ExternalInstallationAnchor,ObjectObservation,AclObservation,AceRecord,
)
from tnc.provenance.provisioning_models import HostProvisioningDescriptor
from tnc.provenance.authorization_models import canonical_bytes,decode_canonical
from tnc.provenance.deployment_validation import validate_installation_records,evaluate_deployment_observations


class DeploymentInspectionError(Exception):
    """No complete, trustworthy report could be constructed."""


class _Missing(ProtectedFileError):
    pass


class _InspectionAPI(_WindowsFileAPI):
    def open_root(self,drive):
        if not re.fullmatch(r'[A-Z]:\\',drive):raise ProtectedFileError('Invalid drive')
        handle=self.kernel.CreateFileW(drive,0x120080,3,None,3,0x02200000,None)
        if handle in (None,c.c_void_p(-1).value):
            if c.get_last_error() in (2,3):raise _Missing('Missing root')
            raise ProtectedFileError('Root unavailable')
        return handle

    def volume(self,handle):
        path,fs=c.create_unicode_buffer(128),c.create_unicode_buffer(32)
        length=self.kernel.GetFinalPathNameByHandleW(handle,path,128,1)
        if not 0<length<128 or not re.fullmatch(r'\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\',path.value):
            raise ProtectedFileError('Local volume root required')
        if not self.kernel.GetVolumeInformationByHandleW(handle,None,0,None,None,None,fs,32):
            raise ProtectedFileError('Volume unavailable')
        # Preserve the Volume prefix while canonicalizing GUID hexadecimal digits.
        return '\\\\?\\Volume{'+path.value.split('{',1)[1].lower(),fs.value

    def open_child(self,parent,name,directory,content=False):
        if not name or len(name)>255 or name in ('.','..') or any(x in name for x in '\\/:\x00'):
            raise ProtectedFileError('Single component required')
        buffer=c.create_unicode_buffer(name)
        length=len(name.encode('utf-16-le'))
        string=_Unicode(length,length+2,c.cast(buffer,c.c_void_p))
        attrs=_Attributes(c.sizeof(_Attributes),parent,c.pointer(string),0x40,None,None)
        handle,status=w.HANDLE(),_IoStatus()
        # Directory ancestors cannot be renamed. Live files permit normal SQLite
        # read/write/delete sharing. Hash reads retain write-denying sharing.
        share=1 if content else 3 if directory else 7
        code=self.nt.NtCreateFile(c.byref(handle),0x120080|(1 if content else 0),c.byref(attrs),
            c.byref(status),None,0,share,1,0x200020,None,0)
        if code<0 or not handle.value:
            if (code & 0xffffffff) in (0xc0000034,0xc000003a):raise _Missing('Missing object')
            raise ProtectedFileError('Object unavailable')
        return handle.value


def _acl(data):
    owner,entries=parse_security(data)
    control=struct.unpack_from('<H',data,2)[0]
    return AclObservation(owner=owner,present=True,null=False,protected=bool(control&0x1000),
        aces=tuple(AceRecord(kind=k,flags=f,mask=m,sid=s) for k,f,m,s in entries))


def _inspect(envelope,anchor,descriptor,api,utcnow,monotonic,*,timeout_seconds=10):
    # Freeze inputs before any native operation. These are host inputs, not a
    # signature verification or a trust anchor discovered from inspected files.
    for value,kind in ((envelope,InstallationEnvelope),(anchor,ExternalInstallationAnchor),(descriptor,HostProvisioningDescriptor)):
        if type(value) is not kind:raise DeploymentInspectionError('Typed host records required')
    envelope=decode_canonical(InstallationEnvelope,canonical_bytes(envelope))
    anchor=decode_canonical(ExternalInstallationAnchor,canonical_bytes(anchor))
    descriptor=decode_canonical(HostProvisioningDescriptor,canonical_bytes(descriptor))
    last_utc,last_mono=None,None
    def clocks():
        nonlocal last_utc,last_mono
        at,tick=utcnow(),monotonic()
        if (not isinstance(at,datetime) or at.utcoffset() is None or type(tick) not in (int,float)
                or not math.isfinite(tick) or last_utc is not None and at<last_utc
                or last_mono is not None and tick<last_mono):
            raise DeploymentInspectionError('Invalid inspection clock')
        last_utc,last_mono=at,tick
        return at,tick
    started,start_tick=clocks()
    validate_installation_records(envelope,anchor,descriptor,now=started)
    handles,parents,volume_data,observations,checks=[],{},{},{},[]
    content_total=0
    cleanup_failed=False
    def budget():
        _,tick=clocks()
        if tick-start_tick>timeout_seconds or len(handles)>128:raise DeploymentInspectionError('Inspection budget exceeded')
    def hold(handle):
        handles.append(handle)
        budget()
        return handle
    def unavailable(obj,at):
        return ObjectObservation(object_id=obj.object_id,state='UNREADABLE',started_at=at,finished_at=clocks()[0])
    try:
        for obj in sorted(envelope.objects,key=lambda o:(o.path.count('\\'),o.path.lower())):
            budget()
            at=clocks()[0]
            parent=None
            try:
                is_root=obj.path==obj.path[:3]
                content=obj.content_hash is not None and obj.role not in ('private_key','database','wal','shm')
                if is_root:
                    handle=hold(api.open_root(obj.path))
                    volume_data[obj.path]=api.volume(handle)
                else:
                    parent=parents.get(ntpath.normcase(ntpath.dirname(obj.path)))
                    if parent is None:raise ProtectedFileError('Parent not inspectable')
                    handle=hold(api.open_child(parent,ntpath.basename(obj.path),obj.kind=='directory',content))
                facts=api.facts(handle)
                guid,filesystem=volume_data[obj.path[:3]]
                acl=_acl(facts.security)
                digest=None
                if content and not facts.directory and not facts.attributes&0x400:
                    content_total+=facts.size
                    if not 0<=facts.size<=4*1024*1024 or content_total>16*1024*1024:
                        raise DeploymentInspectionError('Content budget exceeded')
                    data=api.read(handle,facts.size)
                    if type(data) is not bytes or len(data)!=facts.size:raise ProtectedFileError('Incomplete content')
                    digest=sha256(data).hexdigest()
                observation=ObjectObservation(object_id=obj.object_id,state='PRESENT',started_at=at,finished_at=clocks()[0],
                    kind='directory' if facts.directory else 'file',volume_guid=guid,volume_serial=facts.volume,
                    filesystem=filesystem,file_id=str(facts.file_id),links=facts.links,reparse=bool(facts.attributes&0x400),
                    acl=acl,content_hash=digest)
                observations[obj.object_id]=observation
                checks.append((obj,handle,facts,parent,content))
                if facts.directory and not facts.attributes&0x400:
                    parents[ntpath.normcase(obj.path)]=handle
            except _Missing:
                observations[obj.object_id]=ObjectObservation(object_id=obj.object_id,state='ABSENT',started_at=at,finished_at=clocks()[0])
            except (ProtectedFileError,ValueError):
                observations[obj.object_id]=unavailable(obj,at)
        # Compare retained handles and independently re-open shared metadata file
        # names to detect replacement. This is detection, not a permanent path lock.
        for obj,handle,before,parent,content in checks:
            budget()
            observation=observations[obj.object_id]
            try:
                changed=api.facts(handle)!=before
                if parent is not None and not before.directory and not content:
                    probe=None
                    try:
                        probe=api.open_child(parent,ntpath.basename(obj.path),False,False)
                        changed |= api.facts(probe)!=before
                    except ProtectedFileError:
                        changed=True
                    finally:
                        if probe is not None:
                            try:api.close(probe)
                            except Exception:cleanup_failed=True
                observations[obj.object_id]=observation.model_copy(update={'changed':changed,'finished_at':clocks()[0]})
            except (ProtectedFileError,ValueError):
                observations[obj.object_id]=unavailable(obj,observation.started_at)
    finally:
        for handle in reversed(handles):
            try:api.close(handle)
            except Exception:cleanup_failed=True
        if cleanup_failed:raise DeploymentInspectionError('Inspection cleanup failed')
    finished,_=clocks()
    budget()
    return evaluate_deployment_observations(envelope,anchor,descriptor,tuple(observations.values()),
        started_at=started,finished_at=finished)


def inspect_windows_deployment(envelope,external_anchor,descriptor):
    """Host-only audit result, never a provisioning or startup authorization."""
    try:
        return _inspect(envelope,external_anchor,descriptor,_InspectionAPI(),
            lambda:datetime.now(timezone.utc),time.monotonic)
    except Exception:
        raise DeploymentInspectionError('Deployment inspection unavailable') from None
