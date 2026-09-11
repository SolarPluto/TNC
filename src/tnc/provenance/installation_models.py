"""Pure deployment inventory contracts. Records are not authenticated evidence."""
from datetime import datetime
import ntpath
import re
from typing import Annotated, Literal

from pydantic import Field, AfterValidator, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier
from tnc.provenance.provisioning_models import Sid, Interval

RECORD_LIMIT = 256 * 1024
UInt32 = Annotated[int, Field(strict=True, ge=0, le=0xffffffff)]
Sids = Annotated[tuple[Sid, ...], Field(max_length=64)]


def _path(value):
    if not re.fullmatch(r'[A-Z]:\\[^<>:"/|?*\x00-\x1f]*', value):
        raise ValueError('Absolute local Windows path required')
    if value != value[:3]:
        for part in value[3:].split('\\'):
            if (not part or len(part)>255 or part in ('.','..') or part.endswith((' ','.'))
                    or re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?',part)):
                raise ValueError('Unsafe path component')
    if len(value)>4096 or len(value.split('\\'))>49:
        raise ValueError('Path budget exceeded')
    return value


LocalPath = Annotated[str, AfterValidator(_path)]
VolumeGuid = Annotated[str, Field(pattern=r'^\\\\\?\\Volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\$')]


class VolumeExpectation(Model):
    volume_id: Identifier
    root: LocalPath
    guid: VolumeGuid
    serial: UInt32
    filesystem: Literal['NTFS'] = 'NTFS'

    @model_validator(mode='after')
    def root_only(self):
        if len(self.root)!=3: raise ValueError('Volume root required')
        return self


class AceRecord(Model):
    kind: int = Field(strict=True,ge=0,le=255)
    flags: int = Field(strict=True,ge=0,le=255)
    mask: UInt32
    sid: Sid | None = None

    @model_validator(mode='after')
    def ordinary_sid(self):
        if self.kind in (0,1) and self.sid is None: raise ValueError('Ordinary ACE SID required')
        return self


class AclObservation(Model):
    owner: Sid
    present: bool = Field(strict=True)
    null: bool = Field(strict=True)
    protected: bool = Field(strict=True)
    aces: tuple[AceRecord,...] = Field(max_length=1024)

    @model_validator(mode='after')
    def consistent(self):
        if (not self.present or self.null) and self.aces: raise ValueError('Contradictory ACL')
        return self


class ObjectExpectation(Model):
    object_id: Identifier
    path: LocalPath
    role: Literal['ancestor','code','descriptor','anchor','configuration','state','database','wal','shm','private_key','log']
    kind: Literal['file','directory']
    volume_id: Identifier
    allowed_owners: Sids
    allowed_writers: Sids
    allowed_readers: Sids | None = None
    protected_dacl: bool = Field(strict=True)
    acl_template_hash: Digest | None = None
    content_hash: Digest | None = None
    required: bool = Field(default=True,strict=True)

    @model_validator(mode='after')
    def role_rules(self):
        for sids in (self.allowed_owners,self.allowed_writers,self.allowed_readers):
            if sids is not None and tuple(sorted(set(sids)))!=sids: raise ValueError('Sorted unique SIDs required')
        if not self.allowed_owners: raise ValueError('Owner expectation required')
        directories={'ancestor','configuration','state'}
        if (self.role in directories)!=(self.kind=='directory'): raise ValueError('Role/type mismatch')
        if not self.required and self.role not in ('wal','shm'): raise ValueError('Only sidecars may be absent')
        if self.role in ('configuration','state') and (not self.protected_dacl or self.acl_template_hash is None):
            raise ValueError('Protected directory template required')
        if self.role in ('database','wal','shm','private_key') and self.content_hash is not None:
            raise ValueError('Metadata-only role')
        if self.role=='private_key' and self.allowed_readers is None: raise ValueError('Key readers must be restricted')
        if self.role in ('code','descriptor','anchor') and self.content_hash is None:
            raise ValueError('Immutable content binding required')
        return self


class InstallationEnvelope(Interval):
    codec_version: Literal[1] = 1
    deployment_id: Identifier
    generation: int = Field(strict=True,gt=0)
    descriptor_hash: Digest
    phase: Literal['BEFORE_BOOTSTRAP','AFTER_HANDOFF']
    operator_sid: Sid
    service_sid: Sid
    maintenance_sids: Sids
    volumes: tuple[VolumeExpectation,...] = Field(min_length=1,max_length=32)
    objects: tuple[ObjectExpectation,...] = Field(min_length=1,max_length=128)

    @model_validator(mode='after')
    def inventory(self):
        if not self.maintenance_sids or tuple(sorted(set(self.maintenance_sids)))!=self.maintenance_sids:
            raise ValueError('Sorted maintenance SIDs required')
        if self.operator_sid==self.service_sid or {self.operator_sid,self.service_sid}&set(self.maintenance_sids):
            raise ValueError('Separate maintenance, operator and service identities required')
        for values in (tuple(v.volume_id for v in self.volumes),tuple(o.object_id for o in self.objects)):
            if values!=tuple(sorted(set(values))): raise ValueError('Sorted unique inventory required')
        volumes={v.volume_id:v for v in self.volumes}
        if len({v.root for v in self.volumes})!=len(volumes) or len({v.guid for v in self.volumes})!=len(volumes):
            raise ValueError('Duplicate volume binding')
        paths={ntpath.normcase(o.path):o for o in self.objects}
        if len(paths)!=len(self.objects): raise ValueError('Path alias')
        roles={role:[o for o in self.objects if o.role==role] for role in ('code','descriptor','anchor','configuration','state','database','wal','shm')}
        if not roles['code'] or any(len(roles[r])!=1 for r in roles if r!='code'):
            raise ValueError('Complete deployment inventory required')
        state,config,db=(roles[r][0] for r in ('state','configuration','database'))
        if (ntpath.normcase(state.path).startswith(ntpath.normcase(config.path)+'\\')
                or ntpath.normcase(config.path).startswith(ntpath.normcase(state.path)+'\\')):
            raise ValueError('Configuration/state overlap')
        if ntpath.normcase(ntpath.dirname(db.path))!=ntpath.normcase(state.path): raise ValueError('Database outside state directory')
        for suffix in ('wal','shm'):
            if ntpath.normcase(roles[suffix][0].path)!=ntpath.normcase(db.path+'-'+suffix): raise ValueError('Invalid sidecar path')
        for obj in self.objects:
            if obj.path.lower().startswith(state.path.lower()+'\\') and obj.role not in ('database','wal','shm','log'):
                raise ValueError('Immutable object inside writable state directory')
            if obj.volume_id not in volumes or obj.path[:3]!=volumes[obj.volume_id].root: raise ValueError('Volume reference mismatch')
            if not set(obj.allowed_owners)<=set(self.maintenance_sids): raise ValueError('Maintenance-owned objects required')
            writers=set(self.maintenance_sids)
            if obj.role in ('state','database','wal','shm','log'): writers.add(self.service_sid)
            if self.phase=='BEFORE_BOOTSTRAP' and obj.role in ('state','database','wal','shm'): writers.add(self.operator_sid)
            if not set(obj.allowed_writers)<=writers: raise ValueError('Writer policy contradicts phase/role')
            if obj.role=='private_key' and not set(obj.allowed_readers)<=set(self.maintenance_sids)|{self.service_sid}:
                raise ValueError('Unauthorized key reader policy')
            parent=ntpath.dirname(obj.path)
            if obj.path!=obj.path[:3] and (ntpath.normcase(parent) not in paths or paths[ntpath.normcase(parent)].kind!='directory'):
                raise ValueError('Missing ancestor expectation')
        if {o.volume_id for o in self.objects}!=set(volumes): raise ValueError('Unused volume')
        return self


class ExternalInstallationAnchor(Interval):
    deployment_id: Identifier
    envelope_hash: Digest
    minimum_generation: int = Field(strict=True,gt=0)


class ObjectObservation(Model):
    object_id: Identifier
    state: Literal['PRESENT','ABSENT','UNREADABLE']
    started_at: datetime
    finished_at: datetime
    kind: Literal['file','directory'] | None = None
    volume_guid: VolumeGuid | None = None
    volume_serial: UInt32 | None = None
    filesystem: str | None = Field(default=None,max_length=32)
    file_id: Identifier | None = None
    links: int | None = Field(default=None,strict=True,ge=0)
    reparse: bool | None = Field(default=None,strict=True)
    acl: AclObservation | None = None
    content_hash: Digest | None = None
    changed: bool = Field(default=False,strict=True)

    @model_validator(mode='after')
    def shape(self):
        if self.started_at>self.finished_at: raise ValueError('Reversed observation interval')
        facts=(self.kind,self.volume_guid,self.volume_serial,self.filesystem,self.file_id,self.links,self.reparse,self.acl)
        if self.state=='PRESENT' and any(v is None for v in facts): raise ValueError('Present object facts incomplete')
        if self.state!='PRESENT' and (any(v is not None for v in facts) or self.content_hash is not None or self.changed):
            raise ValueError('Nonpresent object has facts')
        return self


class PreflightFinding(Model):
    object_id: Identifier
    reason_code: Literal['MISSING_OBSERVATION','EXTRA_OBSERVATION','DUPLICATE_OBSERVATION',
        'INSPECTION_UNAVAILABLE','REQUIRED_OBJECT_MISSING','VOLUME_MISMATCH','FILESYSTEM_MISMATCH',
        'OWNER_DENIED','WRITE_GRANT_DENIED','READ_GRANT_DENIED','ACL_UNSUPPORTED','ACL_TEMPLATE_MISMATCH',
        'INHERITANCE_MISMATCH','REPARSE_POINT','HARDLINK_COUNT','CONTENT_DIGEST_MISMATCH',
        'CONTENT_OBSERVATION_FORBIDDEN','OBJECT_CHANGED','TYPE_MISMATCH','OBSERVATION_TIME_INVALID','BUDGET_EXCEEDED']


class DeploymentPreflightReport(Model):
    codec_version: Literal[1] = 1
    rule_version: Literal['deployment-metadata-v1'] = 'deployment-metadata-v1'
    envelope_hash: Digest
    deployment_id: Identifier
    generation: int = Field(strict=True,gt=0)
    phase: Literal['BEFORE_BOOTSTRAP','AFTER_HANDOFF']
    started_at: datetime
    finished_at: datetime
    status: Literal['CONFORMS','VIOLATIONS','INDETERMINATE']
    findings: tuple[PreflightFinding,...] = Field(max_length=256)
    inspected_object_ids: tuple[Identifier,...] = Field(max_length=128)

    @model_validator(mode='after')
    def consistency(self):
        if self.started_at>self.finished_at: raise ValueError('Reversed report interval')
        keys=tuple((f.object_id,f.reason_code) for f in self.findings)
        if keys!=tuple(sorted(set(keys))): raise ValueError('Sorted unique findings required')
        if self.inspected_object_ids!=tuple(sorted(set(self.inspected_object_ids))): raise ValueError('Sorted inspected IDs required')
        if (self.status=='CONFORMS')!= (not self.findings): raise ValueError('Contradictory report')
        unknown={'MISSING_OBSERVATION','EXTRA_OBSERVATION','DUPLICATE_OBSERVATION','INSPECTION_UNAVAILABLE',
                 'ACL_UNSUPPORTED','OBJECT_CHANGED','OBSERVATION_TIME_INVALID','BUDGET_EXCEEDED'}
        if (self.status=='INDETERMINATE')!=any(f.reason_code in unknown for f in self.findings):
            raise ValueError('Contradictory completeness status')
        return self
