"""Pure synthetic inventory comparison. No native inspection or host mutation."""
from datetime import timedelta
import pytest

from test_provisioning_validation import case, SID, SERVICE, NOW, END
from tnc.provenance.authorization_models import canonical_bytes,record_digest
from tnc.provenance.installation_models import (
    InstallationEnvelope,ExternalInstallationAnchor,ObjectExpectation,ObjectObservation,
    VolumeExpectation,AceRecord,AclObservation,DeploymentPreflightReport,RECORD_LIMIT,
)
from tnc.provenance.deployment_validation import decode_installation_record,validate_installation_records,evaluate_deployment_observations

MAINT='S-1-5-18'
GUID=r'\\?\Volume{11111111-1111-1111-1111-111111111111}'+'\\'


def acl(state=False):
    entries=[AceRecord(kind=0,flags=0,mask=0x1f01ff,sid=MAINT)]
    if state:entries.append(AceRecord(kind=0,flags=3,mask=0x1301bf,sid=SERVICE))
    return AclObservation(owner=MAINT,present=True,null=False,protected=True,aces=tuple(entries))


@pytest.fixture
def inventory(case):
    descriptor=case['descriptor'].model_copy(update={'database_path':r'C:\TNC\state\store.db',
        'trusted_owner_sids':(MAINT,),'trusted_writer_sids':(MAINT,)})
    layout=[('root','C:\\','ancestor'),('base',r'C:\TNC','ancestor'),
        ('configuration',r'C:\TNC\config','configuration'),('state',r'C:\TNC\state','state'),
        ('database',r'C:\TNC\state\store.db','database'),('wal',r'C:\TNC\state\store.db-wal','wal'),
        ('shm',r'C:\TNC\state\store.db-shm','shm'),('code',r'C:\TNC\app.py','code'),
        ('descriptor',r'C:\TNC\host.json','descriptor'),('anchor',r'C:\TNC\anchor.json','anchor'),
        ('key',r'C:\TNC\server.key','private_key')]
    objects,observations=[],[]
    for ident,path,role in sorted(layout):
        mutable=role in ('state','database','wal','shm')
        directory=role in ('ancestor','configuration','state')
        security=acl(mutable)
        content={'code':'a'*64,'descriptor':record_digest(descriptor),
                 'anchor':record_digest(descriptor.bootstrap_anchor)}.get(role)
        obj=ObjectExpectation(object_id=ident,path=path,role=role,kind='directory' if directory else 'file',
            volume_id='volume',allowed_owners=(MAINT,),allowed_writers=tuple(sorted((MAINT,SERVICE))) if mutable else (MAINT,),
            allowed_readers=tuple(sorted((MAINT,SERVICE))) if role=='private_key' else None,
            protected_dacl=True,acl_template_hash=record_digest(security) if role in ('configuration','state') else None,
            content_hash=content,required=role not in ('wal','shm'))
        objects.append(obj)
        observations.append(ObjectObservation(object_id=ident,state='PRESENT',started_at=NOW,finished_at=NOW,
            kind=obj.kind,volume_guid=GUID,volume_serial=123,filesystem='NTFS',file_id=ident,links=1,
            reparse=False,acl=security,content_hash=content))
    envelope=InstallationEnvelope(deployment_id=descriptor.deployment_id,generation=1,
        descriptor_hash=record_digest(descriptor),phase='AFTER_HANDOFF',operator_sid=SID,service_sid=SERVICE,
        maintenance_sids=(MAINT,),valid_from=NOW,valid_until=END,
        volumes=(VolumeExpectation(volume_id='volume',root='C:\\',guid=GUID,serial=123),),objects=tuple(objects))
    anchor=ExternalInstallationAnchor(deployment_id=envelope.deployment_id,envelope_hash=record_digest(envelope),
        minimum_generation=1,valid_from=NOW,valid_until=END)
    return dict(envelope=envelope,external_anchor=anchor,descriptor=descriptor,observations=tuple(observations),
        started_at=NOW,finished_at=NOW)


def change(data,object_id,**changes):
    return data|{'observations':tuple(o.model_copy(update=changes) if o.object_id==object_id else o for o in data['observations'])}


def reasons(report):return {f.reason_code for f in report.findings}


def test_conforms_and_deterministic_roundtrip(inventory):
    report=evaluate_deployment_observations(**inventory)
    assert report.status=='CONFORMS' and not report.findings
    assert report==evaluate_deployment_observations(**(inventory|{'observations':tuple(reversed(inventory['observations']))}))
    assert decode_installation_record(DeploymentPreflightReport,canonical_bytes(report))==report


@pytest.mark.parametrize('mutation',[lambda b:b+b' ',lambda b:b'\xff',lambda b:b'',
    lambda b:b.replace(b'"codec_version":1',b'"codec_version":true'),
    lambda b:b.replace(b'"codec_version":1',b'"codec_version":1,"codec_version":1'),
    lambda b:b.replace(b'.000000Z',b'Z'),lambda b:b[:-1]+b',"other":1}',
    lambda b:b' '*(RECORD_LIMIT+1),lambda b:bytearray(b)])
def test_noncanonical_records(inventory,mutation):
    with pytest.raises(ValueError):decode_installation_record(InstallationEnvelope,mutation(canonical_bytes(inventory['envelope'])))


@pytest.mark.parametrize('field,value',[('envelope_hash','f'*64),('deployment_id','other'),('minimum_generation',2),('valid_until',NOW)])
def test_bad_anchor(inventory,field,value):
    inventory['external_anchor']=inventory['external_anchor'].model_copy(update={field:value})
    with pytest.raises(ValueError):evaluate_deployment_observations(**inventory)


@pytest.mark.parametrize('field,value,reason',[
    ('volume_serial',124,'VOLUME_MISMATCH'),('volume_guid',GUID.replace('11111111','22222222'),'VOLUME_MISMATCH'),
    ('filesystem','FAT32','FILESYSTEM_MISMATCH'),('links',2,'HARDLINK_COUNT'),('reparse',True,'REPARSE_POINT'),
    ('kind','directory','TYPE_MISMATCH'),('changed',True,'OBJECT_CHANGED'),
    ('content_hash','f'*64,'CONTENT_DIGEST_MISMATCH'),('content_hash',None,'INSPECTION_UNAVAILABLE')])
def test_observed_violation(inventory,field,value,reason):
    report=evaluate_deployment_observations(**change(inventory,'code',**{field:value}))
    assert reason in reasons(report) and report.status!='CONFORMS'


@pytest.mark.parametrize('state,ident,status',[('ABSENT','wal','CONFORMS'),('ABSENT','database','VIOLATIONS'),
    ('UNREADABLE','wal','INDETERMINATE')])
def test_absent_vs_unreadable(inventory,state,ident,status):
    replacement=ObjectObservation(object_id=ident,state=state,started_at=NOW,finished_at=NOW)
    inventory['observations']=tuple(replacement if o.object_id==ident else o for o in inventory['observations'])
    assert evaluate_deployment_observations(**inventory).status==status


@pytest.mark.parametrize('kind',['missing','duplicate','extra'])
def test_completeness(inventory,kind):
    obs=inventory['observations']
    if kind=='missing':obs=obs[1:]
    if kind=='duplicate':obs=obs+(obs[0],)
    if kind=='extra':obs=obs+(obs[0].model_copy(update={'object_id':'extra'}),)
    assert evaluate_deployment_observations(**(inventory|{'observations':obs})).status=='INDETERMINATE'


@pytest.mark.parametrize('mask',[2,4,16,64,256,0x10000,0x40000,0x80000,0x40000000,0x10000000])
def test_untrusted_write_grants(inventory,mask):
    security=acl().model_copy(update={'aces':(AceRecord(kind=0,flags=0,mask=mask,sid=SID),)})
    report=evaluate_deployment_observations(**change(inventory,'code',acl=security))
    assert 'WRITE_GRANT_DENIED' in reasons(report)


def test_private_key_and_database_never_accept_content(inventory):
    for ident in ('key','database','wal','shm'):
        assert 'CONTENT_OBSERVATION_FORBIDDEN' in reasons(evaluate_deployment_observations(**change(inventory,ident,content_hash='a'*64)))
    security=acl().model_copy(update={'aces':(AceRecord(kind=0,flags=0,mask=0x80000000,sid=SID),)})
    assert 'READ_GRANT_DENIED' in reasons(evaluate_deployment_observations(**change(inventory,'key',acl=security)))


def test_unknown_acl_plus_definite_violation(inventory):
    security=acl().model_copy(update={'owner':SID,'aces':(AceRecord(kind=5,flags=0,mask=1),)})
    report=evaluate_deployment_observations(**change(inventory,'code',acl=security))
    assert report.status=='INDETERMINATE'
    assert {'OWNER_DENIED','ACL_UNSUPPORTED'}<=reasons(report)


def test_absent_sidecars_still_require_parent_template(inventory):
    bad=change(inventory,'state',acl=acl())
    assert 'ACL_TEMPLATE_MISMATCH' in reasons(evaluate_deployment_observations(**bad))


@pytest.mark.parametrize('kind',['alias','missing_ancestor','missing_role','sidecar','phase','key_hash','state_overlap'])
def test_invalid_inventory(inventory,kind):
    values=inventory['envelope'].model_dump()
    objs=values['objects']
    byrole={o['role']:o for o in objs}
    if kind=='alias':byrole['code']['path']=byrole['descriptor']['path'].lower().replace('c:','C:',1)
    if kind=='missing_ancestor':values['objects']=[o for o in objs if o['object_id']!='base']
    if kind=='missing_role':values['objects']=[o for o in objs if o['role']!='database']
    if kind=='sidecar':byrole['wal']['path']=r'C:\TNC\state\wrong-wal'
    if kind=='phase':byrole['database']['allowed_writers']=tuple(sorted((MAINT,SERVICE,SID)))
    if kind=='key_hash':byrole['private_key']['content_hash']='a'*64
    if kind=='state_overlap':byrole['private_key']['path']=r'C:\TNC\state\server.key'
    with pytest.raises(ValueError):InstallationEnvelope.model_validate(values)


def test_phase_authorization_cannot_be_changed_without_anchor(inventory):
    values=inventory['envelope'].model_dump()
    values['phase']='BEFORE_BOOTSTRAP'
    for o in values['objects']:
        if o['role'] in ('state','database','wal','shm'):o['allowed_writers']=tuple(sorted((MAINT,SERVICE,SID)))
    before=InstallationEnvelope.model_validate(values)
    with pytest.raises(ValueError,match='ANCHOR_MISMATCH'):
        evaluate_deployment_observations(**(inventory|{'envelope':before}))


def test_service_cannot_change_database_acl(inventory):
    security=acl(True).model_copy(update={'aces':(AceRecord(kind=0,flags=0,mask=0x40000,sid=SERVICE),)})
    assert 'WRITE_GRANT_DENIED' in reasons(evaluate_deployment_observations(**change(inventory,'database',acl=security)))


def test_observation_time_bound(inventory):
    report=evaluate_deployment_observations(**change(inventory,'code',started_at=NOW-timedelta(seconds=1)))
    assert report.status=='INDETERMINATE' and 'OBSERVATION_TIME_INVALID' in reasons(report)


def test_future_sidecar_inheritance_does_not_hide_writer(inventory):
    security=acl(True).model_copy(update={'aces':(AceRecord(kind=0,flags=11,mask=2,sid=SID),)})
    assert 'WRITE_GRANT_DENIED' in reasons(evaluate_deployment_observations(**change(inventory,'state',acl=security)))


def test_finding_overflow_is_explicit(inventory):
    source=next(o for o in inventory['envelope'].objects if o.role=='code')
    observed=next(o for o in inventory['observations'] if o.object_id=='code')
    extras=tuple(source.model_copy(update={'object_id':f'code{i:03d}','path':fr'C:\TNC\code{i:03d}.py'}) for i in range(80))
    envelope=inventory['envelope'].model_copy(update={'objects':tuple(sorted((*inventory['envelope'].objects,*extras),key=lambda o:o.object_id))})
    anchor=inventory['external_anchor'].model_copy(update={'envelope_hash':record_digest(envelope)})
    failures=tuple(observed.model_copy(update={'object_id':o.object_id,'links':2,'reparse':True,
        'filesystem':'FAT32','content_hash':'f'*64}) for o in extras)
    report=evaluate_deployment_observations(**(inventory|{'envelope':envelope,'external_anchor':anchor,
        'observations':(*inventory['observations'],*failures)}))
    assert report.status=='INDETERMINATE' and len(report.findings)==256
    assert 'BUDGET_EXCEEDED' in reasons(report)


def test_observation_count_limit(inventory):
    with pytest.raises(ValueError,match='budget'):
        evaluate_deployment_observations(**(inventory|{'observations':(inventory['observations'][0],)*129}))


def test_incomplete_report_cannot_be_relabeled(inventory):
    report=evaluate_deployment_observations(**(inventory|{'observations':()}))
    with pytest.raises(ValueError):decode_installation_record(DeploymentPreflightReport,
        canonical_bytes(report.model_copy(update={'status':'VIOLATIONS'})))


def test_no_file_database_or_native_io(inventory,monkeypatch):
    import builtins,sqlite3,ctypes
    def denied(*args,**kwargs):raise AssertionError('Pure evaluator attempted I/O')
    monkeypatch.setattr(builtins,'open',denied)
    monkeypatch.setattr(sqlite3,'connect',denied)
    if hasattr(ctypes,'WinDLL'):monkeypatch.setattr(ctypes,'WinDLL',denied)
    assert evaluate_deployment_observations(**inventory).status=='CONFORMS'
