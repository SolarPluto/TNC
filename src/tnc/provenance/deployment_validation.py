"""Pure metadata comparison; no native calls, file reads, SQLite or authorization."""
import ntpath
from datetime import datetime

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical, record_digest
from tnc.provenance.provisioning_models import HostProvisioningDescriptor
from tnc.provenance.installation_models import (
    RECORD_LIMIT,InstallationEnvelope,ExternalInstallationAnchor,ObjectObservation,
    DeploymentPreflightReport,PreflightFinding,
)


class InstallationValidationError(ValueError):
    """Invalid records or external bindings produce no usable audit report."""


def decode_installation_record(kind,data):
    if kind not in (InstallationEnvelope,ExternalInstallationAnchor,ObjectObservation,DeploymentPreflightReport):
        raise InstallationValidationError('Unsupported record')
    if type(data) is not bytes or not 0<len(data)<=RECORD_LIMIT:
        raise InstallationValidationError('Record size exceeded')
    return decode_canonical(kind,data)


def _copy(record,kind):
    if type(record) is not kind: raise InstallationValidationError('Exact typed record required')
    data=canonical_bytes(record)
    if len(data)>RECORD_LIMIT: raise InstallationValidationError('Record size exceeded')
    return decode_canonical(kind,data)


def _time(now):
    if not isinstance(now,datetime) or now.utcoffset() is None:
        raise InstallationValidationError('Aware time required')


def validate_installation_records(envelope,external_anchor,descriptor,*,now):
    """Check a host-supplied anchor binding; does not authenticate the anchor."""
    envelope=_copy(envelope,InstallationEnvelope)
    anchor=_copy(external_anchor,ExternalInstallationAnchor)
    descriptor=_copy(descriptor,HostProvisioningDescriptor)
    _time(now)
    if anchor.envelope_hash!=record_digest(envelope) or anchor.deployment_id!=envelope.deployment_id:
        raise InstallationValidationError('ANCHOR_MISMATCH')
    if envelope.generation<anchor.minimum_generation: raise InstallationValidationError('GENERATION_TOO_OLD')
    if not all(v.valid_from<=now<v.valid_until for v in (envelope,anchor)):
        raise InstallationValidationError('VALIDITY_INTERVAL')
    objects={o.role:o for o in envelope.objects}
    if (envelope.descriptor_hash!=record_digest(descriptor) or descriptor.deployment_id!=envelope.deployment_id
            or not set(descriptor.trusted_owner_sids)<=set(envelope.maintenance_sids)
            or not set(descriptor.trusted_writer_sids)<=set(envelope.maintenance_sids)
            or descriptor.service_sid!=envelope.service_sid
            or descriptor.bootstrap_anchor.operator_id!=envelope.operator_sid
            or ntpath.normcase(descriptor.configuration_root)!=ntpath.normcase(objects['configuration'].path)
            or ntpath.normcase(descriptor.database_path)!=ntpath.normcase(objects['database'].path)
            or objects['descriptor'].content_hash!=envelope.descriptor_hash
            or objects['anchor'].content_hash!=record_digest(descriptor.bootstrap_anchor)):
        raise InstallationValidationError('DESCRIPTOR_MISMATCH')


def evaluate_deployment_observations(envelope,external_anchor,descriptor,observations,*,started_at,finished_at):
    validate_installation_records(envelope,external_anchor,descriptor,now=finished_at)
    envelope=_copy(envelope,InstallationEnvelope)
    _time(started_at)
    if started_at>finished_at or started_at<max(envelope.valid_from,external_anchor.valid_from):
        raise InstallationValidationError('Invalid inspection interval')
    if type(observations) is not tuple or len(observations)>128:
        raise InstallationValidationError('Observation budget exceeded')
    observations=tuple(_copy(o,ObjectObservation) for o in observations)
    findings=set()
    incomplete=False
    def add(object_id,reason,unknown=False):
        nonlocal incomplete
        findings.add((object_id,reason))
        incomplete |= unknown
    expected={o.object_id:o for o in envelope.objects}
    groups={}
    for o in observations:groups.setdefault(o.object_id,[]).append(o)
    for object_id in set(groups)-set(expected):add(object_id,'EXTRA_OBSERVATION',True)
    volumes={v.volume_id:v for v in envelope.volumes}
    inspected=[]
    for object_id,obj in expected.items():
        matches=groups.get(object_id,[])
        if not matches:
            add(object_id,'MISSING_OBSERVATION',True)
            continue
        if len(matches)!=1:
            add(object_id,'DUPLICATE_OBSERVATION',True)
            continue
        observation=matches[0]
        if not started_at<=observation.started_at<=observation.finished_at<=finished_at:
            add(object_id,'OBSERVATION_TIME_INVALID',True)
        if observation.state=='UNREADABLE':
            add(object_id,'INSPECTION_UNAVAILABLE',True)
            continue
        inspected.append(object_id)
        if observation.state=='ABSENT':
            if obj.required:add(object_id,'REQUIRED_OBJECT_MISSING')
            continue
        if observation.changed:add(object_id,'OBJECT_CHANGED',True)
        if observation.kind!=obj.kind:add(object_id,'TYPE_MISMATCH')
        volume=volumes[obj.volume_id]
        if (observation.volume_guid,observation.volume_serial)!=(volume.guid,volume.serial):add(object_id,'VOLUME_MISMATCH')
        if observation.filesystem!='NTFS':add(object_id,'FILESYSTEM_MISMATCH')
        if observation.reparse:add(object_id,'REPARSE_POINT')
        if observation.kind=='file' and observation.links!=1:add(object_id,'HARDLINK_COUNT')
        if obj.role in ('database','wal','shm','private_key') and observation.content_hash is not None:
            add(object_id,'CONTENT_OBSERVATION_FORBIDDEN')
        if obj.content_hash is not None:
            if observation.content_hash is None:add(object_id,'INSPECTION_UNAVAILABLE',True)
            elif observation.content_hash!=obj.content_hash:add(object_id,'CONTENT_DIGEST_MISMATCH')
        acl=observation.acl
        if acl.owner not in obj.allowed_owners:add(object_id,'OWNER_DENIED')
        if not acl.present or acl.null:add(object_id,'ACL_UNSUPPORTED',True)
        if acl.protected!=obj.protected_dacl:add(object_id,'INHERITANCE_MISMATCH')
        if obj.acl_template_hash is not None and record_digest(acl)!=obj.acl_template_hash:add(object_id,'ACL_TEMPLATE_MISMATCH')
        for ace in acl.aces:
            if ace.kind not in (0,1) or ace.flags & ~0x1f or ace.mask & ~0xf31f01ff:
                add(object_id,'ACL_UNSUPPORTED',True)
                continue
            # Check inheritable directory grants too: optional future sidecars do
            # not yet have a child ACL that could expose an unsafe inherited grant.
            if ace.kind!=0 or ace.flags & 8 and not (observation.kind=='directory' and ace.flags & 3):continue
            write=ace.mask & (0x52000000|0x000d0156)
            control=ace.mask & (0x12000000|0x000c0000)
            read=ace.mask & (0x92000000|1)
            if write and ace.sid not in obj.allowed_writers or control and ace.sid not in envelope.maintenance_sids:
                add(object_id,'WRITE_GRANT_DENIED')
            if read and obj.allowed_readers is not None and ace.sid not in obj.allowed_readers:
                add(object_id,'READ_GRANT_DENIED')
    ordered=sorted(findings)
    if len(ordered)>256:
        incomplete=True
        ordered=sorted(set(ordered[:255])|{('preflight','BUDGET_EXCEEDED')})
    return DeploymentPreflightReport(envelope_hash=record_digest(envelope),deployment_id=envelope.deployment_id,
        generation=envelope.generation,phase=envelope.phase,started_at=started_at,finished_at=finished_at,
        status='INDETERMINATE' if incomplete else 'VIOLATIONS' if ordered else 'CONFORMS',
        findings=tuple(PreflightFinding(object_id=o,reason_code=r) for o,r in ordered),
        inspected_object_ids=tuple(sorted(inspected)))
