"""Host-only read-only audit orchestration; never an execution authorization."""
from datetime import datetime, timezone
import math
import ntpath
import time
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.installation_models import (
    LocalPath, RECORD_LIMIT, InstallationEnvelope, ExternalInstallationAnchor, DeploymentPreflightReport,
)
from tnc.provenance.provisioning_models import HostProvisioningDescriptor
from tnc.provenance.deployment_validation import validate_installation_records
from tnc.provenance.windows_deployment_inspection import _InspectionAPI, _inspect


class PreflightAuditRequest(Model):
    envelope_path: LocalPath
    external_anchor_path: LocalPath
    descriptor_path: LocalPath
    target_phase: Literal['BEFORE_BOOTSTRAP', 'AFTER_HANDOFF']
    inspection_timeout_seconds: int = Field(default=10, strict=True, ge=1, le=10)

    @model_validator(mode='after')
    def distinct_paths(self):
        if len({ntpath.normcase(p) for p in (self.envelope_path, self.external_anchor_path, self.descriptor_path)}) != 3:
            raise ValueError('Distinct input paths required')
        return self


class PreflightAuditResult(Model):
    status: Literal['CONFORMS', 'VIOLATIONS', 'INDETERMINATE']
    report: DeploymentPreflightReport | None = None
    reason_codes: tuple[Literal['INVALID_REQUEST', 'INPUT_UNAVAILABLE', 'INPUT_INVALID',
        'ANCHOR_MISMATCH', 'PHASE_MISMATCH', 'BINDING_INVALID', 'INSPECTION_UNAVAILABLE',
        'BUDGET_EXCEEDED', 'CLOCK_INVALID', 'TRUSTED_CONFIGURATION_UNAVAILABLE',
        'TRUSTED_CONFIGURATION_INVALID', 'TRUSTED_CONFIGURATION_EXPIRED', 'ROLLBACK_DETECTED'], ...] = Field(max_length=1)
    inspected_object_count: int = Field(strict=True, ge=0, le=128)
    execution_time_ms: int = Field(strict=True, ge=0)

    @model_validator(mode='after')
    def consistent(self):
        if self.report is None:
            if self.status != 'INDETERMINATE' or not self.reason_codes or self.inspected_object_count:
                raise ValueError('Incomplete audit must be indeterminate')
        elif (self.reason_codes or self.status != self.report.status
              or self.inspected_object_count != len(self.report.inspected_object_ids)):
            raise ValueError('Inconsistent report summary')
        return self


class _Deadline(Exception):
    pass


class _ClockError(Exception):
    pass


def _load_inputs(request, api, check):
    """Read bounded bytes through pinned ancestors; authenticity comes from host anchor."""
    handles, checks, result = [], [], []
    try:
        for path in (request.envelope_path, request.external_anchor_path, request.descriptor_path):
            parent = None
            for index, component in enumerate((path[:3], *path[3:].split('\\'))):
                check()
                if len(handles) >= 128:
                    raise ValueError('Handle limit')
                final = index == len(path[3:].split('\\'))
                handle = api.open_root(component) if index == 0 else api.open_child(parent, component, not final, final)
                handles.append(handle)
                facts = api.facts(handle)
                if facts.attributes & 0x400 or facts.directory == final or (final and facts.links != 1):
                    raise ValueError('Unsafe input object')
                checks.append((handle, facts))
                if final:
                    if not 0 < facts.size <= RECORD_LIMIT:
                        raise ValueError('Input size limit')
                    data = api.read(handle, facts.size)
                    if type(data) is not bytes or len(data) != facts.size:
                        raise ValueError('Incomplete input')
                    result.append(data)
                parent = handle
        for handle, before in checks:
            check()
            if api.facts(handle) != before:
                raise ValueError('Input changed')
        return tuple(result)
    finally:
        failed = False
        for handle in reversed(handles):
            try:
                api.close(handle)
            except Exception:
                failed = True
        if failed:
            raise ValueError('Input cleanup failed')


def _run(request, trusted_anchor, api_factory, inspector, utcnow, monotonic, *, input_loader=_load_inputs):
    stage = 'INVALID_REQUEST'
    start = last = None
    elapsed = 0
    def check():
        nonlocal start, last, elapsed
        tick = monotonic()
        if type(tick) not in (int, float) or not math.isfinite(tick) or last is not None and tick < last:
            raise _ClockError()
        if start is None:
            start = tick
        last = tick
        elapsed = int((tick - start) * 1000)
        if tick - start > request.inspection_timeout_seconds:
            raise _Deadline()
    try:
        if type(request) is not PreflightAuditRequest or type(trusted_anchor) is not ExternalInstallationAnchor:
            raise ValueError()
        request = decode_canonical(PreflightAuditRequest, canonical_bytes(request))
        trusted_anchor = decode_canonical(ExternalInstallationAnchor, canonical_bytes(trusted_anchor))
        check()
        stage = 'INPUT_UNAVAILABLE'
        blobs = input_loader(request, api_factory(), check)
        check()
        stage = 'INPUT_INVALID'
        envelope, anchor, descriptor = tuple(decode_canonical(kind, data) for kind, data in zip(
            (InstallationEnvelope, ExternalInstallationAnchor, HostProvisioningDescriptor), blobs))
        stage = 'ANCHOR_MISMATCH'
        if canonical_bytes(anchor) != canonical_bytes(trusted_anchor):
            raise ValueError()
        stage = 'PHASE_MISMATCH'
        if envelope.phase != request.target_phase:
            raise ValueError()
        stage = 'BINDING_INVALID'
        validate_installation_records(envelope, trusted_anchor, descriptor, now=utcnow())
        expected = next(o.path for o in envelope.objects if o.role == 'descriptor')
        if ntpath.normcase(expected) != ntpath.normcase(request.descriptor_path):
            raise ValueError()
        check()
        stage = 'INSPECTION_UNAVAILABLE'
        def inspection_clock():
            check()
            return last
        report = inspector(envelope, trusted_anchor, descriptor, api_factory(), utcnow, inspection_clock,
                           timeout_seconds=max(0, request.inspection_timeout_seconds - (last - start)))
        check()
        report = decode_canonical(DeploymentPreflightReport, canonical_bytes(report))
        if (report.envelope_hash, report.deployment_id, report.generation, report.phase) != (
                record_digest(envelope), envelope.deployment_id, envelope.generation, envelope.phase):
            raise ValueError()
        return PreflightAuditResult(status=report.status, report=report, reason_codes=(),
            inspected_object_count=len(report.inspected_object_ids), execution_time_ms=elapsed)
    except _Deadline:
        stage = 'BUDGET_EXCEEDED'
    except _ClockError:
        stage = 'CLOCK_INVALID'
    except Exception:
        pass
    return PreflightAuditResult(status='INDETERMINATE', reason_codes=(stage,),
                               inspected_object_count=0, execution_time_ms=elapsed)


def run_host_preflight(request, *, trusted_anchor):
    """The independent anchor is supplied by trusted host code, never by a client file."""
    return _run(request, trusted_anchor, _InspectionAPI, _inspect,
                lambda: datetime.now(timezone.utc), time.monotonic)
