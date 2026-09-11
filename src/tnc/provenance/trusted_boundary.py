"""Read-only installer configuration boundary. No checkpoint updates or activation."""
from datetime import datetime, timezone
import math
import ntpath
import struct
import time
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.provisioning_models import Interval, HostProvisioningDescriptor, Sid
from tnc.provenance.installation_models import LocalPath, VolumeExpectation, InstallationEnvelope, ExternalInstallationAnchor
from tnc.provenance.deployment_validation import validate_installation_records
from tnc.provenance.deployment_runner import PreflightAuditRequest, PreflightAuditResult, _load_inputs, _run
from tnc.provenance.windows_deployment_inspection import _InspectionAPI, _inspect
from tnc.provenance.windows_protected_files import parse_security, ProtectedFileError


class TrustedInstallationPolicy(Interval):
    """Installer-supplied locations and ACL policy, not loaded from audit inputs."""
    codec_version: Literal[1] = 1
    deployment_id: Identifier
    installation_root: LocalPath
    request: PreflightAuditRequest
    volume: VolumeExpectation
    installer_sids: tuple[Sid, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode='after')
    def layout(self):
        root = ntpath.normcase(self.installation_root)
        if len(root) == 3 or self.installation_root[:3] != self.volume.root:
            raise ValueError('Dedicated installation directory required')
        if tuple(sorted(set(self.installer_sids))) != self.installer_sids:
            raise ValueError('Sorted unique installer SIDs required')
        for path in (self.request.envelope_path, self.request.external_anchor_path, self.request.descriptor_path):
            if not ntpath.normcase(path).startswith(root + '\\'):
                raise ValueError('Input outside installation root')
        return self


class InstallationCheckpoint(Interval):
    """Independent current installer checkpoint; typed data is not authentication."""
    codec_version: Literal[1] = 1
    deployment_id: Identifier
    policy_hash: Digest
    anchor_hash: Digest
    high_water_generation: int = Field(strict=True, gt=0)


class LoadedInstallationConfiguration(Interval):
    """Immutable verified input snapshot, never a permission to execute."""
    request: PreflightAuditRequest
    anchor: ExternalInstallationAnchor
    envelope: InstallationEnvelope
    descriptor: HostProvisioningDescriptor


class TrustedConfigurationError(Exception):
    """Sanitized failure; details from OS exceptions are not exposed."""
    def __init__(self, reason_code='TRUSTED_CONFIGURATION_UNAVAILABLE'):
        self.reason_code = reason_code
        super().__init__(reason_code)


class _ProtectedInputs:
    def __init__(self, api, policy):
        self.api, self.policy, self.paths = api, policy, {}

    def open_root(self, path):
        handle = self.api.open_root(path)
        self.paths[handle] = path
        # Volume validation is performed by facts after the loader owns the handle.
        return handle

    def open_child(self, parent, name, directory, content=False):
        handle = self.api.open_child(parent, name, directory, content)
        self.paths[handle] = ntpath.join(self.paths[parent], name)
        return handle

    def facts(self, handle):
        facts = self.api.facts(handle)
        path = self.paths[handle]
        if path == path[:3]:
            if self.api.volume(handle) != (self.policy.volume.guid, 'NTFS'):
                raise ProtectedFileError('Volume mismatch')
        if facts.volume != self.policy.volume.serial:
            raise ProtectedFileError('Volume mismatch')
        owner, aces = parse_security(facts.security)
        if owner not in self.policy.installer_sids:
            raise ProtectedFileError('Owner denied')
        root = ntpath.normcase(self.policy.installation_root)
        under_root = ntpath.normcase(path) == root or ntpath.normcase(path).startswith(root + '\\')
        if under_root and not struct.unpack_from('<H', facts.security, 2)[0] & 0x1000:
            raise ProtectedFileError('Protected DACL required')
        for kind, flags, mask, sid in aces:
            if mask & ~0xf31f01ff:
                raise ProtectedFileError('Unsupported rights')
            # Conservatively reject inherited/future-child write grants too;
            # deny ACEs cannot compensate for an unauthorized allow grant.
            if kind == 0 and mask & (0x52000000 | 0x000d0156) and sid not in self.policy.installer_sids:
                raise ProtectedFileError('Writer denied')
        return facts

    def read(self, handle, size):
        return self.api.read(handle, size)

    def close(self, handle):
        return self.api.close(handle)


class TrustedConfigurationLoader:
    def __init__(self, policy, checkpoint):
        try:
            if type(policy) is not TrustedInstallationPolicy or type(checkpoint) is not InstallationCheckpoint:
                raise ValueError()
            self._policy = decode_canonical(TrustedInstallationPolicy, canonical_bytes(policy))
            self._checkpoint = decode_canonical(InstallationCheckpoint, canonical_bytes(checkpoint))
            if checkpoint.deployment_id != policy.deployment_id or checkpoint.policy_hash != record_digest(policy):
                raise ValueError()
        except Exception:
            raise TrustedConfigurationError('TRUSTED_CONFIGURATION_INVALID') from None

    def load(self):
        return self._execute(False, _InspectionAPI, _inspect, lambda: datetime.now(timezone.utc), time.monotonic)

    def audit(self):
        """No caller-selected paths, phase overrides, or supplied credential objects."""
        return self._execute(True, _InspectionAPI, _inspect, lambda: datetime.now(timezone.utc), time.monotonic)

    def _execute(self, audit, api_factory, inspector, utcnow, monotonic):
        elapsed = 0
        stage = 'TRUSTED_CONFIGURATION_UNAVAILABLE'
        last_tick = start_tick = last_utc = None
        policy, checkpoint = self._policy, self._checkpoint
        def check():
            nonlocal elapsed, last_tick, start_tick, last_utc
            now, tick = utcnow(), monotonic()
            if (not isinstance(now, datetime) or now.utcoffset() is None
                    or type(tick) not in (float, int) or not math.isfinite(tick)
                    or last_tick is not None and tick < last_tick or last_utc is not None and now < last_utc):
                raise TrustedConfigurationError('CLOCK_INVALID')
            if start_tick is None:
                start_tick = tick
            last_tick, last_utc = tick, now
            elapsed = int((tick - start_tick) * 1000)
            if tick - start_tick > policy.request.inspection_timeout_seconds:
                raise TrustedConfigurationError('BUDGET_EXCEEDED')
            if not all(item.valid_from <= now < item.valid_until for item in (policy, checkpoint)):
                raise TrustedConfigurationError('TRUSTED_CONFIGURATION_EXPIRED')
            return now
        try:
            check()
            blobs = _load_inputs(policy.request, _ProtectedInputs(api_factory(), policy), check)
            check()
            stage = 'TRUSTED_CONFIGURATION_INVALID'
            envelope, anchor, descriptor = tuple(decode_canonical(kind, data) for kind, data in zip(
                (InstallationEnvelope, ExternalInstallationAnchor, HostProvisioningDescriptor), blobs))
            if record_digest(anchor) != checkpoint.anchor_hash or anchor.deployment_id != policy.deployment_id:
                raise TrustedConfigurationError('ANCHOR_MISMATCH')
            if envelope.generation < checkpoint.high_water_generation or anchor.minimum_generation < checkpoint.high_water_generation:
                raise TrustedConfigurationError('ROLLBACK_DETECTED')
            validate_installation_records(envelope, anchor, descriptor, now=check())
            if envelope.phase != policy.request.target_phase:
                raise TrustedConfigurationError('PHASE_MISMATCH')
            if set(policy.installer_sids) != set(envelope.maintenance_sids):
                raise ValueError()
            expected = next(o.path for o in envelope.objects if o.role == 'descriptor')
            state = next(o.path for o in envelope.objects if o.role == 'state')
            if ntpath.normcase(expected) != ntpath.normcase(policy.request.descriptor_path):
                raise ValueError()
            # No immutable input may be located in application-writable state.
            if any(ntpath.normcase(p) == ntpath.normcase(state) or ntpath.normcase(p).startswith(ntpath.normcase(state) + '\\')
                   for p in (policy.installation_root, policy.request.envelope_path,
                             policy.request.external_anchor_path, policy.request.descriptor_path)):
                raise ValueError()
            snapshot = LoadedInstallationConfiguration(request=policy.request, anchor=anchor, envelope=envelope,
                descriptor=descriptor, valid_from=max(v.valid_from for v in (policy, checkpoint, envelope, anchor)),
                valid_until=min(v.valid_until for v in (policy, checkpoint, envelope, anchor)))
            if not audit:
                now = check()
                if not snapshot.valid_from <= now < snapshot.valid_until:
                    raise TrustedConfigurationError('TRUSTED_CONFIGURATION_EXPIRED')
                return snapshot
            # Feed the exact verified bytes into the runner, avoiding a second
            # open that could replace the checked input snapshot.
            def clock():
                check()
                return last_tick
            result = _run(policy.request, anchor, api_factory, inspector, utcnow, clock,
                          input_loader=lambda request, api, budget: blobs)
            now = check()
            if not snapshot.valid_from <= now < snapshot.valid_until:
                raise TrustedConfigurationError('TRUSTED_CONFIGURATION_EXPIRED')
            return result.model_copy(update={'execution_time_ms': elapsed})
        except TrustedConfigurationError as exc:
            stage = exc.reason_code
        except Exception:
            pass
        if audit:
            return PreflightAuditResult(status='INDETERMINATE', reason_codes=(stage,),
                inspected_object_count=0, execution_time_ms=elapsed)
        raise TrustedConfigurationError(stage) from None
