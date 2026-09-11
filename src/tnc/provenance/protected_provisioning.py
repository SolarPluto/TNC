"""Protected configuration reads only. No certificate or operator authorization."""
from hashlib import sha256
import sys
import time
from types import MappingProxyType

from tnc.provenance.authorization_models import BootstrapManifest, canonical_bytes
from tnc.provenance.provisioning_models import (
    HostProvisioningDescriptor, ProvisioningPolicy, ProtectedArtifactRecord, JSON_LIMIT,
)
from tnc.provenance.provisioning_validation import decode_provisioning_record, validate_provisioning_snapshot
from tnc.provenance.windows_protected_files import _WindowsFileAPI, ProtectedFileError, validate_security


class ProtectedProvisioningSnapshot:
    """Host-owned handle lifetime. Use as a context manager and retain exact bytes."""
    def __init__(self, api, handles, descriptor, policy, manifest, artifacts, record):
        self._api, self._handles = api, handles
        self.descriptor, self.policy, self.manifest, self.record = descriptor, policy, manifest, record
        self._artifacts = MappingProxyType(dict(artifacts))

    @property
    def artifacts(self):
        if not self._handles:
            raise ProtectedFileError('Snapshot closed')
        return self._artifacts

    def close(self):
        handles, self._handles = self._handles, []
        failed = False
        for handle in reversed(handles):
            try:
                self._api.close(handle)
            except Exception:
                failed = True
        if failed:
            raise ProtectedFileError('Snapshot cleanup failed')

    def __enter__(self):
        if not self._handles:
            raise ProtectedFileError('Snapshot closed')
        return self

    def __exit__(self, *args):
        self.close()


def _load(descriptor, api, clock=time.monotonic):
    handles, checked = [], []
    start = clock()
    def budget():
        if clock() - start > 10 or len(handles) > 64:
            raise ProtectedFileError('Loader budget exceeded')
    def inspect(handle, directory, limit=None):
        budget()
        facts = api.facts(handle)
        if facts.directory != directory or facts.attributes & 0x400:
            raise ProtectedFileError('Unexpected file type or reparse point')
        if not directory and (facts.links != 1 or not 0 < facts.size <= limit):
            raise ProtectedFileError('Unsafe file size or links')
        validate_security(facts.security, descriptor.trusted_owner_sids, descriptor.trusted_writer_sids)
        checked.append((handle, facts))
        return facts
    def opened(handle):
        handles.append(handle)
        budget()
        return handle
    def read(name, limit):
        handle = opened(api.open_child(parent, name, False))
        facts = inspect(handle, False, limit)
        data = api.read(handle, facts.size)
        if type(data) is not bytes or len(data) != facts.size or api.facts(handle) != facts:
            raise ProtectedFileError('File changed')
        budget()
        return data, facts
    try:
        if type(descriptor) is not HostProvisioningDescriptor:
            raise ProtectedFileError('Host descriptor required')
        descriptor = decode_provisioning_record(HostProvisioningDescriptor, canonical_bytes(descriptor))
        parts = descriptor.configuration_root[3:].split('\\')
        if len(parts) > 48 or any(len(p) > 255 for p in parts):
            raise ProtectedFileError('Path too deep')
        parent = opened(api.open_root(descriptor.configuration_root[:3]))
        root = inspect(parent, True)
        for part in parts:
            parent = opened(api.open_child(parent, part, True))
            if inspect(parent, True).volume != root.volume:
                raise ProtectedFileError('Volume changed')
        policy_bytes, _ = read('policy.json', JSON_LIMIT)
        if sha256(policy_bytes).hexdigest() != descriptor.policy_hash:
            raise ProtectedFileError('Policy digest mismatch')
        policy = decode_provisioning_record(ProvisioningPolicy, policy_bytes)
        manifest_bytes, _ = read('manifest.json', JSON_LIMIT)
        manifest = decode_provisioning_record(BootstrapManifest, manifest_bytes)
        artifacts, observations = {}, []
        for binding in policy.artifacts:
            if binding.name in ('policy.json', 'manifest.json'):
                raise ProtectedFileError('Reserved artifact name')
            data, facts = read(binding.name, binding.length)
            if facts.volume != root.volume:
                raise ProtectedFileError('Artifact volume changed')
            artifacts[binding.name] = data
            observations.append(ProtectedArtifactRecord(name=binding.name, sha256=sha256(data).hexdigest(),
                length=len(data), volume_id=str(facts.volume), file_id=str(facts.file_id),
                security_descriptor_hash=sha256(facts.security).hexdigest()))
        record = validate_provisioning_snapshot(descriptor=descriptor, policy=policy, manifest=manifest,
            artifacts=artifacts, observations=tuple(observations))
        for handle, facts in checked:
            if api.facts(handle) != facts:
                raise ProtectedFileError('Snapshot changed')
            budget()
        return ProtectedProvisioningSnapshot(api, handles, descriptor, policy, manifest, artifacts, record)
    except BaseException:
        for handle in reversed(handles):
            try:
                api.close(handle)
            except Exception:
                pass  # Continue attempting every remaining close; return no snapshot.
        raise


def load_protected_provisioning(descriptor):
    """Descriptor is independently installed host input, never caller-selected policy."""
    try:
        if sys.platform != 'win32':
            raise ProtectedFileError('Windows required')
        return _load(descriptor, _WindowsFileAPI())
    except Exception:
        raise ProtectedFileError('Protected provisioning unavailable') from None
