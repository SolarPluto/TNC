from dataclasses import replace
from datetime import timedelta
import struct
import sys

import pytest

from test_deployment_validation import inventory, MAINT, NOW, GUID
from test_provisioning_validation import case, SID
from test_deployment_runner import Inputs
from test_protected_provisioning import sd
from test_windows_deployment_inspection import Fake
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.deployment_runner import PreflightAuditRequest, _load_inputs
from tnc.provenance.deployment_validation import evaluate_deployment_observations
from tnc.provenance.windows_deployment_inspection import _InspectionAPI, _inspect
from tnc.provenance.windows_protected_files import ProtectedFileError
from tnc.provenance.trusted_boundary import (
    TrustedInstallationPolicy, InstallationCheckpoint, TrustedConfigurationLoader,
    TrustedConfigurationError, _ProtectedInputs,
)


def security(owner=MAINT, entries=((0, 0, 0x1f01ff, MAINT),), protected=True):
    data = bytearray(sd(owner, entries))
    struct.pack_into('<H', data, 2, 0x9004 if protected else 0x8004)
    return bytes(data)


class ProtectedInputs(Inputs):
    def __init__(self, request, inventory):
        super().__init__(request, inventory)
        self.bad = None
        self.reads = []
    def volume(self, handle): return GUID, 'NTFS'
    def facts(self, handle):
        facts = replace(super().facts(handle), volume=123, security=security())
        return self.bad(facts, self.paths[handle]) if self.bad else facts
    def read(self, handle, size):
        self.reads.append(self.paths[handle])
        return super().read(handle, size)


@pytest.fixture
def config(inventory):
    request = PreflightAuditRequest(envelope_path=r'C:\TNC\envelope.json', external_anchor_path=r'C:\TNC\external.json',
        descriptor_path=r'C:\TNC\host.json', target_phase='AFTER_HANDOFF')
    policy = TrustedInstallationPolicy(deployment_id=inventory['envelope'].deployment_id,
        installation_root=r'C:\TNC', request=request, volume=inventory['envelope'].volumes[0], installer_sids=(MAINT,),
        valid_from=NOW, valid_until=NOW+timedelta(days=1))
    checkpoint = InstallationCheckpoint(deployment_id=policy.deployment_id, policy_hash=record_digest(policy),
        anchor_hash=record_digest(inventory['external_anchor']), high_water_generation=1,
        valid_from=NOW, valid_until=NOW+timedelta(days=1))
    return policy, checkpoint, ProtectedInputs(request, inventory)


def run(config, inventory, audit=False, utc=lambda:NOW, mono=lambda:1., inspector=None):
    policy, checkpoint, inputs = config
    def inspect(*a, **kw): return evaluate_deployment_observations(**inventory)
    return TrustedConfigurationLoader(policy, checkpoint)._execute(audit, lambda:inputs, inspector or inspect, utc, mono)


def test_valid_frozen_load_and_cleanup(config, inventory):
    result = run(config, inventory)
    assert result.envelope == inventory['envelope']
    assert result.anchor == inventory['external_anchor']
    assert sorted(config[2].closed) == sorted(config[2].paths)
    with pytest.raises(ValueError): result.request = config[0].request


def test_audit_uses_exact_loaded_bytes(config, inventory):
    policy, checkpoint, inputs = config
    calls = [0]
    def factory():
        calls[0] += 1
        if calls[0] > 1:
            inputs.files.clear()  # Later file content cannot replace the snapshot.
        return inputs
    result = TrustedConfigurationLoader(policy, checkpoint)._execute(True, factory,
        lambda *a, **k:evaluate_deployment_observations(**inventory), lambda:NOW, lambda:1.)
    assert result.status == 'CONFORMS'
    assert len(inputs.reads) == 3


def test_runner_and_native_observer_orchestration(config, inventory):
    native = Fake(inventory)
    apis = iter((config[2], object(), native))
    result = TrustedConfigurationLoader(*config[:2])._execute(True, lambda:next(apis), _inspect, lambda:NOW, lambda:1.)
    assert result.status == 'VIOLATIONS'
    assert set(native.reads) == {'code', 'descriptor', 'anchor'}
    assert sorted(native.opened) == sorted(native.closed)


@pytest.mark.parametrize('field,value', [('high_water_generation',2), ('high_water_generation',999)])
def test_rollback_rejected(config, inventory, field, value):
    policy, checkpoint, inputs = config
    checkpoint = checkpoint.model_copy(update={field:value})
    assert run((policy, checkpoint, inputs), inventory, True).reason_codes == ('ROLLBACK_DETECTED',)


def test_anchor_floor_cannot_lag_checkpoint(config, inventory):
    policy, checkpoint, inputs = config
    envelope = inventory['envelope'].model_copy(update={'generation':2})
    anchor = inventory['external_anchor'].model_copy(update={'envelope_hash':record_digest(envelope)})
    inputs.files[policy.request.envelope_path] = canonical_bytes(envelope)
    inputs.files[policy.request.external_anchor_path] = canonical_bytes(anchor)
    checkpoint = checkpoint.model_copy(update={'anchor_hash':record_digest(anchor), 'high_water_generation':2})
    assert run((policy, checkpoint, inputs), inventory, True).reason_codes == ('ROLLBACK_DETECTED',)


@pytest.mark.parametrize('key', ['envelope', 'external_anchor'])
def test_expired_installation_records(config, inventory, key):
    policy, checkpoint, inputs = config
    changed = inventory[key].model_copy(update={'valid_from':NOW-timedelta(days=1), 'valid_until':NOW})
    envelope = changed if key=='envelope' else inventory['envelope']
    anchor = changed if key=='external_anchor' else inventory['external_anchor'].model_copy(update={'envelope_hash':record_digest(envelope)})
    inputs.files[policy.request.envelope_path] = canonical_bytes(envelope)
    inputs.files[policy.request.external_anchor_path] = canonical_bytes(anchor)
    checkpoint = checkpoint.model_copy(update={'anchor_hash':record_digest(anchor)})
    assert run((policy, checkpoint, inputs), inventory, True).status == 'INDETERMINATE'


def test_same_generation_anchor_replacement_is_not_accepted(config, inventory):
    changed = inventory['external_anchor'].model_copy(update={'valid_until':NOW+timedelta(hours=12)})
    config[2].files[config[0].request.external_anchor_path] = canonical_bytes(changed)
    assert run(config, inventory, True).reason_codes == ('ANCHOR_MISMATCH',)


def test_load_does_not_advance_checkpoint_or_change_inputs(config, inventory):
    before = canonical_bytes(config[1]), dict(config[2].files)
    run(config, inventory)
    assert before == (canonical_bytes(config[1]), config[2].files)


@pytest.mark.parametrize('which', ['policy', 'checkpoint'])
@pytest.mark.parametrize('field,value', [('valid_until',NOW), ('valid_from',NOW+timedelta(seconds=1))])
def test_invalid_trust_intervals(config, inventory, which, field, value):
    policy, checkpoint, inputs = config
    if which == 'policy':
        policy = policy.model_copy(update={field:value, 'valid_from':NOW-timedelta(seconds=1) if field=='valid_until' else value})
        checkpoint = checkpoint.model_copy(update={'policy_hash':record_digest(policy)})
    else:
        checkpoint = checkpoint.model_copy(update={field:value, 'valid_from':NOW-timedelta(seconds=1) if field=='valid_until' else value})
    assert run((policy, checkpoint, inputs), inventory, True).reason_codes == ('TRUSTED_CONFIGURATION_EXPIRED',)
    assert not inputs.paths


@pytest.mark.parametrize('key', ['envelope', 'external_anchor', 'descriptor'])
def test_tampering_blocks_inspection(config, inventory, key):
    index = ('envelope', 'external_anchor', 'descriptor').index(key)
    path = (config[0].request.envelope_path, config[0].request.external_anchor_path, config[0].request.descriptor_path)[index]
    original = canonical_bytes(inventory[key])
    config[2].files[path] = original.replace(inventory[key].deployment_id.encode(), b'other-deployment')
    def forbidden(*a, **kw): pytest.fail('Untrusted data reached inspection')
    result = run(config, inventory, True, inspector=forbidden)
    assert result.status == 'INDETERMINATE' and result.report is None


@pytest.mark.parametrize('fault', ['owner','write','inherit_only_write','unprotected','unsupported_ace','unknown_mask',
    'reparse','hardlink','volume','size'])
def test_protected_acquisition_failures(config, inventory, fault):
    def bad(facts, path):
        if fault=='owner': return replace(facts, security=security(owner=SID))
        if fault=='write': return replace(facts, security=security(entries=((0,0,0x40000000,SID),)))
        if fault=='inherit_only_write': return replace(facts, security=security(entries=((0,9,0x40000000,SID),)))
        if fault=='unprotected' and path==r'C:\TNC': return replace(facts, security=security(protected=False))
        if fault=='unsupported_ace': return replace(facts, security=security(entries=((5,0,1,SID),)))
        if fault=='unknown_mask': return replace(facts, security=security(entries=((0,0,0x400,MAINT),)))
        if fault=='reparse': return replace(facts, attributes=0x400)
        if fault=='hardlink' and not facts.directory: return replace(facts, links=2)
        if fault=='volume': return replace(facts, volume=999)
        if fault=='size' and not facts.directory: return replace(facts, size=262145)
        return facts
    config[2].bad = bad
    result = run(config, inventory, True)
    assert result.reason_codes == ('TRUSTED_CONFIGURATION_UNAVAILABLE',)
    assert sorted(config[2].closed) == sorted(config[2].paths)


def test_wrong_guid_rejected_before_read(config, inventory):
    config[2].volume = lambda h:(GUID.replace('11111111','22222222'),'NTFS')
    assert run(config, inventory, True).status == 'INDETERMINATE'
    assert not config[2].reads
    assert sorted(config[2].closed) == sorted(config[2].paths)


def test_cleanup_failure_blocks_result(config, inventory):
    config[2].fail_close = True
    assert run(config, inventory, True).status == 'INDETERMINATE'
    assert sorted(config[2].closed) == sorted(config[2].paths)


@pytest.mark.parametrize('path', [r'..\anchor.json', r'C:\elsewhere\anchor.json', r'\\server\share\anchor.json', r'C:\TNC\file:stream'])
def test_unapproved_paths(config, path):
    with pytest.raises(ValueError):
        request = PreflightAuditRequest.model_validate(config[0].request.model_dump() | {'external_anchor_path':path})
        TrustedInstallationPolicy.model_validate(config[0].model_dump() | {'request':request})


@pytest.mark.parametrize('field,value', [('deployment_id','other'), ('policy_hash','f'*64)])
def test_mismatched_checkpoint(config, field, value):
    with pytest.raises(TrustedConfigurationError):
        TrustedConfigurationLoader(config[0], config[1].model_copy(update={field:value}))


def test_deadline_and_cleanup(config, inventory):
    ticks = iter((1., 12.))
    assert run(config, inventory, True, mono=lambda:next(ticks)).reason_codes == ('BUDGET_EXCEEDED',)
    assert sorted(config[2].closed) == sorted(config[2].paths)


@pytest.mark.parametrize('ticks', [(1.,0.), (float('nan'),)])
def test_clock_failure(config, inventory, ticks):
    values = iter(ticks)
    assert run(config, inventory, True, mono=lambda:next(values)).reason_codes == ('CLOCK_INVALID',)


def test_checkpoint_expiry_during_audit(config, inventory):
    now = [NOW]
    def inspector(*a, **kw):
        now[0] = NOW+timedelta(days=2)
        return evaluate_deployment_observations(**inventory)
    assert run(config, inventory, True, utc=lambda:now[0], inspector=inspector).reason_codes == ('TRUSTED_CONFIGURATION_EXPIRED',)


def test_failures_do_not_expose_exception_details(config, inventory):
    def fail(*a): raise OSError('secret-file-content-and-path')
    config[2].read = fail
    assert b'secret-file' not in canonical_bytes(run(config, inventory, True))


@pytest.mark.skipif(sys.platform!='win32', reason='Native Windows security metadata')
def test_native_untrusted_temporary_tree_is_rejected(tmp_path, config):
    # Do not alter the live host's ACLs merely to manufacture a conforming test.
    paths = tuple(tmp_path / name for name in ('e.json','a.json','d.json'))
    for path in paths: path.write_bytes(b'unchanged')
    request = PreflightAuditRequest(envelope_path=str(paths[0]), external_anchor_path=str(paths[1]),
        descriptor_path=str(paths[2]), target_phase='AFTER_HANDOFF')
    api = _InspectionAPI()
    root = api.open_root(str(tmp_path)[:3])
    try:
        guid, filesystem = api.volume(root)
        serial = api.facts(root).volume
    finally:
        api.close(root)
    volume = config[0].volume.model_copy(update={'root':str(tmp_path)[:3], 'guid':guid, 'serial':serial})
    policy = config[0].model_copy(update={'installation_root':str(tmp_path), 'request':request,
        'volume':volume, 'installer_sids':('S-1-5-21-987654321',)})
    def forbidden(*a): pytest.fail('Rejected owner must prevent input reads')
    api.read = forbidden
    with pytest.raises(ProtectedFileError, match='Owner denied'):
        _load_inputs(request, _ProtectedInputs(api, policy), lambda:None)
    for path in paths:
        assert path.read_bytes()==b'unchanged'
        path.unlink()
