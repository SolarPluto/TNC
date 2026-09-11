from dataclasses import replace
import ntpath
import sys
import pytest

from test_deployment_validation import inventory, NOW
from test_provisioning_validation import case
from test_windows_deployment_inspection import Fake
from test_protected_provisioning import sd
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.deployment_validation import evaluate_deployment_observations
from tnc.provenance.windows_protected_files import FileFacts
from tnc.provenance.windows_deployment_inspection import _InspectionAPI, _inspect
from tnc.provenance.deployment_runner import PreflightAuditRequest, PreflightAuditResult, _run, _load_inputs


class Inputs:
    def __init__(self, request, inventory):
        self.files = dict(zip((request.envelope_path, request.external_anchor_path, request.descriptor_path),
            (canonical_bytes(inventory[k]) for k in ('envelope', 'external_anchor', 'descriptor'))))
        self.paths, self.closed = {}, []
        self.fail_close = False
    def open_root(self, path):
        return self.open_child(None, path, True)
    def open_child(self, parent, name, directory, content=False):
        handle = len(self.paths) + 1
        self.paths[handle] = ntpath.join(self.paths[parent], name) if parent else name
        return handle
    def facts(self, handle):
        path = self.paths[handle]
        return FileFacts(path not in self.files, 0, 1, len(self.files.get(path, b'')), 1, handle, sd())
    def read(self, handle, size):
        return self.files[self.paths[handle]]
    def close(self, handle):
        self.closed.append(handle)
        if self.fail_close:
            raise OSError('sensitive path')


@pytest.fixture
def setup(inventory):
    request = PreflightAuditRequest(envelope_path=r'C:\TNC\envelope.json', external_anchor_path=r'C:\TNC\external.json',
        descriptor_path=r'C:\TNC\host.json', target_phase='AFTER_HANDOFF')
    return request, Inputs(request, inventory)


def run(inventory, setup, inspector=None, mono=lambda: 1.):
    request, inputs = setup
    def inspect(*args, **kwargs):
        return evaluate_deployment_observations(**inventory)
    return _run(request, inventory['external_anchor'], lambda: inputs, inspector or inspect, lambda: NOW, mono)


def test_complete_conforming_report(inventory, setup):
    result = run(inventory, setup)
    assert result.status == 'CONFORMS'
    assert result.inspected_object_count == len(inventory['observations'])
    assert sorted(setup[1].paths) == sorted(setup[1].closed)
    assert 'C:\\' not in canonical_bytes(result).decode()


def test_actual_adapter_flow(inventory, setup):
    inputs = setup[1]
    native = Fake(inventory)
    apis = iter((inputs, native))
    result = _run(setup[0], inventory['external_anchor'], lambda: next(apis), _inspect, lambda: NOW, lambda: 1.)
    assert result.status == 'VIOLATIONS'
    assert set(native.reads) == {'code', 'descriptor', 'anchor'}
    assert sorted(native.opened) == sorted(native.closed)


@pytest.mark.parametrize('mutation', [lambda b:b+b' ', lambda b:b'', lambda b:b'{}', lambda b:b'\xff'])
def test_invalid_input_no_inspection(inventory, setup, mutation):
    setup[1].files[setup[0].envelope_path] = mutation(setup[1].files[setup[0].envelope_path])
    def forbidden(*a, **k):
        pytest.fail('Inspector must not run')
    result = run(inventory, setup, forbidden)
    assert result.status == 'INDETERMINATE' and result.report is None
    assert sorted(setup[1].paths) == sorted(setup[1].closed)


def test_anchor_is_independent(inventory, setup):
    altered = inventory['external_anchor'].model_copy(update={'minimum_generation': 2})
    setup[1].files[setup[0].external_anchor_path] = canonical_bytes(altered)
    assert run(inventory, setup).reason_codes == ('ANCHOR_MISMATCH',)


def test_phase_is_not_override(inventory, setup):
    req = setup[0].model_copy(update={'target_phase':'BEFORE_BOOTSTRAP'})
    assert run(inventory, (req, setup[1])).reason_codes == ('PHASE_MISMATCH',)


@pytest.mark.parametrize('fault', ['read', 'close', 'reparse', 'hardlink', 'size', 'changed'])
def test_input_failures_cleanup(inventory, setup, fault):
    api = setup[1]
    if fault == 'read':
        def fail(*a): raise OSError('secret contents')
        api.read = fail
    elif fault == 'close': api.fail_close = True
    else:
        original = api.facts
        visits = {}
        def facts(h):
            item = original(h)
            visits[h] = visits.get(h, 0) + 1
            if fault == 'reparse': return replace(item, attributes=0x400)
            if fault == 'hardlink' and not item.directory: return replace(item, links=2)
            if fault == 'size' and not item.directory: return replace(item, size=262145)
            if fault == 'changed' and visits[h]>1: return replace(item, file_id=9999)
            return item
        api.facts = facts
    result = run(inventory, setup)
    assert result.reason_codes == ('INPUT_UNAVAILABLE',)
    assert sorted(api.paths) == sorted(api.closed)
    assert b'secret' not in canonical_bytes(result)


@pytest.mark.parametrize('ticks,reason', [([1.,12.], 'BUDGET_EXCEEDED'), ([1.,0.], 'CLOCK_INVALID'),
    ([float('nan')], 'CLOCK_INVALID')])
def test_clocks(inventory, setup, ticks, reason):
    values = iter(ticks)
    assert run(inventory, setup, mono=lambda:next(values)).reason_codes == (reason,)


def test_inspection_error_is_generic(inventory, setup):
    def fail(*a, **k): raise OSError('secret database path')
    result = run(inventory, setup, fail)
    assert result.reason_codes == ('INSPECTION_UNAVAILABLE',)
    assert b'secret' not in canonical_bytes(result)


@pytest.mark.parametrize('ident,updates,status', [
    ('wal', {'state':'ABSENT'}, 'CONFORMS'),
    ('database', {'state':'ABSENT'}, 'VIOLATIONS'),
    ('code', {'changed':True}, 'INDETERMINATE'),
    ('code', {'reparse':True}, 'VIOLATIONS'),
    ('code', {'volume_serial':999}, 'VIOLATIONS'),
])
def test_observation_outcomes(inventory, setup, ident, updates, status):
    from tnc.provenance.installation_models import ObjectObservation
    observations = []
    for observation in inventory['observations']:
        if observation.object_id == ident:
            if updates.get('state') == 'ABSENT':
                observation = ObjectObservation(object_id=ident, state='ABSENT', started_at=NOW, finished_at=NOW)
            else: observation = observation.model_copy(update=updates)
        observations.append(observation)
    inventory = inventory | {'observations':tuple(observations)}
    assert run(inventory, setup).status == status


def test_foreign_report_rejected(inventory, setup):
    def foreign(*a, **k):
        return evaluate_deployment_observations(**inventory).model_copy(update={'envelope_hash':'f'*64})
    assert run(inventory, setup, foreign).reason_codes == ('INSPECTION_UNAVAILABLE',)


def test_deadline_during_inspection(inventory, setup):
    tick = [1.]
    def late(e, a, d, api, utc, mono, **kw):
        tick[0] = 12.
        mono()
    result = run(inventory, setup, late, mono=lambda:tick[0])
    assert result.reason_codes == ('BUDGET_EXCEEDED',)


@pytest.mark.parametrize('value', [0, 11, True, 1.5])
def test_invalid_timeout(setup, value):
    with pytest.raises(ValueError):
        PreflightAuditRequest.model_validate(setup[0].model_dump() | {'inspection_timeout_seconds':value})


def test_result_cannot_claim_success_without_report():
    with pytest.raises(ValueError):
        PreflightAuditResult(status='CONFORMS', reason_codes=(), inspected_object_count=0, execution_time_ms=0)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows native input acquisition')
def test_native_input_loading(tmp_path):
    paths = [tmp_path / name for name in ('envelope.json', 'external.json', 'host.json')]
    for index, path in enumerate(paths): path.write_bytes(str(index).encode())
    request = PreflightAuditRequest(envelope_path=str(paths[0]), external_anchor_path=str(paths[1]),
        descriptor_path=str(paths[2]), target_phase='AFTER_HANDOFF')
    assert _load_inputs(request, _InspectionAPI(), lambda:None) == (b'0', b'1', b'2')
    for path in paths: path.unlink()  # Successful deletion verifies native handles were released.
