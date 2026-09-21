"""Producer-only tests for bound dual-axis native AppContainer evidence."""
import ctypes as c
import os
import subprocess
import sys
import threading

import pytest
from pydantic import TypeAdapter, ValidationError

from tnc.provenance import windows_appcontainer_probe as ap
from tnc.provenance.windows_appcontainer_evidence import AppContainerTokenEvidence
from tnc.provenance.windows_pipe_context_producer import (
    EXIT_REVERT_FAILED,
    PeerAdmissionEvidence,
    PipeContextProducer,
    PipeContextProducerError,
    PipePeerAdmissionEvidence,
    ProcessPrimaryAppContainerEvidence,
)
from tnc.provenance.windows_pipe_native import OwnedPipeEndpoint
from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan
from tnc.provenance.windows_pipe_process_lease import (
    OwnedProcessLease,
    ProcessInstancePin,
    ProcessLeasePlan,
)
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


class Function:
    def __init__(self, fn):
        self.fn, self.argtypes, self.restype = fn, None, None

    def __call__(self, *args):
        return self.fn(*args)


class FakeKernel:
    def __init__(self, events):
        self.events = events
        self.GetCurrentThread = Function(lambda: 1)
        self.CloseHandle = Function(self.close)
        self.GetCurrentProcess = Function(lambda: 2)
        self.TerminateProcess = Function(self.terminate)

    def close(self, handle):
        self.events.append(('close', int(handle)))
        return True

    def terminate(self, process, code):
        self.events.append(('terminate', int(code)))
        raise SystemExit(int(code))


class FakeSecurity:
    def __init__(
        self,
        events,
        *,
        impersonate=True,
        open_ok=True,
        revert=True,
        open_error=5,
        process_open_ok=True,
        process_open_error=5,
        process_open_exception=None,
    ):
        self.events = events
        self.impersonate_ok, self.open_ok, self.revert_ok = impersonate, open_ok, revert
        self.process_open_ok = process_open_ok
        self.process_open_exception = process_open_exception
        self.error = open_error
        self.process_open_error = process_open_error
        self.ImpersonateNamedPipeClient = Function(self.impersonate)
        self.OpenThreadToken = Function(self.open)
        self.OpenProcessToken = Function(self.open_process)
        self.RevertToSelf = Function(self.revert)
        self.GetTokenInformation = Function(lambda *args: False)

    def impersonate(self, pipe):
        self.events.append(('impersonate', int(pipe)))
        return self.impersonate_ok

    def open(self, thread, rights, open_as_self, out):
        self.events.append(('open_thread_token', int(rights), bool(open_as_self)))
        if not self.open_ok:
            return False
        c.cast(out, c.POINTER(c.c_void_p)).contents.value = 42
        return True

    def open_process(self, process, rights, out):
        self.events.append(('open_process_token', int(process), int(rights)))
        if self.process_open_exception is not None:
            raise self.process_open_exception
        if not self.process_open_ok:
            self.error = self.process_open_error
            return False
        c.cast(out, c.POINTER(c.c_void_p)).contents.value = 43
        return True

    def revert(self):
        self.events.append(('revert',))
        return self.revert_ok


class ProbeSecurity:
    def __init__(
        self,
        *,
        pipe_app=False,
        process_app=False,
        pipe_fail_kind=None,
        process_fail_kind=None,
    ):
        self.error = ap.ERROR_INSUFFICIENT_BUFFER
        self.pipe_app = pipe_app
        self.process_app = process_app
        self.pipe_fail_kind = pipe_fail_kind
        self.process_fail_kind = process_fail_kind
        self.calls = []
        self.GetTokenInformation = Function(self.query)

    def query(self, token, kind, buffer, capacity, returned):
        token = int(token)
        self.calls.append((token, kind, buffer is None, int(capacity)))
        out = c.cast(returned, c.POINTER(ap.DWORD)).contents
        fail_kind = self.pipe_fail_kind if token == 42 else self.process_fail_kind
        if kind == fail_kind:
            self.error, out.value = 5, 0
            return False
        if kind == ap.TOKEN_IS_APPCONTAINER:
            app = self.pipe_app if token == 42 else self.process_app
            c.cast(buffer, c.POINTER(ap.DWORD)).contents.value = int(app)
            out.value = 4
            return True
        if buffer is None:
            self.error, out.value = ap.ERROR_INSUFFICIENT_BUFFER, (
                4 if kind == ap.TOKEN_CAPABILITIES
                else c.sizeof(ap.TOKEN_APPCONTAINER_INFORMATION)
            )
            return False
        c.memset(c.addressof(buffer), 0, capacity)
        out.value = capacity
        return True


def native_api(events, **security_options):
    kernel = FakeKernel(events)
    security = FakeSecurity(events, **security_options)
    return NativePipeTokenAPI(
        kernel_for_testing=kernel,
        security_for_testing=security,
        last_error_for_testing=lambda: security.error,
    )


def probe(**options):
    security = ProbeSecurity(**options)
    return (
        ap.NativeAppContainerProbe(
            security_for_testing=security,
            last_error_for_testing=lambda: security.error,
        ),
        security,
    )


def live_lease():
    endpoint = object.__new__(OwnedPipeEndpoint)
    endpoint._identity = (os.getpid(), threading.get_ident())
    endpoint._fatal = endpoint._closed = False
    endpoint._handle, endpoint._connected, endpoint._active = 77, True, None
    plan = PipeOperationPlan(
        operation_id='connect-op',
        kind='CONNECT',
        pipe_lease_id='pipe-lease',
        event_id='event',
        overlapped_id='overlapped',
        buffer_id='buffer',
        buffer_size=0,
        created_tick=1,
        request_deadline=10,
        cleanup_deadline=11,
    )
    operation = type('Operation', (), {})()
    operation._plan = plan
    endpoint._operations = {'connect-op': operation}

    lease = object.__new__(OwnedProcessLease)
    lease._owner = (os.getpid(), threading.get_ident())
    lease._fatal = lease._consumed = False
    lease._endpoint, lease._pipe, lease._handle = endpoint, 77, 88
    lease._plan = ProcessLeasePlan(
        operation_id='process-lease',
        created_tick=1,
        deadline=9,
        cleanup_deadline=10,
    )
    lease._pin = ProcessInstancePin(pid=1234, creation_filetime=5678)
    return lease


def produce(*, probe_options=None, **api_options):
    events = []
    app_probe, probe_security = probe(**(probe_options or {}))
    item = PipeContextProducer(
        api=native_api(events, **api_options),
        probe=app_probe,
    ).produce(live_lease())
    return item, events, probe_security


def axis_binding(axis):
    return (
        axis.connection_operation_id,
        axis.pipe_lease_id,
        axis.process_lease_operation_id,
        axis.process_pid,
        axis.process_creation_filetime,
        axis.capture_ordinal,
    )


def test_native_sequence_reverts_before_process_primary_and_closes_lifo():
    item, events, _ = produce()
    assert item.pipe_context.status == 'CAPTURED_NON_APPCONTAINER'
    assert item.process_primary.status == 'CAPTURED_NON_APPCONTAINER'
    assert events == [
        ('impersonate', 77),
        ('open_thread_token', 8, True),
        ('revert',),
        ('open_process_token', 88, 8),
        ('close', 43),
        ('close', 42),
    ]


def test_process_primary_evidence_is_primary_token_evidence():
    item, _, _ = produce()
    evidence = item.process_primary.evidence
    assert evidence.token_type == 'PRIMARY'
    assert evidence.level is None


def test_both_axes_are_bound_to_same_transaction():
    item, _, _ = produce()
    assert axis_binding(item.pipe_context) == (
        'connect-op',
        'pipe-lease',
        'process-lease',
        1234,
        5678,
        1,
    )
    assert axis_binding(item.process_primary) == axis_binding(item.pipe_context)
    assert item.pipe_context.classification_source == 'PIPE_TOKEN'
    assert item.process_primary.classification_source == 'PROCESS_PRIMARY_TOKEN'


@pytest.mark.parametrize(
    'stage,options',
    [
        ('IMPERSONATE', dict(impersonate=False)),
        ('OPEN_THREAD_TOKEN', dict(open_ok=False, open_error=5)),
    ],
)
def test_pipe_capture_unavailable_still_records_process_primary(stage, options):
    item, events, _ = produce(**options)
    assert item.pipe_context.status == 'CAPTURE_UNAVAILABLE'
    assert item.pipe_context.failed_stage == stage
    assert item.process_primary.status == 'CAPTURED_NON_APPCONTAINER'
    assert axis_binding(item.pipe_context) == axis_binding(item.process_primary)
    assert ('open_process_token', 88, 8) in events
    if stage == 'OPEN_THREAD_TOKEN':
        assert item.pipe_context.winerror == 5
        assert ('revert',) in events


@pytest.mark.parametrize('kind', [ap.TOKEN_IS_APPCONTAINER, ap.TOKEN_APPCONTAINER_SID])
def test_pipe_required_probe_failure_does_not_skip_process_axis(kind):
    item, events, _ = produce(probe_options={'pipe_fail_kind': kind})
    pipe = item.pipe_context
    assert pipe.status == 'CAPTURED_CLASSIFICATION_UNAVAILABLE'
    assert pipe.failure_scope == 'SERVER_CLASSIFICATION'
    assert pipe.information_class == kind
    assert pipe.winerror == 5
    assert item.process_primary.status == 'CAPTURED_NON_APPCONTAINER'
    assert events.index(('revert',)) < events.index(('open_process_token', 88, 8))


def test_class_30_unavailability_is_audit_only_on_both_axes():
    item, events, _ = produce(
        probe_options={
            'pipe_fail_kind': ap.TOKEN_CAPABILITIES,
            'process_fail_kind': ap.TOKEN_CAPABILITIES,
        }
    )
    assert item.pipe_context.status == 'CAPTURED_NON_APPCONTAINER'
    assert item.pipe_context.evidence.capability_sids is None
    assert item.process_primary.status == 'CAPTURED_NON_APPCONTAINER'
    assert item.process_primary.evidence.capability_sids is None
    assert events[-2:] == [('close', 43), ('close', 42)]


@pytest.mark.parametrize(
    'kind,expected_reason,expected_winerror',
    [
        (ap.TOKEN_IS_APPCONTAINER, 'QUERY_FAILED', 5),
        # Class 31 is variable-sized. This injected failure occurs on the required
        # size-probe call before any data query; the producer records the structural
        # size-probe failure reason, so there is no data-query Win32 error to retain.
        (ap.TOKEN_APPCONTAINER_SID, 'QUERY_SIZE_PROBE_FAILED', None),
    ],
)
def test_process_primary_required_query_failure_is_structured_unavailable(
    kind,
    expected_reason,
    expected_winerror,
):
    item, events, _ = produce(probe_options={'process_fail_kind': kind})
    process = item.process_primary
    assert item.pipe_context.status == 'CAPTURED_NON_APPCONTAINER'
    assert process.status == 'CAPTURED_CLASSIFICATION_UNAVAILABLE'
    assert process.failed_stage == 'GET_TOKEN_INFORMATION'
    assert process.information_class == kind
    assert process.failure_reason == expected_reason
    assert process.winerror == expected_winerror
    assert events[-2:] == [('close', 43), ('close', 42)]


def test_process_primary_open_failure_is_structured_unavailable_and_pipe_closes():
    item, events, _ = produce(process_open_ok=False, process_open_error=5)
    process = item.process_primary
    assert item.pipe_context.status == 'CAPTURED_NON_APPCONTAINER'
    assert process.status == 'CAPTURED_CLASSIFICATION_UNAVAILABLE'
    assert process.failed_stage == 'OPEN_PROCESS_TOKEN'
    assert process.information_class is None
    assert process.failure_reason == 'OPEN_PROCESS_TOKEN_FAILED'
    assert process.winerror == 5
    assert events[-1] == ('close', 42)
    assert ('close', 43) not in events


def test_unexpected_process_primary_open_exception_is_not_laundered_and_pipe_closes():
    events = []
    app_probe, _ = probe()
    producer = PipeContextProducer(
        api=native_api(events, process_open_exception=RuntimeError('boom')),
        probe=app_probe,
    )
    with pytest.raises(RuntimeError, match='boom'):
        producer.produce(live_lease())
    assert events[-1] == ('close', 42)
    assert ('close', 43) not in events


@pytest.mark.parametrize(
    'pipe_app,process_app,pipe_status,process_status',
    [
        (False, False, 'CAPTURED_NON_APPCONTAINER', 'CAPTURED_NON_APPCONTAINER'),
        (True, False, 'CAPTURED_APPCONTAINER', 'CAPTURED_NON_APPCONTAINER'),
        (False, True, 'CAPTURED_NON_APPCONTAINER', 'CAPTURED_APPCONTAINER'),
        (True, True, 'CAPTURED_APPCONTAINER', 'CAPTURED_APPCONTAINER'),
    ],
)
def test_dual_classification_quadrants(
    pipe_app,
    process_app,
    pipe_status,
    process_status,
):
    item, _, _ = produce(
        probe_options={'pipe_app': pipe_app, 'process_app': process_app}
    )
    assert item.pipe_context.status == pipe_status
    assert item.process_primary.status == process_status


def test_pipe_real_classifier_conflict_routes_to_pipe_conflict(monkeypatch):
    original = ap.NativeAppContainerProbe.probe

    def conflict_pipe(self, token, *, token_type, level):
        if token_type == 'IMPERSONATION':
            return AppContainerTokenEvidence(
                source='FAKE_TOKEN_API',
                token_type='IMPERSONATION',
                level='IMPERSONATION',
                token_is_app_container=False,
                app_container_sid='S-1-15-2-1',
                capability_sids=(),
            )
        return original(self, token, token_type=token_type, level=level)

    monkeypatch.setattr(ap.NativeAppContainerProbe, 'probe', conflict_pipe)
    item, events, _ = produce()
    assert item.pipe_context.status == 'CAPTURED_CLASSIFICATION_CONFLICT'
    assert item.pipe_context.reason == 'APPCONTAINER_SIGNAL_CONFLICT'
    assert item.process_primary.status == 'CAPTURED_NON_APPCONTAINER'
    assert events[-2:] == [('close', 43), ('close', 42)]


def test_process_primary_real_classifier_conflict_routes_to_process_conflict(monkeypatch):
    original = ap.NativeAppContainerProbe.probe

    def conflict_primary(self, token, *, token_type, level):
        if token_type == 'PRIMARY':
            return AppContainerTokenEvidence(
                source='FAKE_TOKEN_API',
                token_type='PRIMARY',
                level=None,
                token_is_app_container=False,
                app_container_sid='S-1-15-2-1',
                capability_sids=(),
            )
        return original(self, token, token_type=token_type, level=level)

    monkeypatch.setattr(ap.NativeAppContainerProbe, 'probe', conflict_primary)
    item, events, _ = produce()
    assert item.pipe_context.status == 'CAPTURED_NON_APPCONTAINER'
    assert item.process_primary.status == 'CAPTURED_CLASSIFICATION_CONFLICT'
    assert item.process_primary.reason == 'APPCONTAINER_SIGNAL_CONFLICT'
    assert events[-2:] == [('close', 43), ('close', 42)]


@pytest.mark.parametrize(
    'raw,expected_class,expected_reason,expected_winerror',
    [
        ('QUERY_29_FAILED_5', 29, 'QUERY_FAILED', 5),
        ('QUERY_29_LENGTH', 29, 'QUERY_LENGTH_INVALID', None),
        ('QUERY_29_BOOLEAN', 29, 'QUERY_BOOLEAN_INVALID', None),
        ('QUERY_31_SIZE_PROBE', 31, 'QUERY_SIZE_PROBE_FAILED', None),
        ('QUERY_31_BOUND', 31, 'QUERY_BOUND_INVALID', None),
        ('QUERY_31_FAILED_5', 31, 'QUERY_FAILED', 5),
        ('QUERY_31_RETURN_LENGTH', 31, 'QUERY_RETURN_LENGTH_INVALID', None),
        ('APPCONTAINER_INFO_HEADER', 31, 'APPCONTAINER_INFO_HEADER_INVALID', None),
        ('APPCONTAINER_SID_INVALID', 31, 'APPCONTAINER_SID_INVALID', None),
    ],
)
def test_process_probe_error_family_maps_exhaustively(
    raw,
    expected_class,
    expected_reason,
    expected_winerror,
):
    from tnc.provenance import windows_pipe_context_producer as producer_module

    class Probe:
        _error = staticmethod(lambda: 5)

    error = ap.AppContainerProbeError(raw)
    assert producer_module._process_probe_failure(Probe(), error) == (
        expected_class,
        expected_reason,
        expected_winerror,
    )


@pytest.mark.parametrize(
    'raw,expected_error',
    [
        ('FUTURE_PROBE_REASON', 'UNEXPECTED_PIPE_PROBE_FAILURE'),
        ('QUERY_29_FUTURE', 'UNMAPPED_PIPE_PROBE_FAILURE'),
        ('QUERY_31_FUTURE', 'UNMAPPED_PIPE_PROBE_FAILURE'),
        pytest.param(
            'QUERY_31_FAILED_NOT_AN_INT',
            'MALFORMED_PIPE_PROBE_FAILURE',
            id='defensive-corrupt-probe-output-not-native-mode',
        ),
    ],
)
def test_unmapped_pipe_probe_error_is_fail_loud(raw, expected_error):
    from tnc.provenance import windows_pipe_context_producer as producer_module

    with pytest.raises(PipeContextProducerError, match=expected_error):
        producer_module._probe_failure(
            object(),
            ap.AppContainerProbeError(raw),
        )


@pytest.mark.parametrize(
    'raw,expected_error',
    [
        ('FUTURE_PROBE_REASON', 'UNEXPECTED_PROCESS_PRIMARY_PROBE_FAILURE'),
        ('QUERY_29_FUTURE', 'UNMAPPED_PROCESS_PRIMARY_PROBE_FAILURE'),
        ('QUERY_31_FUTURE', 'UNMAPPED_PROCESS_PRIMARY_PROBE_FAILURE'),
        pytest.param(
            'QUERY_29_FAILED_NOT_AN_INT',
            'MALFORMED_PROCESS_PRIMARY_PROBE_FAILURE',
            id='defensive-corrupt-probe-output-not-native-mode',
        ),
    ],
)
def test_unmapped_process_probe_error_is_fail_loud(raw, expected_error):
    from tnc.provenance import windows_pipe_context_producer as producer_module

    with pytest.raises(PipeContextProducerError, match=expected_error):
        producer_module._process_probe_failure(
            object(),
            ap.AppContainerProbeError(raw),
        )


def test_unmapped_process_primary_classifier_output_is_fail_loud_and_closes_tokens(
    monkeypatch,
):
    from tnc.provenance import windows_pipe_context_producer as producer_module

    real = producer_module.evaluate_appcontainer_exclusion

    def classify(evidence):
        if evidence.token_type == 'PRIMARY':
            return type(
                'Result',
                (),
                {
                    'status': 'UNPROVEN',
                    'reason': 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN',
                },
            )()
        return real(evidence)

    monkeypatch.setattr(producer_module, 'evaluate_appcontainer_exclusion', classify)
    events = []
    app_probe, _ = probe()
    producer = PipeContextProducer(api=native_api(events), probe=app_probe)
    with pytest.raises(
        PipeContextProducerError,
        match='UNEXPECTED_PROCESS_PRIMARY_CLASSIFIER_OUTCOME',
    ):
        producer.produce(live_lease())
    assert events[-2:] == [('close', 43), ('close', 42)]


def test_unmapped_pipe_classifier_output_is_fail_loud_and_closes_pipe_token(
    monkeypatch,
):
    from tnc.provenance import windows_pipe_context_producer as producer_module

    real = producer_module.evaluate_appcontainer_exclusion

    def classify(evidence):
        if evidence.token_type == 'IMPERSONATION':
            return type(
                'Result',
                (),
                {
                    'status': 'UNPROVEN',
                    'reason': 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN',
                },
            )()
        return real(evidence)

    monkeypatch.setattr(producer_module, 'evaluate_appcontainer_exclusion', classify)
    events = []
    app_probe, _ = probe()
    producer = PipeContextProducer(api=native_api(events), probe=app_probe)
    with pytest.raises(PipeContextProducerError, match='UNEXPECTED_CLASSIFIER_OUTCOME'):
        producer.produce(live_lease())
    assert events[-1] == ('close', 42)
    assert ('open_process_token', 88, 8) not in events


def test_capture_is_one_shot_per_live_lease():
    events = []
    lease = live_lease()
    app_probe, _ = probe()
    producer = PipeContextProducer(api=native_api(events), probe=app_probe)
    assert producer.produce(lease).pipe_context.capture_ordinal == 1
    with pytest.raises(PipeContextProducerError, match='CONNECTION_ALREADY_CAPTURED'):
        producer.produce(lease)


def test_process_unavailable_schema_rejects_class_30_and_stage_mismatch():
    adapter = TypeAdapter(ProcessPrimaryAppContainerEvidence)
    binding = dict(
        connection_operation_id='connect-op',
        pipe_lease_id='pipe-lease',
        process_lease_operation_id='process-lease',
        process_pid=1234,
        process_creation_filetime=5678,
        capture_ordinal=1,
        status='CAPTURED_CLASSIFICATION_UNAVAILABLE',
        classification_source='PROCESS_PRIMARY_TOKEN',
        failed_stage='GET_TOKEN_INFORMATION',
        failure_reason='QUERY_FAILED',
        winerror=5,
    )
    with pytest.raises(ValidationError):
        adapter.validate_python(dict(binding, information_class=30))
    with pytest.raises(ValidationError):
        adapter.validate_python(
            dict(
                binding,
                failed_stage='OPEN_PROCESS_TOKEN',
                information_class=29,
                failure_reason='OPEN_PROCESS_TOKEN_FAILED',
            )
        )


def test_wrapper_validation_failure_is_fail_loud_and_closes_both_tokens(monkeypatch):
    from tnc.provenance import windows_pipe_context_producer as producer_module

    real = producer_module._classify_process_primary_axis

    def mismatched(*args, **kwargs):
        value = real(*args, **kwargs)
        return value.model_copy(update={'process_pid': value.process_pid + 1})

    monkeypatch.setattr(producer_module, '_classify_process_primary_axis', mismatched)
    events = []
    app_probe, _ = probe()
    producer = PipeContextProducer(api=native_api(events), probe=app_probe)
    with pytest.raises(
        PipeContextProducerError,
        match='PEER_ADMISSION_EVIDENCE_VALIDATION_FAILED',
    ):
        producer.produce(live_lease())
    assert events[-2:] == [('close', 43), ('close', 42)]


def test_wrapper_rejects_cross_axis_binding_mismatch():
    item, _, _ = produce()
    raw = item.model_dump()
    raw['process_primary']['process_pid'] += 1
    with pytest.raises(ValidationError, match='CROSS_AXIS_BINDING_MISMATCH'):
        PeerAdmissionEvidence.model_validate(raw)


def test_schema_is_frozen_and_public_surface_has_no_variant_constructors():
    item, _, _ = produce()
    with pytest.raises(Exception):
        item.pipe_context.capture_ordinal = 2
    import tnc.provenance.windows_pipe_context_producer as module

    assert all(not name.startswith('_Captured') for name in module.__all__)
    assert all(not name.startswith('_ProcessPrimary') for name in module.__all__)


def test_wrapper_schema_preserves_both_discriminated_axes():
    pipe = TypeAdapter(PipePeerAdmissionEvidence).json_schema()
    process = TypeAdapter(ProcessPrimaryAppContainerEvidence).json_schema()
    assert set(pipe['discriminator']['mapping']) == {
        'CAPTURED_APPCONTAINER',
        'CAPTURED_NON_APPCONTAINER',
        'CAPTURED_CLASSIFICATION_CONFLICT',
        'CAPTURED_CLASSIFICATION_UNAVAILABLE',
        'CAPTURE_UNAVAILABLE',
    }
    assert set(process['discriminator']['mapping']) == {
        'CAPTURED_APPCONTAINER',
        'CAPTURED_NON_APPCONTAINER',
        'CAPTURED_CLASSIFICATION_CONFLICT',
        'CAPTURED_CLASSIFICATION_UNAVAILABLE',
    }


@pytest.mark.skipif(os.name != 'nt', reason='TerminateProcess exit-code test is Windows-only')
def test_revert_failure_terminates_subprocess_with_distinct_code(tmp_path):
    code = r"""
import ctypes as c
import os
import threading
from tnc.provenance import windows_appcontainer_probe as ap
from tnc.provenance.windows_pipe_context_producer import PipeContextProducer
from tnc.provenance.windows_pipe_native import OwnedPipeEndpoint
from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan
from tnc.provenance.windows_pipe_process_lease import OwnedProcessLease, ProcessInstancePin, ProcessLeasePlan
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI

class F:
    def __init__(self, fn): self.fn=fn; self.argtypes=None; self.restype=None
    def __call__(self,*a): return self.fn(*a)
real = c.WinDLL('kernel32.dll', use_last_error=True)
real.GetCurrentProcess.argtypes=[]; real.GetCurrentProcess.restype=c.c_void_p
real.TerminateProcess.argtypes=[c.c_void_p,c.c_uint32]; real.TerminateProcess.restype=c.c_int32
class K:
    def __init__(self):
        self.GetCurrentThread=F(lambda: 1)
        self.CloseHandle=F(lambda h: True)
        self.GetCurrentProcess=F(real.GetCurrentProcess)
        self.TerminateProcess=F(real.TerminateProcess)
class S:
    def __init__(self):
        self.error=0
        self.ImpersonateNamedPipeClient=F(lambda p: True)
        self.OpenThreadToken=F(self.open_thread)
        self.OpenProcessToken=F(self.open_process)
        self.RevertToSelf=F(lambda: False)
        self.GetTokenInformation=F(lambda *a: False)
    def open_thread(self,t,r,a,o):
        c.cast(o,c.POINTER(c.c_void_p)).contents.value=42
        return True
    def open_process(self,p,r,o):
        c.cast(o,c.POINTER(c.c_void_p)).contents.value=43
        return True
security=S()
api=NativePipeTokenAPI(kernel_for_testing=K(),security_for_testing=security,last_error_for_testing=lambda:security.error)
probe=ap.NativeAppContainerProbe(security_for_testing=type('Q',(),{'GetTokenInformation':F(lambda *a:False)})(),last_error_for_testing=lambda:5)
ep=object.__new__(OwnedPipeEndpoint); ep._identity=(os.getpid(),threading.get_ident()); ep._fatal=ep._closed=False; ep._handle=77; ep._connected=True; ep._active=None
plan=PipeOperationPlan(operation_id='connect-op',kind='CONNECT',pipe_lease_id='pipe-lease',event_id='event',overlapped_id='overlapped',buffer_id='buffer',buffer_size=0,created_tick=1,request_deadline=10,cleanup_deadline=11)
op=type('O',(),{})(); op._plan=plan; ep._operations={'connect-op':op}
lease=object.__new__(OwnedProcessLease); lease._owner=(os.getpid(),threading.get_ident()); lease._fatal=lease._consumed=False; lease._endpoint=ep; lease._pipe=77; lease._handle=88; lease._plan=ProcessLeasePlan(operation_id='process-lease',created_tick=1,deadline=9,cleanup_deadline=10); lease._pin=ProcessInstancePin(pid=1234,creation_filetime=5678)
PipeContextProducer(api=api,probe=probe).produce(lease)
print('UNSAFE_AFTER_REVERT')
"""
    completed = subprocess.run(
        [sys.executable, '-c', code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == EXIT_REVERT_FAILED
    assert completed.stdout == ''
    assert completed.stderr == ''
