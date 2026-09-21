"""Producer-only tests for bound native pipe-context evidence."""
import ctypes as c
import os
import subprocess
import sys
import threading

import pytest
from pydantic import TypeAdapter

from tnc.provenance import windows_appcontainer_probe as ap
from tnc.provenance.windows_appcontainer_evidence import AppContainerTokenEvidence
from tnc.provenance.windows_pipe_context_producer import (
    EXIT_REVERT_FAILED,
    PipeContextProducer,
    PipeContextProducerError,
    PipePeerAdmissionEvidence,
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
    def __init__(self, events, *, impersonate=True, open_ok=True, revert=True, open_error=5):
        self.events = events
        self.impersonate_ok, self.open_ok, self.revert_ok = impersonate, open_ok, revert
        self.error = open_error
        self.ImpersonateNamedPipeClient = Function(self.impersonate)
        self.OpenThreadToken = Function(self.open)
        self.RevertToSelf = Function(self.revert)
        self.GetTokenInformation = Function(lambda *args: False)
    def impersonate(self, pipe):
        self.events.append(('impersonate', int(pipe)))
        return self.impersonate_ok
    def open(self, thread, rights, open_as_self, out):
        self.events.append(('open', int(rights), bool(open_as_self)))
        if not self.open_ok:
            return False
        c.cast(out, c.POINTER(c.c_void_p)).contents.value = 42
        return True
    def revert(self):
        self.events.append(('revert',))
        return self.revert_ok


class ProbeSecurity:
    def __init__(self, *, app=False, fail_kind=None):
        self.error = ap.ERROR_INSUFFICIENT_BUFFER
        self.app, self.fail_kind = app, fail_kind
        self.GetTokenInformation = Function(self.query)
    def query(self, token, kind, buffer, capacity, returned):
        out = c.cast(returned, c.POINTER(ap.DWORD)).contents
        if kind == self.fail_kind:
            self.error, out.value = 5, 0
            return False
        if kind == ap.TOKEN_IS_APPCONTAINER:
            c.cast(buffer, c.POINTER(ap.DWORD)).contents.value = int(self.app)
            out.value = 4
            return True
        if buffer is None:
            self.error, out.value = ap.ERROR_INSUFFICIENT_BUFFER, (
                4 if kind == ap.TOKEN_CAPABILITIES else c.sizeof(ap.TOKEN_APPCONTAINER_INFORMATION)
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


def probe(*, app=False, fail_kind=None):
    security = ProbeSecurity(app=app, fail_kind=fail_kind)
    return ap.NativeAppContainerProbe(
        security_for_testing=security,
        last_error_for_testing=lambda: security.error,
    )


def live_lease():
    endpoint = object.__new__(OwnedPipeEndpoint)
    endpoint._identity = (os.getpid(), threading.get_ident())
    endpoint._fatal = endpoint._closed = False
    endpoint._handle, endpoint._connected, endpoint._active = 77, True, None
    plan = PipeOperationPlan(
        operation_id='connect-op', kind='CONNECT', pipe_lease_id='pipe-lease',
        event_id='event', overlapped_id='overlapped', buffer_id='buffer',
        buffer_size=0, created_tick=1, request_deadline=10, cleanup_deadline=11,
    )
    operation = type('Operation', (), {})()
    operation._plan = plan
    endpoint._operations = {'connect-op': operation}

    lease = object.__new__(OwnedProcessLease)
    lease._owner = (os.getpid(), threading.get_ident())
    lease._fatal = lease._consumed = False
    lease._endpoint, lease._pipe, lease._handle = endpoint, 77, 88
    lease._plan = ProcessLeasePlan(
        operation_id='process-lease', created_tick=1, deadline=9, cleanup_deadline=10
    )
    lease._pin = ProcessInstancePin(pid=1234, creation_filetime=5678)
    return lease


def produce(*, app=False, fail_kind=None, **api_options):
    events = []
    item = PipeContextProducer(
        api=native_api(events, **api_options),
        probe=probe(app=app, fail_kind=fail_kind),
    ).produce(live_lease())
    return item, events


def test_native_sequence_and_open_as_self_are_explicit():
    item, events = produce()
    assert item.status == 'CAPTURED_NON_APPCONTAINER'
    assert events[:3] == [
        ('impersonate', 77),
        ('open', 8, True),
        ('revert',),
    ]
    assert events[-1] == ('close', 42)


@pytest.mark.parametrize('stage,options', [
    ('IMPERSONATE', dict(impersonate=False)),
    ('OPEN_THREAD_TOKEN', dict(open_ok=False, open_error=5)),
])
def test_capture_unavailable_is_bound_and_diagnostic(stage, options):
    item, events = produce(**options)
    assert item.status == 'CAPTURE_UNAVAILABLE'
    assert item.failed_stage == stage
    assert item.connection_operation_id == 'connect-op'
    assert item.pipe_lease_id == 'pipe-lease'
    assert item.process_lease_operation_id == 'process-lease'
    assert item.process_pid == 1234 and item.process_creation_filetime == 5678
    assert item.capture_ordinal == 1
    if stage == 'OPEN_THREAD_TOKEN':
        assert item.winerror == 5
        assert ('revert',) in events


@pytest.mark.parametrize('kind', [ap.TOKEN_IS_APPCONTAINER, ap.TOKEN_APPCONTAINER_SID])
def test_post_revert_probe_failure_is_server_side_and_closes(kind):
    item, events = produce(fail_kind=kind)
    assert item.status == 'CAPTURED_CLASSIFICATION_UNAVAILABLE'
    assert item.failure_scope == 'SERVER_CLASSIFICATION'
    assert item.information_class == kind
    assert item.failure_reason != 'PEER_EVIDENCE_UNAVAILABLE'
    assert item.winerror == 5
    assert events.index(('revert',)) < events.index(('close', 42))


def test_class_30_unavailability_still_classifies_and_closes():
    item, events = produce(fail_kind=ap.TOKEN_CAPABILITIES)
    assert item.status == 'CAPTURED_NON_APPCONTAINER'
    assert item.evidence.capability_sids is None
    assert events[-1] == ('close', 42)


def test_appcontainer_variant_is_bound_pipe_token_evidence():
    item, _ = produce(app=True)
    assert item.status == 'CAPTURED_APPCONTAINER'
    assert item.classification_source == 'PIPE_TOKEN'
    assert item.evidence.token_is_app_container is True


def test_real_classifier_conflict_routes_to_conflict_variant(monkeypatch):
    conflict_evidence = AppContainerTokenEvidence(
        source='FAKE_TOKEN_API',
        token_type='IMPERSONATION',
        level='IMPERSONATION',
        token_is_app_container=False,
        app_container_sid='S-1-15-2-1',
        capability_sids=(),
    )
    monkeypatch.setattr(
        ap.NativeAppContainerProbe,
        'probe',
        lambda self, token, *, token_type, level: conflict_evidence,
    )
    item, events = produce()
    assert item.status == 'CAPTURED_CLASSIFICATION_CONFLICT'
    assert item.reason == 'APPCONTAINER_SIGNAL_CONFLICT'
    assert events.index(('revert',)) < events.index(('close', 42))


def test_classifier_conflict_is_distinct_from_query_unavailability(monkeypatch):
    class Result:
        status = 'INDETERMINATE'
        reason = 'APPCONTAINER_SIGNAL_CONFLICT'
    monkeypatch.setattr(
        'tnc.provenance.windows_pipe_context_producer.evaluate_appcontainer_exclusion',
        lambda evidence: Result(),
    )
    item, events = produce()
    assert item.status == 'CAPTURED_CLASSIFICATION_CONFLICT'
    assert item.classification_source == 'PIPE_TOKEN'
    assert item.reason == 'APPCONTAINER_SIGNAL_CONFLICT'
    assert not hasattr(item, 'information_class')
    assert not hasattr(item, 'winerror')
    assert events.index(('revert',)) < events.index(('close', 42))


def test_unproven_at_impersonation_is_an_invariant_violation(monkeypatch):
    class Result:
        status = 'UNPROVEN'
        reason = 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN'
    monkeypatch.setattr(
        'tnc.provenance.windows_pipe_context_producer.evaluate_appcontainer_exclusion',
        lambda evidence: Result(),
    )
    with pytest.raises(PipeContextProducerError, match='UNEXPECTED_CLASSIFIER_OUTCOME'):
        produce()


def test_capture_is_one_shot_per_live_lease():
    events = []
    lease = live_lease()
    producer = PipeContextProducer(api=native_api(events), probe=probe())
    assert producer.produce(lease).capture_ordinal == 1
    with pytest.raises(PipeContextProducerError, match='CONNECTION_ALREADY_CAPTURED'):
        producer.produce(lease)


def test_schema_is_frozen_and_public_surface_has_no_variant_constructors():
    item, _ = produce()
    with pytest.raises(Exception):
        item.capture_ordinal = 2
    import tnc.provenance.windows_pipe_context_producer as module
    assert all(not name.startswith('_Captured') for name in module.__all__)


def test_schema_is_sufficient_for_future_evaluator_mapping(monkeypatch):
    adapter = TypeAdapter(PipePeerAdmissionEvidence)

    class ConflictResult:
        status = 'INDETERMINATE'
        reason = 'APPCONTAINER_SIGNAL_CONFLICT'

    with monkeypatch.context() as patch:
        patch.setattr(
            'tnc.provenance.windows_pipe_context_producer.evaluate_appcontainer_exclusion',
            lambda evidence: ConflictResult(),
        )
        conflict = produce()[0]

    samples = [
        produce(app=True)[0],
        produce()[0],
        conflict,
        produce(fail_kind=ap.TOKEN_IS_APPCONTAINER)[0],
        produce(open_ok=False)[0],
    ]

    def future_disposition(value):
        value = adapter.validate_python(value)
        return {
            'CAPTURED_APPCONTAINER': 'DENY_APP_CONTAINER',
            'CAPTURED_NON_APPCONTAINER': 'CONTINUE',
            'CAPTURED_CLASSIFICATION_CONFLICT': 'INDETERMINATE_CLASSIFICATION_CONFLICT',
            'CAPTURED_CLASSIFICATION_UNAVAILABLE': 'INDETERMINATE_SERVER_CLASSIFICATION',
            'CAPTURE_UNAVAILABLE': 'INDETERMINATE_CAPTURE',
        }[value.status]

    assert [future_disposition(value) for value in samples] == [
        'DENY_APP_CONTAINER',
        'CONTINUE',
        'INDETERMINATE_CLASSIFICATION_CONFLICT',
        'INDETERMINATE_SERVER_CLASSIFICATION',
        'INDETERMINATE_CAPTURE',
    ]


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
        self.OpenThreadToken=F(self.open)
        self.RevertToSelf=F(lambda: False)
        self.GetTokenInformation=F(lambda *a: False)
    def open(self,t,r,a,o):
        c.cast(o,c.POINTER(c.c_void_p)).contents.value=42
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
        [sys.executable, '-c', code], capture_output=True, text=True, check=False
    )
    assert completed.returncode == EXIT_REVERT_FAILED
    assert completed.stdout == ''
    assert completed.stderr == ''
