"""Native process-lease integration tests without authorization promotion."""
import ctypes as c
import os
import sys
import time
import uuid

import pytest
import test_windows_pipe_token as token_test
from tnc.provenance import windows_pipe_native as pipe_native
from tnc.provenance import windows_pipe_process_lease as lease_mod
from tnc.provenance import windows_pipe_process_native as process_native
from tnc.provenance.windows_custody_peer import WindowsPeerPolicy, PeerProcess


class FakeFunction:
    def __init__(self, result=None, callback=None):
        self.result, self.callback, self.calls = result, callback, []
        self.argtypes = self.restype = None

    def __call__(self, *args):
        self.calls.append(args)
        return self.callback(*args) if self.callback is not None else self.result


class FakeKernel:
    def __init__(self):
        self.pipe_pid, self.pid, self.birth, self.handle = 1, 1, 100, 500
        self.OpenProcess = FakeFunction(self.handle)
        self.GetProcessId = FakeFunction(callback=lambda _h: self.pid)
        self.GetProcessTimes = FakeFunction(callback=self._times)
        self.WaitForSingleObject = FakeFunction(process_native.WAIT_TIMEOUT)
        self.CloseHandle = FakeFunction(1)
        self.GetNamedPipeClientProcessId = FakeFunction(callback=self._pipe_pid)

    def _pipe_pid(self, _handle, output):
        c.cast(output, c.POINTER(process_native.DWORD)).contents.value = self.pipe_pid
        return 1

    def _times(self, _handle, created, _exited, _kernel, _user):
        value = c.cast(created, c.POINTER(process_native.FILETIME)).contents
        value.dwHighDateTime = self.birth >> 32
        value.dwLowDateTime = self.birth & 0xFFFFFFFF
        return 1


@pytest.fixture
def native_env(monkeypatch):
    monkeypatch.setattr('ctypes.WinDLL', lambda *a, **k: pytest.fail('Real DLL load forbidden'), raising=False)
    clock, pipe_api, kernel = token_test.Clock(), token_test.FakePipe(), FakeKernel()
    policy = WindowsPeerPolicy(deployment_id='d', store_instance_id='s', pipe_name=r'\\.\pipe\TNC-native-lease',
        service_sid='S-1-5-80-100', client_sid='S-1-5-21-100', logon_sid='S-1-5-5-300-400',
        authentication_id=6, expected_process=PeerProcess(pid=1, creation_filetime=100, session_id=3, running=True),
        timestamp=1, expiry=2)
    endpoint = pipe_native.OwnedPipeEndpoint(policy=policy, api=pipe_api, clock=clock)
    connect = endpoint.begin_connect(token_test.plan('CONNECT', 'connect'))
    connect.dispose()
    api = process_native.NativeProcessAPI(kernel)
    yield endpoint, api, kernel, clock
    with lease_mod._LOCK:
        lease_mod._LEASES.clear()
    with pipe_native._OWNERS_LOCK:
        pipe_native._OWNERS.clear()


def _pin():
    return lease_mod.ProcessInstancePin(pid=1, creation_filetime=100)


def _plan():
    return lease_mod.ProcessLeasePlan(operation_id='native-lease', created_tick=10, deadline=20, cleanup_deadline=30)


def acquire(env):
    endpoint, api, _, clock = env
    return lease_mod.acquire_process_lease_native(endpoint, _pin(), _plan(), api=api, clock=clock)


def test_native_entry_retains_and_releases_exact_handle(native_env):
    endpoint, _, kernel, _ = native_env
    owned = acquire(native_env)
    assert len(kernel.OpenProcess.calls) == 1 and not kernel.CloseHandle.calls
    result = owned.finish()
    assert result.status == 'CORRELATED' and result.reason == 'AUDIT_MATCHED'
    assert result.source == 'NATIVE_PROCESS_API' and result.audit_only and not result.authorization_granted
    assert len(kernel.CloseHandle.calls) == 1 and not lease_mod._LEASES
    endpoint.close()


def test_native_entry_rejects_subclass_to_protect_source_label(native_env):
    class Derived(process_native.NativeProcessAPI):
        pass
    endpoint, api, _, clock = native_env
    derived = Derived(api._kernel32)
    with pytest.raises(lease_mod.ProcessLeaseError, match='EXPLICIT_NATIVE_INPUTS_REQUIRED'):
        lease_mod.acquire_process_lease_native(endpoint, _pin(), _plan(), api=derived, clock=clock)


def test_native_pipe_pid_mismatch_releases_without_open(native_env):
    endpoint, _, kernel, _ = native_env
    kernel.pipe_pid = 2
    with pytest.raises(lease_mod.ProcessLeaseError, match='PIPE_PID_MISMATCH'):
        acquire(native_env)
    assert not kernel.OpenProcess.calls and not kernel.CloseHandle.calls and not lease_mod._LEASES
    assert not endpoint._process_lease_active


def test_native_open_failure_is_definitive_unavailable(native_env, monkeypatch):
    endpoint, _, kernel, _ = native_env
    kernel.OpenProcess.result = 0
    monkeypatch.setattr(process_native.c, 'get_last_error', lambda: 5, raising=False)
    with pytest.raises(lease_mod.ProcessLeaseError, match='PROCESS_UNAVAILABLE'):
        acquire(native_env)
    assert len(kernel.OpenProcess.calls) == 1 and not kernel.CloseHandle.calls and not lease_mod._LEASES
    assert not endpoint._process_lease_active


def test_native_post_open_api_failure_closes_then_reports_uncertain(native_env, monkeypatch):
    endpoint, _, kernel, _ = native_env
    kernel.GetProcessId.callback = None
    kernel.GetProcessId.result = 0
    monkeypatch.setattr(process_native.c, 'get_last_error', lambda: 6, raising=False)
    with pytest.raises(lease_mod.ProcessLeaseError, match='NATIVE_API_UNCERTAIN'):
        acquire(native_env)
    assert len(kernel.OpenProcess.calls) == 1 and len(kernel.CloseHandle.calls) == 1
    assert not lease_mod._LEASES and not endpoint._process_lease_active


def test_native_creation_mismatch_closes_known_handle(native_env):
    endpoint, _, kernel, _ = native_env
    kernel.birth = 101
    with pytest.raises(lease_mod.ProcessLeaseError, match='PROCESS_CORRELATION_FAILED'):
        acquire(native_env)
    assert len(kernel.CloseHandle.calls) == 1 and not lease_mod._LEASES
    assert not endpoint._process_lease_active


def test_native_close_failure_requires_containment(native_env, monkeypatch):
    owned = acquire(native_env)
    endpoint, _, kernel, _ = native_env
    kernel.CloseHandle.result = 0
    monkeypatch.setattr(process_native.c, 'get_last_error', lambda: 6, raising=False)
    with pytest.raises(lease_mod.ProcessLeaseContainment, match='WORKER_SHUTDOWN_REQUIRED'):
        owned.finish()
    assert lease_mod._LEASES[id(owned)] is owned and endpoint._fatal


def test_native_adapter_close_contract_returns_true(native_env):
    _, api, kernel, _ = native_env
    assert api.close(500) is True
    assert len(kernel.CloseHandle.calls) == 1


def _native_client(control, name):
    import test_windows_pipe_process as pipe_test
    try:
        process_api = process_native.NativeProcessAPI()
        own = process_api.open_process(os.getpid(), process_native.PROCESS_LEASE_RIGHTS, False)
        try:
            birth = process_api.creation_filetime(own)
        finally:
            assert process_api.close(own) is True
        pipe_test._send(control, kind='ready', pid=os.getpid(), birth=birth)
        assert pipe_test._receive(control)['kind'] == 'open'
        pipe_api = pipe_native.NativePipeApi()
        checks = pipe_test._NativeChecks(pipe_api)
        handle, error = checks.open_client(name)
        assert pipe_native._valid_handle(handle), error
        pipe_test._send(control, kind='opened')
        assert pipe_test._receive(control)['kind'] == 'close'
        assert pipe_api.close(handle)
        pipe_test._send(control, kind='closed')
    finally:
        control.close()


def _native_server(control, name, expected):
    import test_windows_pipe_process as pipe_test
    from tnc.provenance.windows_identity import read_windows_operator_identity
    try:
        identity = read_windows_operator_identity()
        pipe_api = pipe_native.NativePipeApi()
        checks = pipe_test._NativeChecks(pipe_api)
        other = 'S-1-5-18' if identity.user_sid != 'S-1-5-18' else 'S-1-5-19'
        policy = WindowsPeerPolicy(deployment_id='native-test', store_instance_id='native-store', pipe_name=name,
            service_sid=identity.user_sid, client_sid=other, logon_sid='S-1-5-5-1-2', authentication_id=1,
            expected_process=PeerProcess(pid=expected['pid'], creation_filetime=expected['birth'], session_id=0, running=True),
            timestamp=1, expiry=2)
        baseline = checks.handles()
        endpoint = pipe_native.OwnedPipeEndpoint(policy=policy, api=pipe_api)
        connect = endpoint.begin_connect(pipe_test._plan('CONNECT', 1))
        pipe_test._send(control, kind='connecting')
        assert connect.wait_until(connect._plan.request_deadline)
        connect.dispose()
        tick = time.monotonic_ns() // 1_000_000
        plan = lease_mod.ProcessLeasePlan(operation_id='native-real-lease', created_tick=tick,
            deadline=tick+4000, cleanup_deadline=tick+5000)
        pin = lease_mod.ProcessInstancePin(pid=expected['pid'], creation_filetime=expected['birth'])
        process_api = process_native.NativeProcessAPI()
        owned = lease_mod.acquire_process_lease_native(endpoint, pin, plan,
            api=process_api, clock=lambda: time.monotonic_ns() // 1_000_000)
        result = owned.finish()
        endpoint.close()
        pipe_test._send(control, kind='done', status=result.status, source=result.source,
            authorized=result.authorization_granted, delta=checks.handles()-baseline)
    finally:
        control.close()


@pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows process lease integration')
def test_real_named_pipe_process_lease_correlates_and_cleans_up():
    import test_windows_pipe_process as pipe_test
    harness = pipe_test._Harness()
    try:
        name = r'\\.\pipe\TNC-native-lease-' + uuid.uuid4().hex
        client, client_control = harness.spawn(_native_client, name)
        expected = pipe_test._receive(client_control)
        assert expected['kind'] == 'ready' and expected['pid'] == client.pid
        server, server_control = harness.spawn(_native_server, name, expected)
        assert pipe_test._receive(server_control)['kind'] == 'connecting'
        pipe_test._send(client_control, kind='open')
        assert pipe_test._receive(client_control)['kind'] == 'opened'
        done = pipe_test._receive(server_control)
        assert done == {'kind': 'done', 'status': 'CORRELATED', 'source': 'NATIVE_PROCESS_API',
                        'authorized': False, 'delta': 0}
        pipe_test._send(client_control, kind='close')
        assert pipe_test._receive(client_control)['kind'] == 'closed'
        harness.join(client)
        harness.join(server)
    finally:
        harness.stop()
