"""Disposable native Windows tests for the process API boundary.

These tests exercise real kernel process handles and named-pipe peer PID queries.
They do not connect the native adapter to OwnedProcessLease, grants, or signing.
"""
import ctypes as c
import os
import sys

import pytest

import test_windows_pipe_process as pipe
from tnc.provenance import windows_pipe_native as n
from tnc.provenance import windows_pipe_process_native as p
from tnc.provenance.windows_identity import read_windows_operator_identity

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows process API tests')


def _idle_child(control):
    try:
        pipe._send(control, kind='ready', pid=os.getpid())
        assert pipe._receive(control)['kind'] == 'exit'
        pipe._send(control, kind='exiting')
    finally:
        control.close()


def _handle_count():
    kernel = c.WinDLL('kernel32', use_last_error=True, winmode=0x800)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = p.HANDLE
    kernel.GetProcessHandleCount.argtypes = [p.HANDLE, c.POINTER(p.DWORD)]
    kernel.GetProcessHandleCount.restype = p.BOOL
    value = p.DWORD()
    assert kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), c.byref(value))
    return value.value


def _native_peer_server(control, name):
    try:
        identity = read_windows_operator_identity()
        pipe_api = n.NativePipeApi()
        checks = pipe._NativeChecks(pipe_api)
        endpoint = n.OwnedPipeEndpoint(policy=pipe._policy(name, identity, checks), api=pipe_api)
        pipe._send(control, kind='ready', name=name, pid=os.getpid(), birth=checks.birth(os.getpid()))
        assert pipe._receive(control)['kind'] == 'connect'
        connect = endpoint.begin_connect(pipe._plan('CONNECT', 1))
        pipe._send(control, kind='connecting')
        assert connect.wait_until(connect._plan.request_deadline)
        connect.dispose()
        process_api = p.NativeProcessAPI()
        client_pid = process_api.client_process_id(endpoint._handle)
        pipe._send(control, kind='peer', client_pid=client_pid)
        assert pipe._receive(control)['kind'] == 'close'
        endpoint.close()
        pipe._send(control, kind='closed')
    except BaseException as error:
        try:
            pipe._send(control, kind='error', detail=type(error).__name__+':'+str(error)[:500])
        finally:
            os._exit(81)
    finally:
        control.close()


@pytest.fixture
def harness():
    value = pipe._Harness()
    yield value
    value.stop()


def test_native_process_handle_identity_lifetime_and_close(harness):
    child, control = harness.spawn(_idle_child)
    ready = pipe._receive(control)
    assert ready == {'kind': 'ready', 'pid': child.pid}

    api = p.NativeProcessAPI()
    baseline = _handle_count()
    handle = api.open_process(child.pid, p.PROCESS_LEASE_RIGHTS, False)
    assert _handle_count() == baseline + 1
    assert api.process_id(handle) == child.pid
    created = api.creation_filetime(handle)
    assert type(created) is int and 0 < created <= 0xFFFFFFFFFFFFFFFF
    assert api.creation_filetime(handle) == created
    assert api.wait_process(handle, 0) == p.WAIT_TIMEOUT

    pipe._send(control, kind='exit')
    assert pipe._receive(control) == {'kind': 'exiting'}
    harness.join(child)
    assert api.wait_process(handle, 0) == p.WAIT_OBJECT_0
    assert api.process_id(handle) == ready['pid']
    assert api.creation_filetime(handle) == created
    api.close(handle)
    assert _handle_count() == baseline


def test_native_repeated_open_close_does_not_accumulate_handles(harness):
    child, control = harness.spawn(_idle_child)
    assert pipe._receive(control)['pid'] == child.pid
    api = p.NativeProcessAPI()
    baseline = _handle_count()
    for _ in range(8):
        handle = api.open_process(child.pid, p.PROCESS_LEASE_RIGHTS, False)
        assert api.process_id(handle) == child.pid
        assert api.wait_process(handle, 0) == p.WAIT_TIMEOUT
        api.close(handle)
        assert _handle_count() == baseline
    pipe._send(control, kind='exit')
    assert pipe._receive(control) == {'kind': 'exiting'}
    harness.join(child)


def test_native_named_pipe_client_pid_matches_disposable_client(harness):
    name = r'\\.\pipe\TNC-native-process-' + os.urandom(12).hex()
    server, server_control = harness.spawn(_native_peer_server, name)
    info = pipe._receive(server_control)
    assert info['kind'] == 'ready' and info['pid'] == server.pid
    pipe._send(server_control, kind='connect')
    assert pipe._receive(server_control) == {'kind': 'connecting'}

    client, client_control = harness.spawn(pipe._client, info, 'idle')
    opened = pipe._receive(client_control)
    assert opened['kind'] == 'opened' and opened['pid'] == client.pid
    peer = pipe._receive(server_control)
    assert peer == {'kind': 'peer', 'client_pid': client.pid}

    pipe._send(client_control, kind='close')
    assert pipe._receive(client_control) == {'kind': 'done'}
    harness.join(client)
    pipe._send(server_control, kind='close')
    assert pipe._receive(server_control) == {'kind': 'closed'}
    harness.join(server)


def test_native_process_adapter_does_not_claim_lease_or_authorization():
    api = p.NativeProcessAPI()
    assert not hasattr(api, 'authorization_granted')
    assert not hasattr(api, 'acquire_process_lease')
