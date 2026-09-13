"""Fake-injection tests for the lazy native Windows process adapter."""
import ctypes as c
import importlib
import sys

import pytest

from tnc.provenance import windows_pipe_process_native as n


class FakeFunction:
    def __init__(self, result=None, callback=None):
        self.result = result
        self.callback = callback
        self.calls = []
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        self.calls.append(args)
        if self.callback is not None:
            return self.callback(*args)
        return self.result


class FakeKernel:
    def __init__(self):
        self.OpenProcess = FakeFunction(500)
        self.GetProcessId = FakeFunction(123)
        self.GetProcessTimes = FakeFunction(callback=self._times)
        self.WaitForSingleObject = FakeFunction(n.WAIT_TIMEOUT)
        self.CloseHandle = FakeFunction(1)
        self.GetNamedPipeClientProcessId = FakeFunction(callback=self._pipe_pid)
        self.pipe_pid = 123
        self.creation_high = 0
        self.creation_low = 100

    def _pipe_pid(self, _handle, out_pid):
        c.cast(out_pid, c.POINTER(n.DWORD)).contents.value = self.pipe_pid
        return 1

    def _times(self, _handle, creation, _exit_time, _kernel_time, _user_time):
        value = c.cast(creation, c.POINTER(n.FILETIME)).contents
        value.dwHighDateTime = self.creation_high
        value.dwLowDateTime = self.creation_low
        return 1


def api():
    kernel = FakeKernel()
    return n.NativeProcessAPI(kernel), kernel


def test_import_is_side_effect_free(monkeypatch):
    called = []
    monkeypatch.setattr(c, "WinDLL", lambda *a, **k: called.append((a, k)), raising=False)
    importlib.reload(n)
    assert called == []


def test_injected_kernel_never_loads_windll(monkeypatch):
    monkeypatch.setattr(n.c, "WinDLL", lambda *a, **k: pytest.fail("WinDLL called"), raising=False)
    instance, _ = api()
    assert instance.process_id(500) == 123


def test_exact_ctypes_signatures_are_bound():
    instance, kernel = api()
    instance._ensure_bound()
    assert kernel.OpenProcess.argtypes == [n.DWORD, n.BOOL, n.DWORD]
    assert kernel.OpenProcess.restype is n.HANDLE
    assert kernel.GetProcessId.argtypes == [n.HANDLE]
    assert kernel.GetProcessId.restype is n.DWORD
    assert kernel.WaitForSingleObject.argtypes == [n.HANDLE, n.DWORD]
    assert kernel.WaitForSingleObject.restype is n.DWORD
    assert kernel.CloseHandle.argtypes == [n.HANDLE]
    assert kernel.CloseHandle.restype is n.BOOL
    assert kernel.GetNamedPipeClientProcessId.argtypes == [n.HANDLE, c.POINTER(n.DWORD)]
    assert kernel.GetNamedPipeClientProcessId.restype is n.BOOL
    assert kernel.GetProcessTimes.argtypes == [
        n.HANDLE,
        c.POINTER(n.FILETIME),
        c.POINTER(n.FILETIME),
        c.POINTER(n.FILETIME),
        c.POINTER(n.FILETIME),
    ]
    assert kernel.GetProcessTimes.restype is n.BOOL


def test_open_process_uses_exact_rights_and_noninheritance():
    instance, kernel = api()
    assert instance.open_process(123, n.PROCESS_LEASE_RIGHTS, False) == 500
    rights, inherit, pid = kernel.OpenProcess.calls[-1]
    assert rights.value == n.PROCESS_LEASE_RIGHTS
    assert inherit.value == 0
    assert pid.value == 123


@pytest.mark.parametrize("rights", [0, n.PROCESS_QUERY_LIMITED_INFORMATION, n.SYNCHRONIZE, True])
def test_open_process_rejects_wrong_rights_before_dispatch(rights):
    instance, kernel = api()
    with pytest.raises(ValueError, match="PROCESS_RIGHTS_MISMATCH"):
        instance.open_process(123, rights, False)
    assert not kernel.OpenProcess.calls


@pytest.mark.parametrize("inherit", [True, 0, 1, None])
def test_open_process_rejects_nonexact_false_inheritance(inherit):
    instance, kernel = api()
    with pytest.raises(ValueError, match="INHERITANCE_FORBIDDEN"):
        instance.open_process(123, n.PROCESS_LEASE_RIGHTS, inherit)
    assert not kernel.OpenProcess.calls


@pytest.mark.parametrize("pid", [True, False, 0, -1, 2**32])
def test_pid_validation_is_exact_and_predispatch(pid):
    instance, kernel = api()
    with pytest.raises(ValueError, match="INVALID_PID"):
        instance.open_process(pid, n.PROCESS_LEASE_RIGHTS, False)
    assert not kernel.OpenProcess.calls


def test_client_process_id_is_normalized_int():
    instance, kernel = api()
    kernel.pipe_pid = 456
    value = instance.client_process_id(700)
    assert type(value) is int and value == 456


def test_client_process_id_zero_fails_closed():
    instance, kernel = api()
    kernel.pipe_pid = 0
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.client_process_id(700)
    assert caught.value.operation == "GetNamedPipeClientProcessId_InvalidResult"
    assert caught.value.winerror == 0


def test_client_process_id_failure_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.GetNamedPipeClientProcessId.result = 0
    kernel.GetNamedPipeClientProcessId.callback = None
    monkeypatch.setattr(n.c, "get_last_error", lambda: 5, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.client_process_id(700)
    assert (caught.value.operation, caught.value.winerror) == ("GetNamedPipeClientProcessId", 5)


def test_open_process_null_failure_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.OpenProcess.result = 0
    monkeypatch.setattr(n.c, "get_last_error", lambda: 87, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.open_process(123, n.PROCESS_LEASE_RIGHTS, False)
    assert (caught.value.operation, caught.value.winerror) == ("OpenProcess", 87)


def test_open_process_invalid_handle_failure_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.OpenProcess.result = n.INVALID_HANDLE_VALUE
    monkeypatch.setattr(n.c, "get_last_error", lambda: 6, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.open_process(123, n.PROCESS_LEASE_RIGHTS, False)
    assert (caught.value.operation, caught.value.winerror) == ("OpenProcess", 6)


def test_process_id_zero_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.GetProcessId.result = 0
    monkeypatch.setattr(n.c, "get_last_error", lambda: 6, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.process_id(500)
    assert (caught.value.operation, caught.value.winerror) == ("GetProcessId", 6)


@pytest.mark.parametrize(
    "high,low,expected",
    [(0, 1, 1), (1, 0, 1 << 32), (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)],
)
def test_creation_filetime_exact_reconstruction(high, low, expected):
    instance, kernel = api()
    kernel.creation_high = high
    kernel.creation_low = low
    assert instance.creation_filetime(500) == expected


def test_creation_time_failure_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.GetProcessTimes.callback = None
    kernel.GetProcessTimes.result = 0
    monkeypatch.setattr(n.c, "get_last_error", lambda: 299, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.creation_filetime(500)
    assert (caught.value.operation, caught.value.winerror) == ("GetProcessTimes", 299)


@pytest.mark.parametrize("result", [n.WAIT_OBJECT_0, n.WAIT_TIMEOUT])
def test_wait_results_survive_unchanged(result):
    instance, kernel = api()
    kernel.WaitForSingleObject.result = result
    value = instance.wait_process(500, 0)
    assert type(value) is int and value == result


def test_wait_failed_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.WaitForSingleObject.result = n.WAIT_FAILED
    monkeypatch.setattr(n.c, "get_last_error", lambda: 6, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.wait_process(500, 0)
    assert (caught.value.operation, caught.value.winerror) == ("WaitForSingleObject", 6)


def test_unknown_wait_result_fails_closed():
    instance, kernel = api()
    kernel.WaitForSingleObject.result = 0x80
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.wait_process(500, 0)
    assert (caught.value.operation, caught.value.winerror) == ("WaitForSingleObject_Unexpected", 0x80)


@pytest.mark.parametrize("timeout", [True, False, -1, 2**32])
def test_invalid_wait_timeout_never_dispatches(timeout):
    instance, kernel = api()
    with pytest.raises(ValueError, match="INVALID_WAIT_TIMEOUT"):
        instance.wait_process(500, timeout)
    assert not kernel.WaitForSingleObject.calls


def test_close_failure_preserves_last_error(monkeypatch):
    instance, kernel = api()
    kernel.CloseHandle.result = 0
    monkeypatch.setattr(n.c, "get_last_error", lambda: 6, raising=False)
    with pytest.raises(n.NativeProcessAPIError) as caught:
        instance.close(500)
    assert (caught.value.operation, caught.value.winerror) == ("CloseHandle", 6)


@pytest.mark.parametrize(
    "handle",
    [True, False, 0, -1, n.INVALID_HANDLE_VALUE, n.MAX_HANDLE + 1],
)
def test_invalid_handles_never_dispatch(handle):
    for method, call_name, args in [
        ("client_process_id", "GetNamedPipeClientProcessId", (handle,)),
        ("process_id", "GetProcessId", (handle,)),
        ("creation_filetime", "GetProcessTimes", (handle,)),
        ("wait_process", "WaitForSingleObject", (handle, 0)),
        ("close", "CloseHandle", (handle,)),
    ]:
        instance, kernel = api()
        with pytest.raises(ValueError, match="INVALID_NATIVE_HANDLE"):
            getattr(instance, method)(*args)
        assert not getattr(kernel, call_name).calls


def test_fake_backend_operates_when_platform_is_not_windows(monkeypatch):
    monkeypatch.setattr(n.sys, "platform", "linux")
    instance, _ = api()
    assert instance.process_id(500) == 123


def test_real_backend_is_rejected_off_windows(monkeypatch):
    monkeypatch.setattr(n.sys, "platform", "linux")
    monkeypatch.setattr(n.c, "WinDLL", lambda *a, **k: pytest.fail("WinDLL called"), raising=False)
    instance = n.NativeProcessAPI()
    with pytest.raises(RuntimeError, match="NATIVE_PROCESS_API_REQUIRES_WINDOWS"):
        instance.process_id(500)


def test_error_record_is_stable_and_bounded():
    error = n.NativeProcessAPIError("OpenProcess", 5)
    assert str(error) == "OpenProcess"
    assert error.operation == "OpenProcess" and error.winerror == 5
    with pytest.raises(TypeError):
        n.NativeProcessAPIError("", 5)
    with pytest.raises(TypeError):
        n.NativeProcessAPIError("OpenProcess", -1)
