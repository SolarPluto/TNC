"""Read-only real Windows checks plus deterministic token-error/cleanup tests."""
import csv
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import tnc.provenance.windows_identity as module


class FakeAPI:
    def __init__(self, *, threads=(None, None), failure=None, elevation=0, token_type=1, sid='S-1-5-21-1-2-3-1001'):
        self.threads = iter(threads)
        self.failure, self.elevation, self.token_type, self.sid = failure, elevation, token_type, sid
        self.calls, self.closed = [], []

    def open_thread_token(self):
        self.calls.append('thread')
        result = next(self.threads)
        if isinstance(result, Exception):
            raise result
        return result

    def open_process_token(self):
        self.calls.append('process')
        if self.failure == 'process':
            raise OSError('private OS error')
        return 42

    def dword(self, token, kind):
        self.calls.append(kind)
        if self.failure == kind:
            raise OSError('private token error')
        return self.token_type if kind == module.TOKEN_TYPE else self.elevation

    def user_sid(self, token):
        self.calls.append('sid')
        if self.failure == 'sid':
            raise OSError('private SID error')
        return self.sid

    def close(self, token):
        self.closed.append(token)
        if self.failure == 'close':
            raise OSError('cleanup failed')

    def process_id(self):
        return 100

    def thread_id(self):
        return 200


@pytest.mark.parametrize('elevation', [0, 1])
def test_returns_facts_only_and_closes_process_token(elevation):
    api = FakeAPI(elevation=elevation)
    result = module._read_current_operator(api)
    assert result.process_id == 100 and result.thread_id == 200
    assert result.elevated is bool(elevation)
    assert set(result.model_dump()) == {'user_sid', 'process_id', 'thread_id', 'elevated'}
    assert api.closed == [42]
    assert api.calls == ['thread', 'process', module.TOKEN_TYPE, 'sid', module.TOKEN_ELEVATION, 'thread']
    with pytest.raises(ValidationError):
        result.user_sid = 'S-1-5-18'


def test_impersonation_denied_without_process_fallback():
    api = FakeAPI(threads=(77,))
    with pytest.raises(module.WindowsIdentityError):
        module._read_current_operator(api)
    assert api.calls == ['thread'] and api.closed == [77]


def test_thread_error_does_not_fall_back():
    api = FakeAPI(threads=(OSError('access denied'),))
    with pytest.raises(OSError):
        module._read_current_operator(api)
    assert api.calls == ['thread'] and api.closed == []


def test_impersonation_detected_at_final_observation_closes_both_handles():
    api = FakeAPI(threads=(None, 77))
    with pytest.raises(module.WindowsIdentityError):
        module._read_current_operator(api)
    assert api.closed == [77, 42]


@pytest.mark.parametrize('failure', ['process', 'sid', module.TOKEN_TYPE, module.TOKEN_ELEVATION, 'close'])
def test_failures_release_acquired_process_token(failure):
    api = FakeAPI(failure=failure)
    with pytest.raises(OSError):
        module._read_current_operator(api)
    assert api.closed == ([] if failure == 'process' else [42])


@pytest.mark.parametrize('changes', [{'token_type': 2}, {'elevation': 2}, {'sid': 'not-a-sid'}])
def test_malformed_facts_fail_closed(changes):
    api = FakeAPI(**changes)
    with pytest.raises((module.WindowsIdentityError, ValidationError)):
        module._read_current_operator(api)
    assert api.closed == [42]


def test_public_error_is_generic(monkeypatch):
    monkeypatch.setattr(module.sys, 'platform', 'win32')
    monkeypatch.setattr(module, '_WindowsTokenAPI', lambda: FakeAPI(failure='sid'))
    with pytest.raises(module.WindowsIdentityError, match='^Windows operator identity unavailable$'):
        module.read_windows_operator_identity()


def test_non_windows_has_no_fallback(monkeypatch):
    monkeypatch.setattr(module.sys, 'platform', 'linux')
    def never():
        raise AssertionError('must not load native libraries')
    monkeypatch.setattr(module, '_WindowsTokenAPI', never)
    with pytest.raises(module.WindowsIdentityError):
        module.read_windows_operator_identity()


def test_public_api_accepts_no_claimed_identity():
    with pytest.raises(TypeError):
        module.read_windows_operator_identity(user_sid='S-1-5-18')


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows last-error API')
@pytest.mark.parametrize('error', [module.ERROR_NO_TOKEN, 5, 1347])
def test_only_no_token_allows_native_fallback(error):
    api = object.__new__(module._WindowsTokenAPI)
    def open_thread(thread, access, as_self, handle):
        assert access == module.TOKEN_QUERY and as_self is True
        ctypes.set_last_error(error)
        return False
    api.security = SimpleNamespace(OpenThreadToken=open_thread)
    api.kernel = SimpleNamespace(GetCurrentThread=lambda: -2)
    if error == module.ERROR_NO_TOKEN:
        assert api.open_thread_token() is None
    else:
        with pytest.raises(module.WindowsIdentityError):
            api.open_thread_token()


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows last-error API')
@pytest.mark.parametrize('size', [0, module.MAX_TOKEN_BUFFER+1])
def test_native_buffer_size_bounded(size):
    api = object.__new__(module._WindowsTokenAPI)
    def information(handle, kind, buffer, capacity, returned):
        ctypes.cast(returned, ctypes.POINTER(wintypes.DWORD))[0] = size
        ctypes.set_last_error(module.ERROR_INSUFFICIENT_BUFFER)
        return False
    api.security = SimpleNamespace(GetTokenInformation=information)
    with pytest.raises(module.WindowsIdentityError):
        api.information(42, module.TOKEN_USER)


@pytest.mark.parametrize('kind', ['short', 'null', 'outside', 'truncated', 'too_many'])
def test_native_sid_bounds_checked_before_conversion(kind):
    api = object.__new__(module._WindowsTokenAPI)
    buffer = ctypes.create_string_buffer(128)
    start = ctypes.addressof(buffer)
    record = module._SID_AND_ATTRIBUTES.from_buffer(buffer)
    address = start + ctypes.sizeof(record)
    record.Sid = address
    ctypes.c_ubyte.from_address(address).value = 1
    ctypes.c_ubyte.from_address(address+1).value = 4
    length = 128
    if kind == 'short':
        length = 1
    elif kind == 'null':
        record.Sid = None
    elif kind == 'outside':
        record.Sid = start-1
    elif kind == 'truncated':
        length = ctypes.sizeof(record)+8
    else:
        ctypes.c_ubyte.from_address(address+1).value = 16
    api.information = lambda *_: (buffer, length)
    api.security = SimpleNamespace()  # Any native call would fail the test.
    with pytest.raises(module.WindowsIdentityError):
        api.user_sid(42)


def test_sid_allocation_is_freed():
    api = object.__new__(module._WindowsTokenAPI)
    buffer = ctypes.create_string_buffer(128)
    record = module._SID_AND_ATTRIBUTES.from_buffer(buffer)
    record.Sid = ctypes.addressof(buffer)+ctypes.sizeof(record)
    ctypes.c_ubyte.from_address(record.Sid+1).value = 1
    sid_string = ctypes.create_unicode_buffer('S-1-5-18')
    freed = []
    def convert(sid, target):
        ctypes.cast(target, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(sid_string)
        return True
    api.information = lambda *_: (buffer, 128)
    api.security = SimpleNamespace(IsValidSid=lambda _: True, ConvertSidToStringSidW=convert)
    api.kernel = SimpleNamespace(LocalFree=lambda value: freed.append(value.value))
    assert api.user_sid(42) == 'S-1-5-18'
    assert freed == [ctypes.addressof(sid_string)]


@pytest.mark.parametrize('length,ok', [(0, True), (8, True), (4, False), (4, True)])
def test_native_fixed_size_scalar(length, ok):
    api = object.__new__(module._WindowsTokenAPI)
    def information(handle, kind, buffer, capacity, returned):
        assert capacity == ctypes.sizeof(wintypes.DWORD)
        ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0] = 1
        ctypes.cast(returned, ctypes.POINTER(wintypes.DWORD))[0] = length
        return ok
    api.security = SimpleNamespace(GetTokenInformation=information)
    if ok and length == ctypes.sizeof(wintypes.DWORD):
        assert api.dword(42, module.TOKEN_ELEVATION) == 1
    else:
        with pytest.raises(module.WindowsIdentityError):
            api.dword(42, module.TOKEN_ELEVATION)


@pytest.mark.skipif(sys.platform != 'win32', reason='Real Windows token inspection')
def test_real_current_process_identity_matches_windows_whoami():
    result = module.read_windows_operator_identity()
    # Independent OS utility; no SID or token contents are printed in test output.
    executable = Path(os.environ['SystemRoot'])/'System32'/'whoami.exe'
    output = subprocess.run([str(executable), '/user', '/fo', 'csv', '/nh'],
                            check=True, capture_output=True, text=True, timeout=10).stdout
    expected = next(csv.reader(output.strip().splitlines()))[1]
    assert result.user_sid == expected
    assert result.process_id == os.getpid()
    assert result.thread_id == threading.get_native_id()
    assert type(result.elevated) is bool


@pytest.mark.skipif(sys.platform != 'win32', reason='Real Windows token inspection')
def test_repeated_reads_return_same_operator_facts():
    first = module.read_windows_operator_identity()
    for _ in range(20):
        assert module.read_windows_operator_identity() == first
