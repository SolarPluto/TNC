"""Shared native Windows test plumbing for AppContainer pipe experiments.

This module is a mechanical extraction of the helpers previously defined in
``test_windows_appcontainer_pipe_positive_control.py``. Keep ctypes bindings
fresh per call; callers mutate ``argtypes`` for experiment-specific APIs.
"""
# Imported by bare name under pytest prepend mode; adding tests/__init__.py or
# switching to --import-mode=importlib will break every consumer.
import ctypes as c
import sys
import time

import pytest


HANDLE = c.c_void_p
DWORD = c.c_uint32
BOOL = c.c_int32
SIZE_T = c.c_size_t
INVALID_HANDLE_VALUE = c.c_void_p(-1).value
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_PIPE_CONNECTED = 535
ERROR_IO_PENDING = 997
ERROR_NOT_FOUND = 1168
WAIT_OBJECT_0 = 0
IO_TIMEOUT_MS = 30_000
CANCEL_TIMEOUT_MS = 5_000

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_IS_APPCONTAINER = 29
TOKEN_APPCONTAINER_SID = 31
SECURITY_DESCRIPTOR_REVISION = 1
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000


class OVERLAPPED(c.Structure):
    _fields_ = [
        ('Internal', SIZE_T), ('InternalHigh', SIZE_T),
        ('Offset', DWORD), ('OffsetHigh', DWORD), ('hEvent', HANDLE),
    ]


# If cancellation itself stalls, retain native storage until process teardown.
# CancelIoEx requests cancellation; it does not make OVERLAPPED/buffers safe to
# release. Leaking on this exceptional failure is safer than use-after-free.
_undrained_io = []


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [
        ('nLength', DWORD),
        ('lpSecurityDescriptor', c.c_void_p),
        ('bInheritHandle', BOOL),
    ]


class STARTUPINFOW(c.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', c.c_wchar_p),
        ('lpDesktop', c.c_wchar_p),
        ('lpTitle', c.c_wchar_p),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', c.c_uint16),
        ('cbReserved2', c.c_uint16),
        ('lpReserved2', c.c_void_p),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE),
    ]


class STARTUPINFOEXW(c.Structure):
    _fields_ = [
        ('StartupInfo', STARTUPINFOW),
        ('lpAttributeList', c.c_void_p),
    ]


class PROCESS_INFORMATION(c.Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD),
    ]


class SECURITY_CAPABILITIES(c.Structure):
    _fields_ = [
        ('AppContainerSid', c.c_void_p),
        ('Capabilities', c.c_void_p),
        ('CapabilityCount', DWORD),
        ('Reserved', DWORD),
    ]


class TOKEN_APPCONTAINER_INFORMATION(c.Structure):
    _fields_ = [('TokenAppContainer', c.c_void_p)]


def _kernel32():
    k = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    k.CreateNamedPipeW.argtypes = [c.c_wchar_p, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, c.POINTER(SECURITY_ATTRIBUTES)]
    k.CreateNamedPipeW.restype = HANDLE
    k.CreateFileW.argtypes = [c.c_wchar_p, DWORD, DWORD, c.c_void_p, DWORD, DWORD, HANDLE]
    k.CreateFileW.restype = HANDLE
    k.ConnectNamedPipe.argtypes = [HANDLE, c.c_void_p]
    k.ConnectNamedPipe.restype = BOOL
    k.DisconnectNamedPipe.argtypes = [HANDLE]
    k.DisconnectNamedPipe.restype = BOOL
    k.ReadFile.argtypes = [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p]
    k.ReadFile.restype = BOOL
    k.WriteFile.argtypes = k.ReadFile.argtypes
    k.WriteFile.restype = BOOL
    k.CreateEventW.argtypes = [c.c_void_p, BOOL, BOOL, c.c_wchar_p]
    k.CreateEventW.restype = HANDLE
    k.GetOverlappedResult.argtypes = [HANDLE, c.POINTER(OVERLAPPED), c.POINTER(DWORD), BOOL]
    k.GetOverlappedResult.restype = BOOL
    k.CancelIoEx.argtypes = [HANDLE, c.POINTER(OVERLAPPED)]
    k.CancelIoEx.restype = BOOL
    k.CloseHandle.argtypes = [HANDLE]
    k.CloseHandle.restype = BOOL
    k.LocalFree.argtypes = [c.c_void_p]
    k.LocalFree.restype = c.c_void_p
    k.InitializeProcThreadAttributeList.argtypes = [c.c_void_p, DWORD, DWORD, c.POINTER(SIZE_T)]
    k.InitializeProcThreadAttributeList.restype = BOOL
    k.UpdateProcThreadAttribute.argtypes = [c.c_void_p, DWORD, SIZE_T, c.c_void_p, SIZE_T, c.c_void_p, c.c_void_p]
    k.UpdateProcThreadAttribute.restype = BOOL
    k.DeleteProcThreadAttributeList.argtypes = [c.c_void_p]
    k.DeleteProcThreadAttributeList.restype = None
    k.CreateProcessW.argtypes = [
        c.c_wchar_p, c.c_wchar_p, c.c_void_p, c.c_void_p, BOOL, DWORD,
        c.c_void_p, c.c_wchar_p, c.POINTER(STARTUPINFOW), c.POINTER(PROCESS_INFORMATION),
    ]
    k.CreateProcessW.restype = BOOL
    k.ResumeThread.argtypes = [HANDLE]
    k.ResumeThread.restype = DWORD
    k.WaitForSingleObject.argtypes = [HANDLE, DWORD]
    k.WaitForSingleObject.restype = DWORD
    k.TerminateProcess.argtypes = [HANDLE, c.c_uint32]
    k.TerminateProcess.restype = BOOL
    k.GetExitCodeProcess.argtypes = [HANDLE, c.POINTER(DWORD)]
    k.GetExitCodeProcess.restype = BOOL
    k.GetCurrentProcess.argtypes = []
    k.GetCurrentProcess.restype = HANDLE
    return k


def _pipe_io(k, server, operation, buffer=None, *, length=1, timeout_ms=IO_TIMEOUT_MS):
    """Complete bounded pipe I/O; reads accumulate exactly length bytes in byte mode."""
    assert isinstance(length, int) and length >= 1

    def once(target, requested, wait_ms):
        overlapped = OVERLAPPED()
        overlapped.hEvent = k.CreateEventW(None, True, False, None)
        assert overlapped.hEvent, c.get_last_error()
        transferred = DWORD()
        pending = False
        try:
            if operation == 'connect':
                ok = k.ConnectNamedPipe(server, c.byref(overlapped))
            else:
                function = {'read': k.ReadFile, 'write': k.WriteFile}[operation]
                ok = function(server, target, requested, c.byref(transferred), c.byref(overlapped))
            if not ok:
                error = c.get_last_error()
                if operation == 'connect' and error == ERROR_PIPE_CONNECTED:
                    return 0
                assert error == ERROR_IO_PENDING, f'pipe {operation}: WinError {error}'
                pending = True
                wait = k.WaitForSingleObject(overlapped.hEvent, wait_ms)
                assert wait == WAIT_OBJECT_0, (
                    f'pipe {operation} did not complete within {wait_ms}ms; wait={wait:#x}'
                )
                pending = False
            assert k.GetOverlappedResult(server, c.byref(overlapped), c.byref(transferred), False), (
                f'pipe {operation} completion: WinError {c.get_last_error()}'
            )
            return transferred.value
        finally:
            if pending:
                cancelled = k.CancelIoEx(server, c.byref(overlapped))
                error = c.get_last_error()
                # ERROR_NOT_FOUND is benign when cancellation raced completion;
                # still wait for the event before releasing native storage.
                drained = k.WaitForSingleObject(overlapped.hEvent, CANCEL_TIMEOUT_MS) == WAIT_OBJECT_0
                if not drained:
                    _undrained_io.append((overlapped, buffer, transferred))
                failure = sys.exception()
                if failure is not None and (
                    not drained or (not cancelled and error != ERROR_NOT_FOUND)
                ):
                    failure.add_note(
                        f'pipe cancellation: cancelled={bool(cancelled)}, '
                        f'error={error}, drained={drained}'
                    )
                if not drained:
                    # Keep the event and buffers alive while the OS may still use them.
                    overlapped = None
            if overlapped is not None:
                if not k.CloseHandle(overlapped.hEvent):
                    message = f'CloseHandle pipe event: WinError {c.get_last_error()}'
                    failure = sys.exception()
                    if failure is not None:
                        failure.add_note(message)
                    else:
                        pytest.fail(message)

    if operation != 'read' or length == 1:
        return once(buffer, length, timeout_ms)

    # All current pipes are byte-mode. A multi-byte ReadFile may legally complete
    # short, so accumulate under one overall deadline rather than assuming framing.
    deadline = time.monotonic() + timeout_ms / 1000
    total = 0
    while total < length:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f'pipe read did not complete {length} bytes within {timeout_ms}ms'
        wait_ms = max(1, int(remaining * 1000))
        count = once(c.byref(buffer, total), length - total, wait_ms)
        assert count > 0, 'pipe read completed with zero bytes before frame was complete'
        total += count
    return total


def _advapi32():
    a = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
    a.OpenProcessToken.argtypes = [HANDLE, DWORD, c.POINTER(HANDLE)]
    a.OpenProcessToken.restype = BOOL
    a.GetTokenInformation.argtypes = [HANDLE, c.c_int32, c.c_void_p, DWORD, c.POINTER(DWORD)]
    a.GetTokenInformation.restype = BOOL
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        c.c_wchar_p, DWORD, c.POINTER(c.c_void_p), c.POINTER(DWORD),
    ]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = BOOL
    a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_wchar_p)]
    a.ConvertSidToStringSidW.restype = BOOL
    a.FreeSid.argtypes = [c.c_void_p]
    a.FreeSid.restype = c.c_void_p
    return a


def _userenv():
    u = c.WinDLL('userenv.dll', use_last_error=True, winmode=0x800)
    u.CreateAppContainerProfile.argtypes = [
        c.c_wchar_p, c.c_wchar_p, c.c_wchar_p, c.c_void_p, DWORD, c.POINTER(c.c_void_p),
    ]
    u.CreateAppContainerProfile.restype = c.c_int32
    u.DeleteAppContainerProfile.argtypes = [c.c_wchar_p]
    u.DeleteAppContainerProfile.restype = c.c_int32
    return u


def _sid_string(advapi, kernel32, sid):
    text = c.c_wchar_p()
    assert advapi.ConvertSidToStringSidW(sid, c.byref(text)), c.get_last_error()
    try:
        return text.value
    finally:
        kernel32.LocalFree(c.cast(text, c.c_void_p))


def _raw_primary_oracle(advapi, kernel32, token, expected_sid):
    """Independent oracle: query the child process token without the TNC probe."""
    is_appcontainer = DWORD()
    returned = DWORD()
    assert advapi.GetTokenInformation(
        token, TOKEN_IS_APPCONTAINER, c.byref(is_appcontainer), c.sizeof(is_appcontainer), c.byref(returned)
    ), c.get_last_error()
    assert returned.value == c.sizeof(is_appcontainer)
    assert is_appcontainer.value == 1

    size = DWORD()
    assert not advapi.GetTokenInformation(token, TOKEN_APPCONTAINER_SID, None, 0, c.byref(size))
    assert c.get_last_error() == ERROR_INSUFFICIENT_BUFFER
    buffer = c.create_string_buffer(size.value)
    assert advapi.GetTokenInformation(token, TOKEN_APPCONTAINER_SID, buffer, size.value, c.byref(size)), c.get_last_error()
    info = TOKEN_APPCONTAINER_INFORMATION.from_buffer(buffer)
    assert info.TokenAppContainer
    assert _sid_string(advapi, kernel32, info.TokenAppContainer) == expected_sid


def _current_user_sid(advapi, kernel32):
    token = HANDLE()
    assert advapi.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, c.byref(token)), c.get_last_error()
    try:
        size = DWORD()
        assert not advapi.GetTokenInformation(token, TOKEN_USER, None, 0, c.byref(size))
        assert c.get_last_error() == ERROR_INSUFFICIENT_BUFFER
        buffer = c.create_string_buffer(size.value)
        assert advapi.GetTokenInformation(token, TOKEN_USER, buffer, size.value, c.byref(size)), c.get_last_error()
        # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first member is PSID.
        # Read only that native pointer, avoiding a duplicate struct layout.
        return _sid_string(advapi, kernel32, c.c_void_p.from_buffer(buffer))
    finally:
        assert kernel32.CloseHandle(token), c.get_last_error()


def _pipe_security(advapi, appcontainer_sid, user_sid):
    descriptor = c.c_void_p()
    # AppContainer checks both the user and package principals. Package-only
    # access failed the real-client handshake; narrow World to the launching
    # user instead. No other local user or package is granted an ACE.
    sddl = f'D:(A;;GRGW;;;{user_sid})(A;;GRGW;;;{appcontainer_sid})S:(ML;;NW;;;LW)'
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SECURITY_DESCRIPTOR_REVISION, c.byref(descriptor), None
    ), c.get_last_error()
    return descriptor, SECURITY_ATTRIBUTES(
        nLength=c.sizeof(SECURITY_ATTRIBUTES),
        lpSecurityDescriptor=descriptor,
        bInheritHandle=False,
    )


def _no_temporal_guard():
    """Test-only bypass; production PipeTokenInspector still enforces deadlines."""
    return None


def _checked_cleanup(function, *args):
    try:
        ok = function(*args)
    except Exception as error:
        message = f'{function!r} cleanup raised: {error!r}'
    else:
        if ok:
            return
        message = f'{function!r} cleanup failed: WinError {c.get_last_error()}'
    failure = sys.exception()
    if failure is not None:
        failure.add_note(message)
    else:
        pytest.fail(message)


def _revert_or_fail_fast(api):
    """Do not let pytest continue in an unconfirmed thread security context.

    Native fail_fast uses os._exit(78): this terminates the test runner without
    unwinding, further cleanup callbacks, or a guaranteed pytest summary. That
    terminal outcome is intentional; an ordinary test failure could leave the
    thread running subsequent tests in the client's security context.

    Catch BaseException deliberately: KeyboardInterrupt or SystemExit raised
    during revert must also abort with exit 78 rather than unwind while the
    thread security context is unconfirmed.
    """
    try:
        reverted = api.revert()
    except BaseException:
        api.fail_fast()
        raise
    if not reverted:
        api.fail_fast()
        # Defensive guard only: both the native and supplied fake fail_fast
        # implementations are non-returning.
        raise AssertionError('fail_fast unexpectedly returned')
