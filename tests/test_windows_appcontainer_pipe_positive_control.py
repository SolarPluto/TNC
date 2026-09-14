"""Windows matched-pair positive control for AppContainer pipe-token evidence.

This test complements the ordinary-client identification diagnostic with a real
AppContainer client. The client is independently identified from its primary
process token before it runs; the named-pipe impersonation token is then probed
at identification level. Neither observation is an admission or authorization
path.
"""
import base64
from contextlib import ExitStack
import ctypes as c
import os
import sys
import time
import uuid

import pytest

from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows AppContainer positive control only')

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


def _pipe_io(k, server, operation, buffer=None, *, timeout_ms=IO_TIMEOUT_MS):
    """Complete one pipe operation, with bounded waiting and cancellation."""
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
            ok = function(server, buffer, 1, c.byref(transferred), c.byref(overlapped))
        if not ok:
            error = c.get_last_error()
            if operation == 'connect' and error == ERROR_PIPE_CONNECTED:
                return 0
            assert error == ERROR_IO_PENDING, f'pipe {operation}: WinError {error}'
            pending = True
            wait = k.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            assert wait == WAIT_OBJECT_0, (
                f'pipe {operation} did not complete within {timeout_ms}ms; wait={wait:#x}'
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
            if failure is not None and (not drained or (not cancelled and error != ERROR_NOT_FOUND)):
                failure.add_note(f'pipe cancellation: cancelled={bool(cancelled)}, error={error}, drained={drained}')
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
    """
    try:
        reverted = api.revert()
    except BaseException:
        api.fail_fast()
        raise
    if not reverted:
        api.fail_fast()
        raise AssertionError('fail_fast unexpectedly returned')


def test_appcontainer_client_identification_token_positive_control(emit_observation):
    k = _kernel32()
    advapi = _advapi32()
    userenv = _userenv()
    profile_name = f'TNC.PositiveControl.{uuid.uuid4().hex}'
    app_sid = c.c_void_p()
    descriptor = None
    attr_buffer = None
    attr_list = None
    server = None
    primary_token = HANDLE()
    pi = PROCESS_INFORMATION()
    api = NativePipeTokenAPI()
    token_cleanup = ExitStack()
    profile_created = False

    try:
        hr = int(userenv.CreateAppContainerProfile(
            profile_name, profile_name, 'TNC AppContainer matched-pair positive control', None, 0, c.byref(app_sid)
        ))
        assert hr == 0, f'CreateAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}'
        profile_created = True
        expected_sid = _sid_string(advapi, k, app_sid)

        descriptor, security_attributes = _pipe_security(advapi, expected_sid, _current_user_sid(advapi, k))
        pipe_component = f'tnc-appcontainer-positive-{os.getpid()}-{uuid.uuid4().hex}'
        pipe_name = rf'\\.\pipe\{pipe_component}'
        server = k.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            c.byref(security_attributes),
        )
        assert server not in (None, 0, INVALID_HANDLE_VALUE), c.get_last_error()

        size = SIZE_T()
        assert not k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        assert c.get_last_error() == ERROR_INSUFFICIENT_BUFFER
        attr_buffer = c.create_string_buffer(size.value)
        assert k.InitializeProcThreadAttributeList(attr_buffer, 1, 0, c.byref(size)), c.get_last_error()
        attr_list = c.cast(attr_buffer, c.c_void_p)

        capabilities = SECURITY_CAPABILITIES(
            AppContainerSid=app_sid,
            Capabilities=None,
            # The launched control genuinely has no requested capabilities;
            # an empty identification observation alone cannot establish that.
            CapabilityCount=0,
            Reserved=0,
        )
        assert k.UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            c.byref(capabilities),
            c.sizeof(capabilities),
            None,
            None,
        ), c.get_last_error()

        powershell = os.path.join(os.environ['SystemRoot'], 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
        script = (
            "$ErrorActionPreference='Stop';$p=[System.IO.Pipes.NamedPipeClientStream]::new('.', '"
            + pipe_component
            + "', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, "
              "[System.Security.Principal.TokenImpersonationLevel]::Identification);"
              "try {$p.Connect(30000);$p.WriteByte(88);$p.Flush();"
              "if ($p.ReadByte() -ne 89) {throw 'Missing server completion byte'}}"
              "finally {$p.Dispose()}"
        )
        encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
        command_line = c.create_unicode_buffer(
            f'"{powershell}" -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}'
        )
        si = STARTUPINFOEXW()
        si.StartupInfo.cb = c.sizeof(si)
        si.lpAttributeList = attr_list
        flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW
        assert k.CreateProcessW(
            None,
            command_line,
            None,
            None,
            False,
            flags,
            None,
            None,
            c.cast(c.byref(si), c.POINTER(STARTUPINFOW)),
            c.byref(pi),
        ), c.get_last_error()

        # Independent known-positive oracle before the child can touch the pipe.
        assert advapi.OpenProcessToken(pi.hProcess, TOKEN_QUERY, c.byref(primary_token)), c.get_last_error()
        _raw_primary_oracle(advapi, k, primary_token, expected_sid)

        # Probe the same known-positive primary token as a mechanism control. Its
        # classification is independently anchored by the raw oracle above.
        primary_evidence = NativeAppContainerProbe().probe(
            int(primary_token.value), token_type='PRIMARY', level=None
        )
        primary_result = evaluate_appcontainer_exclusion(primary_evidence)
        assert primary_evidence.token_is_app_container
        assert primary_evidence.app_container_sid == expected_sid
        assert primary_result.status == 'APPCONTAINER'
        assert primary_result.reason == 'TOKEN_IS_APPCONTAINER'
        assert not primary_result.authorization_granted
        assert not primary_result.admission_granted

        assert k.ResumeThread(pi.hThread) != 0xFFFFFFFF, c.get_last_error()
        byte = c.create_string_buffer(1)
        try:
            _pipe_io(k, server, 'connect')
            assert _pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'
        except AssertionError as failure:
            exit_code = DWORD()
            if k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)):
                failure.add_note(f'PRIMARY oracle/control passed; pipe handshake failed; child exit code={exit_code.value} (259=still active)')
            raise

        assert api.open_thread_token() is None
        assert api.impersonate(server)
        token_cleanup.callback(_revert_or_fail_fast, api)
        pipe_token = api.open_thread_token()
        assert pipe_token is not None
        token_cleanup.callback(_checked_cleanup, api.close, pipe_token)
        facts = api.capture(pipe_token, _no_temporal_guard)
        assert facts.token_type == 'IMPERSONATION'
        assert facts.level == 'IDENTIFICATION'

        identification_evidence = NativeAppContainerProbe().probe(
            pipe_token,
            token_type=facts.token_type,
            level=facts.level,
        )
        identification_result = evaluate_appcontainer_exclusion(identification_evidence)

        emit_observation(
            'TNC_APPCONTAINER_MATCHED_PAIR_POSITIVE_OBSERVATION '
            f'oracle_is_appcontainer=True oracle_sid={expected_sid!r} '
            f'is_appcontainer={identification_evidence.token_is_app_container!r} '
            f'appcontainer_sid={identification_evidence.app_container_sid!r} '
            f'capability_count={len(identification_evidence.capability_sids)} '
            f'status={identification_result.status} reason={identification_result.reason}'
        )

        # Identification-level evidence remains fail-closed even for a client
        # independently proven to be AppContainer. Positive evidence may deny;
        # absence must never be turned into non-AppContainer proof or an allow.
        assert identification_result.status != 'PROVEN_NON_APPCONTAINER'
        assert not identification_result.authorization_granted
        assert not identification_result.admission_granted
        # ExitStack consumes each callback before calling it. A failing close
        # still triggers reversion and cannot be retried by the outer finally.
        token_cleanup.close()
        # The child stays connected until probing and safety checks are done.
        assert _pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(pi.hProcess, IO_TIMEOUT_MS) == WAIT_OBJECT_0, 'client did not exit after completion'
        exit_code = DWORD()
        assert k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)), c.get_last_error()
        assert exit_code.value == 0, f'client exit code={exit_code.value}'
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        token_cleanup.close()

        if primary_token.value:
            check(k.CloseHandle(primary_token), 'CloseHandle primary token')
        if server not in (None, 0, INVALID_HANDLE_VALUE):
            k.DisconnectNamedPipe(server)
            check(k.CloseHandle(server), 'CloseHandle server')
        if pi.hProcess:
            if k.WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0:
                check(k.TerminateProcess(pi.hProcess, 1), 'TerminateProcess')
                check(k.WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0, 'wait for terminated client')
            check(k.CloseHandle(pi.hProcess), 'CloseHandle process')
        if pi.hThread:
            check(k.CloseHandle(pi.hThread), 'CloseHandle thread')
        if attr_list:
            k.DeleteProcThreadAttributeList(attr_list)
        if descriptor:
            k.LocalFree(descriptor)
        if app_sid:
            advapi.FreeSid(app_sid)
        if profile_created:
            hr = int(userenv.DeleteAppContainerProfile(profile_name))
            if hr != 0:
                cleanup_errors.append(f'DeleteAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}')
        if cleanup_errors:
            message = '; '.join(cleanup_errors)
            if failure is not None:
                failure.add_note(message)
            else:
                pytest.fail(message)

    assert api.open_thread_token() is None


@pytest.fixture
def local_pipe():
    """Real disposable pipe for failure-path checks, without AppContainer setup."""
    k = _kernel32()
    name = rf'\\.\pipe\tnc-overlapped-{uuid.uuid4().hex}'
    server = k.CreateNamedPipeW(
        name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, None,
    )
    assert server not in (None, 0, INVALID_HANDLE_VALUE), c.get_last_error()
    clients = []

    def connect():
        client = k.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
        assert client not in (None, 0, INVALID_HANDLE_VALUE), c.get_last_error()
        clients.append(client)
        return client

    try:
        yield k, server, connect
    finally:
        for client in clients:
            assert k.CloseHandle(client), c.get_last_error()
        assert k.CloseHandle(server), c.get_last_error()


@pytest.mark.parametrize('operation', ['connect', 'read'])
def test_pipe_io_stalled_peer_is_bounded(local_pipe, operation):
    k, server, connect = local_pipe
    if operation == 'read':
        client = connect()
        _pipe_io(k, server, 'connect')
    retained = len(_undrained_io)
    started = time.monotonic()
    with pytest.raises(AssertionError, match=f'pipe {operation} did not complete within 50ms'):
        _pipe_io(k, server, operation, c.create_string_buffer(1), timeout_ms=50)
    assert time.monotonic() - started < 6
    assert len(_undrained_io) == retained, 'cancelled I/O failed to drain'
    if operation == 'read':
        # A cancelled read must not consume data sent to the next operation.
        written = DWORD()
        assert k.WriteFile(client, c.create_string_buffer(b'X'), 1, c.byref(written), None)
        byte = c.create_string_buffer(1)
        assert _pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'


def test_pipe_io_connected_peer_round_trip(local_pipe):
    k, server, connect = local_pipe
    client = connect()  # Exercise ERROR_PIPE_CONNECTED before ConnectNamedPipe.
    _pipe_io(k, server, 'connect')
    transferred = DWORD()
    assert k.WriteFile(client, c.create_string_buffer(b'X'), 1, c.byref(transferred), None)
    byte = c.create_string_buffer(1)
    assert _pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'
    assert _pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
    assert k.ReadFile(client, byte, 1, c.byref(transferred), None)
    assert transferred.value == 1 and byte.raw == b'Y'
