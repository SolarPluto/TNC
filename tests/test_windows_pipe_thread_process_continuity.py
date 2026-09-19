"""Cross-process continuity probe for named-pipe client thread versus process context."""
import base64
from contextlib import ExitStack
import ctypes as c
import os
import sys
import uuid

import pytest

import _native_harness as h
from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import (
    AppContainerProbeError,
    NativeAppContainerProbe,
)
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows named-pipe continuity experiment only')

TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
SECURITY_IMPERSONATION = 2
TOKEN_IMPERSONATION = 2
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002


def _advapi():
    a = h._advapi32()
    a.DuplicateTokenEx.argtypes = [
        h.HANDLE, h.DWORD, c.POINTER(h.SECURITY_ATTRIBUTES),
        c.c_int32, c.c_int32, c.POINTER(h.HANDLE),
    ]
    a.DuplicateTokenEx.restype = h.BOOL
    return a


def _raw_appcontainer_shape(advapi, kernel, token):
    returned = h.DWORD()
    flag = h.DWORD()
    assert advapi.GetTokenInformation(
        token, h.TOKEN_IS_APPCONTAINER,
        c.byref(flag), c.sizeof(flag), c.byref(returned),
    ), c.get_last_error()
    assert returned.value == c.sizeof(flag)
    assert flag.value in (0, 1)

    size = h.DWORD()
    assert not advapi.GetTokenInformation(
        token, h.TOKEN_APPCONTAINER_SID, None, 0, c.byref(size)
    )
    assert c.get_last_error() == h.ERROR_INSUFFICIENT_BUFFER
    assert size.value >= c.sizeof(h.TOKEN_APPCONTAINER_INFORMATION)
    buffer = c.create_string_buffer(size.value)
    assert advapi.GetTokenInformation(
        token, h.TOKEN_APPCONTAINER_SID,
        buffer, size.value, c.byref(returned),
    ), c.get_last_error()
    assert 0 < returned.value <= size.value
    info = h.TOKEN_APPCONTAINER_INFORMATION.from_buffer(buffer)
    sid = h._sid_string(advapi, kernel, info.TokenAppContainer) if info.TokenAppContainer else None
    return bool(flag.value), sid


def _client_command(pipe_name, inherited_token, expected_sid):
    code = f'''import ctypes as c
HANDLE = c.c_void_p
DWORD = c.c_uint32
BOOL = c.c_int32
TOKEN_QUERY = 0x0008
TOKEN_IS_APPCONTAINER = 29
TOKEN_APPCONTAINER_SID = 31
ERROR_INSUFFICIENT_BUFFER = 122
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IMPERSONATION = 0x00020000
INVALID_HANDLE_VALUE = c.c_void_p(-1).value

class TOKEN_APPCONTAINER_INFORMATION(c.Structure):
    _fields_ = [('TokenAppContainer', c.c_void_p)]

k = c.WinDLL("kernel32.dll", use_last_error=True)
a = c.WinDLL("advapi32.dll", use_last_error=True)
k.GetCurrentThread.argtypes = []
k.GetCurrentThread.restype = HANDLE
k.CreateFileW.argtypes = [c.c_wchar_p, DWORD, DWORD, c.c_void_p, DWORD, DWORD, HANDLE]
k.CreateFileW.restype = HANDLE
k.WriteFile.argtypes = [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p]
k.WriteFile.restype = BOOL
k.ReadFile.argtypes = k.WriteFile.argtypes
k.ReadFile.restype = BOOL
k.CloseHandle.argtypes = [HANDLE]
k.CloseHandle.restype = BOOL
k.LocalFree.argtypes = [c.c_void_p]
k.LocalFree.restype = c.c_void_p
a.SetThreadToken.argtypes = [c.POINTER(HANDLE), HANDLE]
a.SetThreadToken.restype = BOOL
a.OpenThreadToken.argtypes = [HANDLE, DWORD, BOOL, c.POINTER(HANDLE)]
a.OpenThreadToken.restype = BOOL
a.GetTokenInformation.argtypes = [HANDLE, c.c_int32, c.c_void_p, DWORD, c.POINTER(DWORD)]
a.GetTokenInformation.restype = BOOL
a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_wchar_p)]
a.ConvertSidToStringSidW.restype = BOOL
a.RevertToSelf.argtypes = []
a.RevertToSelf.restype = BOOL

source = HANDLE({inherited_token})
installed = HANDLE()
pipe = HANDLE()
impersonating = False
try:
    if not a.SetThreadToken(None, source):
        raise OSError(c.get_last_error(), "SetThreadToken")
    impersonating = True

    if not a.OpenThreadToken(k.GetCurrentThread(), TOKEN_QUERY, True, c.byref(installed)):
        raise OSError(c.get_last_error(), "OpenThreadToken")
    returned = DWORD()
    flag = DWORD()
    if not a.GetTokenInformation(
        installed, TOKEN_IS_APPCONTAINER, c.byref(flag), c.sizeof(flag), c.byref(returned)
    ) or flag.value != 1:
        raise RuntimeError("installed thread token is not AppContainer")

    size = DWORD()
    if a.GetTokenInformation(installed, TOKEN_APPCONTAINER_SID, None, 0, c.byref(size)):
        raise RuntimeError("unexpected successful class-31 size probe")
    if c.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        raise OSError(c.get_last_error(), "TokenAppContainerSid size probe")
    buffer = c.create_string_buffer(size.value)
    if not a.GetTokenInformation(
        installed, TOKEN_APPCONTAINER_SID, buffer, size.value, c.byref(returned)
    ):
        raise OSError(c.get_last_error(), "TokenAppContainerSid")
    info = TOKEN_APPCONTAINER_INFORMATION.from_buffer(buffer)
    if not info.TokenAppContainer:
        raise RuntimeError("installed thread token lacks AppContainer SID")
    text = c.c_wchar_p()
    if not a.ConvertSidToStringSidW(info.TokenAppContainer, c.byref(text)):
        raise OSError(c.get_last_error(), "ConvertSidToStringSidW")
    try:
        if text.value != {expected_sid!r}:
            raise RuntimeError("installed thread token AppContainer SID changed")
    finally:
        k.LocalFree(c.cast(text, c.c_void_p))

    pipe = k.CreateFileW(
        {pipe_name!r}, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, None,
    )
    if pipe in (None, 0, INVALID_HANDLE_VALUE):
        raise OSError(c.get_last_error(), "CreateFileW named pipe")

    transferred = DWORD()
    out_byte = c.create_string_buffer(b"X")
    if not k.WriteFile(pipe, out_byte, 1, c.byref(transferred), None) or transferred.value != 1:
        raise OSError(c.get_last_error(), "WriteFile handshake")

    # Keep the AppContainer thread token installed until the server has
    # impersonated and probed this connection, then releases us with Y.
    in_byte = c.create_string_buffer(1)
    if not k.ReadFile(pipe, in_byte, 1, c.byref(transferred), None) or transferred.value != 1:
        raise OSError(c.get_last_error(), "ReadFile acknowledgement")
    if in_byte.raw != b"Y":
        raise RuntimeError("unexpected acknowledgement byte")
finally:
    if pipe not in (None, 0, INVALID_HANDLE_VALUE):
        k.CloseHandle(pipe)
    if installed.value:
        k.CloseHandle(installed)
    if impersonating and not a.RevertToSelf():
        raise OSError(c.get_last_error(), "RevertToSelf")
    if source.value:
        k.CloseHandle(source)
'''
    encoded = base64.b64encode(code.encode('utf-8')).decode('ascii')
    return c.create_unicode_buffer(
        f'"{sys.executable}" -I -c "import base64;exec(base64.b64decode(\'{encoded}\'))"'
    )


def test_pipe_impersonation_uses_thread_or_process_context(emit_observation):
    k = h._kernel32()
    advapi = _advapi()
    userenv = h._userenv()
    api = NativePipeTokenAPI()

    k.GetNamedPipeClientProcessId.argtypes = [h.HANDLE, c.POINTER(h.DWORD)]
    k.GetNamedPipeClientProcessId.restype = h.BOOL

    profile_name = f'TNC.PipeContinuity.{uuid.uuid4().hex}'
    app_sid = c.c_void_p()
    source_attr_buffer = None
    source_attr_list = None
    client_attr_buffer = None
    client_attr_list = None
    descriptor = None
    server = None
    source_pi = h.PROCESS_INFORMATION()
    client_pi = h.PROCESS_INFORMATION()
    source_oracle = h.HANDLE()
    source = h.HANDLE()
    duplicate = h.HANDLE()
    client_primary = h.HANDLE()
    profile_created = False

    def observe(stage, **values):
        fields = [
            'TNC_PIPE_THREAD_PROCESS_CONTINUITY',
            f'stage={stage}',
            f'windows_build={sys.getwindowsversion().build}',
        ]
        fields.extend(f'{key}={value!r}' for key, value in values.items())
        emit_observation(' '.join(fields))

    try:
        assert api.open_thread_token() is None

        # Build an independently verified AppContainer PRIMARY source.
        hr = int(userenv.CreateAppContainerProfile(
            profile_name, profile_name,
            'TNC pipe thread/process continuity source',
            None, 0, c.byref(app_sid),
        ))
        assert hr == 0, f'CreateAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}'
        profile_created = True
        expected_sid = h._sid_string(advapi, k, app_sid)

        size = h.SIZE_T()
        assert not k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        assert c.get_last_error() == h.ERROR_INSUFFICIENT_BUFFER
        source_attr_buffer = c.create_string_buffer(size.value)
        assert k.InitializeProcThreadAttributeList(
            source_attr_buffer, 1, 0, c.byref(size)
        ), c.get_last_error()
        source_attr_list = c.cast(source_attr_buffer, c.c_void_p)

        capabilities = h.SECURITY_CAPABILITIES(
            AppContainerSid=app_sid, Capabilities=None, CapabilityCount=0, Reserved=0,
        )
        assert k.UpdateProcThreadAttribute(
            source_attr_list, 0, h.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            c.byref(capabilities), c.sizeof(capabilities), None, None,
        ), c.get_last_error()

        powershell = os.path.join(
            os.environ['SystemRoot'], 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'
        )
        source_command = c.create_unicode_buffer(
            f'"{powershell}" -NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 30"'
        )
        source_si = h.STARTUPINFOEXW()
        source_si.StartupInfo.cb = c.sizeof(source_si)
        source_si.lpAttributeList = source_attr_list
        assert k.CreateProcessW(
            None, source_command, None, None, False,
            h.EXTENDED_STARTUPINFO_PRESENT | h.CREATE_SUSPENDED | h.CREATE_NO_WINDOW,
            None, None,
            c.cast(c.byref(source_si), c.POINTER(h.STARTUPINFOW)),
            c.byref(source_pi),
        ), c.get_last_error()

        assert advapi.OpenProcessToken(
            source_pi.hProcess, TOKEN_QUERY, c.byref(source_oracle)
        ), c.get_last_error()
        h._raw_primary_oracle(advapi, k, source_oracle, expected_sid)

        assert advapi.OpenProcessToken(
            source_pi.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, c.byref(source)
        ), c.get_last_error()

        inheritable = h.SECURITY_ATTRIBUTES(
            nLength=c.sizeof(h.SECURITY_ATTRIBUTES),
            lpSecurityDescriptor=None,
            bInheritHandle=True,
        )
        assert advapi.DuplicateTokenEx(
            source,
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            c.byref(inheritable),
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            c.byref(duplicate),
        ), c.get_last_error()
        h._raw_primary_oracle(advapi, k, duplicate, expected_sid)

        # The client will open the pipe while carrying the AppContainer thread
        # token, so use the same user+package ACL shape as the positive controls.
        descriptor, pipe_security = h._pipe_security(
            advapi, expected_sid, h._current_user_sid(advapi, k)
        )
        pipe_name = rf'\\.\pipe\tnc-thread-process-continuity-{os.getpid()}-{uuid.uuid4().hex}'
        server = k.CreateNamedPipeW(
            pipe_name,
            h.PIPE_ACCESS_DUPLEX | h.FILE_FLAG_OVERLAPPED,
            h.PIPE_REJECT_REMOTE_CLIENTS,
            1, 4096, 4096, 0, c.byref(pipe_security),
        )
        assert server not in (None, 0, h.INVALID_HANDLE_VALUE), c.get_last_error()

        # Restrict inheritance to the single already-verified impersonation-token
        # handle. Windows preserves inherited handle values in the child process.
        client_size = h.SIZE_T()
        assert not k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(client_size))
        assert c.get_last_error() == h.ERROR_INSUFFICIENT_BUFFER
        client_attr_buffer = c.create_string_buffer(client_size.value)
        assert k.InitializeProcThreadAttributeList(
            client_attr_buffer, 1, 0, c.byref(client_size)
        ), c.get_last_error()
        client_attr_list = c.cast(client_attr_buffer, c.c_void_p)
        inherited_handles = (h.HANDLE * 1)(h.HANDLE(duplicate.value))
        assert k.UpdateProcThreadAttribute(
            client_attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            c.cast(inherited_handles, c.c_void_p), c.sizeof(inherited_handles),
            None, None,
        ), c.get_last_error()

        client_command = _client_command(pipe_name, int(duplicate.value), expected_sid)
        client_si = h.STARTUPINFOEXW()
        client_si.StartupInfo.cb = c.sizeof(client_si)
        client_si.lpAttributeList = client_attr_list
        assert k.CreateProcessW(
            sys.executable,
            client_command,
            None, None,
            True,
            h.EXTENDED_STARTUPINFO_PRESENT | h.CREATE_SUSPENDED | h.CREATE_NO_WINDOW,
            None, None,
            c.cast(c.byref(client_si), c.POINTER(h.STARTUPINFOW)),
            c.byref(client_pi),
        ), c.get_last_error()

        # Independently establish the process-primary side of the asymmetry before
        # the client can install its inherited AppContainer thread token.
        assert advapi.OpenProcessToken(
            client_pi.hProcess, TOKEN_QUERY, c.byref(client_primary)
        ), c.get_last_error()
        client_primary_shape = _raw_appcontainer_shape(advapi, k, client_primary)
        assert client_primary_shape == (False, None), client_primary_shape

        assert k.ResumeThread(client_pi.hThread) != 0xFFFFFFFF, c.get_last_error()

        byte = c.create_string_buffer(1)
        try:
            h._pipe_io(k, server, 'connect')
            assert h._pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'
        except AssertionError as failure:
            exit_code = h.DWORD()
            if k.GetExitCodeProcess(client_pi.hProcess, c.byref(exit_code)):
                failure.add_note(
                    'client failed before continuity probe; '
                    f'exit code={exit_code.value} (259=still active)'
                )
            raise

        client_pid = h.DWORD()
        assert k.GetNamedPipeClientProcessId(server, c.byref(client_pid)), c.get_last_error()
        assert client_pid.value == client_pi.dwProcessId

        if not api.impersonate(server):
            observe('IMPERSONATE_FAILED', winerror=c.get_last_error())
            assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
            assert k.WaitForSingleObject(client_pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0
            return

        with ExitStack() as token_cleanup:
            token_cleanup.callback(h._revert_or_fail_fast, api)
            try:
                pipe_token = api.open_thread_token()
            except Exception as error:
                observe(
                    'PIPE_TOKEN_OPEN_UNAVAILABLE',
                    error_type=type(error).__name__,
                    detail=str(error)[:200],
                )
                pipe_token = None

            if pipe_token is None:
                observe('PIPE_TOKEN_MISSING')
            else:
                token_cleanup.callback(h._checked_cleanup, api.close, pipe_token)
                try:
                    facts = api.capture(pipe_token, h._no_temporal_guard)
                except Exception as error:
                    observe(
                        'PIPE_TOKEN_CAPTURE_UNAVAILABLE',
                        error_type=type(error).__name__,
                        detail=str(error)[:200],
                    )
                else:
                    if facts.token_type != 'IMPERSONATION' or facts.level != 'IMPERSONATION':
                        observe(
                            'SQOS_LEVEL_MISMATCH',
                            token_type=facts.token_type,
                            level=facts.level,
                        )
                    else:
                        try:
                            raw_shape = _raw_appcontainer_shape(
                                advapi, k, h.HANDLE(pipe_token)
                            )
                        except AssertionError as error:
                            observe(
                                'PIPE_APPCONTAINER_QUERY_UNAVAILABLE',
                                detail=str(error)[:200],
                            )
                        else:
                            assert facts.app_container_reported == raw_shape[0]

                            interpretation = (
                                'THREAD_TOKEN'
                                if raw_shape == (True, expected_sid)
                                else 'PROCESS_TOKEN'
                                if raw_shape == client_primary_shape
                                else 'UNEXPECTED_PIPE_CONTEXT'
                            )

                            try:
                                evidence = NativeAppContainerProbe().probe(
                                    pipe_token,
                                    token_type=facts.token_type,
                                    level=facts.level,
                                )
                            except AppContainerProbeError as error:
                                observe(
                                    'OBSERVED',
                                    interpretation=interpretation,
                                    raw_is_appcontainer=raw_shape[0],
                                    raw_sid=raw_shape[1],
                                    classifier='UNAVAILABLE',
                                    probe_error=str(error),
                                )
                            else:
                                assert evidence.token_is_app_container == raw_shape[0]
                                assert (
                                    str(evidence.app_container_sid)
                                    if evidence.app_container_sid is not None else None
                                ) == raw_shape[1]
                                result = evaluate_appcontainer_exclusion(evidence)
                                expected_result = (
                                    ('APPCONTAINER', 'TOKEN_IS_APPCONTAINER')
                                    if interpretation == 'THREAD_TOKEN'
                                    else (
                                        'PROVEN_NON_APPCONTAINER',
                                        'TOKEN_IS_APPCONTAINER_FALSE_USABLE',
                                    )
                                    if interpretation == 'PROCESS_TOKEN'
                                    else None
                                )
                                if expected_result is not None:
                                    assert (result.status, result.reason) == expected_result
                                observe(
                                    'OBSERVED',
                                    interpretation=interpretation,
                                    raw_is_appcontainer=raw_shape[0],
                                    raw_sid=raw_shape[1],
                                    status=result.status,
                                    reason=result.reason,
                                    client_pid=client_pid.value,
                                )

        assert api.open_thread_token() is None

        # Ack only after the server has completed impersonation, observation and
        # reversion. The client cannot revert its AC thread token before this write.
        assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(client_pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0
        client_exit = h.DWORD()
        assert k.GetExitCodeProcess(client_pi.hProcess, c.byref(client_exit)), c.get_last_error()
        assert client_exit.value == 0, f'client exit code={client_exit.value}'
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        if api.open_thread_token() is not None:
            api.fail_fast()

        if client_primary.value:
            check(k.CloseHandle(client_primary), 'CloseHandle client primary token')
        if duplicate.value:
            check(k.CloseHandle(duplicate), 'CloseHandle duplicate token')
        if source.value:
            check(k.CloseHandle(source), 'CloseHandle source token')
        if source_oracle.value:
            check(k.CloseHandle(source_oracle), 'CloseHandle source oracle token')

        if server not in (None, 0, h.INVALID_HANDLE_VALUE):
            k.DisconnectNamedPipe(server)
            check(k.CloseHandle(server), 'CloseHandle server')
        if descriptor:
            check(k.LocalFree(descriptor) is None, 'LocalFree pipe security descriptor')

        for pi, label in ((client_pi, 'client'), (source_pi, 'source')):
            if pi.hProcess:
                if k.WaitForSingleObject(pi.hProcess, 5000) != h.WAIT_OBJECT_0:
                    check(k.TerminateProcess(pi.hProcess, 1), f'TerminateProcess {label}')
                    check(
                        k.WaitForSingleObject(pi.hProcess, 5000) == h.WAIT_OBJECT_0,
                        f'wait terminated {label}',
                    )
                check(k.CloseHandle(pi.hProcess), f'CloseHandle {label} process')
            if pi.hThread:
                check(k.CloseHandle(pi.hThread), f'CloseHandle {label} thread')

        if client_attr_list:
            k.DeleteProcThreadAttributeList(client_attr_list)
        if source_attr_list:
            k.DeleteProcThreadAttributeList(source_attr_list)
        if app_sid:
            advapi.FreeSid(app_sid)
        if profile_created:
            hr = int(userenv.DeleteAppContainerProfile(profile_name))
            if hr != 0:
                cleanup_errors.append(
                    f'DeleteAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}'
                )

        if cleanup_errors:
            message = '; '.join(cleanup_errors)
            if failure is not None:
                failure.add_note(message)
            else:
                pytest.fail(message)
