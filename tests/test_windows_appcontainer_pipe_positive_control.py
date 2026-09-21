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

from _native_harness import (
    CREATE_NO_WINDOW,
    CREATE_SUSPENDED,
    DWORD,
    ERROR_INSUFFICIENT_BUFFER,
    EXTENDED_STARTUPINFO_PRESENT,
    FILE_FLAG_OVERLAPPED,
    HANDLE,
    INVALID_HANDLE_VALUE,
    IO_TIMEOUT_MS,
    PIPE_ACCESS_DUPLEX,
    PIPE_REJECT_REMOTE_CLIENTS,
    PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    SECURITY_CAPABILITIES,
    SIZE_T,
    STARTUPINFOEXW,
    STARTUPINFOW,
    TOKEN_QUERY,
    WAIT_OBJECT_0,
    _advapi32,
    _capability_observation_fields,
    _checked_cleanup,
    _current_user_sid,
    _kernel32,
    _no_temporal_guard,
    _pipe_io,
    _pipe_security,
    _raw_primary_oracle,
    _revert_or_fail_fast,
    _sid_string,
    _undrained_io,
    _userenv,
)
from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows AppContainer positive control only')


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
            f'{_capability_observation_fields(identification_evidence)} '
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
