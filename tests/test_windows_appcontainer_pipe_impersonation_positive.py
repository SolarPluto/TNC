"""Matched-pair AppContainer positive control at pipe IMPERSONATION level.

This is the PR #8 producer with one experimental variable changed: the client
requests TokenImpersonationLevel.Impersonation instead of Identification. The
PRIMARY oracle establishes a real AppContainer before the child runs, and the
captured pipe token level is verified before AppContainer evidence is probed.
"""
import base64
from contextlib import ExitStack
import ctypes as c
import os
import sys
import uuid

import pytest

import _native_harness as h
from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows AppContainer positive control only')


def test_appcontainer_client_impersonation_token_positive_control(emit_observation):
    k = h._kernel32()
    advapi = h._advapi32()
    userenv = h._userenv()
    profile_name = f'TNC.ImpersonationPositive.{uuid.uuid4().hex}'
    app_sid = c.c_void_p()
    descriptor = None
    attr_buffer = None
    attr_list = None
    server = None
    primary_token = h.HANDLE()
    pi = h.PROCESS_INFORMATION()
    api = NativePipeTokenAPI()
    token_cleanup = ExitStack()
    profile_created = False

    try:
        hr = int(userenv.CreateAppContainerProfile(
            profile_name,
            profile_name,
            'TNC AppContainer impersonation-level positive control',
            None,
            0,
            c.byref(app_sid),
        ))
        assert hr == 0, f'CreateAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}'
        profile_created = True
        expected_sid = h._sid_string(advapi, k, app_sid)

        # Keep the PR #8 pipe ACL/SACL construction unchanged.
        descriptor, security_attributes = h._pipe_security(
            advapi, expected_sid, h._current_user_sid(advapi, k)
        )
        pipe_component = f'tnc-appcontainer-impersonation-{os.getpid()}-{uuid.uuid4().hex}'
        pipe_name = rf'\\.\pipe\{pipe_component}'
        server = k.CreateNamedPipeW(
            pipe_name,
            h.PIPE_ACCESS_DUPLEX | h.FILE_FLAG_OVERLAPPED,
            h.PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            c.byref(security_attributes),
        )
        assert server not in (None, 0, h.INVALID_HANDLE_VALUE), c.get_last_error()

        size = h.SIZE_T()
        assert not k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        assert c.get_last_error() == h.ERROR_INSUFFICIENT_BUFFER
        attr_buffer = c.create_string_buffer(size.value)
        assert k.InitializeProcThreadAttributeList(
            attr_buffer, 1, 0, c.byref(size)
        ), c.get_last_error()
        attr_list = c.cast(attr_buffer, c.c_void_p)

        capabilities = h.SECURITY_CAPABILITIES(
            AppContainerSid=app_sid,
            Capabilities=None,
            CapabilityCount=0,
            Reserved=0,
        )
        assert k.UpdateProcThreadAttribute(
            attr_list,
            0,
            h.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            c.byref(capabilities),
            c.sizeof(capabilities),
            None,
            None,
        ), c.get_last_error()

        powershell = os.path.join(
            os.environ['SystemRoot'],
            'System32',
            'WindowsPowerShell',
            'v1.0',
            'powershell.exe',
        )
        # Single experimental variable versus PR #8: request Impersonation.
        script = (
            "$ErrorActionPreference='Stop';$p=[System.IO.Pipes.NamedPipeClientStream]::new('.', '"
            + pipe_component
            + "', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, "
              "[System.Security.Principal.TokenImpersonationLevel]::Impersonation);"
              "try {$p.Connect(30000);$p.WriteByte(88);$p.Flush();"
              "if ($p.ReadByte() -ne 89) {throw 'Missing server completion byte'}}"
              "finally {$p.Dispose()}"
        )
        encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
        command_line = c.create_unicode_buffer(
            f'"{powershell}" -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}'
        )
        si = h.STARTUPINFOEXW()
        si.StartupInfo.cb = c.sizeof(si)
        si.lpAttributeList = attr_list
        flags = h.EXTENDED_STARTUPINFO_PRESENT | h.CREATE_SUSPENDED | h.CREATE_NO_WINDOW
        assert k.CreateProcessW(
            None,
            command_line,
            None,
            None,
            False,
            flags,
            None,
            None,
            c.cast(c.byref(si), c.POINTER(h.STARTUPINFOW)),
            c.byref(pi),
        ), c.get_last_error()

        # Same independent PRIMARY oracle/control as PR #8.
        assert advapi.OpenProcessToken(
            pi.hProcess, h.TOKEN_QUERY, c.byref(primary_token)
        ), c.get_last_error()
        h._raw_primary_oracle(advapi, k, primary_token, expected_sid)
        primary_evidence = NativeAppContainerProbe().probe(
            int(primary_token.value), token_type='PRIMARY', level=None
        )
        primary_result = evaluate_appcontainer_exclusion(primary_evidence)
        assert primary_evidence.token_is_app_container
        assert str(primary_evidence.app_container_sid) == expected_sid
        assert primary_result.status == 'APPCONTAINER'
        assert primary_result.reason == 'TOKEN_IS_APPCONTAINER'
        assert not primary_result.authorization_granted
        assert not primary_result.admission_granted

        assert k.ResumeThread(pi.hThread) != 0xFFFFFFFF, c.get_last_error()
        byte = c.create_string_buffer(1)
        try:
            h._pipe_io(k, server, 'connect')
            assert h._pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'
        except AssertionError as failure:
            exit_code = h.DWORD()
            if k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)):
                failure.add_note(
                    'PRIMARY AppContainer oracle/control passed; impersonation-level '
                    f'pipe handshake failed; child exit code={exit_code.value} (259=still active)'
                )
            raise

        assert api.open_thread_token() is None
        assert api.impersonate(server)
        token_cleanup.callback(h._revert_or_fail_fast, api)
        pipe_token = api.open_thread_token()
        assert pipe_token is not None
        token_cleanup.callback(h._checked_cleanup, api.close, pipe_token)

        # Producer gate: do not probe or interpret AppContainer evidence unless
        # Windows actually granted an IMPERSONATION-level pipe token.
        facts = api.capture(pipe_token, h._no_temporal_guard)
        assert facts.token_type == 'IMPERSONATION'
        assert facts.level == 'IMPERSONATION', (
            'requested pipe impersonation level was not granted: '
            f'actual={facts.level!r}'
        )

        evidence = NativeAppContainerProbe().probe(
            pipe_token,
            token_type=facts.token_type,
            level=facts.level,
        )
        result = evaluate_appcontainer_exclusion(evidence)

        emit_observation(
            'TNC_APPCONTAINER_IMPERSONATION_POSITIVE_OBSERVATION '
            "construction='matched_pair_security_impersonation' "
            f'oracle_is_appcontainer=True oracle_sid={expected_sid!r} '
            f'level={facts.level} '
            f'is_appcontainer={evidence.token_is_app_container!r} '
            f'appcontainer_sid={str(evidence.app_container_sid) if evidence.app_container_sid is not None else None!r} '
            f'capabilities={[str(sid) for sid in evidence.capability_sids]!r} '
            f'status={result.status} reason={result.reason}'
        )

        # Precommitted expected pole. Any loss of the positive flag/SID is an
        # empirical anomaly, not a reason to reinterpret a negative result.
        assert evidence.token_is_app_container is True
        assert evidence.app_container_sid is not None
        assert str(evidence.app_container_sid) == expected_sid
        assert not evidence.capability_sids
        assert result.status == 'APPCONTAINER'
        assert result.reason == 'TOKEN_IS_APPCONTAINER'
        assert not result.authorization_granted
        assert not result.admission_granted

        token_cleanup.close()
        assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0, (
            'AppContainer client did not exit after completion'
        )
        exit_code = h.DWORD()
        assert k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)), c.get_last_error()
        assert exit_code.value == 0, f'AppContainer client exit code={exit_code.value}'
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        token_cleanup.close()
        if primary_token.value:
            check(k.CloseHandle(primary_token), 'CloseHandle primary token')
        if server not in (None, 0, h.INVALID_HANDLE_VALUE):
            k.DisconnectNamedPipe(server)
            check(k.CloseHandle(server), 'CloseHandle server')
        if pi.hProcess:
            if k.WaitForSingleObject(pi.hProcess, 5000) != h.WAIT_OBJECT_0:
                check(k.TerminateProcess(pi.hProcess, 1), 'TerminateProcess')
                check(
                    k.WaitForSingleObject(pi.hProcess, 5000) == h.WAIT_OBJECT_0,
                    'wait for terminated AppContainer client',
                )
            check(k.CloseHandle(pi.hProcess), 'CloseHandle process')
        if pi.hThread:
            check(k.CloseHandle(pi.hThread), 'CloseHandle thread')
        if attr_list:
            k.DeleteProcThreadAttributeList(attr_list)
        if descriptor:
            check(k.LocalFree(descriptor) is None, 'LocalFree pipe security descriptor')
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

    assert api.open_thread_token() is None
