"""Capability-positive AppContainer control for identification-level class 30.

A green test means the harness reached the experiment and fail-closed invariants
held. It does not mean TokenCapabilities survived identification impersonation;
that experimental answer is carried only by the emitted observation payload.
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


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows AppContainer capability control only')

INTERNET_CLIENT_SID = 'S-1-15-3-1'
SE_GROUP_ENABLED = 0x00000004


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [('Sid', c.c_void_p), ('Attributes', h.DWORD)]


def _advapi32_with_sid_parser():
    advapi = h._advapi32()
    advapi.ConvertStringSidToSidW.argtypes = [c.c_wchar_p, c.POINTER(c.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = h.BOOL
    return advapi


def _sid_list(values):
    return [str(value) for value in values]


def test_appcontainer_capability_survival_at_identification(emit_observation):
    k = h._kernel32()
    advapi = _advapi32_with_sid_parser()
    userenv = h._userenv()
    profile_name = f'TNC.CapabilityPositive.{uuid.uuid4().hex}'
    app_sid = c.c_void_p()
    internet_client_sid = c.c_void_p()
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
            'TNC AppContainer capability-positive control',
            None,
            0,
            c.byref(app_sid),
        ))
        assert hr == 0, f'CreateAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}'
        profile_created = True
        expected_app_sid = h._sid_string(advapi, k, app_sid)

        # internetClient is a fixed, well-known AppContainer capability SID. Use
        # the canonical SID directly so this experiment does not depend on
        # DeriveCapabilitySidsFromName or capability-name resolution behavior.
        assert advapi.ConvertStringSidToSidW(INTERNET_CLIENT_SID, c.byref(internet_client_sid)), c.get_last_error()
        assert internet_client_sid.value

        descriptor, security_attributes = h._pipe_security(
            advapi,
            expected_app_sid,
            h._current_user_sid(advapi, k),
        )
        pipe_component = f'tnc-appcontainer-capability-{os.getpid()}-{uuid.uuid4().hex}'
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
        assert k.InitializeProcThreadAttributeList(attr_buffer, 1, 0, c.byref(size)), c.get_last_error()
        attr_list = c.cast(attr_buffer, c.c_void_p)

        # SECURITY_CAPABILITIES points at caller-owned SID_AND_ATTRIBUTES storage.
        # Keep cap_array and the converted PSID strongly referenced through the
        # CreateProcessW call; Windows consumes the attribute during creation.
        cap_array = (SID_AND_ATTRIBUTES * 1)()
        cap_array[0].Sid = internet_client_sid
        cap_array[0].Attributes = SE_GROUP_ENABLED
        capabilities = h.SECURITY_CAPABILITIES(
            AppContainerSid=app_sid,
            Capabilities=c.cast(cap_array, c.c_void_p),
            CapabilityCount=1,
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

        # Gate the identification experiment on a genuinely capability-positive
        # PRIMARY token. A failure here is upstream of identification semantics.
        assert advapi.OpenProcessToken(pi.hProcess, h.TOKEN_QUERY, c.byref(primary_token)), c.get_last_error()
        h._raw_primary_oracle(advapi, k, primary_token, expected_app_sid)
        primary_evidence = NativeAppContainerProbe().probe(
            int(primary_token.value), token_type='PRIMARY', level=None
        )
        primary_result = evaluate_appcontainer_exclusion(primary_evidence)
        primary_capabilities = _sid_list(primary_evidence.capability_sids)
        assert INTERNET_CLIENT_SID in primary_capabilities, (
            f'PRIMARY token missing requested capability {INTERNET_CLIENT_SID}; '
            f'observed={primary_capabilities!r}'
        )
        assert primary_evidence.token_is_app_container
        assert str(primary_evidence.app_container_sid) == expected_app_sid
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
                    'PRIMARY capability oracle/control passed; pipe handshake failed; '
                    f'child exit code={exit_code.value} (259=still active)'
                )
            raise

        assert api.open_thread_token() is None
        assert api.impersonate(server)
        token_cleanup.callback(h._revert_or_fail_fast, api)
        pipe_token = api.open_thread_token()
        assert pipe_token is not None
        token_cleanup.callback(h._checked_cleanup, api.close, pipe_token)
        facts = api.capture(pipe_token, h._no_temporal_guard)
        assert facts.token_type == 'IMPERSONATION'
        assert facts.level == 'IDENTIFICATION'

        identification_evidence = NativeAppContainerProbe().probe(
            pipe_token,
            token_type=facts.token_type,
            level=facts.level,
        )
        identification_result = evaluate_appcontainer_exclusion(identification_evidence)
        identification_capabilities = _sid_list(identification_evidence.capability_sids)

        # This line, not pytest green/red, carries the class-30 experimental answer.
        # Include class-29/31 state so an empty capability set is interpretable in
        # isolation rather than being silently compared with PR #8 after the fact.
        emit_observation(
            'TNC_APPCONTAINER_CAPABILITY_OBSERVATION '
            f'primary_capabilities={primary_capabilities!r} '
            f'identification_capabilities={identification_capabilities!r} '
            f'identification_is_appcontainer={identification_evidence.token_is_app_container!r} '
            f'identification_sid={str(identification_evidence.app_container_sid) if identification_evidence.app_container_sid is not None else None!r} '
            f'identification_status={identification_result.status} '
            f'identification_reason={identification_result.reason}'
        )

        # Orthogonal safety invariant: class-30 behavior cannot manufacture an
        # identification-level allow or non-AppContainer proof.
        assert identification_result.status != 'PROVEN_NON_APPCONTAINER'
        assert not identification_result.authorization_granted
        assert not identification_result.admission_granted

        token_cleanup.close()
        assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0, (
            'client did not exit after completion'
        )
        exit_code = h.DWORD()
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
        if server not in (None, 0, h.INVALID_HANDLE_VALUE):
            k.DisconnectNamedPipe(server)
            check(k.CloseHandle(server), 'CloseHandle server')
        if pi.hProcess:
            if k.WaitForSingleObject(pi.hProcess, 5000) != h.WAIT_OBJECT_0:
                check(k.TerminateProcess(pi.hProcess, 1), 'TerminateProcess')
                check(k.WaitForSingleObject(pi.hProcess, 5000) == h.WAIT_OBJECT_0, 'wait for terminated client')
            check(k.CloseHandle(pi.hProcess), 'CloseHandle process')
        if pi.hThread:
            check(k.CloseHandle(pi.hThread), 'CloseHandle thread')
        if attr_list:
            k.DeleteProcThreadAttributeList(attr_list)
        if descriptor:
            k.LocalFree(descriptor)
        if internet_client_sid.value:
            advapi.FreeSid(internet_client_sid)
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
