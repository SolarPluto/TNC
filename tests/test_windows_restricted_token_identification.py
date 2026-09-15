"""Restricted-token control for AppContainer evidence at identification level.

A green test means the restriction/identity gates succeeded, the named-pipe
experiment was reached, and fail-closed invariants held. The negative-pole
answer itself lives in the emitted observation payload.

TODO: after the experiment sequence, move the shared native Windows helpers
from sibling test modules into tests/_native_harness.py and update this import.
"""
import base64
from contextlib import ExitStack
import ctypes as c
import importlib.util
import os
from pathlib import Path
import sys
import uuid

import pytest

from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows restricted-token control only')

TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_PRIVILEGES = 3
DISABLE_MAX_PRIVILEGE = 0x00000001
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_PRIVILEGE_NOT_HELD = 1314
SE_CHANGE_NOTIFY_NAME = 'SeChangeNotifyPrivilege'


def _load_hardened_harness():
    path = Path(__file__).with_name('test_windows_appcontainer_pipe_positive_control.py')
    spec = importlib.util.spec_from_file_location('_tnc_appcontainer_positive_harness', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = _load_hardened_harness()


class LUID(c.Structure):
    _fields_ = [('LowPart', h.DWORD), ('HighPart', c.c_int32)]


class LUID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [('Luid', LUID), ('Attributes', h.DWORD)]


def _advapi32_restricted():
    a = h._advapi32()
    a.CreateRestrictedToken.argtypes = [
        h.HANDLE, h.DWORD,
        h.DWORD, c.c_void_p,
        h.DWORD, c.c_void_p,
        h.DWORD, c.c_void_p,
        c.POINTER(h.HANDLE),
    ]
    a.CreateRestrictedToken.restype = h.BOOL
    a.CreateProcessAsUserW.argtypes = [
        h.HANDLE,
        c.c_wchar_p,
        c.c_wchar_p,
        c.c_void_p,
        c.c_void_p,
        h.BOOL,
        h.DWORD,
        c.c_void_p,
        c.c_wchar_p,
        c.POINTER(h.STARTUPINFOW),
        c.POINTER(h.PROCESS_INFORMATION),
    ]
    a.CreateProcessAsUserW.restype = h.BOOL
    a.LookupPrivilegeNameW.argtypes = [
        c.c_wchar_p,
        c.POINTER(LUID),
        c.c_wchar_p,
        c.POINTER(h.DWORD),
    ]
    a.LookupPrivilegeNameW.restype = h.BOOL
    return a


def _token_info(advapi, token, kind):
    size = h.DWORD()
    assert not advapi.GetTokenInformation(token, kind, None, 0, c.byref(size))
    assert c.get_last_error() == h.ERROR_INSUFFICIENT_BUFFER
    assert size.value > 0
    buffer = c.create_string_buffer(size.value)
    returned = h.DWORD()
    assert advapi.GetTokenInformation(
        token, kind, buffer, size.value, c.byref(returned)
    ), c.get_last_error()
    assert 0 < returned.value <= size.value
    return buffer, returned.value


def _token_user_sid(advapi, kernel32, token):
    buffer, length = _token_info(advapi, token, TOKEN_USER)
    assert length >= c.sizeof(c.c_void_p)
    sid = c.c_void_p.from_buffer(buffer)
    assert sid.value
    return h._sid_string(advapi, kernel32, sid)


def _lookup_privilege_name(advapi, luid):
    # Privilege names are small stable identifiers. A fixed 256-wide buffer keeps
    # the logging path simple and avoids making size-probe behavior part of this experiment.
    name = c.create_unicode_buffer(256)
    size = h.DWORD(len(name))
    assert advapi.LookupPrivilegeNameW(None, c.byref(luid), name, c.byref(size)), c.get_last_error()
    return name.value


def _enabled_privileges(advapi, token):
    buffer, length = _token_info(advapi, token, TOKEN_PRIVILEGES)
    assert length >= c.sizeof(h.DWORD)
    count = h.DWORD.from_buffer(buffer).value
    needed = c.sizeof(h.DWORD) + count * c.sizeof(LUID_AND_ATTRIBUTES)
    assert needed <= length, f'TokenPrivileges truncated: count={count} length={length} needed={needed}'
    entries = (LUID_AND_ATTRIBUTES * count).from_buffer(buffer, c.sizeof(h.DWORD))
    names = [
        _lookup_privilege_name(advapi, entry.Luid)
        for entry in entries
        if entry.Attributes & SE_PRIVILEGE_ENABLED
    ]
    return sorted(names)


def _evidence(probe, token, *, token_type, level):
    evidence = probe.probe(int(token.value) if hasattr(token, 'value') else token,
                           token_type=token_type, level=level)
    result = evaluate_appcontainer_exclusion(evidence)
    return evidence, result


def _sid_list(values):
    return [str(value) for value in values]


def test_restricted_token_identification_negative_pole(emit_observation):
    k = h._kernel32()
    advapi = _advapi32_restricted()
    probe = NativeAppContainerProbe()
    api = NativePipeTokenAPI()

    source = h.HANDLE()
    restricted = h.HANDLE()
    child_primary = h.HANDLE()
    server = None
    pi = h.PROCESS_INFORMATION()
    token_cleanup = ExitStack()

    try:
        # CreateRestrictedToken returns a handle with the same granted access as
        # ExistingTokenHandle. Include TOKEN_ASSIGN_PRIMARY here because the
        # returned handle is passed directly to CreateProcessAsUserW.
        source_access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
        assert advapi.OpenProcessToken(k.GetCurrentProcess(), source_access, c.byref(source)), c.get_last_error()

        source_user_sid = _token_user_sid(advapi, k, source)
        source_enabled_privileges = _enabled_privileges(advapi, source)
        source_evidence, source_result = _evidence(
            probe, source, token_type='PRIMARY', level=None
        )

        assert advapi.CreateRestrictedToken(
            source,
            DISABLE_MAX_PRIVILEGE,
            0, None,
            0, None,
            0, None,
            c.byref(restricted),
        ), c.get_last_error()
        assert restricted.value

        restricted_user_sid = _token_user_sid(advapi, k, restricted)
        restricted_enabled_privileges = _enabled_privileges(advapi, restricted)
        restricted_evidence, restricted_result = _evidence(
            probe, restricted, token_type='PRIMARY', level=None
        )

        # Restriction gate: preserve identity and ensure DISABLE_MAX_PRIVILEGE
        # did not leave any enabled privilege except SeChangeNotifyPrivilege.
        assert restricted_user_sid == source_user_sid, (
            f'restricted user SID changed: source={source_user_sid!r} restricted={restricted_user_sid!r}'
        )
        unexpected_enabled = [
            name for name in restricted_enabled_privileges
            if name != SE_CHANGE_NOTIFY_NAME
        ]
        assert not unexpected_enabled, (
            'DISABLE_MAX_PRIVILEGE left unexpected enabled privileges: '
            f'{unexpected_enabled!r}; all={restricted_enabled_privileges!r}'
        )

        pipe_name = rf'\\.\pipe\tnc-restricted-ident-{os.getpid()}-{uuid.uuid4().hex}'
        server = k.CreateNamedPipeW(
            pipe_name,
            h.PIPE_ACCESS_DUPLEX | h.FILE_FLAG_OVERLAPPED,
            h.PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            None,
        )
        assert server not in (None, 0, h.INVALID_HANDLE_VALUE), c.get_last_error()

        powershell = os.path.join(
            os.environ['SystemRoot'], 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'
        )
        pipe_component = pipe_name.rsplit('\\', 1)[-1]
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
        si = h.STARTUPINFOW()
        si.cb = c.sizeof(si)
        flags = h.CREATE_SUSPENDED | h.CREATE_NO_WINDOW

        if not advapi.CreateProcessAsUserW(
            restricted,
            None,
            command_line,
            None,
            None,
            False,
            flags,
            None,
            None,
            c.byref(si),
            c.byref(pi),
        ):
            error = c.get_last_error()
            if error == ERROR_PRIVILEGE_NOT_HELD:
                pytest.skip(
                    'CreateProcessAsUserW requires a privilege unavailable on this runner '
                    f'(ERROR_PRIVILEGE_NOT_HELD={ERROR_PRIVILEGE_NOT_HELD})'
                )
            pytest.fail(f'CreateProcessAsUserW failed: WinError {error}')

        assert advapi.OpenProcessToken(pi.hProcess, TOKEN_QUERY, c.byref(child_primary)), c.get_last_error()
        child_primary_user_sid = _token_user_sid(advapi, k, child_primary)
        child_primary_enabled_privileges = _enabled_privileges(advapi, child_primary)
        child_primary_evidence, child_primary_result = _evidence(
            probe, child_primary, token_type='PRIMARY', level=None
        )

        assert child_primary_user_sid == source_user_sid, (
            'child primary identity discontinuity: '
            f'source={source_user_sid!r} restricted={restricted_user_sid!r} child={child_primary_user_sid!r}'
        )
        assert child_primary_enabled_privileges == restricted_enabled_privileges, (
            'child primary privilege state differs from restricted launch token: '
            f'restricted={restricted_enabled_privileges!r} child={child_primary_enabled_privileges!r}'
        )

        assert k.ResumeThread(pi.hThread) != 0xFFFFFFFF, c.get_last_error()
        byte = c.create_string_buffer(1)
        try:
            h._pipe_io(k, server, 'connect')
            assert h._pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'
        except AssertionError as failure:
            exit_code = h.DWORD()
            if k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)):
                failure.add_note(
                    'restricted PRIMARY gates passed; pipe handshake failed; '
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
        identification_user_sid = _token_user_sid(advapi, k, h.HANDLE(pipe_token))
        identification_evidence = probe.probe(
            pipe_token, token_type=facts.token_type, level=facts.level
        )
        identification_result = evaluate_appcontainer_exclusion(identification_evidence)

        emit_observation(
            'TNC_RESTRICTED_TOKEN_IDENTIFICATION_OBSERVATION '
            f'source_user_sid={source_user_sid!r} '
            f'source_enabled_privileges={source_enabled_privileges!r} '
            f'source_is_appcontainer={source_evidence.token_is_app_container!r} '
            f'source_appcontainer_sid={str(source_evidence.app_container_sid) if source_evidence.app_container_sid is not None else None!r} '
            f'source_capabilities={_sid_list(source_evidence.capability_sids)!r} '
            f'source_status={source_result.status} source_reason={source_result.reason} '
            f'restricted_primary_user_sid={restricted_user_sid!r} '
            f'restricted_primary_enabled_privileges={restricted_enabled_privileges!r} '
            f'restricted_primary_is_appcontainer={restricted_evidence.token_is_app_container!r} '
            f'restricted_primary_appcontainer_sid={str(restricted_evidence.app_container_sid) if restricted_evidence.app_container_sid is not None else None!r} '
            f'restricted_primary_capabilities={_sid_list(restricted_evidence.capability_sids)!r} '
            f'restricted_primary_status={restricted_result.status} restricted_primary_reason={restricted_result.reason} '
            f'child_primary_user_sid={child_primary_user_sid!r} '
            f'child_primary_enabled_privileges={child_primary_enabled_privileges!r} '
            f'child_primary_is_appcontainer={child_primary_evidence.token_is_app_container!r} '
            f'child_primary_appcontainer_sid={str(child_primary_evidence.app_container_sid) if child_primary_evidence.app_container_sid is not None else None!r} '
            f'child_primary_capabilities={_sid_list(child_primary_evidence.capability_sids)!r} '
            f'child_primary_status={child_primary_result.status} child_primary_reason={child_primary_result.reason} '
            f'identification_user_sid={identification_user_sid!r} '
            f'identification_is_appcontainer={identification_evidence.token_is_app_container!r} '
            f'identification_appcontainer_sid={str(identification_evidence.app_container_sid) if identification_evidence.app_container_sid is not None else None!r} '
            f'identification_capabilities={_sid_list(identification_evidence.capability_sids)!r} '
            f'identification_status={identification_result.status} '
            f'identification_reason={identification_result.reason}'
        )

        # Identity continuity is a gate, not an inferred reading from matching
        # AppContainer fields. Emit both operands above, then assert directly.
        assert identification_user_sid == source_user_sid, (
            'identification identity discontinuity: '
            f'source={source_user_sid!r} restricted={restricted_user_sid!r} '
            f'child={child_primary_user_sid!r} identification={identification_user_sid!r}'
        )

        # Orthogonal safety invariant: whatever 29/30/31 report for this restricted
        # client, identification evidence cannot manufacture admission or proof of
        # non-AppContainer status.
        assert identification_result.status != 'PROVEN_NON_APPCONTAINER'
        assert not identification_result.authorization_granted
        assert not identification_result.admission_granted

        token_cleanup.close()
        assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0, (
            'restricted client did not exit after completion'
        )
        exit_code = h.DWORD()
        assert k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)), c.get_last_error()
        assert exit_code.value == 0, f'restricted client exit code={exit_code.value}'
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        token_cleanup.close()
        if child_primary.value:
            check(k.CloseHandle(child_primary), 'CloseHandle child primary token')
        if restricted.value:
            check(k.CloseHandle(restricted), 'CloseHandle restricted token')
        if source.value:
            check(k.CloseHandle(source), 'CloseHandle source token')
        if server not in (None, 0, h.INVALID_HANDLE_VALUE):
            k.DisconnectNamedPipe(server)
            check(k.CloseHandle(server), 'CloseHandle server')
        if pi.hProcess:
            if k.WaitForSingleObject(pi.hProcess, 5000) != h.WAIT_OBJECT_0:
                check(k.TerminateProcess(pi.hProcess, 1), 'TerminateProcess')
                check(k.WaitForSingleObject(pi.hProcess, 5000) == h.WAIT_OBJECT_0,
                      'wait for terminated restricted client')
            check(k.CloseHandle(pi.hProcess), 'CloseHandle process')
        if pi.hThread:
            check(k.CloseHandle(pi.hThread), 'CloseHandle thread')
        if cleanup_errors:
            message = '; '.join(cleanup_errors)
            if failure is not None:
                failure.add_note(message)
            else:
                pytest.fail(message)

    assert api.open_thread_token() is None
