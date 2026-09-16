"""Low-integrity control for AppContainer evidence at identification level.

The launch token is duplicated, lowered to low mandatory integrity, and verified
before any child exists. The suspended child's primary token and the eventual
named-pipe identification token are then independently checked for the same
integrity and user SID before the AppContainer evidence reading is interpreted.
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


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows low-integrity control only')

TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_USER = 1
TOKEN_INTEGRITY_LEVEL = 25
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1
SE_GROUP_INTEGRITY = 0x00000020
ERROR_PRIVILEGE_NOT_HELD = 1314
LOW_INTEGRITY_SID = 'S-1-16-4096'


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [('Sid', c.c_void_p), ('Attributes', h.DWORD)]


class TOKEN_MANDATORY_LABEL(c.Structure):
    _fields_ = [('Label', SID_AND_ATTRIBUTES)]


def _advapi32_low_integrity():
    a = h._advapi32()
    a.DuplicateTokenEx.argtypes = [
        h.HANDLE,
        h.DWORD,
        c.c_void_p,
        c.c_int32,
        c.c_int32,
        c.POINTER(h.HANDLE),
    ]
    a.DuplicateTokenEx.restype = h.BOOL
    a.SetTokenInformation.argtypes = [
        h.HANDLE, c.c_int32, c.c_void_p, h.DWORD,
    ]
    a.SetTokenInformation.restype = h.BOOL
    a.ConvertStringSidToSidW.argtypes = [c.c_wchar_p, c.POINTER(c.c_void_p)]
    a.ConvertStringSidToSidW.restype = h.BOOL
    a.GetLengthSid.argtypes = [c.c_void_p]
    a.GetLengthSid.restype = h.DWORD
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


def _token_integrity_sid(advapi, kernel32, token):
    buffer, length = _token_info(advapi, token, TOKEN_INTEGRITY_LEVEL)
    assert length >= c.sizeof(TOKEN_MANDATORY_LABEL)
    label = TOKEN_MANDATORY_LABEL.from_buffer(buffer)
    assert label.Label.Sid
    return h._sid_string(advapi, kernel32, label.Label.Sid)


def _low_pipe_security(advapi, user_sid):
    descriptor = c.c_void_p()
    sddl = f'D:(A;;GRGW;;;{user_sid})S:(ML;;NW;;;LW)'
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, h.SECURITY_DESCRIPTOR_REVISION, c.byref(descriptor), None
    ), c.get_last_error()
    return descriptor, h.SECURITY_ATTRIBUTES(
        nLength=c.sizeof(h.SECURITY_ATTRIBUTES),
        lpSecurityDescriptor=descriptor,
        bInheritHandle=False,
    )


def _python_pipe_client(pipe_name):
    # Avoid PowerShell/CLR/profile/TEMP dependencies under low integrity. The
    # client asks the kernel for SECURITY_IDENTIFICATION directly on CreateFileW.
    code = f'''import ctypes as c
k = c.WinDLL("kernel32.dll", use_last_error=True)
HANDLE = c.c_void_p
DWORD = c.c_uint32
BOOL = c.c_int32
INVALID_HANDLE_VALUE = c.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
SECURITY_IDENTIFICATION = 0x00010000
SECURITY_SQOS_PRESENT = 0x00100000
k.CreateFileW.argtypes = [c.c_wchar_p, DWORD, DWORD, c.c_void_p, DWORD, DWORD, HANDLE]
k.CreateFileW.restype = HANDLE
k.WriteFile.argtypes = [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p]
k.WriteFile.restype = BOOL
k.ReadFile.argtypes = k.WriteFile.argtypes
k.ReadFile.restype = BOOL
k.CloseHandle.argtypes = [HANDLE]
k.CloseHandle.restype = BOOL
handle = k.CreateFileW({pipe_name!r}, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
                       SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None)
if handle in (None, 0, INVALID_HANDLE_VALUE):
    raise OSError(c.get_last_error(), "CreateFileW named pipe")
try:
    transferred = DWORD()
    out_byte = c.create_string_buffer(b"X")
    if not k.WriteFile(handle, out_byte, 1, c.byref(transferred), None) or transferred.value != 1:
        raise OSError(c.get_last_error(), "WriteFile named pipe")
    in_byte = c.create_string_buffer(1)
    if not k.ReadFile(handle, in_byte, 1, c.byref(transferred), None) or transferred.value != 1:
        raise OSError(c.get_last_error(), "ReadFile named pipe")
    if in_byte.raw != b"Y":
        raise RuntimeError(f"unexpected completion byte: {{in_byte.raw!r}}")
finally:
    if not k.CloseHandle(handle):
        raise OSError(c.get_last_error(), "CloseHandle named pipe")
'''
    encoded = base64.b64encode(code.encode('utf-8')).decode('ascii')
    return c.create_unicode_buffer(
        f'"{sys.executable}" -I -c "import base64;exec(base64.b64decode(\'{encoded}\'))"'
    )


def _sid_list(values):
    return [str(value) for value in values]


def test_low_integrity_token_identification_negative_pole(emit_observation):
    k = h._kernel32()
    advapi = _advapi32_low_integrity()
    probe = NativeAppContainerProbe()
    api = NativePipeTokenAPI()

    source = h.HANDLE()
    low_primary = h.HANDLE()
    child_primary = h.HANDLE()
    low_sid = c.c_void_p()
    descriptor = None
    server = None
    pi = h.PROCESS_INFORMATION()
    token_cleanup = ExitStack()

    try:
        source_access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY
        assert advapi.OpenProcessToken(
            k.GetCurrentProcess(), source_access, c.byref(source)
        ), c.get_last_error()

        source_user_sid = _token_user_sid(advapi, k, source)
        source_integrity_sid = _token_integrity_sid(advapi, k, source)
        if source_integrity_sid == LOW_INTEGRITY_SID:
            pytest.skip('source process is already low integrity; transition cannot be established')

        duplicate_access = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT
        assert advapi.DuplicateTokenEx(
            source,
            duplicate_access,
            None,
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            c.byref(low_primary),
        ), c.get_last_error()
        assert low_primary.value

        assert advapi.ConvertStringSidToSidW(LOW_INTEGRITY_SID, c.byref(low_sid)), c.get_last_error()
        assert low_sid.value
        sid_length = advapi.GetLengthSid(low_sid)
        assert sid_length > 0, c.get_last_error()
        label = TOKEN_MANDATORY_LABEL(
            SID_AND_ATTRIBUTES(low_sid.value, SE_GROUP_INTEGRITY)
        )
        info_length = c.sizeof(TOKEN_MANDATORY_LABEL) + sid_length
        assert advapi.SetTokenInformation(
            low_primary,
            TOKEN_INTEGRITY_LEVEL,
            c.byref(label),
            info_length,
        ), c.get_last_error()

        low_primary_user_sid = _token_user_sid(advapi, k, low_primary)
        low_primary_integrity_sid = _token_integrity_sid(advapi, k, low_primary)
        assert low_primary_user_sid == source_user_sid, (
            f'low-primary user SID changed: source={source_user_sid!r} low={low_primary_user_sid!r}'
        )
        assert low_primary_integrity_sid == LOW_INTEGRITY_SID, (
            f'low-primary integrity gate failed: {low_primary_integrity_sid!r}'
        )

        descriptor, security_attributes = _low_pipe_security(advapi, source_user_sid)
        pipe_name = rf'\\.\pipe\tnc-low-integrity-ident-{os.getpid()}-{uuid.uuid4().hex}'
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

        command_line = _python_pipe_client(pipe_name)
        si = h.STARTUPINFOW()
        si.cb = c.sizeof(si)
        flags = h.CREATE_SUSPENDED | h.CREATE_NO_WINDOW
        if not advapi.CreateProcessAsUserW(
            low_primary,
            sys.executable,
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

        assert advapi.OpenProcessToken(
            pi.hProcess, TOKEN_QUERY, c.byref(child_primary)
        ), c.get_last_error()
        child_primary_user_sid = _token_user_sid(advapi, k, child_primary)
        child_primary_integrity_sid = _token_integrity_sid(advapi, k, child_primary)
        assert child_primary_user_sid == source_user_sid, (
            'child primary identity discontinuity: '
            f'source={source_user_sid!r} low={low_primary_user_sid!r} child={child_primary_user_sid!r}'
        )
        assert child_primary_integrity_sid == LOW_INTEGRITY_SID, (
            'child primary integrity discontinuity: '
            f'low={low_primary_integrity_sid!r} child={child_primary_integrity_sid!r}'
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
                    'low-integrity PRIMARY gates passed; pipe handshake failed; '
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
        identification_integrity_sid = _token_integrity_sid(advapi, k, h.HANDLE(pipe_token))
        identification_evidence = probe.probe(
            pipe_token, token_type=facts.token_type, level=facts.level
        )
        identification_result = evaluate_appcontainer_exclusion(identification_evidence)

        emit_observation(
            'TNC_LOW_INTEGRITY_TOKEN_IDENTIFICATION_OBSERVATION '
            "construction='prelaunch_duplicate' "
            f'source_user_sid={source_user_sid!r} '
            f'source_integrity_sid={source_integrity_sid!r} '
            f'low_primary_user_sid={low_primary_user_sid!r} '
            f'low_primary_integrity_sid={low_primary_integrity_sid!r} '
            f'child_primary_user_sid={child_primary_user_sid!r} '
            f'child_primary_integrity_sid={child_primary_integrity_sid!r} '
            f'identification_user_sid={identification_user_sid!r} '
            f'identification_integrity_sid={identification_integrity_sid!r} '
            f'identification_is_appcontainer={identification_evidence.token_is_app_container!r} '
            f'identification_appcontainer_sid={str(identification_evidence.app_container_sid) if identification_evidence.app_container_sid is not None else None!r} '
            f'identification_capabilities={_sid_list(identification_evidence.capability_sids)!r} '
            f'identification_status={identification_result.status} '
            f'identification_reason={identification_result.reason}'
        )

        assert identification_user_sid == source_user_sid, (
            'identification identity discontinuity: '
            f'source={source_user_sid!r} low={low_primary_user_sid!r} '
            f'child={child_primary_user_sid!r} identification={identification_user_sid!r}'
        )
        assert identification_integrity_sid == LOW_INTEGRITY_SID, (
            'identification token is not low integrity: '
            f'expected={LOW_INTEGRITY_SID!r} actual={identification_integrity_sid!r}'
        )

        # Any 29/30/31 signal here is cross-property leakage, not a stable
        # low-integrity result. The expected negative evidence remains fail-closed
        # solely because the token is at identification impersonation level.
        assert not identification_evidence.token_is_app_container
        assert identification_evidence.app_container_sid is None
        assert not identification_evidence.capability_sids
        assert identification_result.status == 'UNPROVEN'
        assert identification_result.reason == 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN'
        assert not identification_result.authorization_granted
        assert not identification_result.admission_granted

        token_cleanup.close()
        assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0, (
            'low-integrity client did not exit after completion'
        )
        exit_code = h.DWORD()
        assert k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)), c.get_last_error()
        assert exit_code.value == 0, f'low-integrity client exit code={exit_code.value}'
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        token_cleanup.close()
        if child_primary.value:
            check(k.CloseHandle(child_primary), 'CloseHandle child primary token')
        if low_primary.value:
            check(k.CloseHandle(low_primary), 'CloseHandle low-integrity token')
        if source.value:
            check(k.CloseHandle(source), 'CloseHandle source token')
        if low_sid.value:
            check(k.LocalFree(low_sid) is None, 'LocalFree low integrity SID')
        if descriptor:
            check(k.LocalFree(descriptor) is None, 'LocalFree pipe security descriptor')
        if server not in (None, 0, h.INVALID_HANDLE_VALUE):
            k.DisconnectNamedPipe(server)
            check(k.CloseHandle(server), 'CloseHandle server')
        if pi.hProcess:
            if k.WaitForSingleObject(pi.hProcess, 5000) != h.WAIT_OBJECT_0:
                check(k.TerminateProcess(pi.hProcess, 1), 'TerminateProcess')
                check(
                    k.WaitForSingleObject(pi.hProcess, 5000) == h.WAIT_OBJECT_0,
                    'wait for terminated low-integrity client',
                )
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
