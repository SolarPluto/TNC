"""Feasibility probe for assigning an AppContainer impersonation token to a non-AC thread."""
import ctypes as c
import os
import sys
import uuid

import pytest

import _native_harness as h


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows AppContainer thread-token feasibility only')

TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
SECURITY_IMPERSONATION = 2
TOKEN_IMPERSONATION = 2


def _advapi():
    a = h._advapi32()
    a.DuplicateTokenEx.argtypes = [
        h.HANDLE, h.DWORD, c.c_void_p, c.c_int32, c.c_int32, c.POINTER(h.HANDLE),
    ]
    a.DuplicateTokenEx.restype = h.BOOL
    a.SetThreadToken.argtypes = [c.POINTER(h.HANDLE), h.HANDLE]
    a.SetThreadToken.restype = h.BOOL
    a.RevertToSelf.argtypes = []
    a.RevertToSelf.restype = h.BOOL
    return a


def test_appcontainer_token_can_be_assigned_to_non_appcontainer_thread(emit_observation):
    k = h._kernel32()
    advapi = _advapi()
    userenv = h._userenv()

    profile_name = f'TNC.ThreadTokenFeasibility.{uuid.uuid4().hex}'
    app_sid = c.c_void_p()
    attr_buffer = None
    attr_list = None
    pi = h.PROCESS_INFORMATION()
    source = h.HANDLE()
    duplicate = h.HANDLE()
    profile_created = False
    thread_token_set = False

    try:
        hr = int(userenv.CreateAppContainerProfile(
            profile_name,
            profile_name,
            'TNC AppContainer thread-token feasibility source',
            None,
            0,
            c.byref(app_sid),
        ))
        assert hr == 0, f'CreateAppContainerProfile HRESULT 0x{hr & 0xffffffff:08x}'
        profile_created = True
        expected_sid = h._sid_string(advapi, k, app_sid)

        size = h.SIZE_T()
        assert not k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        assert c.get_last_error() == h.ERROR_INSUFFICIENT_BUFFER
        attr_buffer = c.create_string_buffer(size.value)
        assert k.InitializeProcThreadAttributeList(attr_buffer, 1, 0, c.byref(size)), c.get_last_error()
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
            os.environ['SystemRoot'], 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'
        )
        command_line = c.create_unicode_buffer(
            f'"{powershell}" -NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 30"'
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

        source_access = TOKEN_QUERY | TOKEN_DUPLICATE
        if not advapi.OpenProcessToken(pi.hProcess, source_access, c.byref(source)):
            error = c.get_last_error()
            pytest.fail(f'OpenProcessToken(TOKEN_QUERY|TOKEN_DUPLICATE) failed: WinError {error}')
        assert source.value

        # Independent raw oracle before duplication.
        flag = h.DWORD()
        returned = h.DWORD()
        assert advapi.GetTokenInformation(
            source,
            h.TOKEN_IS_APPCONTAINER,
            c.byref(flag),
            c.sizeof(flag),
            c.byref(returned),
        ), c.get_last_error()
        assert returned.value == c.sizeof(flag)
        assert flag.value == 1, 'source token oracle is not AppContainer'

        duplicate_access = TOKEN_QUERY | TOKEN_IMPERSONATE
        if not advapi.DuplicateTokenEx(
            source,
            duplicate_access,
            None,
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            c.byref(duplicate),
        ):
            error = c.get_last_error()
            pytest.fail(f'DuplicateTokenEx(SecurityImpersonation) failed: WinError {error}')
        assert duplicate.value

        # NULL ThreadHandle means the calling thread.
        if not advapi.SetThreadToken(None, duplicate):
            error = c.get_last_error()
            pytest.fail(f'SetThreadToken(AppContainer impersonation token) failed: WinError {error}')
        thread_token_set = True

        # Do not perform unrelated work while impersonating. The only operation
        # before reversion is the reversion itself.
        if not advapi.RevertToSelf():
            error = c.get_last_error()
            os._exit(90 if error == 0 else 91)
        thread_token_set = False

        emit_observation(
            'TNC_APPCONTAINER_THREAD_TOKEN_FEASIBILITY '
            'source_oracle_is_appcontainer=True '
            'open_process_token_duplicate=True '
            'duplicate_token_ex=True '
            'set_thread_token=True '
            f'source_sid={expected_sid!r}'
        )
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        if thread_token_set:
            # Continuing pytest under an unconfirmed impersonation context is unsafe.
            try:
                reverted = advapi.RevertToSelf()
            except BaseException:
                os._exit(92)
            if not reverted:
                os._exit(93)
        if duplicate.value:
            check(k.CloseHandle(duplicate), 'CloseHandle duplicate token')
        if source.value:
            check(k.CloseHandle(source), 'CloseHandle source token')
        if pi.hProcess:
            check(k.TerminateProcess(pi.hProcess, 1), 'TerminateProcess source child')
            check(k.WaitForSingleObject(pi.hProcess, 5000) == h.WAIT_OBJECT_0, 'wait source child')
            check(k.CloseHandle(pi.hProcess), 'CloseHandle process')
        if pi.hThread:
            check(k.CloseHandle(pi.hThread), 'CloseHandle thread')
        if attr_list:
            k.DeleteProcThreadAttributeList(attr_list)
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
