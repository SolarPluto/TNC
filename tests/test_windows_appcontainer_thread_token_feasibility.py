"""Feasibility probe for assigning an AppContainer impersonation token to a non-AC thread."""
import ctypes as c
import os
import sys
import threading
import uuid

import pytest

import _native_harness as h


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows AppContainer thread-token feasibility only')

TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
SECURITY_IMPERSONATION = 2
TOKEN_IMPERSONATION = 2


def _raw_non_appcontainer_oracle(advapi, kernel, token):
    returned = h.DWORD()
    flag = h.DWORD()
    assert advapi.GetTokenInformation(
        token, h.TOKEN_IS_APPCONTAINER,
        c.byref(flag), c.sizeof(flag), c.byref(returned),
    ), c.get_last_error()
    assert returned.value == c.sizeof(flag)
    assert flag.value == 0, 'server process unexpectedly reports AppContainer'

    info = h.TOKEN_APPCONTAINER_INFORMATION()
    assert advapi.GetTokenInformation(
        token, h.TOKEN_APPCONTAINER_SID,
        c.byref(info), c.sizeof(info), c.byref(returned),
    ), c.get_last_error()
    assert returned.value == c.sizeof(info)
    assert not info.TokenAppContainer, 'server process unexpectedly has an AppContainer SID'


def _advapi():
    a = h._advapi32()
    a.DuplicateTokenEx.argtypes = [
        h.HANDLE, h.DWORD, c.c_void_p, c.c_int32, c.c_int32, c.POINTER(h.HANDLE),
    ]
    a.DuplicateTokenEx.restype = h.BOOL
    a.SetThreadToken.argtypes = [c.POINTER(h.HANDLE), h.HANDLE]
    a.SetThreadToken.restype = h.BOOL
    a.OpenThreadToken.argtypes = [h.HANDLE, h.DWORD, h.BOOL, c.POINTER(h.HANDLE)]
    a.OpenThreadToken.restype = h.BOOL
    a.RevertToSelf.argtypes = []
    a.RevertToSelf.restype = h.BOOL
    return a


def test_appcontainer_thread_token_construction_feasibility(emit_observation):
    k = h._kernel32()
    k.GetCurrentThread.argtypes = []
    k.GetCurrentThread.restype = h.HANDLE
    advapi = _advapi()
    userenv = h._userenv()

    profile_name = f'TNC.ThreadTokenFeasibility.{uuid.uuid4().hex}'
    app_sid = c.c_void_p()
    attr_buffer = None
    attr_list = None
    pi = h.PROCESS_INFORMATION()
    server_oracle = h.HANDLE()
    oracle = h.HANDLE()
    source = h.HANDLE()
    duplicate = h.HANDLE()
    installed = h.HANDLE()
    profile_created = False
    thread_token_set = False
    owner_thread = threading.get_ident()

    def same_thread():
        assert threading.get_ident() == owner_thread, 'construction moved to a different Python thread'

    def outcome(stage, *, ok, error=None, detail=None):
        parts = [
            'TNC_APPCONTAINER_THREAD_TOKEN_FEASIBILITY',
            f'stage={stage}',
            f'ok={ok!r}',
            'server_oracle_is_appcontainer=False',
            'source_oracle_is_appcontainer=True',
        ]
        if error is not None:
            parts.append(f'winerror={error}')
        if detail is not None:
            parts.append(f'detail={detail!r}')
        emit_observation(' '.join(parts))

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

        same_thread()

        # Establish the negative side of the asymmetry independently: the pytest
        # process itself must be an ordinary non-AppContainer process.
        assert advapi.OpenProcessToken(
            k.GetCurrentProcess(), TOKEN_QUERY, c.byref(server_oracle)
        ), c.get_last_error()
        assert server_oracle.value
        _raw_non_appcontainer_oracle(advapi, k, server_oracle)

        same_thread()

        # Establish the source independently with TOKEN_QUERY alone so a later
        # TOKEN_DUPLICATE access denial remains an interpretable experiment result.
        assert advapi.OpenProcessToken(pi.hProcess, TOKEN_QUERY, c.byref(oracle)), c.get_last_error()
        assert oracle.value
        h._raw_primary_oracle(advapi, k, oracle, expected_sid)

        same_thread()
        source_access = TOKEN_QUERY | TOKEN_DUPLICATE
        if not advapi.OpenProcessToken(pi.hProcess, source_access, c.byref(source)):
            outcome('OpenProcessToken_TOKEN_DUPLICATE', ok=False, error=c.get_last_error())
            return
        assert source.value

        same_thread()
        duplicate_access = TOKEN_QUERY | TOKEN_IMPERSONATE
        if not advapi.DuplicateTokenEx(
            source,
            duplicate_access,
            None,
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            c.byref(duplicate),
        ):
            outcome('DuplicateTokenEx', ok=False, error=c.get_last_error())
            return
        assert duplicate.value

        # A successful duplication that changes the AppContainer shape is itself
        # an experiment result: this construction cannot establish the intended
        # asymmetry on this runner, but the harness is not corrupt.
        try:
            h._raw_primary_oracle(advapi, k, duplicate, expected_sid)
        except AssertionError as error:
            outcome('DuplicateTokenSemanticDivergence', ok=False, detail=str(error)[:200])
            return

        same_thread()
        # NULL ThreadHandle means the calling thread.
        if not advapi.SetThreadToken(None, duplicate):
            outcome('SetThreadToken', ok=False, error=c.get_last_error())
            return
        thread_token_set = True

        # Verify the actual effective token on the same thread before interpreting
        # the construction as feasible. OpenAsSelf=True avoids using the newly
        # impersonated client context for the token-handle access check.
        same_thread()
        if not advapi.OpenThreadToken(
            k.GetCurrentThread(), TOKEN_QUERY, True, c.byref(installed)
        ):
            error = c.get_last_error()
            if not advapi.RevertToSelf():
                os._exit(90)
            thread_token_set = False
            outcome('OpenThreadTokenVerify', ok=False, error=error)
            return
        assert installed.value

        # SetThreadToken reported success; the actual current-thread token must
        # now match the already-verified duplicate. A mismatch is a harness/state
        # violation, not a construction-denial result, so it hard-fails after the
        # finally block safely reverts the thread.
        h._raw_primary_oracle(advapi, k, installed, expected_sid)

        same_thread()
        if not k.CloseHandle(installed):
            os._exit(93)
        installed = h.HANDLE()

        # Revert before emitting or doing unrelated pytest work.
        if not advapi.RevertToSelf():
            os._exit(94)
        thread_token_set = False
        same_thread()

        outcome('COMPLETE', ok=True, detail=f'source_sid={expected_sid}')
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        if installed.value:
            check(k.CloseHandle(installed), 'CloseHandle installed thread token')
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
        if oracle.value:
            check(k.CloseHandle(oracle), 'CloseHandle source oracle token')
        if server_oracle.value:
            check(k.CloseHandle(server_oracle), 'CloseHandle server oracle token')
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
