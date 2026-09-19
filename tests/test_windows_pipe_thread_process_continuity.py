"""Cross-process continuity probe for named-pipe client thread versus process context."""
import base64
from contextlib import ExitStack
import ctypes as c
import json
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
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI, TokenCaptureError


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


class _QueryFailure(Exception):
    def __init__(self, kind, step, winerror=None):
        super().__init__(f'class={kind} step={step} winerror={winerror}')
        self.details = dict(information_class=kind, query_step=step, winerror=winerror)


def _raw_scalar(advapi, token, kind):
    returned, value = h.DWORD(), h.DWORD()
    if not advapi.GetTokenInformation(token, kind, c.byref(value), c.sizeof(value), c.byref(returned)):
        raise _QueryFailure(kind, 'query', c.get_last_error())
    if returned.value != c.sizeof(value):
        raise _QueryFailure(kind, 'return_length')
    return int(value.value)


def _raw_appcontainer_shape(advapi, kernel, token):
    flag = _raw_scalar(advapi, token, 29)
    if flag not in (0, 1):
        raise _QueryFailure(29, 'boolean')
    size, returned = h.DWORD(), h.DWORD()
    ok = advapi.GetTokenInformation(token, 31, None, 0, c.byref(size))
    error = 0 if ok else c.get_last_error()
    if ok or error != h.ERROR_INSUFFICIENT_BUFFER:
        raise _QueryFailure(31, 'size_probe', error)
    if not c.sizeof(h.TOKEN_APPCONTAINER_INFORMATION) <= size.value <= 65536:
        raise _QueryFailure(31, 'allocation_bound')
    buffer = c.create_string_buffer(size.value)
    if not advapi.GetTokenInformation(token, 31, buffer, size.value, c.byref(returned)):
        raise _QueryFailure(31, 'query', c.get_last_error())
    if not c.sizeof(h.TOKEN_APPCONTAINER_INFORMATION) <= returned.value <= size.value:
        raise _QueryFailure(31, 'return_length')
    info = h.TOKEN_APPCONTAINER_INFORMATION.from_buffer(buffer)
    if not info.TokenAppContainer:
        return bool(flag), None
    start, end = c.addressof(buffer), c.addressof(buffer) + returned.value
    pointer = info.TokenAppContainer
    if not start + c.sizeof(info) <= pointer <= end - 8:
        raise _QueryFailure(31, 'sid_pointer')
    offset = pointer - start
    header = bytes(buffer[offset:offset + 8])
    if header[0] != 1 or not 1 <= header[1] <= 15 or pointer + 8 + 4 * header[1] > end:
        raise _QueryFailure(31, 'sid_extent')
    try:
        sid = h._sid_string(advapi, kernel, pointer)
    except AssertionError:
        raise _QueryFailure(31, 'sid_conversion', c.get_last_error()) from None
    return bool(flag), sid


def _pipe_reading(api, advapi, kernel, server, expected_sid, primary_shape):
    """Return a provisional reading; publish only after client completion."""
    with ExitStack() as cleanup:
        # No application work is allowed on any exit with uncertain reversion.
        cleanup.callback(h._revert_or_fail_fast, api)
        if not api.impersonate(server):
            return 'IMPERSONATE_FAILED', dict(winerror=c.get_last_error())
        try:
            token = api.open_thread_token()
        except TokenCaptureError as error:
            return 'PIPE_TOKEN_OPEN_UNAVAILABLE', dict(reason=str(error))
        if token is None:
            return 'PIPE_TOKEN_MISSING', {}
        cleanup.callback(h._checked_cleanup, api.close, token)

        # Full NativePipeTokenAPI.capture would already read class 29. Use raw
        # type/level gates first so downgraded tokens never reach classes 29/31.
        try:
            kind = _raw_scalar(advapi, h.HANDLE(token), 8)
            if kind != TOKEN_IMPERSONATION:
                return 'TOKEN_TYPE_MISMATCH', dict(token_type=kind)
            level = _raw_scalar(advapi, h.HANDLE(token), 9)
        except _QueryFailure as error:
            return 'PIPE_TOKEN_METADATA_UNAVAILABLE', error.details
        if level != SECURITY_IMPERSONATION:
            return 'SQOS_LEVEL_MISMATCH', dict(token_type=kind, level=level)
        try:
            raw = _raw_appcontainer_shape(advapi, kernel, h.HANDLE(token))
        except _QueryFailure as error:
            return 'PIPE_APPCONTAINER_QUERY_UNAVAILABLE', error.details

        match = ('THREAD_TOKEN' if raw == (True, expected_sid) else
                 'PROCESS_TOKEN' if raw == primary_shape else 'UNEXPECTED_PIPE_CONTEXT')
        values = dict(token_type='IMPERSONATION', level='IMPERSONATION',
                      raw_is_appcontainer=raw[0], raw_sid=raw[1])
        try:
            evidence = NativeAppContainerProbe().probe(
                token, token_type='IMPERSONATION', level='IMPERSONATION'
            )
        except AppContainerProbeError as error:
            return 'CLASSIFIER_EVIDENCE_UNAVAILABLE', dict(values, raw_match=match, reason=str(error))
        assert (evidence.token_is_app_container, evidence.app_container_sid) == raw
        result = evaluate_appcontainer_exclusion(evidence)
        assert not result.admission_granted and not result.authorization_granted
        expected = {
            'THREAD_TOKEN': ('APPCONTAINER', 'TOKEN_IS_APPCONTAINER'),
            'PROCESS_TOKEN': ('PROVEN_NON_APPCONTAINER', 'TOKEN_IS_APPCONTAINER_FALSE_USABLE'),
        }
        if match in expected:
            assert (result.status, result.reason) == expected[match]
        stage = 'UNEXPECTED_PIPE_CONTEXT' if match not in expected else 'OBSERVED'
        return stage, dict(values, interpretation=match, status=result.status, reason=result.reason)


_CLIENT_SOURCE = r'''import ctypes as c
import json
import os
from pathlib import Path
import sys

HANDLE = c.c_void_p
DWORD = c.c_uint32
BOOL = c.c_int32
INVALID_HANDLE_VALUE = c.c_void_p(-1).value

class OVERLAPPED(c.Structure):
    _fields_ = [('Internal', c.c_size_t), ('InternalHigh', c.c_size_t),
                ('Offset', DWORD), ('OffsetHigh', DWORD), ('hEvent', HANDLE)]

class TOKEN_APPCONTAINER_INFORMATION(c.Structure):
    _fields_ = [('TokenAppContainer', c.c_void_p)]

k = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
a = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
for library, name, args, restype in (
    (k, 'GetCurrentThread', [], HANDLE),
    (k, 'GetCurrentThreadId', [], DWORD),
    (k, 'CreateFileW', [c.c_wchar_p, DWORD, DWORD, c.c_void_p, DWORD, DWORD, HANDLE], HANDLE),
    (k, 'ReadFile', [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p], BOOL),
    (k, 'WriteFile', [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p], BOOL),
    (k, 'CreateEventW', [c.c_void_p, BOOL, BOOL, c.c_wchar_p], HANDLE),
    (k, 'WaitForSingleObject', [HANDLE, DWORD], DWORD),
    (k, 'GetOverlappedResult', [HANDLE, c.POINTER(OVERLAPPED), c.POINTER(DWORD), BOOL], BOOL),
    (k, 'CancelIoEx', [HANDLE, c.POINTER(OVERLAPPED)], BOOL),
    (k, 'CloseHandle', [HANDLE], BOOL),
    (k, 'LocalFree', [c.c_void_p], c.c_void_p),
    (a, 'SetThreadToken', [c.POINTER(HANDLE), HANDLE], BOOL),
    (a, 'OpenThreadToken', [HANDLE, DWORD, BOOL, c.POINTER(HANDLE)], BOOL),
    (a, 'GetTokenInformation', [HANDLE, c.c_int32, c.c_void_p, DWORD, c.POINTER(DWORD)], BOOL),
    (a, 'ConvertSidToStringSidW', [c.c_void_p, c.POINTER(c.c_wchar_p)], BOOL),
    (a, 'RevertToSelf', [], BOOL),
):
    fn = getattr(library, name)
    fn.argtypes, fn.restype = args, restype


def require(ok, operation):
    if not ok:
        raise OSError(c.get_last_error(), operation)


def transfer(pipe, function, buffer, size):
    """Bound each client I/O; never free an undrained OVERLAPPED/buffer."""
    ov = OVERLAPPED()
    ov.hEvent = k.CreateEventW(None, True, False, None)
    require(ov.hEvent, 'CreateEventW')
    count = DWORD()
    pending = False
    try:
        ok = function(pipe, buffer, size, c.byref(count), c.byref(ov))
        if not ok:
            error = c.get_last_error()
            if error != 997:
                raise OSError(error, 'pipe I/O')
            pending = True
            wait = k.WaitForSingleObject(ov.hEvent, 30000)
            if wait != 0:
                raise OSError(1460 if wait == 258 else c.get_last_error(), 'pipe I/O wait')
            require(k.GetOverlappedResult(pipe, c.byref(ov), c.byref(count), False),
                    'GetOverlappedResult')
            pending = False
        if count.value != size:
            raise RuntimeError('short pipe transfer')
    finally:
        if pending:
            k.CancelIoEx(pipe, c.byref(ov))
            if k.WaitForSingleObject(ov.hEvent, 5000) != 0:
                os._exit(95)  # OS may still reference ov/buffer: no unwinding.
            ok = k.GetOverlappedResult(pipe, c.byref(ov), c.byref(count), False)
            if not ok and c.get_last_error() == 996:
                os._exit(96)
        require(k.CloseHandle(ov.hEvent), 'CloseHandle I/O event')


source = HANDLE(config['token'])
installed = HANDLE()
pipe = None
revert_required = False
report = dict(ok=False, stage='PREFLIGHT', winerror=None, error_type=None,
              ready=False, ack_received=False, reverted=False, cleanup_errors=[])
owner = int(k.GetCurrentThreadId())


def same_thread(field):
    report[field] = int(k.GetCurrentThreadId())
    if report[field] != owner:
        raise RuntimeError('native thread changed')


try:
    # A fresh child must not already be impersonating. Do not overwrite a token.
    initial = HANDLE()
    ok = a.OpenThreadToken(k.GetCurrentThread(), 8, True, c.byref(initial))
    error = 0 if ok else c.get_last_error()
    if ok:
        k.CloseHandle(initial)
        raise RuntimeError('preexisting client thread token')
    if error != 1008:
        raise OSError(error, 'OpenThreadToken preflight')

    report['stage'] = 'SetThreadToken'
    same_thread('thread_before_set')
    revert_required = True  # Finally also covers exceptions around installation.
    require(a.SetThreadToken(None, source), 'SetThreadToken')
    report['stage'] = 'InstalledTokenOracle'
    require(a.OpenThreadToken(k.GetCurrentThread(), 8, True, c.byref(installed)),
            'OpenThreadToken')
    returned = DWORD()
    for kind, expected in ((8, 2), (9, 2), (29, 1)):
        value = DWORD()
        require(a.GetTokenInformation(installed, kind, c.byref(value), 4, c.byref(returned)),
                'GetTokenInformation')
        if returned.value != 4 or value.value != expected:
            raise RuntimeError('installed token type/level/AppContainer flag mismatch')
    size = DWORD()
    ok = a.GetTokenInformation(installed, 31, None, 0, c.byref(size))
    if ok or c.get_last_error() != 122:
        raise RuntimeError('invalid class-31 size probe')
    if not c.sizeof(TOKEN_APPCONTAINER_INFORMATION) <= size.value <= 65536:
        raise RuntimeError('class-31 allocation bound')
    buffer = c.create_string_buffer(size.value)
    require(a.GetTokenInformation(installed, 31, buffer, size.value, c.byref(returned)),
            'GetTokenInformation class 31')
    if not c.sizeof(TOKEN_APPCONTAINER_INFORMATION) <= returned.value <= size.value:
        raise RuntimeError('class-31 return length')
    info = TOKEN_APPCONTAINER_INFORMATION.from_buffer(buffer)
    start, end = c.addressof(buffer), c.addressof(buffer) + returned.value
    sid = info.TokenAppContainer
    if not sid or not start + c.sizeof(info) <= sid <= end - 8:
        raise RuntimeError('class-31 SID pointer')
    offset = sid - start
    sid_header = bytes(buffer[offset:offset + 8])
    if sid_header[0] != 1 or not 1 <= sid_header[1] <= 15 or sid + 8 + 4 * sid_header[1] > end:
        raise RuntimeError('class-31 SID extent')
    text = c.c_wchar_p()
    require(a.ConvertSidToStringSidW(sid, c.byref(text)), 'ConvertSidToStringSidW')
    try:
        if text.value != config['sid']:
            raise RuntimeError('installed AppContainer SID mismatch')
    finally:
        if k.LocalFree(c.cast(text, c.c_void_p)):
            raise RuntimeError('LocalFree SID')

    report['stage'] = 'CreateFileW'
    same_thread('thread_before_open')
    pipe = k.CreateFileW(config['pipe'], 0xC0000000, 0, None, 3,
                         0x40000000 | 0x00100000 | 0x00020000, None)
    require(pipe not in (None, 0, INVALID_HANDLE_VALUE), 'CreateFileW')
    same_thread('thread_after_open')
    report['stage'] = 'WriteReady'
    # X is emitted only after successful installation, independent oracle and
    # same-native-thread CreateFile. No process-token fallback connection exists.
    transfer(pipe, k.WriteFile, c.create_string_buffer(b'X'), 1)
    report['ready'] = True
    report['stage'] = 'ReadAcknowledgement'
    byte = c.create_string_buffer(1)
    transfer(pipe, k.ReadFile, byte, 1)
    if byte.raw != b'Y':
        raise RuntimeError('unexpected acknowledgement')
    report['ack_received'] = True
    same_thread('thread_after_ack')
    report['stage'] = 'COMPLETE'
    report['ok'] = True
except BaseException as error:
    report['ok'] = False
    report['winerror'] = error.errno if isinstance(error, OSError) else None
    report['error_type'] = type(error).__name__
finally:
    # Revert before filesystem reporting, cleanup diagnostics or interpreter exit.
    if revert_required:
        try:
            if int(k.GetCurrentThreadId()) != owner or not a.RevertToSelf():
                os._exit(90)
        except BaseException:
            os._exit(91)
        leftover = HANDLE()
        ok = a.OpenThreadToken(k.GetCurrentThread(), 8, True, c.byref(leftover))
        error = 0 if ok else c.get_last_error()
        if ok or error != 1008:
            os._exit(92)
    report['reverted'] = True
    for handle, label in ((pipe, 'pipe'), (installed.value, 'installed'), (source.value, 'source')):
        if handle not in (None, 0, INVALID_HANDLE_VALUE) and not k.CloseHandle(handle):
            report['cleanup_errors'].append([label, c.get_last_error()])
    if report['cleanup_errors']:
        report['ok'] = False
    # This is a controlled child diagnostic, not trusted production evidence.
    Path(config['report']).write_text(json.dumps(report, sort_keys=True), encoding='utf-8')
sys.exit(0 if report['ok'] else 1)
'''


def _client_command(pipe_name, inherited_token, expected_sid, report_path):
    config = dict(pipe=pipe_name, token=inherited_token, sid=expected_sid, report=str(report_path))
    code = 'config = ' + repr(config) + '\n' + _CLIENT_SOURCE
    compile(code, '<continuity-client>', 'exec')
    encoded = base64.b64encode(code.encode('utf-8')).decode('ascii')
    return c.create_unicode_buffer(
        f'"{sys.executable}" -I -c "import base64;exec(base64.b64decode(\'{encoded}\'))"'
    )


def test_pipe_impersonation_uses_thread_or_process_context(emit_observation, tmp_path):
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
    report_path = tmp_path / 'continuity-client.json'
    handshake_complete = False

    def client_report():
        if not report_path.exists():
            return None
        assert report_path.stat().st_size <= 4096, 'client report bound'
        value = json.loads(report_path.read_text(encoding='utf-8'))
        assert type(value) is dict, 'invalid client report'
        return value

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

        client_command = _client_command(
            pipe_name, int(duplicate.value), expected_sid, report_path
        )
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
        except AssertionError:
            # No X means no interpreted pipe result, even if the child opened a
            # pipe before failing. Collect the child's controlled stage/error.
            if k.WaitForSingleObject(client_pi.hProcess, 5000) == h.WAIT_OBJECT_0:
                report = client_report()
                observe('CLIENT_SETUP_FAILED', client=report)
                assert report is not None and report.get('reverted') is True
                assert not report.get('cleanup_errors'), report
                assert report.get('error_type') == 'OSError', report
                return
            observe('CLIENT_HANDSHAKE_UNAVAILABLE')
            raise
        handshake_complete = True

        client_pid = h.DWORD()
        assert k.GetNamedPipeClientProcessId(server, c.byref(client_pid)), c.get_last_error()
        assert client_pid.value == client_pi.dwProcessId and client_pid.value != os.getpid()

        # Both parent-owned handles are retained through the entire exchange.
        # Recheck them immediately before measuring the pipe's security context.
        assert _raw_appcontainer_shape(advapi, k, client_primary) == client_primary_shape
        assert _raw_appcontainer_shape(advapi, k, duplicate) == (True, expected_sid)
        stage, values = _pipe_reading(api, advapi, k, server, expected_sid, client_primary_shape)
        assert api.open_thread_token() is None

        # The client has its own 30s I/O timeout. A timeout/revert must invalidate
        # the reading rather than masquerading as a PROCESS_TOKEN observation.
        assert h._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
        assert k.WaitForSingleObject(client_pi.hProcess, h.IO_TIMEOUT_MS) == h.WAIT_OBJECT_0
        client_exit = h.DWORD()
        assert k.GetExitCodeProcess(client_pi.hProcess, c.byref(client_exit)), c.get_last_error()
        report = client_report()
        observe('CLIENT_COMPLETION', client_exit=client_exit.value, client=report)
        assert client_exit.value == 0 and report is not None, report
        assert report.get('ok') is True and report.get('ready') is True, report
        assert report.get('ack_received') is True and report.get('reverted') is True, report
        assert not report.get('cleanup_errors'), report
        tids = [report.get(key) for key in (
            'thread_before_set', 'thread_before_open', 'thread_after_open', 'thread_after_ack',
        )]
        assert all(type(tid) is int and tid > 0 for tid in tids) and len(set(tids)) == 1, report
        observe(stage, client_pid=client_pid.value, client_thread_ids=tids,
                primary_oracle=client_primary_shape, thread_oracle=(True, expected_sid), **values)
    finally:
        failure = sys.exception()
        cleanup_errors = []

        def check(ok, label):
            if not ok:
                cleanup_errors.append(f'{label}: WinError {c.get_last_error()}')

        try:
            leftover = api.open_thread_token()
        except BaseException:
            api.fail_fast()
        if leftover is not None:
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
                if label == 'client' and failure is not None:
                    exit_code = h.DWORD()
                    if k.GetExitCodeProcess(pi.hProcess, c.byref(exit_code)):
                        observe('CLIENT_ABORTED' if handshake_complete else 'CLIENT_SETUP_FAILED',
                                client_exit=exit_code.value, client=client_report())
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
