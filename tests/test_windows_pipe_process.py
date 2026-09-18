"""Disposable native Windows pipes; parent coordinates only bounded JSON messages.

Normal peers use the existing operator account through the service ACE. Anonymous
denial is tested in a disposable client. This is not an enrollment/authentication
service and does not provision accounts, change privileges, or exercise signing.
"""
import ctypes as c
import json
import multiprocessing as mp
import os
import sys
import time
import traceback
import uuid
from contextlib import contextmanager

import pytest

from tnc.provenance import windows_pipe_native as n
from tnc.provenance.windows_custody_peer import WindowsPeerPolicy, PeerProcess
from tnc.provenance.windows_identity import read_windows_operator_identity
from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan, replay_pipe_ledger

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Disposable native Windows pipe processes')


def _send(control, **message):
    raw = json.dumps(message, sort_keys=True, separators=(',', ':')).encode()
    assert len(raw) <= 4096
    control.send_bytes(raw)


def _receive(control, timeout=15):
    assert control.poll(timeout), 'Child control deadline exceeded'
    message = json.loads(control.recv_bytes(4096))
    assert message.get('kind') != 'error', message
    return message


@contextmanager
def _handle_delta_diagnostic(samples, identity=None):
    try:
        yield
    except AssertionError as error:
        if samples is not None:
            error.add_note(
                'handle persistence (baseline={baseline}): T={T}, +100ms={+100ms}, +1000ms={+1000ms}'.format(**samples))
        if identity is not None:
            error.add_note(identity)
        raise


def _tick():
    return time.monotonic_ns() // 1_000_000


def _plan(kind, number, size=0, budget=5000):
    tick = _tick()
    name = 'native-' + str(number)
    return PipeOperationPlan(operation_id=name, kind=kind, pipe_lease_id=name+'-pipe',
        event_id=name+'-event', overlapped_id=name+'-overlapped', buffer_id=name+'-buffer',
        buffer_size=size, created_tick=tick, request_deadline=tick+budget,
        cleanup_deadline=tick+budget+1000)


class _FILETIME(c.Structure):
    _fields_ = [('low', n.DWORD), ('high', n.DWORD)]


class _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(c.Structure):
    _fields_ = [
        ('object', c.c_void_p),
        ('pid', c.c_size_t),
        ('handle', c.c_size_t),
        ('granted_access', n.DWORD),
        ('creator_backtrace_index', c.c_ushort),
        ('object_type_index', c.c_ushort),
        ('attributes', n.DWORD),
        ('reserved', n.DWORD),
    ]


class _UNICODE_STRING(c.Structure):
    _fields_ = [('length', c.c_ushort), ('maximum_length', c.c_ushort), ('buffer', c.c_void_p)]


_SYSTEM_EXTENDED_HANDLE_INFORMATION = 0x40
_OBJECT_TYPE_INFORMATION = 2
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_STATUS_INVALID_HANDLE = 0xC0000008
_TOKEN_TYPE = 8
_TOKEN_IMPERSONATION_LEVEL = 9


class _NativeChecks:
    def __init__(self, api):
        self.api = api
        self.kernel = api._dll
        self.security = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
        self.ntdll = c.WinDLL('ntdll.dll', winmode=0x800)
        p = c.POINTER
        for name, args, result in (
            ('CreateFileW', [c.c_wchar_p, n.DWORD, n.DWORD, c.c_void_p, n.DWORD, n.DWORD, n.HANDLE], n.HANDLE),
            ('GetNamedPipeServerProcessId', [n.HANDLE, p(n.DWORD)], n.BOOL),
            ('GetNamedPipeClientProcessId', [n.HANDLE, p(n.DWORD)], n.BOOL),
            ('OpenProcess', [n.DWORD, n.BOOL, n.DWORD], n.HANDLE),
            ('GetProcessTimes', [n.HANDLE, p(_FILETIME), p(_FILETIME), p(_FILETIME), p(_FILETIME)], n.BOOL),
            ('GetCurrentProcess', [], n.HANDLE), ('GetCurrentThread', [], n.HANDLE),
            ('GetProcessHandleCount', [n.HANDLE, p(n.DWORD)], n.BOOL),
        ):
            fn = getattr(self.kernel, name)
            fn.argtypes, fn.restype = args, result
        for name, args in (
            ('GetKernelObjectSecurity', [n.HANDLE, n.DWORD, c.c_void_p, n.DWORD, p(n.DWORD)]),
            ('ImpersonateAnonymousToken', [n.HANDLE]), ('RevertToSelf', []),
        ):
            fn = getattr(self.security, name)
            fn.argtypes, fn.restype = args, n.BOOL
        self.security.GetTokenInformation.argtypes = [n.HANDLE, n.DWORD, c.c_void_p, n.DWORD, p(n.DWORD)]
        self.security.GetTokenInformation.restype = n.BOOL
        self.ntdll.NtQuerySystemInformation.argtypes = [n.DWORD, c.c_void_p, n.DWORD, p(n.DWORD)]
        self.ntdll.NtQuerySystemInformation.restype = c.c_long
        self.ntdll.NtQueryObject.argtypes = [n.HANDLE, n.DWORD, c.c_void_p, n.DWORD, p(n.DWORD)]
        self.ntdll.NtQueryObject.restype = c.c_long

    def birth(self, pid):
        process = self.kernel.OpenProcess(0x1000, False, pid)
        assert n._valid_handle(process), 'Process query failed'
        try:
            created, exited, kernel, user = (_FILETIME() for _ in range(4))
            assert self.kernel.GetProcessTimes(process, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user))
            return (created.high << 32) | created.low
        finally:
            assert self.api.close(process)

    def peer(self, handle, server):
        fn = self.kernel.GetNamedPipeServerProcessId if server else self.kernel.GetNamedPipeClientProcessId
        pid = n.DWORD()
        assert fn(handle, c.byref(pid)) and pid.value > 0
        birth = self.birth(pid.value)
        again = n.DWORD()
        assert fn(handle, c.byref(again)) and again.value == pid.value
        return pid.value, birth

    def descriptor(self, handle):
        size = n.DWORD()
        ok = self.security.GetKernelObjectSecurity(handle, 5, None, 0, c.byref(size))
        error = c.get_last_error()
        assert not ok and error == 122 and 20 <= size.value <= 65536, ('descriptor_probe', bool(ok), error, size.value)
        buffer = c.create_string_buffer(size.value)
        assert self.security.GetKernelObjectSecurity(handle, 5, buffer, len(buffer), c.byref(size))
        # The successful call can clear LengthNeeded. Bound parsing by the
        # probed allocation; every descriptor offset is validated by parse_security.
        assert size.value <= len(buffer)
        return bytes(buffer)

    def handles(self):
        value = n.DWORD()
        assert self.kernel.GetProcessHandleCount(self.kernel.GetCurrentProcess(), c.byref(value))
        return value.value

    @staticmethod
    def _status(status):
        return c.c_ulong(status).value

    def handle_values(self):
        """Best-effort value-only snapshot of this process handle table."""
        try:
            size = 65536
            for _ in range(8):
                buffer = c.create_string_buffer(size)
                needed = n.DWORD()
                status = self.ntdll.NtQuerySystemInformation(
                    _SYSTEM_EXTENDED_HANDLE_INFORMATION, buffer, len(buffer), c.byref(needed))
                code = self._status(status)
                if code == 0:
                    break
                if code != _STATUS_INFO_LENGTH_MISMATCH:
                    return None, 'SystemExtendedHandleInformation status=0x%08X' % code
                size = max(size * 2, int(needed.value) + 4096)
            else:
                return None, 'SystemExtendedHandleInformation buffer sizing did not converge'
            header = c.sizeof(c.c_size_t) * 2
            count = c.c_size_t.from_buffer_copy(buffer.raw[:c.sizeof(c.c_size_t)]).value
            entry_size = c.sizeof(_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
            if header + count * entry_size > len(buffer):
                return None, 'SystemExtendedHandleInformation returned truncated table'
            pid = os.getpid()
            values = set()
            for index in range(count):
                start = header + index * entry_size
                entry = _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer_copy(
                    buffer.raw[start:start + entry_size])
                if entry.pid == pid:
                    values.add(int(entry.handle))
            return values, None
        except BaseException as error:
            return None, type(error).__name__ + ': ' + str(error)[:200]

    def _object_type(self, value):
        try:
            size = 256
            for _ in range(5):
                buffer = c.create_string_buffer(size)
                needed = n.DWORD()
                status = self.ntdll.NtQueryObject(
                    n.HANDLE(value), _OBJECT_TYPE_INFORMATION, buffer, len(buffer), c.byref(needed))
                code = self._status(status)
                if code == 0:
                    name = _UNICODE_STRING.from_buffer_copy(buffer.raw[:c.sizeof(_UNICODE_STRING)])
                    if not name.buffer or not name.length:
                        return '<unnamed-type>', None
                    return c.wstring_at(name.buffer, name.length // c.sizeof(c.c_wchar)), None
                if code == _STATUS_INVALID_HANDLE:
                    return None, 'vanished between snapshot and resolution'
                if code != _STATUS_INFO_LENGTH_MISMATCH:
                    return None, 'NtQueryObject status=0x%08X' % code
                size = max(size * 2, int(needed.value) + 64)
            return None, 'NtQueryObject buffer sizing did not converge'
        except BaseException as error:
            return None, type(error).__name__ + ': ' + str(error)[:200]

    def _token_metadata(self, value):
        kind = n.DWORD()
        needed = n.DWORD()
        if not self.security.GetTokenInformation(
                n.HANDLE(value), _TOKEN_TYPE, c.byref(kind), c.sizeof(kind), c.byref(needed)):
            return 'TOKEN metadata unavailable error=%d' % c.get_last_error()
        if kind.value == 1:
            return 'TOKEN type=PRIMARY'
        if kind.value != 2:
            return 'TOKEN type=%d' % kind.value
        level = n.DWORD()
        if not self.security.GetTokenInformation(
                n.HANDLE(value), _TOKEN_IMPERSONATION_LEVEL,
                c.byref(level), c.sizeof(level), c.byref(needed)):
            return 'TOKEN type=IMPERSONATION level=unavailable error=%d' % c.get_last_error()
        names = {0: 'ANONYMOUS', 1: 'IDENTIFICATION', 2: 'IMPERSONATION', 3: 'DELEGATION'}
        return 'TOKEN type=IMPERSONATION level=' + names.get(level.value, str(level.value))

    def handle_identity_diagnostic(self, baseline, pre_cleanup, post_cleanup):
        """Describe phase-localized survivors without changing the count invariant."""
        try:
            unavailable = [reason for _, reason in (baseline, pre_cleanup, post_cleanup) if reason]
            if unavailable:
                return 'enumeration unavailable: ' + '; '.join(unavailable)
            baseline_values, pre_values, post_values = (
                baseline[0], pre_cleanup[0], post_cleanup[0])
            added = pre_values - baseline_values
            released = pre_values - post_values
            persisted = post_values - baseline_values
            expected = added - released
            cleanup_created = persisted - expected
            overlap = baseline_values & post_values

            def fmt(values):
                return '[' + ', '.join('0x%X' % value for value in sorted(values)) + ']'

            lines = [
                'handle identity snapshots:',
                '  added_during_inspect=' + fmt(added),
                '  released_by_cleanup=' + fmt(released),
                '  persisted_past_cleanup=' + fmt(persisted),
            ]
            if persisted == expected:
                lines.append('  phase invariant: persisted_past_cleanup == added_during_inspect - released_by_cleanup')
            else:
                lines.append('  cleanup-originated survivors=' + fmt(cleanup_created))

            # Resolve full metadata only for strict survivors. Baseline/post overlap is
            # type-checked only to detect a suspicious TOKEN occupying a pre-inspect slot.
            for value in sorted(persisted):
                object_type, error = self._object_type(value)
                if error:
                    lines.append('  0x%X: %s' % (value, error))
                elif object_type.upper() == 'TOKEN':
                    lines.append('  0x%X: %s' % (value, self._token_metadata(value)))
                else:
                    lines.append('  0x%X: type=%s' % (value, object_type))
            for value in sorted(overlap):
                object_type, error = self._object_type(value)
                if not error and object_type.upper() == 'TOKEN':
                    lines.append('  suspicious baseline/post-cleanup TOKEN slot 0x%X: %s' % (
                        value, self._token_metadata(value)))
            return '\n'.join(lines)
        except BaseException as error:
            return 'enumeration unavailable: ' + type(error).__name__ + ': ' + str(error)[:200]

    def sample_handle_delta(self, baseline, initial=None):
        """Sample this child before exit; concurrent handle activity may make samples fluctuate."""
        if initial is None:
            delta = self.handles() - baseline
            started = time.monotonic()
        else:
            delta, started = initial
        if delta == 0:
            return 0, None
        time.sleep(max(0.0, 0.1 - (time.monotonic() - started)))
        after_100ms = self.handles() - baseline
        time.sleep(max(0.0, 1.0 - (time.monotonic() - started)))
        after_1000ms = self.handles() - baseline
        return delta, {'baseline': baseline, 'T': delta, '+100ms': after_100ms, '+1000ms': after_1000ms}

    def open_client(self, name):
        # Exact minimal data/query rights; no client create-instance or generic write.
        handle = self.kernel.CreateFileW(name, n.CLIENT_RIGHTS, 0, None, 3,
            0x40000000 | 0x00100000 | 0x00010000, None)
        return handle, 0 if n._valid_handle(handle) else c.get_last_error()


class _ClientIO:
    def __init__(self, api, handle):
        self.api, self.handle = api, handle
        self.allocations = []

    def transfer(self, kind, payload):
        size = len(payload) if kind == 'WRITE' else payload
        buffer = c.create_string_buffer(payload, size) if kind == 'WRITE' else c.create_string_buffer(size)
        event = self.api.create_event()
        overlapped = n.OVERLAPPED()
        overlapped.hEvent = event
        self.allocations.append((event, overlapped, buffer))
        result = self.api.submit(self.handle, kind, overlapped, buffer, size)
        deadline = _tick() + 5000
        if not result.ok:
            assert result.error == n.IO_PENDING, result
            while _tick() < deadline:
                wait = self.api.wait(event, max(0, deadline-_tick()))
                assert wait in (n.WAIT_OBJECT, n.WAIT_TIMEOUT)
                result = self.api.completion(self.handle, overlapped)
                if result.ok or result.error != n.IO_INCOMPLETE:
                    break
        if not result.ok:
            # Fail this disposable helper without unwinding pending ctypes memory.
            os._exit(72)
        assert 0 <= result.transferred <= size
        data = bytes(buffer[:result.transferred])
        assert self.api.close(event)
        self.allocations.pop()
        return data if kind == 'READ' else result.transferred


def _policy(name, identity, checks):
    # Existing account as service principal; distinct well-known client ACE retained.
    other = 'S-1-5-18' if identity.user_sid != 'S-1-5-18' else 'S-1-5-19'
    return WindowsPeerPolicy(deployment_id='native-test', store_instance_id='native-store',
        pipe_name=name, service_sid=identity.user_sid, client_sid=other,
        logon_sid='S-1-5-5-1-2', authentication_id=1,
        expected_process=PeerProcess(pid=os.getpid(), creation_filetime=checks.birth(os.getpid()),
            session_id=0, running=True), timestamp=1, expiry=2)


def _server(control, name, scenario):
    try:
        identity = read_windows_operator_identity()
        api = n.NativePipeApi()
        checks = _NativeChecks(api)
        policy = _policy(name, identity, checks)
        baseline = checks.handles()
        endpoint = n.OwnedPipeEndpoint(policy=policy, api=api)
        raw = checks.descriptor(endpoint._handle)
        assert n.parse_security(raw) == n.parse_security(n._descriptor(policy))
        assert int.from_bytes(raw[2:4], 'little') & 0x1000
        _send(control, kind='ready', pid=os.getpid(), birth=checks.birth(os.getpid()), name=name)
        command = _receive(control)
        if command['kind'] == 'close':
            endpoint.close()
            delta, samples = checks.sample_handle_delta(baseline)
            _send(control, kind='closed', delta=delta, handle_samples=samples)
            return
        assert command['kind'] == 'connect'
        op = endpoint.begin_connect(_plan('CONNECT', 1))
        _send(control, kind='connecting', pending=op._pending, code=op._raw_result.error)
        if scenario in ('kill', 'contain'):
            if scenario == 'contain':
                endpoint._clock = lambda: -1
                try:
                    op.wait_until(op._plan.request_deadline)
                except n.WorkerContainmentRequired:
                    _send(control, kind='contained', retained=op._pending and op._buffer is not None)
            control.poll(15)  # Registry remains alive; supervisor terminates this worker.
            os._exit(73)
        if scenario == 'cancel_connect':
            assert op._pending
            op.cancel_and_drain()
            state = replay_pipe_ledger(op.audit_ledger)
            assert state.terminal == 'ABORTED' and not state.result_available
            op.dispose()
            endpoint.close()
            delta, samples = checks.sample_handle_delta(baseline)
            _send(control, kind='done', terminal=state.terminal, delta=delta, handle_samples=samples)
            return
        assert op.wait_until(op._plan.request_deadline)
        assert op.result_bytes() == b''
        op.dispose()
        client_pid, client_birth = checks.peer(endpoint._handle, False)
        if scenario in ('roundtrip', 'early'):
            read = endpoint.begin_read(_plan('READ', 2, 4))
            assert read.wait_until(read._plan.request_deadline)
            assert read.result_bytes() == b'ping'
            read.dispose()
            write = endpoint.begin_write(_plan('WRITE', 3, 4), b'pong')
            assert write.wait_until(write._plan.request_deadline)
            assert replay_pipe_ledger(write.audit_ledger).transferred == 4
            write.dispose()
            terminal = 'SUCCESS'
        elif scenario == 'cancel_write':
            found_pending = False
            for index in range(8):
                write = endpoint.begin_write(_plan('WRITE', index+2, 65536), b'x'*65536)
                if write._pending:
                    found_pending = True
                    write.cancel_and_drain()
                    terminal = replay_pipe_ledger(write.audit_ledger).terminal
                    assert terminal == 'ABORTED'
                    write.dispose()
                    break
                write.dispose()
            assert found_pending, 'Bounded writes did not reach backpressure'
        else:
            read = endpoint.begin_read(_plan('READ', 2, 4, budget=250 if scenario == 'deadline' else 5000))
            assert read._pending
            _send(control, kind='read_pending')
            if scenario == 'disconnect':
                assert read.wait_until(read._plan.request_deadline)
            else:
                if scenario == 'deadline':
                    assert not read.wait_until(read._plan.request_deadline)
                read.cancel_and_drain()
            state = replay_pipe_ledger(read.audit_ledger)
            terminal = state.terminal
            assert terminal in ('ERROR', 'ABORTED') and not state.result_available
            read.dispose()
        _send(control, kind='done', terminal=terminal, client_pid=client_pid, client_birth=client_birth)
        assert _receive(control)['kind'] == 'close'
        endpoint.close()
        assert not n._OWNERS
        delta, samples = checks.sample_handle_delta(baseline)
        _send(control, kind='closed', delta=delta, handle_samples=samples)
    except BaseException as error:
        try:
            _send(control, kind='error', detail=type(error).__name__+':'+str(error)[:500],
                  line=traceback.extract_tb(error.__traceback__)[-1].lineno)
        finally:
            os._exit(74)  # No unsafe cleanup of uncertain native allocations.
    finally:
        control.close()


def _client(control, info, scenario):
    try:
        identity = read_windows_operator_identity()
        api = n.NativePipeApi()
        checks = _NativeChecks(api)
        if scenario == 'anonymous':
            assert checks.security.ImpersonateAnonymousToken(checks.kernel.GetCurrentThread()), 'Anonymous test token unavailable'
            try:
                handle, error = checks.open_client(info['name'])
            finally:
                if not checks.security.RevertToSelf():
                    os._exit(76)
            assert read_windows_operator_identity().user_sid == identity.user_sid
            if n._valid_handle(handle):
                assert api.close(handle)
            _send(control, kind='denied', error=error, reverted=True)
            return
        handle, error = checks.open_client(info['name'])
        assert n._valid_handle(handle), 'Client open failed:'+str(error)
        pid, birth = checks.peer(handle, True)
        if (pid, birth) != (info['pid'], info['birth']):
            assert api.close(handle)
            _send(control, kind='mismatch')
            return
        _send(control, kind='opened', pid=os.getpid(), birth=checks.birth(os.getpid()))
        io = _ClientIO(api, handle)
        if scenario in ('roundtrip', 'early'):
            assert io.transfer('WRITE', b'ping') == 4
            assert io.transfer('READ', 4) == b'pong'
        else:
            assert _receive(control)['kind'] == 'close'
        assert not io.allocations
        assert api.close(handle)
        _send(control, kind='done')
    except BaseException as error:
        try:
            _send(control, kind='error', detail=type(error).__name__+':'+str(error)[:500],
                  line=traceback.extract_tb(error.__traceback__)[-1].lineno)
        finally:
            os._exit(75)
    finally:
        control.close()


def _collision(control, name):
    try:
        identity = read_windows_operator_identity()
        api = n.NativePipeApi()
        checks = _NativeChecks(api)
        try:
            endpoint = n.OwnedPipeEndpoint(policy=_policy(name, identity, checks), api=api)
        except n.PipeAdapterError as error:
            _send(control, kind='collision', reason=str(error))
        else:
            endpoint.close()
            _send(control, kind='unexpected_open')
    finally:
        control.close()


class _Harness:
    def __init__(self):
        self.ctx = mp.get_context('spawn')
        self.children = []

    def spawn(self, target, *args):
        parent, child = self.ctx.Pipe()
        process = self.ctx.Process(target=target, args=(child, *args))
        process.start()
        child.close()
        self.children.append((process, parent))
        return process, parent

    def join(self, process):
        process.join(5)
        assert not process.is_alive() and process.exitcode == 0

    def stop(self):
        for process, control in reversed(self.children):
            if process.is_alive():
                process.terminate()
            process.join(5)
            assert not process.is_alive()
            control.close()
            process.close()


@pytest.fixture
def harness():
    value = _Harness()
    yield value
    value.stop()


def _start(harness, scenario, name=None):
    name = name or r'\\.\pipe\TNC-' + uuid.uuid4().hex
    process, control = harness.spawn(_server, name, scenario)
    info = _receive(control)
    assert info['kind'] == 'ready' and info['pid'] == process.pid
    return process, control, info


@pytest.mark.parametrize('scenario', ['roundtrip', 'early'])
def test_native_roundtrip_and_kernel_peer_lifetimes(harness, scenario):
    server, control, info = _start(harness, scenario)
    if scenario == 'roundtrip':
        _send(control, kind='connect')
        assert _receive(control)['pending']
    client, client_control = harness.spawn(_client, info, scenario)
    opened = _receive(client_control)
    assert opened['kind'] == 'opened'
    if scenario == 'early':
        _send(control, kind='connect')
        assert _receive(control)['code'] == n.PIPE_CONNECTED
    done = _receive(control)
    assert done['kind'] == 'done' and done['terminal'] == 'SUCCESS'
    assert (done['client_pid'], done['client_birth']) == (client.pid, opened['birth'])
    assert _receive(client_control)['kind'] == 'done'
    harness.join(client)
    _send(control, kind='close')
    closed = _receive(control)
    samples = closed.pop('handle_samples', None)
    with _handle_delta_diagnostic(samples if closed.get('delta') else None):
        assert closed == {'kind': 'closed', 'delta': 0}
    harness.join(server)


def test_native_cancel_pending_connect(harness):
    server, control, _ = _start(harness, 'cancel_connect')
    _send(control, kind='connect')
    assert _receive(control)['pending']
    done = _receive(control)
    samples = done.pop('handle_samples', None)
    with _handle_delta_diagnostic(samples if done.get('delta') else None):
        assert done == {'kind': 'done', 'terminal': 'ABORTED', 'delta': 0}
    harness.join(server)


@pytest.mark.parametrize('scenario', ['cancel_read', 'cancel_write', 'deadline', 'disconnect'])
def test_native_pending_io_cancellation_or_disconnect(harness, scenario):
    server, control, info = _start(harness, scenario)
    _send(control, kind='connect')
    assert _receive(control)['pending']
    client, client_control = harness.spawn(_client, info, scenario)
    assert _receive(client_control)['kind'] == 'opened'
    if scenario != 'cancel_write':
        assert _receive(control)['kind'] == 'read_pending'
    if scenario == 'disconnect':
        _send(client_control, kind='close')
        assert _receive(client_control)['kind'] == 'done'
    done = _receive(control)
    assert done['kind'] == 'done' and done['terminal'] in ('ABORTED', 'ERROR')
    if scenario != 'disconnect':
        _send(client_control, kind='close')
        assert _receive(client_control)['kind'] == 'done'
    harness.join(client)
    _send(control, kind='close')
    # Reliability inventory: docs/TNC_Test_Reliability.md. The [cancel_write] case
    # reported delta=1 in run 35121176638 attempt 1 and passed on attempt 2; keep strict.
    closed = _receive(control)
    samples = closed.pop('handle_samples', None)
    with _handle_delta_diagnostic(samples if closed.get('delta') else None):
        assert closed == {'kind': 'closed', 'delta': 0}
    harness.join(server)


def test_native_first_instance_collision_fails_closed(harness):
    server, control, info = _start(harness, 'idle')
    collision, channel = harness.spawn(_collision, info['name'])
    collision_result = _receive(channel)
    assert collision_result['kind'] == 'collision'
    # Either the first-instance guard or the one-instance limit can reject first.
    assert collision_result['reason'] in ('PIPE_CREATION_FAILED:5', 'PIPE_CREATION_FAILED:231')
    harness.join(collision)
    _send(control, kind='close')
    closed = _receive(control)
    closed.pop('handle_samples', None)
    assert closed['kind'] == 'closed'
    harness.join(server)


@pytest.mark.parametrize('field', ['pid', 'birth'])
def test_native_server_pin_mismatch_rejects_before_data(harness, field):
    server, control, info = _start(harness, 'idle')
    changed = {**info, field: info[field]+1}
    client, channel = harness.spawn(_client, changed, 'mismatch')
    assert _receive(channel) == {'kind': 'mismatch'}
    harness.join(client)
    _send(control, kind='close')
    closed = _receive(control)
    closed.pop('handle_samples', None)
    assert closed['kind'] == 'closed'
    harness.join(server)


def test_native_anonymous_client_denied_and_reverted(harness):
    server, control, info = _start(harness, 'idle')
    client, channel = harness.spawn(_client, info, 'anonymous')
    assert _receive(channel) == {'kind': 'denied', 'error': 5, 'reverted': True}
    harness.join(client)
    _send(control, kind='close')
    closed = _receive(control)
    closed.pop('handle_samples', None)
    assert closed['kind'] == 'closed'
    harness.join(server)


@pytest.mark.parametrize('scenario', ['kill', 'contain'])
def test_supervisor_termination_reclaims_pending_pipe(harness, scenario):
    server, control, info = _start(harness, scenario)
    _send(control, kind='connect')
    assert _receive(control)['pending']
    if scenario == 'contain':
        assert _receive(control) == {'kind': 'contained', 'retained': True}
    server.terminate()
    server.join(5)
    assert not server.is_alive() and server.exitcode != 0
    replacement, channel, _ = _start(harness, 'idle', name=info['name'])
    _send(channel, kind='close')
    closed = _receive(channel)
    closed.pop('handle_samples', None)
    assert closed['kind'] == 'closed'
    harness.join(replacement)
