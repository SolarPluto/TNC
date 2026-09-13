"""Fake-injected ABI and ownership acceptance tests; no native pipes are opened."""
import ctypes as c
import gc
import threading
import weakref

import pytest
import tnc.provenance.windows_pipe_native as n
from tnc.provenance.windows_custody_peer import WindowsPeerPolicy, PeerProcess
from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan, replay_pipe_ledger


class Clock:
    tick = 10
    def __call__(self):
        return self.tick


class FakeApi:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.submission = n.ApiResult(True)
        self.completions = [n.ApiResult(True)]
        self.cancellation = n.ApiResult(True)
        self.wait_result = n.WAIT_OBJECT
        self.wait_advance = 1
        self.submit_advance = 0
        self.next_event = 200
        self.fail = None
        self.close_failure = None
        self.on_submit = None

    def hit(self, name, *args):
        self.calls.append((name, *args))
        if self.fail == name:
            raise RuntimeError('Injected failure')

    def create_pipe(self, name, descriptor):
        self.hit('create_pipe', name, descriptor)
        return 100

    def create_event(self):
        self.hit('create_event')
        self.next_event += 1
        return self.next_event

    def submit(self, handle, kind, overlapped, buffer, size):
        self.hit('submit', handle, kind, c.addressof(overlapped), c.addressof(buffer), size)
        if self.on_submit:
            self.on_submit(overlapped, buffer)
        if kind == 'READ':
            buffer[:4] = b'test'
        self.clock.tick += self.submit_advance
        return self.submission

    def completion(self, handle, overlapped):
        self.hit('completion', handle, c.addressof(overlapped))
        return self.completions.pop(0) if len(self.completions) > 1 else self.completions[0]

    def cancel(self, handle, overlapped):
        self.hit('cancel', handle, c.addressof(overlapped))
        return self.cancellation

    def wait(self, event, milliseconds):
        self.hit('wait', event, milliseconds)
        self.clock.tick += min(milliseconds, self.wait_advance)
        return self.wait_result

    def close(self, handle):
        self.hit('close', handle)
        return handle != self.close_failure


@pytest.fixture
def setup(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Native DLL loading forbidden')
    monkeypatch.setattr(c, 'WinDLL', forbidden, raising=False)
    clock = Clock()
    api = FakeApi(clock)
    policy = WindowsPeerPolicy(deployment_id='deployment', store_instance_id='store',
        pipe_name=r'\\.\pipe\TNC-native-test', service_sid='S-1-5-80-100', client_sid='S-1-5-21-200',
        logon_sid='S-1-5-5-300-400', authentication_id=42,
        expected_process=PeerProcess(pid=123, creation_filetime=100, session_id=1, running=True),
        timestamp=100, expiry=200)
    endpoint = n.OwnedPipeEndpoint(policy=policy, api=api, clock=clock)
    yield endpoint, api, clock
    # Models disposable-process death only for this entirely fake API.
    with n._OWNERS_LOCK:
        for key, value in tuple(n._OWNERS.items()):
            assert isinstance(value._api, FakeApi)
            del n._OWNERS[key]


def plan(kind='CONNECT', identity='one'):
    return PipeOperationPlan(operation_id=identity, kind=kind, pipe_lease_id=identity+'-pipe',
        event_id=identity+'-event', overlapped_id=identity+'-overlapped', buffer_id=identity+'-buffer',
        buffer_size=0 if kind == 'CONNECT' else 4, created_tick=10,
        request_deadline=20, cleanup_deadline=30)


def connected(setup):
    endpoint, api, clock = setup
    operation = endpoint.begin_connect(plan())
    operation.dispose()
    return endpoint, api, clock


def pending(setup):
    endpoint, api, clock = setup
    api.submission = n.ApiResult(False, n.IO_PENDING)
    return endpoint.begin_connect(plan())


def test_abi_layout():
    n.validate_abi()
    assert n.OVERLAPPED.Internal.offset == 0
    assert n.OVERLAPPED.InternalHigh.offset == c.sizeof(c.c_void_p)


def test_explicit_creation_descriptor(setup):
    endpoint, api, _ = setup
    name, raw = api.calls[0][1:]
    owner, entries = n.parse_security(raw)
    assert name == endpoint._policy.pipe_name and owner == endpoint._policy.service_sid
    assert entries == ((0, 0, n.SERVICE_RIGHTS, owner), (0, 0, n.CLIENT_RIGHTS, endpoint._policy.client_sid))
    assert int.from_bytes(raw[2:4], 'little') == 0x9004
    endpoint.close()
    assert id(endpoint) not in n._OWNERS


@pytest.mark.parametrize('result', [n.ApiResult(True), n.ApiResult(False, n.PIPE_CONNECTED)])
def test_immediate_connection_no_wait(setup, result):
    endpoint, api, _ = setup
    api.submission = result
    op = endpoint.begin_connect(plan())
    assert op.result_bytes() == b''
    assert not any(call[0] == 'wait' for call in api.calls)
    op.dispose()
    endpoint.close()


def test_short_read_and_private_write_buffer(setup):
    endpoint, api, _ = connected(setup)
    api.submission = n.ApiResult(True, transferred=2)
    read = endpoint.begin_read(plan('READ', 'read'))
    assert read.result_bytes() == b'te'
    read.dispose()
    write = endpoint.begin_write(plan('WRITE', 'write'), b'abcd')
    assert bytes(write._buffer) == b'abcd'
    assert replay_pipe_ledger(write.audit_ledger).transferred == 2
    write.dispose()
    endpoint.close()


def test_ownership_registered_before_dispatch(setup):
    endpoint, api, _ = setup
    def inspect(overlapped, buffer):
        assert n._OWNERS[id(endpoint)] is endpoint
        assert endpoint._active._overlapped is overlapped
        assert endpoint._operations['one']._buffer is buffer
    api.on_submit = inspect
    op = endpoint.begin_connect(plan())
    op.dispose()


def test_pending_cannot_dispose_or_close(setup):
    op = pending(setup)
    for action in (op.dispose, op._endpoint.close):
        with pytest.raises(n.PipeAdapterError):
            action()
    assert not any(call[0] == 'close' for call in setup[1].calls)


def test_incomplete_then_completion(setup):
    op = pending(setup)
    setup[1].completions = [n.ApiResult(False, n.IO_INCOMPLETE), n.ApiResult(True, transferred=0xffffffff)]
    assert op.wait_until(20)
    assert replay_pipe_ledger(op.audit_ledger).transferred == 0  # CONNECT count undefined.
    assert op.result_bytes() == b''
    op.dispose()


@pytest.mark.parametrize('cancel', [n.ApiResult(True), n.ApiResult(False, n.NOT_FOUND), n.ApiResult(False, 5)])
@pytest.mark.parametrize('completion', [n.ApiResult(True), n.ApiResult(False, n.OP_ABORTED), n.ApiResult(False, 109)])
def test_cancellation_races(setup, cancel, completion):
    op = pending(setup)
    api = setup[1]
    api.cancellation, api.completions = cancel, [completion]
    address = c.addressof(op._overlapped)
    op.cancel_and_drain()
    assert ('cancel', 100, address) in api.calls
    assert ('completion', 100, address) in api.calls
    with pytest.raises(n.PipeAdapterError):
        op.result_bytes()
    op.dispose()


@pytest.mark.parametrize('error', [6, 5, 9999, n.IO_PENDING])
def test_query_errors_never_prove_completion(setup, error):
    op = pending(setup)
    setup[1].completions = [n.ApiResult(False, error)]
    with pytest.raises(n.WorkerContainmentRequired):
        op.wait_until(20)
    assert op._pending and op._buffer is not None and op._event is not None
    assert not any(call[0] == 'close' for call in setup[1].calls)


@pytest.mark.parametrize('failure', ['submit', 'completion', 'wait', 'cancel'])
def test_api_exceptions_contain_with_references(setup, failure):
    endpoint, api, _ = setup
    if failure == 'submit':
        api.fail = failure
        with pytest.raises(n.WorkerContainmentRequired):
            endpoint.begin_connect(plan())
        op = endpoint._active
    else:
        op = pending(setup)
        api.fail = failure
        with pytest.raises(n.WorkerContainmentRequired):
            op.cancel_and_drain() if failure == 'cancel' else op.wait_until(20)
    assert n._OWNERS[id(endpoint)]._active is op and op._buffer is not None


def test_post_dispatch_ledger_failure_retains_allocations(setup, monkeypatch):
    endpoint, api, _ = setup
    def fail(*args, **kwargs):
        raise ValueError('Ledger fault after dispatch')
    monkeypatch.setattr(n, 'propose_pipe_event', fail)
    with pytest.raises(n.WorkerContainmentRequired):
        endpoint.begin_connect(plan())
    assert endpoint._active._raw_result == n.ApiResult(True)
    assert endpoint._active._buffer is not None and not endpoint._active._disposed


def test_caller_abandonment_retains_pending_memory(setup):
    op = pending(setup)
    reference = weakref.ref(op._buffer)
    del op
    gc.collect()
    assert reference() is n._OWNERS[id(setup[0])]._active._buffer


def test_cleanup_deadline_containment(setup):
    op = pending(setup)
    api = setup[1]
    api.completions = [n.ApiResult(False, n.IO_INCOMPLETE)]
    api.wait_advance = 30
    with pytest.raises(n.WorkerContainmentRequired):
        op.cancel_and_drain()
    assert op._pending and op._event is not None


def test_post_sync_deadline_suppresses_result(setup):
    endpoint, api, _ = setup
    api.submit_advance = 10
    op = endpoint.begin_connect(plan())
    with pytest.raises(n.PipeAdapterError):
        op.result_bytes()
    op.dispose()


def test_late_completion_requires_sticky_worker_shutdown(setup):
    op = pending(setup)
    endpoint, api, clock = setup
    clock.tick = 30
    with pytest.raises(n.WorkerContainmentRequired):
        op.cancel_and_drain()
    assert endpoint._fatal and op._buffer is not None
    with pytest.raises(n.WorkerContainmentRequired):
        op.dispose()


def test_record_capacity_checked_before_cancel_dispatch(setup, monkeypatch):
    op = pending(setup)
    monkeypatch.setattr(n, 'MAX_EVENTS', 2)
    with pytest.raises(n.WorkerContainmentRequired):
        op.cancel_and_drain()
    assert not any(call[0] == 'cancel' for call in setup[1].calls)
    assert op._pending and op._buffer is not None


@pytest.mark.parametrize('count', [5, 0xffffffff])
def test_read_completion_overrun_contains(setup, count):
    endpoint, api, _ = connected(setup)
    api.submission = n.ApiResult(False, n.IO_PENDING)
    op = endpoint.begin_read(plan('READ', 'read'))
    api.completions = [n.ApiResult(True, transferred=count)]
    with pytest.raises(n.WorkerContainmentRequired):
        op.wait_until(20)
    assert op._buffer is not None


def test_disposed_resource_identity_reuse_rejected(setup):
    endpoint, api, _ = connected(setup)
    op = endpoint.begin_read(plan('READ', 'read'))
    op.dispose()
    before = len(api.calls)
    with pytest.raises(n.PipeAdapterError):
        endpoint.begin_read(plan('READ', 'read'))
    assert len(api.calls) == before


def test_creation_failure_has_no_retry(setup):
    endpoint, api, clock = setup
    api.fail = 'create_pipe'
    before = len(api.calls)
    with pytest.raises(RuntimeError):
        n.OwnedPipeEndpoint(policy=endpoint._policy, api=api, clock=clock)
    assert [call[0] for call in api.calls[before:]] == ['create_pipe']


def test_deadline_checked_again_at_release(setup):
    endpoint, _, clock = setup
    op = endpoint.begin_connect(plan())
    clock.tick = 20
    with pytest.raises(n.PipeAdapterError):
        op.result_bytes()


def test_deadline_extension_refused(setup):
    op = pending(setup)
    with pytest.raises(ValueError):
        op.wait_until(21)


@pytest.mark.parametrize('tick', [True, -1, 9, 2**63])
def test_clock_invalid_retains_operation(setup, tick):
    op = pending(setup)
    setup[2].tick = tick
    with pytest.raises(n.WorkerContainmentRequired):
        op.wait_until(20)
    assert op._buffer is not None


def test_wait_failure_not_terminal(setup):
    op = pending(setup)
    setup[1].wait_result = 0xffffffff
    with pytest.raises(n.WorkerContainmentRequired):
        op.wait_until(20)
    assert op._pending


def test_close_failure_does_not_record_disposed(setup):
    endpoint, api, _ = setup
    op = endpoint.begin_connect(plan())
    api.close_failure = op._event
    with pytest.raises(n.WorkerContainmentRequired):
        op.dispose()
    assert replay_pipe_ledger(op.audit_ledger).stage == 'TERMINAL'
    with pytest.raises(n.WorkerContainmentRequired):
        op.dispose()
    assert sum(call[0] == 'close' for call in api.calls) == 1


def test_disposal_record_failure_does_not_double_close(setup, monkeypatch):
    endpoint, api, _ = setup
    op = endpoint.begin_connect(plan())
    monkeypatch.setattr(op, '_record', lambda *args, **kw: (_ for _ in ()).throw(ValueError()))
    with pytest.raises(n.WorkerContainmentRequired):
        op.dispose()
    assert op._event is None and op._buffer is not None
    with pytest.raises(n.WorkerContainmentRequired):
        op.dispose()
    assert sum(call[0] == 'close' for call in api.calls) == 1


def test_wrong_thread_rejected_before_calls(setup):
    endpoint, api, _ = setup
    failures = []
    def worker():
        try:
            endpoint.begin_connect(plan())
        except n.PipeAdapterError as error:
            failures.append(str(error))
    before = len(api.calls)
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and failures == ['WRONG_OWNER'] and len(api.calls) == before


def test_double_dispose_and_overlapping_operations(setup):
    endpoint, _, _ = setup
    op = endpoint.begin_connect(plan())
    with pytest.raises(n.PipeAdapterError):
        endpoint.begin_read(plan('READ', 'second'))
    op.dispose()
    with pytest.raises(n.PipeAdapterError):
        op.dispose()


class Function:
    def __init__(self, body):
        self.body = body
    def __call__(self, *args):
        return self.body(*args)


class Library:
    def __init__(self):
        self.calls = []
        self.ok = 1
        for name in ('CreateNamedPipeW', 'CreateEventW', 'ConnectNamedPipe', 'ReadFile',
                     'WriteFile', 'WaitForSingleObject', 'GetOverlappedResult', 'CancelIoEx', 'CloseHandle'):
            setattr(self, name, Function(lambda *args, name=name: self.call(name, args)))
    def call(self, name, args):
        self.calls.append((name, args))
        if name == 'CreateNamedPipeW':
            security = c.cast(args[-1], c.POINTER(n.SECURITY_ATTRIBUTES)).contents
            assert security.bInheritHandle == 0 and security.nLength == c.sizeof(n.SECURITY_ATTRIBUTES)
            self.descriptor = c.string_at(security.lpSecurityDescriptor, 20)
            return 100
        if name == 'CreateEventW':
            return 200
        if name in ('ReadFile', 'WriteFile'):
            c.cast(args[3], c.POINTER(n.DWORD)).contents.value = 3
        if name == 'GetOverlappedResult':
            assert args[-1] is False
            c.cast(args[2], c.POINTER(n.DWORD)).contents.value = 2
        return self.ok


def test_typed_bindings_flags_and_no_stale_error(setup):
    lib = Library()
    def error():
        raise AssertionError('Last error read after success')
    api = n.NativePipeApi(library_for_testing=lib, last_error_for_testing=error)
    assert all(getattr(lib, name).argtypes for name in ('ReadFile', 'CancelIoEx', 'CloseHandle'))
    assert lib.CreateNamedPipeW.restype is n.HANDLE
    api.create_pipe(setup[0]._policy.pipe_name, n._descriptor(setup[0]._policy))
    args = lib.calls[-1][1]
    assert args[1:7] == (n.OPEN_MODE, n.PIPE_MODE, 1, 65536, 65536, 0)
    api.create_event()
    assert lib.calls[-1][1] == (None, True, False, None)
    ov = n.OVERLAPPED()
    assert api.submit(100, 'READ', ov, c.create_string_buffer(4), 4) == n.ApiResult(True, transferred=3)
    assert api.completion(100, ov) == n.ApiResult(True, transferred=2)
    assert api.cancel(100, ov).ok


@pytest.mark.parametrize('method', ['submit', 'completion', 'cancel'])
def test_last_error_capture(method):
    lib = Library()
    lib.ok = 0
    captures = []
    def error():
        captures.append(lib.calls[-1][0])
        return n.IO_PENDING
    api = n.NativePipeApi(library_for_testing=lib, last_error_for_testing=error)
    ov = n.OVERLAPPED()
    result = api.submit(100, 'READ', ov, c.create_string_buffer(4), 4) if method == 'submit' else getattr(api, method)(100, ov)
    assert result == n.ApiResult(False, n.IO_PENDING) and len(captures) == 1


@pytest.mark.parametrize('handle', [None, 0, n.INVALID_HANDLE])
def test_creation_invalid_handles(handle):
    lib = Library()
    lib.CreateNamedPipeW = Function(lambda *args: handle)
    api = n.NativePipeApi(library_for_testing=lib, last_error_for_testing=lambda: 5)
    with pytest.raises(n.PipeAdapterError):
        api.create_pipe(r'\\.\pipe\TNC-test', b'placeholder')


@pytest.mark.parametrize('budget', [-1, True, 5001, 0xffffffff])
def test_binding_rejects_unbounded_wait(budget):
    lib = Library()
    api = n.NativePipeApi(library_for_testing=lib, last_error_for_testing=lambda: 0)
    with pytest.raises(ValueError):
        api.wait(200, budget)
    assert lib.calls == []
