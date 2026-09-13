"""Test-only event-based pipe adapter. Import performs no native allocation.

The ledger is an audit projection. The private registry, not a Python finalizer,
owns every potentially pending native allocation until explicit safe disposal.
No peer authentication or signing is implemented here.
"""
import ctypes as c
import os
import struct
import threading
import time
from dataclasses import dataclass

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical
from tnc.provenance.windows_custody_peer import WindowsPeerPolicy, CLIENT_RIGHTS, SERVICE_RIGHTS
from tnc.provenance.windows_protected_files import parse_security
from tnc.provenance.windows_pipe_operation_logic import (
    PipeOperationPlan, PipeOperationLedger, PipeOperationEvent,
    propose_pipe_event, replay_pipe_ledger, MAX_EVENTS,
)

DWORD, BOOL, HANDLE = c.c_uint32, c.c_int32, c.c_void_p
INVALID_HANDLE = c.c_void_p(-1).value
OPEN_MODE = 0x00000003 | 0x40000000 | 0x00080000
PIPE_MODE = 0x00000008  # BYTE / READMODE_BYTE / WAIT / REJECT_REMOTE_CLIENTS
IO_PENDING, IO_INCOMPLETE, OP_ABORTED = 997, 996, 995
PIPE_CONNECTED, NOT_FOUND = 535, 1168
WAIT_OBJECT, WAIT_TIMEOUT = 0, 258
# Conservative, understood pipe completion failures. Unknown query errors contain.
PIPE_ERRORS = frozenset((109, 232, 233, OP_ABORTED))
MAX_ENDPOINTS = 16
MAX_OPERATIONS = 64
_OWNERS = {}
_OWNERS_LOCK = threading.Lock()


class _Offsets(c.Structure):
    _fields_ = [('Offset', DWORD), ('OffsetHigh', DWORD)]


class _Position(c.Union):
    _fields_ = [('offsets', _Offsets), ('Pointer', c.c_void_p)]


class OVERLAPPED(c.Structure):
    _fields_ = [('Internal', c.c_size_t), ('InternalHigh', c.c_size_t),
                ('position', _Position), ('hEvent', HANDLE)]


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [('nLength', DWORD), ('lpSecurityDescriptor', c.c_void_p),
                ('bInheritHandle', BOOL)]


def validate_abi():
    width = c.sizeof(c.c_void_p)
    expected = {4: (20, 16, 12, 4, 8), 8: (32, 24, 24, 8, 16)}.get(width)
    actual = (c.sizeof(OVERLAPPED), OVERLAPPED.hEvent.offset,
              c.sizeof(SECURITY_ATTRIBUTES), SECURITY_ATTRIBUTES.lpSecurityDescriptor.offset,
              SECURITY_ATTRIBUTES.bInheritHandle.offset)
    if (expected != actual or c.sizeof(DWORD) != 4 or c.sizeof(BOOL) != 4
            or OVERLAPPED.position.offset != 2 * width):
        raise RuntimeError('UNSUPPORTED_ABI')


class PipeAdapterError(RuntimeError):
    pass


class WorkerContainmentRequired(PipeAdapterError):
    """Supervisor must terminate the disposable worker; references stay retained."""


@dataclass(frozen=True)
class ApiResult:
    ok: bool
    error: int = 0
    transferred: int = 0


def _valid_handle(handle):
    return type(handle) is int and 0 < handle < INVALID_HANDLE


def _policy(value):
    if type(value) is not WindowsPeerPolicy:
        raise ValueError('Exact pinned test policy required')
    return decode_canonical(WindowsPeerPolicy, canonical_bytes(value))


def _descriptor(policy):
    def sid(text):
        parts = [int(p) for p in text.split('-')[1:]]
        return (bytes((1, len(parts) - 2)) + parts[1].to_bytes(6, 'big')
                + b''.join(struct.pack('<I', p) for p in parts[2:]))
    owner = sid(policy.service_sid)
    aces = []
    for identity, mask in ((policy.service_sid, SERVICE_RIGHTS), (policy.client_sid, CLIENT_RIGHTS)):
        raw = sid(identity)
        aces.append(struct.pack('<BBHI', 0, 0, 8 + len(raw), mask) + raw)
    body = b''.join(aces)
    acl = struct.pack('<BBHHH', 2, 0, 8 + len(body), 2, 0) + body
    raw = struct.pack('<BBHIIII', 1, 0, 0x9004, 20, 0, 0, 20 + len(owner)) + owner + acl
    expected = ((0, 0, SERVICE_RIGHTS, policy.service_sid), (0, 0, CLIENT_RIGHTS, policy.client_sid))
    if parse_security(raw) != (policy.service_sid, expected):
        raise ValueError('DESCRIPTOR_MISMATCH')
    return raw


class NativePipeApi:
    """Explicit kernel32 binding. Injected libraries are for fake acceptance tests."""

    def __init__(self, *, library_for_testing=None, last_error_for_testing=None):
        validate_abi()
        if library_for_testing is None:
            if os.name != 'nt':
                raise OSError('WINDOWS_REQUIRED')
            if last_error_for_testing is not None:
                raise ValueError('Mixed native/fake binding')
            library_for_testing = c.WinDLL('kernel32.dll', use_last_error=True)
            last_error_for_testing = c.get_last_error
        elif last_error_for_testing is None:
            raise ValueError('Fake last-error reader required')
        self._error = last_error_for_testing
        self._dll = library_for_testing
        p = c.POINTER
        specs = {
            'CreateNamedPipeW': ([c.c_wchar_p, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, p(SECURITY_ATTRIBUTES)], HANDLE),
            'CreateEventW': ([p(SECURITY_ATTRIBUTES), BOOL, BOOL, c.c_wchar_p], HANDLE),
            'ConnectNamedPipe': ([HANDLE, p(OVERLAPPED)], BOOL),
            'ReadFile': ([HANDLE, c.c_void_p, DWORD, p(DWORD), p(OVERLAPPED)], BOOL),
            'WriteFile': ([HANDLE, c.c_void_p, DWORD, p(DWORD), p(OVERLAPPED)], BOOL),
            'WaitForSingleObject': ([HANDLE, DWORD], DWORD),
            'GetOverlappedResult': ([HANDLE, p(OVERLAPPED), p(DWORD), BOOL], BOOL),
            'CancelIoEx': ([HANDLE, p(OVERLAPPED)], BOOL),
            'CloseHandle': ([HANDLE], BOOL),
        }
        for name, (args, result) in specs.items():
            fn = getattr(self._dll, name)
            fn.argtypes, fn.restype = args, result

    def create_pipe(self, name, descriptor):
        memory = c.create_string_buffer(descriptor)
        security = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), c.cast(memory, c.c_void_p), False)
        handle = self._dll.CreateNamedPipeW(name, OPEN_MODE, PIPE_MODE, 1, 65536, 65536, 0, c.byref(security))
        if not _valid_handle(handle):
            error = self._error()
            raise PipeAdapterError('PIPE_CREATION_FAILED:' + str(error))
        return handle

    def create_event(self):
        handle = self._dll.CreateEventW(None, True, False, None)
        if not _valid_handle(handle):
            error = self._error()
            raise PipeAdapterError('EVENT_CREATION_FAILED:' + str(error))
        return handle

    def submit(self, handle, kind, overlapped, buffer, size):
        count = DWORD()
        if kind == 'CONNECT':
            ok = self._dll.ConnectNamedPipe(handle, c.byref(overlapped))
        else:
            fn = self._dll.ReadFile if kind == 'READ' else self._dll.WriteFile
            ok = fn(handle, buffer, size, c.byref(count), c.byref(overlapped))
        error = 0 if ok else self._error()
        return ApiResult(bool(ok), error, count.value if ok and kind != 'CONNECT' else 0)

    def completion(self, handle, overlapped):
        count = DWORD()
        ok = self._dll.GetOverlappedResult(handle, c.byref(overlapped), c.byref(count), False)
        error = 0 if ok else self._error()
        return ApiResult(bool(ok), error, count.value if ok else 0)

    def cancel(self, handle, overlapped):
        ok = self._dll.CancelIoEx(handle, c.byref(overlapped))
        error = 0 if ok else self._error()
        return ApiResult(bool(ok), error)

    def wait(self, event, milliseconds):
        if type(milliseconds) is not int or not 0 <= milliseconds <= 5000:
            raise ValueError('BOUNDED_WAIT_REQUIRED')
        return int(self._dll.WaitForSingleObject(event, milliseconds))

    def close(self, handle):
        return bool(self._dll.CloseHandle(handle))


class OwnedPipeEndpoint:
    """Owns one local test endpoint. No peer-authenticated access is asserted."""

    def __init__(self, *, policy, api, clock=None):
        self._policy = _policy(policy)
        descriptor = _descriptor(self._policy)
        self._api = api
        self._clock = clock if clock is not None else lambda: time.monotonic_ns() // 1_000_000
        self._identity = (os.getpid(), threading.get_ident())
        self._last_tick = -1
        self._handle = None
        self._fatal = False
        self._closed = False
        self._active = None
        self._operations = {}
        self._connect_started = False
        self._connected = False
        with _OWNERS_LOCK:
            if len(_OWNERS) >= MAX_ENDPOINTS:
                raise PipeAdapterError('ENDPOINT_CAPACITY')
            _OWNERS[id(self)] = self
        try:
            self._now()
            self._handle = api.create_pipe(self._policy.pipe_name, descriptor)
            if not _valid_handle(self._handle):
                self._contain('INVALID_PIPE_HANDLE')
        except BaseException:
            self._fatal = True
            if self._handle is None:
                with _OWNERS_LOCK:
                    _OWNERS.pop(id(self), None)
            raise

    def _guard(self):
        if self._identity != (os.getpid(), threading.get_ident()):
            raise PipeAdapterError('WRONG_OWNER')
        if self._fatal:
            raise WorkerContainmentRequired('WORKER_CONTAINMENT_REQUIRED')
        if self._closed:
            raise PipeAdapterError('ENDPOINT_CLOSED')

    def _contain(self, reason):
        self._fatal = True
        raise WorkerContainmentRequired(reason)

    def _now(self):
        try:
            tick = self._clock()
            if type(tick) is not int or not 0 <= tick < 2**63 or tick < self._last_tick:
                raise ValueError('Clock bounds')
            self._last_tick = tick
            return tick
        except BaseException:
            self._contain('CLOCK_INVALID')

    def begin_connect(self, plan):
        return self._begin(plan, 'CONNECT', None)

    def begin_read(self, plan):
        return self._begin(plan, 'READ', None)

    def begin_write(self, plan, payload):
        return self._begin(plan, 'WRITE', payload)

    def _begin(self, plan, kind, payload):
        self._guard()
        if type(plan) is not PipeOperationPlan:
            raise ValueError('Exact plan required')
        plan = decode_canonical(PipeOperationPlan, canonical_bytes(plan))
        if plan.kind != kind or self._active is not None:
            raise PipeAdapterError('OPERATION_PROFILE_MISMATCH')
        if (kind == 'CONNECT' and self._connect_started) or (kind != 'CONNECT' and not self._connected):
            raise PipeAdapterError('CONNECTION_STATE')
        identities = (plan.operation_id, plan.pipe_lease_id, plan.event_id, plan.overlapped_id, plan.buffer_id)
        used = {identity for op in self._operations.values() for identity in op._identities}
        if used.intersection(identities) or len(self._operations) >= MAX_OPERATIONS:
            raise PipeAdapterError('OPERATION_CAPACITY_OR_REUSE')
        if kind == 'WRITE' and (type(payload) is not bytes or len(payload) != plan.buffer_size):
            raise ValueError('Exact bounded write bytes required')
        tick = self._now()
        if not plan.created_tick <= tick < plan.request_deadline:
            raise PipeAdapterError('DEADLINE_EXCEEDED')
        op = OwnedPipeOperation(self, plan, payload)
        self._operations[plan.operation_id] = op
        self._active = op
        if kind == 'CONNECT':
            self._connect_started = True
        op._submit()
        return op

    def close(self):
        self._guard()
        if getattr(self, '_process_lease_active', False):
            raise PipeAdapterError('PROCESS_LEASE_ACTIVE')
        if self._active is not None:
            raise PipeAdapterError('OPERATION_NOT_DISPOSED')
        try:
            if self._api.close(self._handle) is not True:
                self._contain('PIPE_CLOSE_FAILED')
            self._handle = None
            self._closed = True
            with _OWNERS_LOCK:
                _OWNERS.pop(id(self), None)
        except BaseException:
            self._contain('PIPE_CLOSE_FAILED')


class OwnedPipeOperation:
    """Private endpoint-issued operation; registry retains pending ctypes memory."""

    def __init__(self, endpoint, plan, payload):
        self._endpoint = endpoint
        self._plan = plan
        self._identities = (plan.operation_id, plan.pipe_lease_id, plan.event_id, plan.overlapped_id, plan.buffer_id)
        self._ledger = PipeOperationLedger(plan=plan)
        self._buffer = c.create_string_buffer(payload, len(payload)) if payload is not None else c.create_string_buffer(max(1, plan.buffer_size))
        self._overlapped = OVERLAPPED()
        self._event = None
        self._raw_result = None
        self._pending = False
        self._terminal = False
        self._disposed = False
        self._cancelled = False

    @property
    def audit_ledger(self):
        return self._ledger  # Synthetic projection, never native identity evidence.

    def _guard(self):
        self._endpoint._guard()
        if self._endpoint._active is not self or self._disposed:
            raise PipeAdapterError('OPERATION_NOT_ACTIVE')

    def _record(self, action, outcome='NONE', count=0, *, tick):
        event = PipeOperationEvent(sequence=len(self._ledger.events) + 1,
            operation_id=self._plan.operation_id, overlapped_id=self._plan.overlapped_id,
            tick=tick, action=action, outcome=outcome, transferred=count)
        result = propose_pipe_event(self._ledger, event)
        if result.status != 'PROPOSED':
            self._endpoint._contain('LEDGER_REJECTED')
        self._ledger = result.proposed_ledger
        if result.state.shutdown_required:
            self._endpoint._contain('LEDGER_REQUIRES_SHUTDOWN')

    def _reserve(self, count):
        if len(self._ledger.events) > MAX_EVENTS - count:
            self._endpoint._contain('LEDGER_CAPACITY')

    def _expire(self, tick):
        if tick >= self._plan.request_deadline:
            self._record('EXPIRE', tick=tick)
        if self._pending and tick >= self._plan.cleanup_deadline:
            self._endpoint._contain('CLEANUP_DEADLINE')

    @staticmethod
    def _result(value):
        if (type(value) is not ApiResult or type(value.ok) is not bool
                or type(value.error) is not int or not 0 <= value.error < 2**32
                or type(value.transferred) is not int or not 0 <= value.transferred < 2**32
                or (value.ok and value.error) or (not value.ok and value.transferred)):
            raise ValueError('INVALID_API_RESULT')
        return value

    def _submit(self):
        try:
            self._event = self._endpoint._api.create_event()
            if not _valid_handle(self._event) or self._event == self._endpoint._handle:
                self._endpoint._contain('INVALID_EVENT')
            self._overlapped.hEvent = self._event
            tick = self._endpoint._now()
            if tick >= self._plan.request_deadline:
                self._terminal = True
                self._record('EXPIRE', tick=tick)
                return
            # From this line until a definitive return, ownership is uncertain.
            self._reserve(2)
            self._pending = True
            self._raw_result = self._endpoint._api.submit(self._endpoint._handle,
                self._plan.kind, self._overlapped, self._buffer, self._plan.buffer_size)
            result = self._result(self._raw_result)
            if result.ok or (self._plan.kind == 'CONNECT' and result.error == PIPE_CONNECTED):
                outcome = 'SUCCESS'
            elif result.error == IO_PENDING:
                outcome = 'PENDING'
            elif result.error in PIPE_ERRORS:
                outcome = 'ERROR'
            else:
                self._endpoint._contain('UNCONFIRMED_SUBMISSION')
            self._pending = outcome == 'PENDING'
            self._terminal = not self._pending
            count = result.transferred if self._plan.kind != 'CONNECT' and outcome == 'SUCCESS' else 0
            self._record('SUBMIT', outcome, count, tick=tick)
            self._expire(self._endpoint._now())
            if self._plan.kind == 'CONNECT' and outcome == 'SUCCESS':
                self._endpoint._connected = True
        except BaseException:
            self._endpoint._contain('SUBMISSION_CONTAINMENT')

    def _poll(self):
        self._reserve(2)
        self._raw_result = self._endpoint._api.completion(self._endpoint._handle, self._overlapped)
        result = self._result(self._raw_result)
        tick = self._endpoint._now()
        if result.ok:
            outcome = 'SUCCESS'
        elif result.error == IO_INCOMPLETE:
            outcome = 'INCOMPLETE'
        elif result.error in PIPE_ERRORS:
            outcome = 'ABORTED' if result.error == OP_ABORTED else 'ERROR'
        else:
            self._endpoint._contain('COMPLETION_UNCONFIRMED')
        self._pending = outcome == 'INCOMPLETE'
        self._terminal = not self._pending
        count = result.transferred if result.ok and self._plan.kind != 'CONNECT' else 0
        self._record('POLL', outcome, count, tick=tick)
        if self._plan.kind == 'CONNECT' and outcome == 'SUCCESS':
            self._endpoint._connected = True
        self._expire(tick)

    def wait_until(self, deadline_tick):
        self._guard()
        if type(deadline_tick) is not int or not 0 <= deadline_tick <= self._plan.request_deadline:
            raise ValueError('Deadline cannot extend original budget')
        try:
            self._drain(deadline_tick)
            return self._terminal
        except BaseException:
            self._endpoint._contain('WAIT_CONTAINMENT')

    def _drain(self, deadline):
        for _ in range(16):
            tick = self._endpoint._now()
            self._expire(tick)
            if not self._pending or tick >= deadline:
                return
            if len(self._ledger.events) >= MAX_EVENTS - 4:
                self._endpoint._contain('LEDGER_CAPACITY')
            result = self._endpoint._api.wait(self._event, min(deadline - tick, 5000))
            if type(result) is not int or result not in (WAIT_OBJECT, WAIT_TIMEOUT):
                self._endpoint._contain('WAIT_FAILED')
            self._poll()
        self._endpoint._contain('WAIT_ITERATION_BOUND')

    def cancel_and_drain(self):
        self._guard()
        try:
            self._cancelled = True
            self._expire(self._endpoint._now())
            if self._pending:
                self._reserve(4)
                result = self._result(self._endpoint._api.cancel(self._endpoint._handle, self._overlapped))
                outcome = 'CANCEL_ACCEPTED' if result.ok else 'NOT_FOUND' if result.error == NOT_FOUND else 'CANCEL_FAILED'
                self._record('CANCEL', outcome, tick=self._endpoint._now())
                self._poll()
                self._drain(self._plan.cleanup_deadline)
            if self._pending:
                self._endpoint._contain('COMPLETION_UNCONFIRMED')
        except BaseException:
            self._endpoint._contain('CANCELLATION_CONTAINMENT')

    def result_bytes(self):
        self._guard()
        try:
            tick = self._endpoint._now()
            self._expire(tick)
            state = replay_pipe_ledger(self._ledger)
            if (self._cancelled or not state.result_available or state.shutdown_required
                    or not self._terminal or self._pending):
                raise PipeAdapterError('RESULT_UNAVAILABLE')
            return bytes(self._buffer[:state.transferred]) if self._plan.kind == 'READ' else b''
        except PipeAdapterError:
            raise
        except BaseException:
            self._endpoint._contain('RESULT_CONTAINMENT')

    def dispose(self):
        self._guard()
        if self._pending or not self._terminal:
            raise PipeAdapterError('COMPLETION_UNCONFIRMED')
        try:
            tick = self._endpoint._now()
            if self._event is not None:
                if self._endpoint._api.close(self._event) is not True:
                    self._endpoint._contain('EVENT_CLOSE_FAILED')
                self._event = None
            self._record('DISPOSE', tick=tick)
            self._disposed = True
            self._buffer = None
            self._overlapped = None
            self._endpoint._active = None
        except BaseException:
            self._endpoint._contain('DISPOSAL_CONTAINMENT')
