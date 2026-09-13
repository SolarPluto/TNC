"""Owned process-handle correlation with explicitly injected test APIs only.

No native bindings, token exclusion proof, grants, or signing. The fake result
is audit evidence and cannot be promoted to a native identity assertion.
"""
import os
import threading
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Identifier
from tnc.provenance.windows_custody_peer import Tick, _copy
from tnc.provenance.windows_pipe_native import OwnedPipeEndpoint, _valid_handle

PROCESS_RIGHTS = 0x00101000  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
MAX_LEASES = 16
_LEASES = {}
_LOCK = threading.Lock()


class ProcessInstancePin(Model):
    pid: int = Field(strict=True, ge=1, le=2**32-1)
    creation_filetime: int = Field(strict=True, ge=1, le=2**64-1)


class ProcessLeasePlan(Model):
    operation_id: Identifier
    created_tick: Tick
    deadline: Tick
    cleanup_deadline: Tick

    @model_validator(mode='after')
    def valid(self):
        if not self.created_tick < self.deadline < self.cleanup_deadline:
            raise ValueError('Ordered deadlines required')
        if self.deadline-self.created_tick > 5000 or self.cleanup_deadline-self.deadline > 1000:
            raise ValueError('Bounded budgets required')
        return self


class ProcessLeaseAudit(Model):
    status: Literal['CORRELATED', 'INDETERMINATE']
    reason: Identifier
    source: Literal['FAKE_PROCESS_API'] = 'FAKE_PROCESS_API'
    audit_only: Literal[True] = True
    authorization_granted: Literal[False] = False


class ProcessLeaseError(ValueError):
    pass


class ProcessLeaseContainment(RuntimeError):
    """Fake-worker shutdown required; unresolved ownership remains retained."""


class ProcessAPIForTesting:
    """Trusted test injection interface. No implementation loads native libraries."""
    def client_process_id(self, pipe): raise NotImplementedError
    def open_process(self, pid, rights, inherit): raise NotImplementedError
    def process_id(self, handle): raise NotImplementedError
    def creation_filetime(self, handle): raise NotImplementedError
    def wait_process(self, handle, timeout): raise NotImplementedError
    def close(self, handle): raise NotImplementedError


class OwnedProcessLease:
    def __init__(self):
        raise TypeError('Use explicit test acquisition')

    def __reduce__(self):
        raise TypeError('Process leases cannot be serialized')

    def _owner_check(self):
        if self._owner != (os.getpid(), threading.get_ident()):
            raise ProcessLeaseError('WRONG_OWNER')

    def _clock_check(self, cleanup=False):
        tick = self._clock()
        limit = self._plan.cleanup_deadline if cleanup else self._plan.deadline
        if type(tick) is not int or not self._last_tick <= tick < limit:
            raise ProcessLeaseError('DEADLINE_OR_CLOCK')
        self._last_tick = tick

    def _contain(self):
        self._fatal = self._endpoint._fatal = True
        raise ProcessLeaseContainment('WORKER_SHUTDOWN_REQUIRED') from None

    def _call(self, method, *args):
        self._clock_check()
        value = method(*args)
        self._clock_check()
        return value

    def _check(self):
        self._endpoint._guard()
        if self._endpoint._handle != self._pipe or not self._endpoint._connected:
            raise ProcessLeaseError('ENDPOINT_CHANGED')
        for method, expected in (
            (lambda: self._api.wait_process(self._handle, 0), 258),
            (lambda: self._api.process_id(self._handle), self._pin.pid),
            (lambda: self._api.creation_filetime(self._handle), self._pin.creation_filetime),
            (lambda: self._api.client_process_id(self._pipe), self._pin.pid),
            (lambda: self._api.wait_process(self._handle, 0), 258),
        ):
            value = self._call(method)
            if type(value) is not int or value != expected:
                raise ProcessLeaseError('PROCESS_CORRELATION_FAILED')

    def _release(self):
        # Cleanup never depends on a still-valid request window or endpoint guard.
        # Even an expired cleanup budget must attempt known-handle closure.
        unsafe = False
        try:
            self._clock_check(cleanup=True)
        except BaseException:
            unsafe = True
        if self._handle is not None:
            try:
                if self._api.close(self._handle) is not True:
                    unsafe = True
                else:
                    self._handle = None
            except BaseException:
                unsafe = True
        try:
            self._clock_check(cleanup=True)
        except BaseException:
            unsafe = True
        if unsafe:
            self._contain()
        self._endpoint._process_lease_active = False
        with _LOCK:
            _LEASES.pop(id(self), None)

    def finish(self):
        self._owner_check()
        if self._fatal:
            self._contain()
        if self._consumed:
            raise ProcessLeaseError('LEASE_CONSUMED')
        self._consumed = True
        status, reason = 'CORRELATED', 'AUDIT_MATCHED'
        try:
            self._check()
        except Exception:
            status, reason = 'INDETERMINATE', 'PROCESS_CORRELATION_FAILED'
        finally:
            self._release()
        return ProcessLeaseAudit(status=status, reason=reason)

    def abort(self):
        self._owner_check()
        if self._fatal:
            self._contain()
        if self._consumed:
            raise ProcessLeaseError('LEASE_CONSUMED')
        self._consumed = True
        self._release()
        return ProcessLeaseAudit(status='INDETERMINATE', reason='ABORTED')


def acquire_process_lease_for_testing(endpoint, pin, plan, *, api, clock):
    if type(endpoint) is not OwnedPipeEndpoint or not isinstance(api, ProcessAPIForTesting) or not callable(clock):
        raise ProcessLeaseError('EXPLICIT_TEST_INPUTS_REQUIRED')
    pin, plan = _copy(ProcessInstancePin, pin), _copy(ProcessLeasePlan, plan)
    endpoint._guard()
    expected = endpoint._policy.expected_process
    if (pin.pid, pin.creation_filetime) != (expected.pid, expected.creation_filetime):
        raise ProcessLeaseError('INDEPENDENT_PIN_MISMATCH')
    if not endpoint._connected or endpoint._active is not None:
        raise ProcessLeaseError('CONNECTED_IDLE_ENDPOINT_REQUIRED')
    lease = object.__new__(OwnedProcessLease)
    lease._endpoint, lease._api, lease._clock = endpoint, api, clock
    lease._pin, lease._plan, lease._pipe = pin, plan, endpoint._handle
    lease._owner = (os.getpid(), threading.get_ident())
    lease._handle, lease._consumed, lease._fatal = None, False, False
    lease._last_tick = plan.created_tick
    lease._clock_check()
    with _LOCK:
        if len(_LEASES) >= MAX_LEASES or getattr(endpoint, '_process_lease_claimed', False):
            raise ProcessLeaseError('LEASE_CAPACITY_OR_REUSE')
        endpoint._process_lease_claimed = endpoint._process_lease_active = True
        _LEASES[id(lease)] = lease  # Strong ownership registered before dispatch.
    try:
        pid = lease._call(api.client_process_id, lease._pipe)
        if type(pid) is not int or pid != pin.pid:
            raise ProcessLeaseError('PIPE_PID_MISMATCH')
        lease._clock_check()
        try:
            handle = api.open_process(pin.pid, PROCESS_RIGHTS, False)
        except BaseException:
            # Dispatch raised: do not assume no allocation occurred or retry.
            lease._contain()
        lease._handle = handle  # Retain before clock checks or other callbacks.
        if handle is None or type(handle) is int and handle == 0:
            lease._handle = None
            raise ProcessLeaseError('PROCESS_UNAVAILABLE')
        if not _valid_handle(handle):
            lease._contain()
        lease._clock_check()
        lease._check()
        return lease
    except ProcessLeaseContainment:
        raise
    except BaseException:
        lease._consumed = True
        lease._release()
        raise ProcessLeaseError('PROCESS_ACQUISITION_FAILED') from None
