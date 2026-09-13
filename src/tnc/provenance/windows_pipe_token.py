"""Bounded, query-only pipe-token capture. No policy authorization or signing.

Explicit native bindings are tested with injected libraries. Real reversion or
cleanup failures terminate the process; fake bindings raise a containment signal.
"""
import ctypes as c
from dataclasses import dataclass
from hashlib import sha256
import os
import threading
import time
import weakref
from typing import Literal

from pydantic import Field
from tnc.provenance.authorization_models import Model, Digest, Identifier
from tnc.provenance.windows_custody_peer import SID
from tnc.provenance.windows_pipe_native import OwnedPipeEndpoint, OwnedPipeOperation, DWORD, BOOL, HANDLE

TOKEN_QUERY = 8
NO_TOKEN, INSUFFICIENT_BUFFER = 1008, 122
USER, GROUPS, TYPE, LEVEL, STATISTICS, RESTRICTED_SIDS, SESSION = 1, 2, 8, 9, 10, 11, 12
HAS_RESTRICTIONS, INTEGRITY, APP_CONTAINER = 21, 25, 29
MAX_BUFFER, MAX_TOTAL, MAX_GROUPS = 65536, 262144, 256
MAX_BOUNDARIES = 64
PREAMBLE_PREFIX = b'TNCP\x01'
PREAMBLE_SIZE = 37
_CLAIMED_READS = weakref.WeakKeyDictionary()
_CLAIM_LOCK = threading.Lock()


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [('Sid', c.c_void_p), ('Attributes', DWORD)]


class TOKEN_GROUPS_HEADER(c.Structure):
    _fields_ = [('GroupCount', DWORD), ('Groups', SID_AND_ATTRIBUTES * 1)]


class LUID(c.Structure):
    _fields_ = [('LowPart', DWORD), ('HighPart', c.c_int32)]


class TOKEN_STATISTICS(c.Structure):
    _fields_ = [('TokenId', LUID), ('AuthenticationId', LUID), ('ExpirationTime', c.c_int64),
                ('TokenType', DWORD), ('ImpersonationLevel', DWORD), ('DynamicCharged', DWORD),
                ('DynamicAvailable', DWORD), ('GroupCount', DWORD), ('PrivilegeCount', DWORD),
                ('ModifiedId', LUID)]


class TokenCaptureError(ValueError):
    pass


class TokenContainmentRequired(RuntimeError):
    """Fake-mode fatal signal; the inspector and endpoint cannot be reused."""


class CapturedTokenFacts(Model):
    user_sid: SID
    logon_sid: SID
    authentication_id: int = Field(strict=True, ge=0, lt=2**64)
    token_id: int = Field(strict=True, ge=0, lt=2**64)
    modified_id: int = Field(strict=True, ge=0, lt=2**64)
    session_id: int = Field(strict=True, ge=0, lt=2**32)
    token_type: Literal['IMPERSONATION'] = 'IMPERSONATION'
    level: Literal['IDENTIFICATION', 'IMPERSONATION', 'DELEGATION']
    integrity_rid: int = Field(strict=True, ge=0, lt=2**32)
    has_restrictions: bool = Field(strict=True)
    restricted_sids_present: bool = Field(strict=True)
    app_container_reported: bool = Field(strict=True)
    # Especially for identification-level tokens, false is not exclusion proof.
    app_container_exclusion_proven: Literal[False] = False


class TokenCaptureResult(Model):
    status: Literal['CAPTURED', 'INDETERMINATE']
    reason: Identifier
    source: Literal['FAKE_TOKEN_API', 'NATIVE_TOKEN_API']
    facts: CapturedTokenFacts | None = None
    preamble_digest: Digest | None = None
    operation_id: Identifier | None = None
    audit_only: Literal[True] = True
    authorization_granted: Literal[False] = False


def _luid(value):
    return ((value.HighPart & 0xffffffff) << 32) | value.LowPart


@dataclass
class _Budget:
    used: int = 0

    def allocate(self, size):
        if type(size) is not int or not 0 < size <= MAX_BUFFER or self.used + size > MAX_TOTAL:
            raise TokenCaptureError('BUFFER_BOUND')
        self.used += size  # Includes abandoned buffers during the one allowed retry.
        return c.create_string_buffer(size)


def _slice(buffer, length):
    if not isinstance(buffer, c.Array) or type(length) is not int or not 0 < length <= c.sizeof(buffer):
        raise TokenCaptureError('BUFFER_EXTENT')
    return bytes(buffer[:length])


def _sid(buffer, length, pointer, minimum):
    raw = _slice(buffer, length)
    start = c.addressof(buffer)
    if type(pointer) is not int or not start + minimum <= pointer <= start + length - 8:
        raise TokenCaptureError('SID_POINTER')
    offset = pointer - start
    revision, count = raw[offset:offset+2]
    if revision != 1 or not 1 <= count <= 15 or offset + 8 + 4*count > length:
        raise TokenCaptureError('SID_EXTENT')
    authority = int.from_bytes(raw[offset+2:offset+8], 'big')
    parts = [int.from_bytes(raw[offset+8+i*4:offset+12+i*4], 'little') for i in range(count)]
    return 'S-1-' + str(authority) + ''.join('-' + str(part) for part in parts)


def _single_sid(buffer, length):
    if length < c.sizeof(SID_AND_ATTRIBUTES):
        raise TokenCaptureError('SID_HEADER')
    header = SID_AND_ATTRIBUTES.from_buffer_copy(_slice(buffer, length)[:c.sizeof(SID_AND_ATTRIBUTES)])
    return _sid(buffer, length, header.Sid, c.sizeof(SID_AND_ATTRIBUTES)), header.Attributes


def _groups(buffer, length):
    raw = _slice(buffer, length)
    if length < 4:
        raise TokenCaptureError('GROUP_HEADER')
    count = int.from_bytes(raw[:4], 'little')
    offset, stride = TOKEN_GROUPS_HEADER.Groups.offset, c.sizeof(SID_AND_ATTRIBUTES)
    if count > MAX_GROUPS or (count and offset + count*stride > length):
        raise TokenCaptureError('GROUP_BOUND')
    end = offset + count*stride
    result = []
    for index in range(count):
        header = SID_AND_ATTRIBUTES.from_buffer_copy(raw[offset+index*stride:offset+(index+1)*stride])
        sid = _sid(buffer, length, header.Sid, end)
        if header.Attributes & ~0xe000007f:
            raise TokenCaptureError('GROUP_ATTRIBUTES')
        result.append((sid, header.Attributes))
    if len({sid for sid, _ in result}) != len(result):
        raise TokenCaptureError('DUPLICATE_GROUP')
    return tuple(result)


class NativePipeTokenAPI:
    """Explicit system bindings. No OpenProcessToken or token mutation API."""

    def __init__(self, *, kernel_for_testing=None, security_for_testing=None, last_error_for_testing=None):
        if c.sizeof(TOKEN_STATISTICS) != 56 or TOKEN_STATISTICS.ModifiedId.offset != 48:
            raise TokenCaptureError('UNSUPPORTED_ABI')
        width = c.sizeof(c.c_void_p)
        if width not in (4, 8) or c.sizeof(SID_AND_ATTRIBUTES) != 2*width or TOKEN_GROUPS_HEADER.Groups.offset != width:
            raise TokenCaptureError('UNSUPPORTED_ABI')
        fake = kernel_for_testing is not None or security_for_testing is not None or last_error_for_testing is not None
        if fake:
            if kernel_for_testing is None or security_for_testing is None or last_error_for_testing is None:
                raise ValueError('Complete fake binding set required')
            self.kernel, self.security, self._error = kernel_for_testing, security_for_testing, last_error_for_testing
        else:
            if os.name != 'nt':
                raise OSError('WINDOWS_REQUIRED')
            self.kernel = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
            self.security = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
            self._error = c.get_last_error
        self.source = 'FAKE_TOKEN_API' if fake else 'NATIVE_TOKEN_API'
        self._fake = fake
        p = c.POINTER
        for library, name, args, result in (
            (self.kernel, 'GetCurrentThread', [], HANDLE),
            (self.kernel, 'CloseHandle', [HANDLE], BOOL),
            (self.security, 'ImpersonateNamedPipeClient', [HANDLE], BOOL),
            (self.security, 'OpenThreadToken', [HANDLE, DWORD, BOOL, p(HANDLE)], BOOL),
            (self.security, 'RevertToSelf', [], BOOL),
            (self.security, 'GetTokenInformation', [HANDLE, c.c_int32, c.c_void_p, DWORD, p(DWORD)], BOOL),
        ):
            fn = getattr(library, name)
            fn.argtypes, fn.restype = args, result

    def fail_fast(self):
        if self._fake:
            raise TokenContainmentRequired('BROKER_SHUTDOWN_REQUIRED')
        os._exit(78)  # No unwinding, callbacks, or caller-context logging.

    def open_thread_token(self):
        handle = HANDLE()
        ok = self.security.OpenThreadToken(self.kernel.GetCurrentThread(), TOKEN_QUERY, True, c.byref(handle))
        error = 0 if ok else self._error()
        if not ok and error == NO_TOKEN:
            return None
        if not ok:
            raise TokenCaptureError('THREAD_TOKEN_UNAVAILABLE')
        if handle.value is None or not 0 < handle.value < c.c_void_p(-1).value:
            raise TokenCaptureError('INVALID_TOKEN_HANDLE')
        return handle.value

    def impersonate(self, pipe):
        return bool(self.security.ImpersonateNamedPipeClient(pipe))

    def revert(self):
        return bool(self.security.RevertToSelf())

    def close(self, token):
        return bool(self.kernel.CloseHandle(token))

    def _query(self, token, kind, buffer, capacity, check):
        check()
        returned = DWORD()
        ok = self.security.GetTokenInformation(token, kind, buffer, capacity, c.byref(returned))
        error = 0 if ok else self._error()
        check()
        return bool(ok), error, returned.value

    def _variable(self, token, kind, budget, check):
        ok, error, size = self._query(token, kind, None, 0, check)
        if ok or error != INSUFFICIENT_BUFFER:
            raise TokenCaptureError('INVALID_SIZE_PROBE')
        for attempt in range(2):
            buffer = budget.allocate(size)
            ok, error, returned = self._query(token, kind, buffer, size, check)
            if ok:
                if not 0 < returned <= size:
                    raise TokenCaptureError('RETURN_LENGTH')
                return buffer, returned
            if attempt or error != INSUFFICIENT_BUFFER or returned <= size:
                raise TokenCaptureError('QUERY_FAILED')
            size = returned
        raise TokenCaptureError('QUERY_BOUND')

    def _fixed(self, token, kind, struct_type, budget, check):
        size = c.sizeof(struct_type)
        buffer = budget.allocate(size)
        ok, _, returned = self._query(token, kind, buffer, size, check)
        if not ok or returned != size:
            raise TokenCaptureError('FIXED_LENGTH')
        return struct_type.from_buffer_copy(bytes(buffer))

    def capture(self, token, check):
        budget = _Budget()
        before = self._fixed(token, STATISTICS, TOKEN_STATISTICS, budget, check)
        kind = self._fixed(token, TYPE, DWORD, budget, check).value
        level = self._fixed(token, LEVEL, DWORD, budget, check).value
        if kind != 2 or level not in (1, 2, 3):
            raise TokenCaptureError('TOKEN_TYPE_OR_LEVEL')
        user, _ = _single_sid(*self._variable(token, USER, budget, check))
        groups = _groups(*self._variable(token, GROUPS, budget, check))
        logons = [(sid, flags) for sid, flags in groups if flags & 0xc0000000 == 0xc0000000]
        if len(logons) != 1:
            raise TokenCaptureError('LOGON_IDENTITY_AMBIGUOUS')
        logon, flags = logons[0]
        if not logon.startswith('S-1-5-5-') or len(logon.split('-')) != 6 or not flags & 4 or flags & 16:
            raise TokenCaptureError('LOGON_IDENTITY_DISABLED')
        restricted = _groups(*self._variable(token, RESTRICTED_SIDS, budget, check))
        integrity, attributes = _single_sid(*self._variable(token, INTEGRITY, budget, check))
        if not integrity.startswith('S-1-16-') or len(integrity.split('-')) != 4 or not attributes & 0x20:
            raise TokenCaptureError('INTEGRITY_LABEL')
        session = self._fixed(token, SESSION, DWORD, budget, check).value
        # Windows can report a one-byte return length for this documented DWORD
        # class. Keep a DWORD allocation; accept only the explicit 1/4-byte forms.
        flag_buffer = budget.allocate(c.sizeof(DWORD))
        ok, _, length = self._query(token, HAS_RESTRICTIONS, flag_buffer, c.sizeof(DWORD), check)
        if not ok or length not in (1, 4):
            raise TokenCaptureError('RESTRICTION_FLAG_LENGTH')
        filtered = int.from_bytes(bytes(flag_buffer[:length]), 'little')
        app = self._fixed(token, APP_CONTAINER, DWORD, budget, check).value
        if filtered not in (0, 1) or app not in (0, 1):
            raise TokenCaptureError('BOOLEAN_SCALAR')
        after = self._fixed(token, STATISTICS, TOKEN_STATISTICS, budget, check)
        def identity(stats):
            return (_luid(stats.TokenId), _luid(stats.AuthenticationId), _luid(stats.ModifiedId),
                    stats.TokenType, stats.ImpersonationLevel, stats.GroupCount)
        if identity(before) != identity(after) or (before.TokenType, before.ImpersonationLevel, before.GroupCount) != (kind, level, len(groups)):
            raise TokenCaptureError('TOKEN_CHANGED')
        # TokenStatistics.ExpirationTime is not an operational token-expiry gate.
        return CapturedTokenFacts(user_sid=user, logon_sid=logon,
            authentication_id=_luid(before.AuthenticationId), token_id=_luid(before.TokenId),
            modified_id=_luid(before.ModifiedId), session_id=session,
            level={1:'IDENTIFICATION', 2:'IMPERSONATION', 3:'DELEGATION'}[level],
            integrity_rid=int(integrity.rsplit('-', 1)[1]), has_restrictions=bool(filtered),
            restricted_sids_present=bool(restricted), app_container_reported=bool(app))


class _ReadBoundary:
    __slots__ = ()
    def __reduce__(self):
        raise TypeError('Transient read boundary cannot be serialized')


@dataclass(frozen=True)
class _RetainedRead:
    endpoint: OwnedPipeEndpoint
    operation: OwnedPipeOperation
    pipe: int
    preamble: bytes
    deadline: int
    owner: tuple


class PipeTokenInspector:
    """Consumes endpoint-owned completed preamble reads; outputs audit facts only."""

    def __init__(self, api, *, clock=None):
        if type(api) is not NativePipeTokenAPI:
            raise TypeError('Explicit token binding required')
        self._api = api
        self._clock = clock if clock is not None else lambda: time.monotonic_ns() // 1_000_000
        self._owner = (os.getpid(), threading.get_ident())
        self._boundaries, self._consumed_operations = {}, set()
        self._lock = threading.Lock()
        self._fatal = False
        self._last_tick = -1

    def _check(self, deadline):
        tick = self._clock()
        if type(tick) is not int or not self._last_tick <= tick < deadline or tick < 0:
            raise TokenCaptureError('DEADLINE_OR_CLOCK')
        self._last_tick = tick

    def capture_preamble(self, endpoint, operation, *, expected_challenge):
        if self._fatal or self._owner != (os.getpid(), threading.get_ident()):
            raise TokenCaptureError('INSPECTOR_UNAVAILABLE')
        if type(endpoint) is not OwnedPipeEndpoint or type(operation) is not OwnedPipeOperation:
            raise TokenCaptureError('OWNED_READ_REQUIRED')
        endpoint._guard()
        if (endpoint._active is not operation or operation._endpoint is not endpoint
                or operation._plan.kind != 'READ' or operation._plan.buffer_size != PREAMBLE_SIZE):
            raise TokenCaptureError('PREAMBLE_READ_REQUIRED')
        if type(expected_challenge) is not bytes or len(expected_challenge) != 32:
            raise TokenCaptureError('CHALLENGE_BOUND')
        self._check(operation._plan.request_deadline)
        preamble = operation.result_bytes()
        if preamble != PREAMBLE_PREFIX + expected_challenge:
            raise TokenCaptureError('PREAMBLE_MISMATCH')
        with self._lock, _CLAIM_LOCK:
            if len(self._boundaries) >= MAX_BOUNDARIES or operation in _CLAIMED_READS:
                raise TokenCaptureError('READ_REUSED_OR_CAPACITY')
            boundary = _ReadBoundary()
            self._boundaries[boundary] = _RetainedRead(endpoint, operation, endpoint._handle,
                preamble, operation._plan.request_deadline, self._owner)
            self._consumed_operations.add(id(operation))
            _CLAIMED_READS[operation] = True
        return boundary

    def inspect(self, boundary):
        with self._lock:
            retained = self._boundaries.get(boundary) if type(boundary) is _ReadBoundary else None
            if retained is not None:
                self._boundaries[boundary] = None  # Consume before any validation or API call.
        def denied(reason):
            return TokenCaptureResult(status='INDETERMINATE', reason=reason, source=self._api.source)
        if retained is None:
            return denied('BOUNDARY_UNAVAILABLE')
        ep, op = retained.endpoint, retained.operation
        try:
            if self._fatal or retained.owner != (os.getpid(), threading.get_ident()):
                raise TokenCaptureError('OWNER_MISMATCH')
            ep._guard()
            self._check(retained.deadline)
            if ep._active is not op or ep._handle != retained.pipe or op.result_bytes() != retained.preamble:
                raise TokenCaptureError('READ_BOUNDARY_CHANGED')
        except Exception:
            return denied('BOUNDARY_INVALID')
        fatal = False
        token = None
        revert_needed = False
        facts = None
        try:
            token = self._api.open_thread_token()
            if token is not None:
                fatal = True  # Preserve foreign context; never reuse this worker.
                raise TokenCaptureError('PREEXISTING_TOKEN')
            self._check(retained.deadline)
            revert_needed = True
            if not self._api.impersonate(retained.pipe):
                raise TokenCaptureError('IMPERSONATION_FAILED')
            self._check(retained.deadline)
            token = self._api.open_thread_token()
            if token is None:
                raise TokenCaptureError('MISSING_EFFECTIVE_TOKEN')
            facts = self._api.capture(token, lambda: self._check(retained.deadline))
        except BaseException:
            facts = None
        finally:
            if token is not None:
                try:
                    if not self._api.close(token):
                        fatal = True
                except BaseException:
                    fatal = True
            if revert_needed:
                try:
                    if not self._api.revert():
                        fatal = True
                except BaseException:
                    fatal = True
        if fatal:
            self._fatal = ep._fatal = True
            self._api.fail_fast()
        try:
            leftover = self._api.open_thread_token()
        except BaseException:
            self._fatal = ep._fatal = True
            self._api.fail_fast()
        if leftover is not None:
            try:
                self._api.close(leftover)
            finally:
                self._fatal = ep._fatal = True
                self._api.fail_fast()
        try:
            self._check(retained.deadline)
            ep._guard()
            if ep._active is not op or ep._handle != retained.pipe or op.result_bytes() != retained.preamble:
                raise TokenCaptureError('READ_BOUNDARY_CHANGED')
            if facts is None:
                return denied('TOKEN_CAPTURE_FAILED')
            return TokenCaptureResult(status='CAPTURED', reason='AUDIT_CAPTURE_ONLY', source=self._api.source,
                facts=facts, operation_id=op._plan.operation_id,
                preamble_digest=sha256(retained.preamble).hexdigest())
        except Exception:
            return denied('DEADLINE_OR_BOUNDARY_INVALID')
