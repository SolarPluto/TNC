"""Injected Win32 token buffers and fake pipe completions; no live impersonation."""
import ctypes as c
import pickle
import struct
import threading

import pytest
from tnc.provenance import windows_pipe_token as t
from tnc.provenance import windows_pipe_native as n
from tnc.provenance.windows_custody_peer import WindowsPeerPolicy, PeerProcess
from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan


class Clock:
    tick = 10
    def __call__(self):
        return self.tick


class Function:
    def __init__(self, fn):
        self.fn = fn
    def __call__(self, *args):
        return self.fn(*args)


def sid_bytes(text):
    parts = [int(x) for x in text.split('-')[1:]]
    return bytes((1, len(parts)-2)) + parts[1].to_bytes(6, 'big') + b''.join(struct.pack('<I', x) for x in parts[2:])


class FakeTokens:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.error = t.NO_TOKEN
        self.active = False
        self.preexisting = False
        self.residual = False
        self.reverted = False
        self.fail = None
        self.close_ok = True
        self.revert_ok = True
        self.impersonate_ok = True
        self.open_missing = False
        self.open_error = None
        self.queries = {}
        self.scalars = {t.TYPE:2, t.LEVEL:1, t.SESSION:3, t.HAS_RESTRICTIONS:0, t.APP_CONTAINER:0}
        self.user = 'S-1-5-21-100'
        self.integrity = 'S-1-16-8192'
        self.integrity_flags = 0x60
        self.groups = [('S-1-5-5-300-400', 0xc0000004), ('S-1-5-32-545', 4)]
        self.restricted = []
        self.changed = False
        self.mutate = None
        self.length_override = None
        self.probe_override = None
        self.grow = False
        self.grow_forever = False
        self.expire_on_query = False
        self.GetCurrentThread = Function(lambda: -2)
        self.CloseHandle = Function(self.close)
        self.OpenThreadToken = Function(self.open)
        self.ImpersonateNamedPipeClient = Function(self.impersonate)
        self.RevertToSelf = Function(self.revert)
        self.GetTokenInformation = Function(self.information)

    def hit(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError('Injected API failure')

    def open(self, thread, rights, as_self, returned):
        self.hit('open')
        assert thread == -2 and rights == t.TOKEN_QUERY and as_self is True
        if self.open_error is not None and self.active:
            self.error = self.open_error
            return False
        present = self.preexisting or (self.active and not self.open_missing) or (self.reverted and self.residual)
        if present:
            c.cast(returned, c.POINTER(t.HANDLE)).contents.value = 99
            return True
        self.error = t.NO_TOKEN
        return False

    def close(self, handle):
        self.hit('close')
        assert handle == 99
        return self.close_ok

    def impersonate(self, pipe):
        self.hit('impersonate')
        assert pipe == 100
        self.active = self.impersonate_ok
        return self.impersonate_ok

    def revert(self):
        self.hit('revert')
        if self.revert_ok:
            self.active = False
            self.reverted = True
        return self.revert_ok

    def required(self, kind):
        if kind in self.scalars:
            return 4
        if kind == t.STATISTICS:
            return c.sizeof(t.TOKEN_STATISTICS)
        if kind in (t.USER, t.INTEGRITY):
            return c.sizeof(t.SID_AND_ATTRIBUTES) + len(sid_bytes(self.user if kind == t.USER else self.integrity))
        groups = self.groups if kind == t.GROUPS else self.restricted
        return 4 if not groups else t.TOKEN_GROUPS_HEADER.Groups.offset + len(groups)*c.sizeof(t.SID_AND_ATTRIBUTES) + sum(len(sid_bytes(sid)) for sid, _ in groups)

    def information(self, handle, kind, buffer, capacity, returned):
        self.hit('query')
        assert self.active and handle == 99 and kind != 40  # Reserved TokenIsRestricted never queried.
        self.queries[kind] = self.queries.get(kind, 0) + 1
        out = c.cast(returned, c.POINTER(t.DWORD)).contents
        required = self.required(kind)
        if buffer is None:
            out.value = self.probe_override if self.probe_override is not None else max(4, required - 4) if self.grow else required
            self.error = t.INSUFFICIENT_BUFFER
            return False
        if capacity < required or (self.grow_forever and kind == t.USER):
            out.value = max(required, capacity+4)
            self.error = t.INSUFFICIENT_BUFFER
            return False
        base = c.addressof(buffer)
        if kind in self.scalars:
            c.memmove(base, struct.pack('<I', self.scalars[kind]), 4)
        elif kind == t.STATISTICS:
            stats = t.TOKEN_STATISTICS()
            stats.TokenId.LowPart = 5
            stats.AuthenticationId.LowPart = 6
            stats.AuthenticationId.HighPart = -1
            stats.ModifiedId.LowPart = 8 if self.changed and self.queries[kind] > 1 else 7
            stats.TokenType, stats.ImpersonationLevel, stats.GroupCount = self.scalars[t.TYPE], self.scalars[t.LEVEL], len(self.groups)
            c.memmove(base, c.byref(stats), c.sizeof(stats))
        elif kind in (t.USER, t.INTEGRITY):
            raw = sid_bytes(self.user if kind == t.USER else self.integrity)
            offset = c.sizeof(t.SID_AND_ATTRIBUTES)
            header = t.SID_AND_ATTRIBUTES.from_buffer(buffer)
            header.Sid = base + offset
            header.Attributes = 0 if kind == t.USER else self.integrity_flags
            c.memmove(base+offset, raw, len(raw))
        else:
            groups = self.groups if kind == t.GROUPS else self.restricted
            c.memmove(base, struct.pack('<I', len(groups)), 4)
            offset, stride = t.TOKEN_GROUPS_HEADER.Groups.offset, c.sizeof(t.SID_AND_ATTRIBUTES)
            cursor = offset + len(groups)*stride
            for index, (sid, flags) in enumerate(groups):
                raw = sid_bytes(sid)
                header = t.SID_AND_ATTRIBUTES.from_buffer(buffer, offset+index*stride)
                header.Sid, header.Attributes = base+cursor, flags
                c.memmove(base+cursor, raw, len(raw))
                cursor += len(raw)
        if self.mutate is not None:
            self.mutate(kind, buffer, required)
        out.value = self.length_override if self.length_override is not None else required
        if self.expire_on_query:
            self.clock.tick = 20
        return True


class FakePipe:
    def __init__(self):
        self.preamble = t.PREAMBLE_PREFIX + b'c'*32
        self.event = 200
    def create_pipe(self, name, descriptor):
        return 100
    def create_event(self):
        self.event += 1
        return self.event
    def submit(self, handle, kind, overlapped, buffer, size):
        if kind == 'READ':
            buffer[:len(self.preamble)] = self.preamble
            return n.ApiResult(True, transferred=len(self.preamble))
        return n.ApiResult(True)
    def close(self, handle):
        return True


def plan(kind, identity):
    return PipeOperationPlan(operation_id=identity, kind=kind, pipe_lease_id=identity+'p',
        event_id=identity+'e', overlapped_id=identity+'o', buffer_id=identity+'b',
        buffer_size=0 if kind == 'CONNECT' else 37, created_tick=10, request_deadline=20, cleanup_deadline=30)


@pytest.fixture
def env(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Native DLLs forbidden in fake tests')
    monkeypatch.setattr(c, 'WinDLL', forbidden, raising=False)
    clock, pipe = Clock(), FakePipe()
    policy = WindowsPeerPolicy(deployment_id='d', store_instance_id='s', pipe_name=r'\\.\pipe\TNC-token-test',
        service_sid='S-1-5-80-100', client_sid='S-1-5-21-100', logon_sid='S-1-5-5-300-400', authentication_id=6,
        expected_process=PeerProcess(pid=1, creation_filetime=1, session_id=3, running=True), timestamp=1, expiry=2)
    endpoint = n.OwnedPipeEndpoint(policy=policy, api=pipe, clock=clock)
    connect = endpoint.begin_connect(plan('CONNECT', 'connect'))
    connect.dispose()
    op = endpoint.begin_read(plan('READ', 'read'))
    fake = FakeTokens(clock)
    api = t.NativePipeTokenAPI(kernel_for_testing=fake, security_for_testing=fake, last_error_for_testing=lambda: fake.error)
    inspector = t.PipeTokenInspector(api, clock=clock)
    yield endpoint, op, fake, inspector, clock
    # Fake handles only; mirrors disposable worker lifetime for fatal tests.
    with n._OWNERS_LOCK:
        for key, value in tuple(n._OWNERS.items()):
            assert isinstance(value._api, FakePipe)
            del n._OWNERS[key]


def capture(env):
    ep, op, _, inspector, _ = env
    return inspector.capture_preamble(ep, op, expected_challenge=b'c'*32)


def inspect(env):
    return env[3].inspect(capture(env))


def test_capture_fields_and_query_only_bindings(env):
    result = inspect(env)
    assert result.status == 'CAPTURED' and result.source == 'FAKE_TOKEN_API'
    assert result.facts.user_sid == 'S-1-5-21-100'
    assert result.facts.authentication_id == 0xffffffff00000006
    assert result.facts.integrity_rid == 8192 and result.facts.logon_sid == 'S-1-5-5-300-400'
    assert result.facts.app_container_exclusion_proven is False
    assert not result.authorization_granted and result.audit_only
    fake = env[2]
    assert fake.calls.index('close') < fake.calls.index('revert')
    assert fake.calls[-1] == 'open' and not fake.active
    assert fake.OpenThreadToken.argtypes[1] is t.DWORD
    assert fake.GetTokenInformation.restype is t.BOOL


def test_boundary_single_use_and_nonserializable(env):
    boundary = capture(env)
    with pytest.raises(TypeError):
        pickle.dumps(boundary)
    assert env[3].inspect(boundary).status == 'CAPTURED'
    before = list(env[2].calls)
    assert env[3].inspect(boundary).reason == 'BOUNDARY_UNAVAILABLE'
    assert env[2].calls == before
    with pytest.raises(t.TokenCaptureError):
        capture(env)


def test_read_cannot_be_reminted_by_another_inspector(env):
    capture(env)
    other = t.PipeTokenInspector(env[3]._api, clock=env[4])
    with pytest.raises(t.TokenCaptureError):
        other.capture_preamble(env[0], env[1], expected_challenge=b'c'*32)


@pytest.mark.parametrize('value', [b'x'*32, b'c'*31, bytearray(b'c'*32)])
def test_wrong_or_unbounded_challenge(env, value):
    with pytest.raises(t.TokenCaptureError):
        env[3].capture_preamble(env[0], env[1], expected_challenge=value)
    assert env[2].calls == []


def test_no_raw_handle_or_forged_boundary(env):
    with pytest.raises(t.TokenCaptureError):
        env[3].capture_preamble(100, env[1], expected_challenge=b'c'*32)
    assert env[3].inspect(t._ReadBoundary()).reason == 'BOUNDARY_UNAVAILABLE'
    assert env[2].calls == []


@pytest.mark.parametrize('change', ['dispose', 'bytes', 'handle'])
def test_changed_read_boundary_consumed_without_token_calls(env, change):
    boundary = capture(env)
    if change == 'dispose':
        env[1].dispose()
    elif change == 'bytes':
        env[1]._buffer[0] = b'X'
    else:
        env[0]._handle = 101
    assert env[3].inspect(boundary).status == 'INDETERMINATE'
    assert env[3].inspect(boundary).reason == 'BOUNDARY_UNAVAILABLE'
    assert env[2].calls == []


def test_wrong_thread_burns_known_boundary(env):
    boundary, results = capture(env), []
    worker = threading.Thread(target=lambda: results.append(env[3].inspect(boundary)))
    worker.start()
    worker.join(2)
    assert not worker.is_alive() and results[0].reason == 'BOUNDARY_INVALID'
    assert env[3].inspect(boundary).reason == 'BOUNDARY_UNAVAILABLE'
    assert env[2].calls == []


@pytest.mark.parametrize('field', ['close_ok', 'revert_ok'])
def test_cleanup_false_is_fatal_and_replay_cannot_continue(env, field):
    setattr(env[2], field, False)
    boundary = capture(env)
    with pytest.raises(t.TokenContainmentRequired):
        env[3].inspect(boundary)
    assert 'revert' in env[2].calls and env[0]._fatal and env[3]._fatal
    assert env[3].inspect(boundary).reason == 'BOUNDARY_UNAVAILABLE'


@pytest.mark.parametrize('failure', ['close', 'revert'])
def test_cleanup_exception_is_fatal(env, failure):
    env[2].fail = failure
    with pytest.raises(t.TokenContainmentRequired):
        inspect(env)
    assert 'revert' in env[2].calls


def test_preexisting_token_not_overwritten(env):
    env[2].preexisting = True
    with pytest.raises(t.TokenContainmentRequired):
        inspect(env)
    assert env[2].calls == ['open', 'close']


def test_residual_token_is_fatal(env):
    env[2].residual = True
    with pytest.raises(t.TokenContainmentRequired):
        inspect(env)
    assert env[2].calls[-2:] == ['open', 'close']


@pytest.mark.parametrize('mode', ['false', 'exception', 'missing', 'anonymous', 'denied'])
def test_impersonation_or_token_failure_reverts_without_fallback(env, mode):
    fake = env[2]
    if mode == 'false': fake.impersonate_ok = False
    if mode == 'exception': fake.fail = 'impersonate'
    if mode == 'missing': fake.open_missing = True
    if mode == 'anonymous': fake.open_error = 1347
    if mode == 'denied': fake.open_error = 5
    assert inspect(env).status == 'INDETERMINATE'
    assert 'revert' in fake.calls and 'query' not in fake.calls


@pytest.mark.parametrize('tick', [20, 9, -1, True])
def test_boundary_deadline_and_clock_bounds(env, tick):
    boundary = capture(env)
    env[4].tick = tick
    assert env[3].inspect(boundary).status == 'INDETERMINATE'
    assert env[2].calls == []


def test_inflight_deadline_always_reverts(env):
    env[2].expire_on_query = True
    result = inspect(env)
    assert result.status == 'INDETERMINATE' and result.facts is None
    assert env[2].calls[-3:] == ['close', 'revert', 'open']


@pytest.mark.parametrize('size', [0, 65537, 0xffffffff])
def test_probe_size_bound(env, size):
    env[2].probe_override = size
    assert inspect(env).status == 'INDETERMINATE'
    assert env[2].calls[-3:] == ['close', 'revert', 'open']


@pytest.mark.parametrize('length', [0, 3, 65537])
def test_fixed_return_size_mismatch(env, length):
    env[2].length_override = length
    assert inspect(env).status == 'INDETERMINATE'


def test_one_bounded_growth_retry(env):
    env[2].grow = True
    assert inspect(env).status == 'CAPTURED'
    assert env[2].queries[t.USER] == 3


def test_repeated_growth_rejected(env):
    env[2].grow = env[2].grow_forever = True
    assert inspect(env).status == 'INDETERMINATE'
    assert env[2].queries[t.USER] == 3


def test_aggregate_allocation_bound(env, monkeypatch):
    monkeypatch.setattr(t, 'MAX_TOTAL', 60)
    assert inspect(env).status == 'INDETERMINATE'
    assert env[2].calls[-3:] == ['close', 'revert', 'open']


@pytest.mark.parametrize('where', ['null', 'header', 'past', 'count'])
def test_sid_pointer_and_extent_validation(env, where):
    def mutate(kind, buffer, size):
        if kind != t.USER: return
        header = t.SID_AND_ATTRIBUTES.from_buffer(buffer)
        if where == 'null': header.Sid = None
        if where == 'header': header.Sid = c.addressof(buffer)
        if where == 'past': header.Sid = c.addressof(buffer)+size
        if where == 'count': buffer[c.sizeof(t.SID_AND_ATTRIBUTES)+1] = b'\x10'
    env[2].mutate = mutate
    assert inspect(env).status == 'INDETERMINATE'


@pytest.mark.parametrize('mode', ['none', 'duplicate', 'ambiguous', 'disabled', 'deny_only', 'unknown_flags', 'too_many'])
def test_group_and_logon_bounds(env, mode):
    fake = env[2]
    if mode == 'none': fake.groups = []
    if mode == 'duplicate': fake.groups.append(fake.groups[0])
    if mode == 'ambiguous': fake.groups.append(('S-1-5-5-500-600', 0xc0000004))
    if mode == 'disabled': fake.groups[0] = (fake.groups[0][0], 0xc0000000)
    if mode == 'deny_only': fake.groups[0] = (fake.groups[0][0], 0xc0000014)
    if mode == 'unknown_flags': fake.groups[1] = (fake.groups[1][0], 0x100)
    if mode == 'too_many': fake.groups += [('S-1-5-21-'+str(x), 4) for x in range(255)]
    assert inspect(env).status == 'INDETERMINATE'


@pytest.mark.parametrize('kind,value', [(t.TYPE,1), (t.LEVEL,0), (t.LEVEL,4), (t.APP_CONTAINER,2), (t.HAS_RESTRICTIONS,2)])
def test_scalar_type_and_level_rejections(env, kind, value):
    env[2].scalars[kind] = value
    assert inspect(env).status == 'INDETERMINATE'


def test_restrictions_are_captured_not_authorized(env):
    env[2].restricted = [('S-1-5-21-999', 4)]
    env[2].scalars[t.HAS_RESTRICTIONS] = 1
    env[2].scalars[t.APP_CONTAINER] = 1
    result = inspect(env)
    assert result.status == 'CAPTURED'
    assert result.facts.has_restrictions and result.facts.restricted_sids_present and result.facts.app_container_reported
    assert result.authorization_granted is False


def test_changed_token_statistics_rejected(env):
    env[2].changed = True
    assert inspect(env).status == 'INDETERMINATE'


@pytest.mark.parametrize('sid,attributes', [('S-1-5-8192',0x60), ('S-1-16-8192',0)])
def test_integrity_label_validation(env, sid, attributes):
    env[2].integrity, env[2].integrity_flags = sid, attributes
    assert inspect(env).status == 'INDETERMINATE'


def test_query_exception_reverts(env):
    env[2].fail = 'query'
    assert inspect(env).status == 'INDETERMINATE'
    assert env[2].calls[-3:] == ['close', 'revert', 'open']


def test_fake_capture_has_no_external_side_effects(env, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Forbidden side effect')
    for name in ('builtins.open', 'socket.socket', 'sqlite3.connect', 'time.time', 'time.monotonic_ns', 'os._exit'):
        monkeypatch.setattr(name, forbidden)
    assert inspect(env).status == 'CAPTURED'


@pytest.mark.parametrize('length', [1, 2, 3, 5])
def test_restriction_flag_native_return_lengths(env, length):
    fake = env[2]
    original = fake.GetTokenInformation
    def information(handle, kind, buffer, capacity, returned):
        ok = original(handle, kind, buffer, capacity, returned)
        if kind == t.HAS_RESTRICTIONS and ok:
            c.cast(returned, c.POINTER(t.DWORD)).contents.value = length
        return ok
    fake.GetTokenInformation = information
    result = inspect(env)
    assert result.status == ('CAPTURED' if length == 1 else 'INDETERMINATE')
