"""Fake-only ownership, process lifetime and cleanup tests."""
import pickle
import threading
import weakref

import pytest
import test_windows_pipe_token as token_test
from tnc.provenance import windows_pipe_native as n
from tnc.provenance import windows_pipe_process_lease as p
from tnc.provenance.windows_custody_peer import WindowsPeerPolicy, PeerProcess


class FakeProcess(p.ProcessAPIForTesting):
    def __init__(self):
        self.calls = []
        self.pid, self.birth, self.wait, self.handle = 1, 100, 258, 500
        self.fail, self.close_ok = '', True
        self.opened, self.closed = [], []
    def hit(self, name, *args):
        self.calls.append((name, *args))
        if self.fail == name:
            raise RuntimeError('private backend detail')
    def client_process_id(self, pipe):
        self.hit('pipe_pid', pipe)
        return self.pid
    def open_process(self, pid, rights, inherit):
        self.hit('open', pid, rights, inherit)
        self.opened.append(self.handle)
        return self.handle
    def process_id(self, handle):
        self.hit('pid', handle)
        return self.pid
    def creation_filetime(self, handle):
        self.hit('birth', handle)
        return self.birth
    def wait_process(self, handle, timeout):
        self.hit('wait', handle, timeout)
        return self.wait
    def close(self, handle):
        self.hit('close', handle)
        if self.close_ok:
            self.closed.append(handle)
        return self.close_ok


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr('ctypes.WinDLL', lambda *a, **kw: pytest.fail('Native call forbidden'), raising=False)
    clock, pipe, api = token_test.Clock(), token_test.FakePipe(), FakeProcess()
    policy = WindowsPeerPolicy(deployment_id='d', store_instance_id='s', pipe_name=r'\\.\pipe\TNC-process',
        service_sid='S-1-5-80-100', client_sid='S-1-5-21-100', logon_sid='S-1-5-5-300-400',
        authentication_id=6, expected_process=PeerProcess(pid=1, creation_filetime=100, session_id=3, running=True),
        timestamp=1, expiry=2)
    ep = n.OwnedPipeEndpoint(policy=policy, api=pipe, clock=clock)
    connect = ep.begin_connect(token_test.plan('CONNECT', 'connect'))
    connect.dispose()
    yield ep, api, clock
    # Fake-only disposable-worker reclamation for containment scenarios.
    with p._LOCK:
        for key, lease in tuple(p._LEASES.items()):
            assert isinstance(lease._api, FakeProcess)
            del p._LEASES[key]
    with n._OWNERS_LOCK:
        for key, endpoint in tuple(n._OWNERS.items()):
            assert isinstance(endpoint._api, token_test.FakePipe)
            del n._OWNERS[key]


def acquire(env, **kwargs):
    ep, api, clock = env
    return p.acquire_process_lease_for_testing(ep,
        kwargs.get('pin', p.ProcessInstancePin(pid=1, creation_filetime=100)),
        kwargs.get('plan', p.ProcessLeasePlan(operation_id='lease', created_tick=10, deadline=20, cleanup_deadline=30)),
        api=api, clock=clock)


def test_retains_one_handle_and_exact_rights(env):
    lease = acquire(env)
    ep, api, _ = env
    assert api.opened == [500] and not api.closed
    assert ('open', 1, 0x101000, False) in api.calls
    assert all(call[2] == 0 for call in api.calls if call[0] == 'wait')
    result = lease.finish()
    assert result.status == 'CORRELATED' and result.source == 'FAKE_PROCESS_API'
    assert result.audit_only and not result.authorization_granted
    assert api.closed == [500] and len(api.opened) == 1 and not p._LEASES
    ep.close()


def test_endpoint_cannot_close_during_lease(env):
    lease = acquire(env)
    with pytest.raises(n.PipeAdapterError, match='PROCESS_LEASE_ACTIVE'):
        env[0].close()
    lease.abort()
    env[0].close()


def test_registry_retains_dropped_lease(env):
    lease = acquire(env)
    reference = weakref.ref(lease)
    del lease
    assert reference() is not None and not env[1].closed
    reference().abort()
    assert not p._LEASES and env[1].closed == [500]


def test_no_serialization_or_direct_construction(env):
    with pytest.raises(TypeError):
        p.OwnedProcessLease()
    lease = acquire(env)
    with pytest.raises(TypeError):
        pickle.dumps(lease)
    lease.abort()


@pytest.mark.parametrize('method', ['finish','abort'])
def test_single_use_and_no_reacquisition(env, method):
    lease = acquire(env)
    getattr(lease, method)()
    calls = list(env[1].calls)
    with pytest.raises(p.ProcessLeaseError, match='LEASE_CONSUMED'):
        lease.finish()
    with pytest.raises(p.ProcessLeaseError, match='CAPACITY_OR_REUSE'):
        acquire(env)
    assert env[1].calls == calls


@pytest.mark.parametrize('pin', [p.ProcessInstancePin(pid=2,creation_filetime=100), p.ProcessInstancePin(pid=1,creation_filetime=101)])
def test_independent_pin_not_derived_from_lookup(env, pin):
    with pytest.raises(p.ProcessLeaseError, match='INDEPENDENT_PIN_MISMATCH'):
        acquire(env, pin=pin)
    assert not env[1].calls


@pytest.mark.parametrize('field,value', [('pid',2), ('pid',True), ('birth',101), ('wait',0), ('wait',0xffffffff), ('wait',128), ('wait',True)])
def test_acquisition_mismatch_closes_known_handle(env, field, value):
    setattr(env[1], field, value)
    with pytest.raises(p.ProcessLeaseError):
        acquire(env)
    assert not p._LEASES
    assert env[1].closed == ([] if field == 'pid' else [500])


@pytest.mark.parametrize('field,value', [('pid',2), ('birth',101), ('wait',0), ('wait',0xffffffff)])
def test_final_change_denied_and_closed(env, field, value):
    lease = acquire(env)
    setattr(env[1], field, value)
    assert lease.finish().status == 'INDETERMINATE'
    assert env[1].closed == [500] and len(env[1].opened) == 1


@pytest.mark.parametrize('failure', ['pipe_pid','pid','birth','wait'])
def test_query_exceptions_are_sanitized_and_closed(env, failure):
    lease = acquire(env)
    env[1].fail = failure
    assert lease.finish().reason == 'PROCESS_CORRELATION_FAILED'
    assert env[1].closed == [500]


@pytest.mark.parametrize('handle', [None,0])
def test_unavailable_process_no_broader_retry(env, handle):
    env[1].handle = handle
    with pytest.raises(p.ProcessLeaseError):
        acquire(env)
    assert len(env[1].opened) == 1 and not env[1].closed and not p._LEASES


def test_open_exception_unknown_allocation_contains(env):
    env[1].fail = 'open'
    with pytest.raises(p.ProcessLeaseContainment):
        acquire(env)
    assert p._LEASES and env[0]._fatal


@pytest.mark.parametrize('mode', ['false','exception'])
def test_close_failure_retains_ownership(env, mode):
    lease = acquire(env)
    if mode == 'false': env[1].close_ok = False
    else: env[1].fail = 'close'
    with pytest.raises(p.ProcessLeaseContainment): lease.finish()
    assert p._LEASES[id(lease)] is lease and env[0]._fatal
    calls = list(env[1].calls)
    with pytest.raises(p.ProcessLeaseContainment): lease.abort()
    assert env[1].calls == calls


def test_request_expiry_still_closes_under_cleanup_budget(env):
    lease = acquire(env)
    env[2].tick = 20
    assert lease.finish().status == 'INDETERMINATE'
    assert env[1].closed == [500]


@pytest.mark.parametrize('tick', [30,9,-1,True])
def test_invalid_cleanup_clock_attempts_close_then_contains(env, tick):
    lease = acquire(env)
    env[2].tick = tick
    with pytest.raises(p.ProcessLeaseContainment): lease.finish()
    assert env[1].closed == [500] and env[0]._fatal


def test_wrong_thread_cannot_use_or_close_owner_handle(env):
    lease = acquire(env)
    errors = []
    def worker():
        try: lease.finish()
        except p.ProcessLeaseError as error: errors.append(str(error))
    calls = list(env[1].calls)
    thread = threading.Thread(target=worker)
    thread.start(); thread.join(2)
    assert not thread.is_alive() and errors == ['WRONG_OWNER'] and env[1].calls == calls
    lease.abort()


def test_capacity_precedes_dispatch(env, monkeypatch):
    monkeypatch.setattr(p, 'MAX_LEASES', 0)
    with pytest.raises(p.ProcessLeaseError): acquire(env)
    assert not env[1].calls


def test_fake_evaluation_no_external_io(env, monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError('External side effect')
    for target in ('builtins.open','socket.socket','sqlite3.connect','time.time','time.monotonic_ns'):
        monkeypatch.setattr(target, forbidden)
    assert acquire(env).finish().source == 'FAKE_PROCESS_API'


def test_late_open_retains_handle_before_deadline_check(env):
    original = env[1].open_process
    def late(*args):
        handle = original(*args)
        env[2].tick = 20
        return handle
    env[1].open_process = late
    with pytest.raises(p.ProcessLeaseError): acquire(env)
    assert env[1].closed == [500] and not p._LEASES


def test_pipe_pid_changes_during_open(env):
    original = env[1].open_process
    def changed(*args):
        handle = original(*args)
        env[1].pid = 2
        return handle
    env[1].open_process = changed
    with pytest.raises(p.ProcessLeaseError): acquire(env)
    assert env[1].closed == [500]


def test_endpoint_handle_substitution_denied(env):
    lease = acquire(env)
    env[0]._handle = 999
    assert lease.finish().status == 'INDETERMINATE'
    assert env[1].closed == [500]


def test_api_source_cannot_promote_fake_result(env):
    env[1].source = 'NATIVE_PROCESS_API'
    assert acquire(env).finish().source == 'FAKE_PROCESS_API'


@pytest.mark.parametrize('update', [{'deadline':10}, {'deadline':6000,'cleanup_deadline':6100}, {'cleanup_deadline':2000}])
def test_plan_bounds(env, update):
    plan = p.ProcessLeasePlan(operation_id='lease', created_tick=10, deadline=20, cleanup_deadline=30)
    with pytest.raises(ValueError): acquire(env, plan=plan.model_copy(update=update))
    assert not env[1].calls
