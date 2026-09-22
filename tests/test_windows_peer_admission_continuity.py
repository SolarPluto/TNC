"""Admission-continuity lifecycle and use-gate tests."""
import copy
import pickle
import threading

import pytest
from pydantic import TypeAdapter

import test_windows_pipe_token as token_test
from tnc.provenance import windows_pipe_native as pipe_native
from tnc.provenance import windows_pipe_process_lease as lease_mod
from tnc.provenance.windows_custody_peer import PeerProcess, WindowsPeerPolicy
from tnc.provenance.windows_peer_admission_continuity import (
    AdmissionContinuityContainment,
    AdmissionContinuityError,
    ContinuityUseKind,
    PeerAdmissionPolicyProviderForTesting,
    PeerAdmissionPolicySnapshot,
)
from tnc.provenance.windows_pipe_context_producer import PipePeerAdmissionEvidence


_PIPE_CONTEXT = TypeAdapter(PipePeerAdmissionEvidence)


class FakeProcess(lease_mod.ProcessAPIForTesting):
    def __init__(self):
        self.calls = []
        self.handles = [500, 600]
        self.pid = 1
        self.birth = 100
        self.wait = 258
        self.closed = []
        self.close_ok = True
        self.fail = None

    def _hit(self, name, *args):
        self.calls.append((name, *args))
        if self.fail == name:
            raise RuntimeError("injected process failure")

    def client_process_id(self, pipe):
        self._hit("pipe_pid", pipe)
        return self.pid

    def open_process(self, pid, rights, inherit):
        self._hit("open", pid, rights, inherit)
        return self.handles.pop(0)

    def process_id(self, handle):
        self._hit("pid", handle)
        return self.pid

    def creation_filetime(self, handle):
        self._hit("birth", handle)
        return self.birth

    def wait_process(self, handle, timeout):
        self._hit("wait", handle, timeout)
        return self.wait

    def close(self, handle):
        self._hit("close", handle)
        if self.close_ok:
            self.closed.append(handle)
        return self.close_ok


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(
        "ctypes.WinDLL",
        lambda *a, **kw: pytest.fail("Native call forbidden"),
        raising=False,
    )
    clock = token_test.Clock()
    pipe_api = token_test.FakePipe()
    process_api = FakeProcess()
    policy = WindowsPeerPolicy(
        deployment_id="d",
        store_instance_id="s",
        pipe_name=r"\\.\pipe\TNC-continuity",
        service_sid="S-1-5-80-100",
        client_sid="S-1-5-21-100",
        logon_sid="S-1-5-5-300-400",
        authentication_id=6,
        expected_process=PeerProcess(
            pid=1,
            creation_filetime=100,
            session_id=3,
            running=True,
        ),
        timestamp=1,
        expiry=1000,
    )
    endpoint = pipe_native.OwnedPipeEndpoint(
        policy=policy,
        api=pipe_api,
        clock=clock,
    )
    connect = endpoint.begin_connect(token_test.plan("CONNECT", "connect"))
    connect.dispose()
    lease = lease_mod.acquire_process_lease_for_testing(
        endpoint,
        lease_mod.ProcessInstancePin(pid=1, creation_filetime=100),
        lease_mod.ProcessLeasePlan(
            operation_id="lease",
            created_tick=10,
            deadline=20,
            cleanup_deadline=30,
        ),
        api=process_api,
        clock=clock,
    )
    context = _PIPE_CONTEXT.validate_python({
        "status": "CAPTURE_UNAVAILABLE",
        "connection_operation_id": "connect",
        "pipe_lease_id": "connectp",
        "process_lease_operation_id": "lease",
        "process_pid": 1,
        "process_creation_filetime": 100,
        "capture_ordinal": 1,
        "failure_scope": "CAPTURE",
        "failed_stage": "OPEN_THREAD_TOKEN",
        "winerror": 5,
    })
    provider = PeerAdmissionPolicyProviderForTesting(
        PeerAdmissionPolicySnapshot(revision=1, policy_digest="a" * 64)
    )
    yield endpoint, process_api, clock, lease, context, provider

    with lease_mod._LOCK:
        lease_mod._LEASES.clear()
    with pipe_native._OWNERS_LOCK:
        pipe_native._OWNERS.clear()


def prepare(env):
    endpoint, process_api, clock, lease, context, provider = env
    continuity = lease.prepare_continuity(
        pipe_context=context,
        provider=provider,
        continuity_deadline=100,
    )
    return continuity


def finish_and_keep_continuity(env):
    continuity = prepare(env)
    audit = env[3].finish()
    assert audit.status == "CORRELATED"
    assert env[1].closed == [500]
    return continuity


def test_prepare_opens_independent_handle_with_exact_rights_before_finish(env):
    continuity = prepare(env)
    api = env[1]
    assert [call for call in api.calls if call[0] == "open"] == [
        ("open", 1, 0x101000, False),
        ("open", 1, 0x101000, False),
    ]
    assert api.closed == []
    assert continuity._process_handle == 600
    env[3].finish()
    assert api.closed == [500]
    continuity.close()
    assert api.closed == [500, 600]


def test_binding_mismatch_fails_before_second_open(env):
    wrong = env[4].model_copy(update={"process_pid": 2})
    with pytest.raises(AdmissionContinuityError, match="PIPE_CONTEXT_BINDING_MISMATCH"):
        env[3].prepare_continuity(
            pipe_context=wrong,
            provider=env[5],
            continuity_deadline=100,
        )
    assert [call for call in env[1].calls if call[0] == "open"] == [
        ("open", 1, 0x101000, False),
    ]
    env[3].abort()


def test_prepare_is_one_shot(env):
    continuity = prepare(env)
    with pytest.raises(AdmissionContinuityError, match="CONTINUITY_ALREADY_PREPARED"):
        env[3].prepare_continuity(
            pipe_context=env[4],
            provider=env[5],
            continuity_deadline=100,
        )
    env[3].finish()
    continuity.close()


def test_endpoint_close_is_blocked_until_continuity_released(env):
    continuity = finish_and_keep_continuity(env)
    with pytest.raises(pipe_native.PipeAdapterError, match="ADMISSION_CONTINUITY_ACTIVE"):
        env[0].close()
    assert continuity.close() is True
    assert continuity.close() is False
    env[0].close()


def test_context_manager_releases_continuity_on_exception(env):
    continuity = finish_and_keep_continuity(env)
    with pytest.raises(RuntimeError, match="caller failure"):
        with continuity as held:
            assert held is continuity
            raise RuntimeError("caller failure")
    assert env[1].closed == [500, 600]
    assert not env[0]._continuity_active
    env[0].close()


@pytest.mark.parametrize("result", [0, 0xFFFFFFFF, 0x80])
def test_only_wait_timeout_counts_as_live(env, result):
    continuity = finish_and_keep_continuity(env)
    env[1].wait = result
    with pytest.raises(AdmissionContinuityError):
        continuity.mint_use_token(
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
            operation_deadline=50,
        )
    assert env[1].closed == [500, 600]
    env[0].close()


def test_policy_is_compared_current_vs_evaluation_snapshot(env):
    continuity = finish_and_keep_continuity(env)
    env[5].snapshot = PeerAdmissionPolicySnapshot(
        revision=2,
        policy_digest="b" * 64,
    )
    with pytest.raises(AdmissionContinuityError, match="POLICY_CHANGED"):
        continuity.mint_use_token(
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
            operation_deadline=50,
        )
    assert env[1].closed == [500, 600]
    env[0].close()


def test_policy_provider_failure_is_fail_closed(env):
    continuity = finish_and_keep_continuity(env)
    env[5].fail = True
    with pytest.raises(AdmissionContinuityError, match="POLICY_UNAVAILABLE"):
        continuity.mint_use_token(
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
            operation_deadline=50,
        )
    assert env[1].closed == [500, 600]
    env[0].close()


def test_consume_rechecks_liveness_after_mint(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    env[1].wait = 0
    with pytest.raises(AdmissionContinuityError, match="PROCESS_NOT_LIVE"):
        continuity.consume_use_token(
            token,
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        )
    assert token._consumed is True
    assert env[1].closed == [500, 600]
    env[0].close()


def test_consume_rechecks_policy_after_mint(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    env[5].snapshot = PeerAdmissionPolicySnapshot(
        revision=2,
        policy_digest="b" * 64,
    )
    with pytest.raises(AdmissionContinuityError, match="POLICY_CHANGED"):
        continuity.consume_use_token(
            token,
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        )
    assert token._consumed is True
    assert env[1].closed == [500, 600]
    env[0].close()


def test_single_outstanding_token_then_fresh_revalidation(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op-1",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    with pytest.raises(AdmissionContinuityError, match="USE_TOKEN_OUTSTANDING"):
        continuity.mint_use_token(
            operation_id="op-2",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
            operation_deadline=50,
        )
    assert continuity.consume_use_token(
        token,
        operation_id="op-1",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
    )
    second = continuity.mint_use_token(
        operation_id="op-2",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    assert second is not token
    continuity.close()


def test_concurrent_mint_allows_one_outstanding_token(env):
    continuity = finish_and_keep_continuity(env)
    barrier = threading.Barrier(3)
    results = []
    errors = []

    def worker(name):
        barrier.wait()
        try:
            results.append(
                continuity.mint_use_token(
                    operation_id=name,
                    kind=ContinuityUseKind.RESERVED_FOR_TESTING,
                    operation_deadline=50,
                )
            )
        except AdmissionContinuityError as exc:
            errors.append(str(exc))

    threads = [
        threading.Thread(target=worker, args=("op-a",)),
        threading.Thread(target=worker, args=("op-b",)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(2)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 1
    assert errors == ["USE_TOKEN_OUTSTANDING"]
    continuity.close()


def test_token_deadline_is_monotonic_and_bounded(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=12,
    )
    assert token._minted_tick == 10
    assert token._use_deadline == 12
    env[2].tick = 12
    with pytest.raises(AdmissionContinuityError, match="USE_TOKEN_INVALID"):
        continuity.consume_use_token(
            token,
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        )
    continuity.close()


def test_use_token_is_bound_to_operation_and_single_use(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    with pytest.raises(AdmissionContinuityError, match="USE_TOKEN_INVALID"):
        continuity.consume_use_token(
            token,
            operation_id="other",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        )
    with pytest.raises(AdmissionContinuityError):
        continuity.consume_use_token(
            token,
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        )
    continuity.close()


def test_live_artifacts_reject_pickle_copy_and_deepcopy(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    for value in (continuity, token):
        with pytest.raises(TypeError):
            pickle.dumps(value)
        with pytest.raises(TypeError):
            copy.copy(value)
        with pytest.raises(TypeError):
            copy.deepcopy(value)
    continuity.close()


def test_close_failure_requires_containment(env):
    continuity = finish_and_keep_continuity(env)
    env[1].close_ok = False
    with pytest.raises(AdmissionContinuityContainment):
        continuity.close()
    assert env[0]._fatal



def test_close_containment_is_terminal_and_never_retries(env):
    continuity = finish_and_keep_continuity(env)
    env[1].close_ok = False
    with pytest.raises(AdmissionContinuityContainment):
        continuity.close()
    first_close_calls = env[1].calls.count(("close", 600))
    assert first_close_calls == 1
    assert continuity._contained is True
    assert continuity._closed is False

    # Containment is checked before the ordinary closed/idempotent state.
    continuity._closed = True
    with pytest.raises(AdmissionContinuityContainment):
        continuity.close()
    assert env[1].calls.count(("close", 600)) == first_close_calls


def test_close_burns_minted_unconsumed_token(env):
    continuity = finish_and_keep_continuity(env)
    token = continuity.mint_use_token(
        operation_id="op",
        kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        operation_deadline=50,
    )
    assert continuity.close() is True
    assert token._consumed is True
    with pytest.raises(AdmissionContinuityError):
        continuity.consume_use_token(
            token,
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
        )
