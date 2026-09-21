"""Live evaluation-to-use continuity for native Windows peer admission.

No ADMITTED evaluator state is introduced here. This module owns transient
continuity only; frozen audit/evidence records remain non-authoritative.
"""
import threading
from enum import Enum

from pydantic import Field, TypeAdapter

from tnc.provenance.authorization_models import Digest, Identifier, Model
from tnc.provenance.windows_pipe_context_producer import PipePeerAdmissionEvidence
from tnc.provenance.windows_pipe_process_native import (
    PROCESS_LEASE_RIGHTS,
    WAIT_TIMEOUT,
    NativeProcessAPI,
    NativeProcessAPIError,
)

MAX_CONTINUITY_USE_TOKEN_MS = 1000
_PIPE_CONTEXT = TypeAdapter(PipePeerAdmissionEvidence)


class AdmissionContinuityError(RuntimeError):
    """Continuity could not be established or no longer proves safe use."""


class AdmissionContinuityContainment(RuntimeError):
    """Native ownership could not be safely released; worker containment is required."""


class ContinuityUseKind(str, Enum):
    """Closed operation namespace. Integration PRs add explicit privileged kinds."""
    RESERVED_FOR_TESTING = "RESERVED_FOR_TESTING"


class PeerAdmissionPolicySnapshot(Model):
    revision: int = Field(strict=True, gt=0)
    policy_digest: Digest


class PeerAdmissionPolicyProvider:
    """Host-owned mutable policy view used by production continuity objects."""

    def __init__(self, snapshot):
        if type(snapshot) is not PeerAdmissionPolicySnapshot:
            raise TypeError("EXACT_POLICY_SNAPSHOT_REQUIRED")
        self._lock = threading.Lock()
        self._snapshot = snapshot

    def current_snapshot(self):
        with self._lock:
            return PeerAdmissionPolicySnapshot.model_validate(self._snapshot.model_dump())

    def replace(self, snapshot):
        if type(snapshot) is not PeerAdmissionPolicySnapshot:
            raise TypeError("EXACT_POLICY_SNAPSHOT_REQUIRED")
        with self._lock:
            if snapshot.revision <= self._snapshot.revision:
                raise ValueError("POLICY_REVISION_MUST_ADVANCE")
            self._snapshot = snapshot


class PeerAdmissionPolicyProviderForTesting:
    """Explicit test-only provider; never relabelled as the production provider."""

    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.fail = False

    def current_snapshot(self):
        if self.fail:
            raise RuntimeError("TEST_POLICY_UNAVAILABLE")
        return self.snapshot


def _copy_snapshot(value):
    if type(value) is not PeerAdmissionPolicySnapshot:
        raise AdmissionContinuityError("POLICY_SNAPSHOT_INVALID")
    return PeerAdmissionPolicySnapshot.model_validate(value.model_dump())


def _binding(value):
    raw = value.model_dump()
    return (
        raw["connection_operation_id"],
        raw["pipe_lease_id"],
        raw["process_lease_operation_id"],
        raw["process_pid"],
        raw["process_creation_filetime"],
    )


def _live_lease_binding(lease):
    from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan

    endpoint = lease._endpoint
    connect = [
        op._plan for op in endpoint._operations.values()
        if type(op._plan) is PipeOperationPlan and op._plan.kind == "CONNECT"
    ]
    if len(connect) != 1:
        raise AdmissionContinuityError("EXACT_CONNECTION_BINDING_REQUIRED")
    plan = connect[0]
    return (
        plan.operation_id,
        plan.pipe_lease_id,
        lease._plan.operation_id,
        lease._pin.pid,
        lease._pin.creation_filetime,
    )


class ContinuityUseToken:
    """Single-use gate token.

    operation_id is a host-issued opaque operation-instance correlation label.
    It is not policy authority; ContinuityUseKind is the closed authorization
    namespace and both values must match at consumption.
    """

    __slots__ = (
        "_continuity", "_operation_id", "_kind", "_minted_tick",
        "_use_deadline", "_consumed", "_lock",
    )

    def __init__(self):
        raise TypeError("Use AdmissionContinuity.mint_use_token")

    def __reduce__(self):
        raise TypeError("Continuity use tokens cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise TypeError("Continuity use tokens cannot be serialized")

    def __getstate__(self):
        raise TypeError("Continuity use tokens cannot be serialized")


class _AuthoritativePeerAdmission:
    """Future live positive artifact; intentionally not wired into the evaluator yet."""

    __slots__ = ("_continuity", "_lock")

    def __init__(self):
        raise TypeError("Authoritative admission is evaluator-produced only")

    @classmethod
    def _from_continuity(cls, continuity):
        if type(continuity) is not AdmissionContinuity:
            raise TypeError("EXACT_CONTINUITY_REQUIRED")
        value = object.__new__(cls)
        value._continuity = continuity
        value._lock = threading.Lock()
        return value

    def __reduce__(self):
        raise TypeError("Authoritative admission cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise TypeError("Authoritative admission cannot be serialized")

    def __getstate__(self):
        raise TypeError("Authoritative admission cannot be serialized")


class AdmissionContinuity:
    __slots__ = (
        "_endpoint", "_api", "_clock", "_process_handle", "_pipe",
        "_pid", "_creation_filetime", "_binding", "_provider",
        "_policy_snapshot", "_deadline", "_lock", "_closed", "_invalid",
        "_outstanding",
    )

    def __init__(self):
        raise TypeError("Use OwnedProcessLease.prepare_continuity")

    def __reduce__(self):
        raise TypeError("Admission continuity cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise TypeError("Admission continuity cannot be serialized")

    def __getstate__(self):
        raise TypeError("Admission continuity cannot be serialized")

    def __enter__(self):
        with self._lock:
            if self._closed or self._invalid or self._process_handle is None:
                raise AdmissionContinuityError("CONTINUITY_INVALID")
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def _tick_locked(self):
        value = self._clock()
        if type(value) is not int or not 0 <= value < 2**63:
            self._invalidate_locked("CLOCK_INVALID")
        return value

    def _release_endpoint_claim_locked(self):
        endpoint = self._endpoint
        lock = endpoint._continuity_claim_lock
        with lock:
            if getattr(endpoint, "_continuity_owner", None) is self:
                endpoint._continuity_owner = None
                endpoint._continuity_active = False

    def _release_process_locked(self):
        if self._process_handle is None:
            return
        handle = self._process_handle
        try:
            if self._api.close(handle) is not True:
                raise AdmissionContinuityContainment("CONTINUITY_PROCESS_CLOSE_FAILED")
        except BaseException as exc:
            self._endpoint._fatal = True
            raise AdmissionContinuityContainment("CONTINUITY_PROCESS_CLOSE_FAILED") from exc
        self._process_handle = None

    def _invalidate_locked(self, reason):
        self._invalid = True
        self._outstanding = None
        self._release_endpoint_claim_locked()
        self._release_process_locked()
        raise AdmissionContinuityError(reason)

    def _current_policy_locked(self):
        try:
            value = self._provider.current_snapshot()
        except BaseException:
            self._invalidate_locked("POLICY_UNAVAILABLE")
        try:
            current = _copy_snapshot(value)
        except AdmissionContinuityError:
            self._invalidate_locked("POLICY_SNAPSHOT_INVALID")
        if (
            current.revision != self._policy_snapshot.revision
            or current.policy_digest != self._policy_snapshot.policy_digest
        ):
            self._invalidate_locked("POLICY_CHANGED")

    def _revalidate_locked(self):
        if self._closed or self._invalid or self._process_handle is None:
            raise AdmissionContinuityError("CONTINUITY_INVALID")
        tick = self._tick_locked()
        if tick >= self._deadline:
            self._invalidate_locked("CONTINUITY_EXPIRED")
        endpoint = self._endpoint
        with endpoint._continuity_claim_lock:
            endpoint_valid = (
                getattr(endpoint, "_continuity_owner", None) is self
                and getattr(endpoint, "_continuity_active", False)
                and endpoint._handle == self._pipe
                and not endpoint._closed
                and endpoint._connected
            )
        if not endpoint_valid:
            self._invalidate_locked("ENDPOINT_CHANGED")
        try:
            if self._api.wait_process(self._process_handle, 0) != WAIT_TIMEOUT:
                self._invalidate_locked("PROCESS_NOT_LIVE")
            if self._api.process_id(self._process_handle) != self._pid:
                self._invalidate_locked("PROCESS_ID_CHANGED")
            if self._api.creation_filetime(self._process_handle) != self._creation_filetime:
                self._invalidate_locked("PROCESS_INSTANCE_CHANGED")
            if self._api.client_process_id(self._pipe) != self._pid:
                self._invalidate_locked("PIPE_PID_CHANGED")
        except (AdmissionContinuityError, AdmissionContinuityContainment):
            raise
        except BaseException:
            self._invalidate_locked("NATIVE_REVALIDATION_FAILED")
        self._current_policy_locked()
        return tick

    def mint_use_token(self, *, operation_id, kind, operation_deadline):
        if type(operation_id) is not str or not operation_id:
            raise AdmissionContinuityError("OPERATION_ID_REQUIRED")
        if type(kind) is not ContinuityUseKind:
            raise AdmissionContinuityError("EXACT_USE_KIND_REQUIRED")
        if (
            kind is ContinuityUseKind.RESERVED_FOR_TESTING
            and type(self._provider) is PeerAdmissionPolicyProvider
        ):
            raise AdmissionContinuityError("USE_KIND_NOT_IMPLEMENTED")
        if type(operation_deadline) is not int or not 0 < operation_deadline < 2**63:
            raise AdmissionContinuityError("OPERATION_DEADLINE_REQUIRED")
        with self._lock:
            if self._outstanding is not None and not self._outstanding._consumed:
                raise AdmissionContinuityError("USE_TOKEN_OUTSTANDING")
            tick = self._revalidate_locked()
            deadline = min(tick + MAX_CONTINUITY_USE_TOKEN_MS, self._deadline, operation_deadline)
            if tick >= deadline:
                self._invalidate_locked("USE_TOKEN_EXPIRED")
            token = object.__new__(ContinuityUseToken)
            token._continuity = self
            token._operation_id = operation_id
            token._kind = kind
            token._minted_tick = tick
            token._use_deadline = deadline
            token._consumed = False
            token._lock = threading.Lock()
            self._outstanding = token
            return token

    def consume_use_token(self, token, *, operation_id, kind):
        """Consume one token after immediate revalidation.

        Any revalidation failure terminally invalidates continuity, clears the
        outstanding-token slot, and therefore burns this token; retry requires
        a new admission/continuity path rather than reusing the minted token.
        """
        with self._lock:
            if type(token) is not ContinuityUseToken or token is not self._outstanding:
                raise AdmissionContinuityError("USE_TOKEN_MISMATCH")

            # Revalidate immediately before the privileged operation starts.
            # Mint-time validation bounds the token window; consume-time
            # validation closes liveness/policy drift inside that window.
            tick = self._revalidate_locked()

            with token._lock:
                if token._consumed:
                    raise AdmissionContinuityError("USE_TOKEN_CONSUMED")
                token._consumed = True
                self._outstanding = None
                if (
                    token._continuity is not self
                    or token._operation_id != operation_id
                    or token._kind is not kind
                    or tick >= token._use_deadline
                    or self._closed
                    or self._invalid
                ):
                    raise AdmissionContinuityError("USE_TOKEN_INVALID")
                return True

    def close(self):
        with self._lock:
            if self._closed:
                return False
            self._closed = True
            if self._outstanding is not None:
                with self._outstanding._lock:
                    self._outstanding._consumed = True
                self._outstanding = None
            self._release_endpoint_claim_locked()
            self._release_process_locked()
            return True


def prepare_continuity_from_live_lease(
    lease, *, pipe_context, provider, continuity_deadline
):
    """Prepare independent continuity while the original process lease is live."""
    from tnc.provenance.windows_pipe_process_lease import (
        OwnedProcessLease,
        ProcessAPIForTesting,
    )

    if type(lease) is not OwnedProcessLease:
        raise AdmissionContinuityError("OWNED_PROCESS_LEASE_REQUIRED")
    lease._owner_check()
    if lease._fatal or lease._consumed or lease._handle is None:
        raise AdmissionContinuityError("LIVE_PROCESS_LEASE_REQUIRED")
    endpoint = lease._endpoint
    endpoint._guard()
    if endpoint._handle != lease._pipe or not endpoint._connected or endpoint._active is not None:
        raise AdmissionContinuityError("CONNECTED_IDLE_ENDPOINT_REQUIRED")
    if getattr(lease, "_continuity_prepared", False):
        raise AdmissionContinuityError("CONTINUITY_ALREADY_PREPARED")
    if type(continuity_deadline) is not int or not 0 < continuity_deadline < 2**63:
        raise AdmissionContinuityError("CONTINUITY_DEADLINE_REQUIRED")

    try:
        raw = pipe_context.model_dump_json()
        copied = _PIPE_CONTEXT.validate_json(raw)
    except BaseException as exc:
        raise AdmissionContinuityError("EXACT_PIPE_CONTEXT_REQUIRED") from exc
    if type(copied) is not type(pipe_context):
        raise AdmissionContinuityError("EXACT_PIPE_CONTEXT_REQUIRED")
    if _binding(copied) != _live_lease_binding(lease):
        raise AdmissionContinuityError("PIPE_CONTEXT_BINDING_MISMATCH")

    if type(provider) not in {
        PeerAdmissionPolicyProvider,
        PeerAdmissionPolicyProviderForTesting,
    }:
        raise AdmissionContinuityError("EXACT_POLICY_PROVIDER_REQUIRED")
    try:
        policy_snapshot = _copy_snapshot(provider.current_snapshot())
    except BaseException as exc:
        raise AdmissionContinuityError("POLICY_UNAVAILABLE") from exc

    tick = lease._clock()
    if type(tick) is not int or not 0 <= tick < continuity_deadline:
        raise AdmissionContinuityError("CONTINUITY_DEADLINE_EXPIRED")

    api = lease._api
    if lease._source == "NATIVE_PROCESS_API":
        if type(api) is not NativeProcessAPI:
            raise AdmissionContinuityError("EXACT_NATIVE_PROCESS_API_REQUIRED")
    elif not isinstance(api, ProcessAPIForTesting):
        raise AdmissionContinuityError("EXACT_TEST_PROCESS_API_REQUIRED")

    handle = None
    claimed = False
    try:
        handle = api.open_process(lease._pin.pid, PROCESS_LEASE_RIGHTS, False)
        if type(handle) is not int or handle <= 0 or handle == lease._handle:
            raise AdmissionContinuityError("INDEPENDENT_PROCESS_HANDLE_REQUIRED")
        if api.wait_process(handle, 0) != WAIT_TIMEOUT:
            raise AdmissionContinuityError("PROCESS_NOT_LIVE")
        if api.process_id(handle) != lease._pin.pid:
            raise AdmissionContinuityError("PROCESS_ID_CHANGED")
        if api.creation_filetime(handle) != lease._pin.creation_filetime:
            raise AdmissionContinuityError("PROCESS_INSTANCE_CHANGED")
        if api.client_process_id(lease._pipe) != lease._pin.pid:
            raise AdmissionContinuityError("PIPE_PID_CHANGED")
        lease._check()

        value = object.__new__(AdmissionContinuity)
        value._endpoint = endpoint
        value._api = api
        value._clock = lease._clock
        value._process_handle = handle
        value._pipe = lease._pipe
        value._pid = lease._pin.pid
        value._creation_filetime = lease._pin.creation_filetime
        value._binding = _binding(copied)
        value._provider = provider
        value._policy_snapshot = policy_snapshot
        value._deadline = continuity_deadline
        value._lock = threading.Lock()
        value._closed = False
        value._invalid = False
        value._outstanding = None

        with endpoint._continuity_claim_lock:
            if getattr(endpoint, "_continuity_active", False):
                raise AdmissionContinuityError("CONTINUITY_ENDPOINT_ALREADY_CLAIMED")
            endpoint._continuity_active = True
            endpoint._continuity_owner = value
            claimed = True
        lease._continuity_prepared = True
        handle = None
        return value
    except AdmissionContinuityContainment:
        raise
    except BaseException as exc:
        if claimed:
            with endpoint._continuity_claim_lock:
                if getattr(endpoint, "_continuity_owner", None) is value:
                    endpoint._continuity_owner = None
                    endpoint._continuity_active = False
        if handle is not None:
            try:
                if api.close(handle) is not True:
                    endpoint._fatal = True
                    raise AdmissionContinuityContainment(
                        "CONTINUITY_PROCESS_CLOSE_FAILED"
                    ) from exc
            except AdmissionContinuityContainment:
                raise
            except BaseException as close_exc:
                endpoint._fatal = True
                raise AdmissionContinuityContainment(
                    "CONTINUITY_PROCESS_CLOSE_FAILED"
                ) from close_exc
        if isinstance(exc, AdmissionContinuityError):
            raise
        if isinstance(exc, NativeProcessAPIError):
            raise AdmissionContinuityError("NATIVE_CONTINUITY_UNAVAILABLE") from None
        raise AdmissionContinuityError("CONTINUITY_PREPARATION_FAILED") from None


__all__ = [
    "MAX_CONTINUITY_USE_TOKEN_MS",
    "AdmissionContinuity",
    "AdmissionContinuityContainment",
    "AdmissionContinuityError",
    "ContinuityUseKind",
    "ContinuityUseToken",
    "PeerAdmissionPolicyProvider",
    "PeerAdmissionPolicyProviderForTesting",
    "PeerAdmissionPolicySnapshot",
]
