"""Live evaluation-to-use continuity for native Windows peer admission.

No ADMITTED evaluator state is introduced here. This module owns transient
continuity only; frozen audit/evidence records remain non-authoritative.
"""
import threading
from enum import Enum

from pydantic import Field, TypeAdapter

from tnc.provenance.authorization_models import Digest, Identifier, Model
from tnc.provenance.windows_peer_admission_evidence import PipePeerAdmissionEvidence
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
        raw["capture_ordinal"],
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
        1,
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
    """Exact live authority; construction is evaluator-internal only."""

    __slots__ = (
        "_continuity", "_lock", "_allowed_kinds", "_closed",
        "_contained", "_containment_reason",
    )

    def __init__(self):
        raise TypeError("Authoritative admission is evaluator-produced only")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("Authoritative admission cannot be subclassed")

    def __reduce__(self):
        raise TypeError("Authoritative admission cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise TypeError("Authoritative admission cannot be serialized")

    def __getstate__(self):
        raise TypeError("Authoritative admission cannot be serialized")

    def __copy__(self):
        raise TypeError("Authoritative admission cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Authoritative admission cannot be copied")

    def _raise_containment_locked(self):
        if self._contained:
            raise self._containment_reason

    def _evaluation_binding_available(self, binding):
        with self._lock:
            self._raise_containment_locked()
            return self._process_handle is not None and self._binding == binding

    def _evaluation_policy_matches(self, snapshot):
        if type(snapshot) is not PeerAdmissionPolicySnapshot:
            return False
        with self._lock:
            self._raise_containment_locked()
            return (
                self._policy_snapshot.revision == snapshot.revision
                and self._policy_snapshot.policy_digest == snapshot.policy_digest
            )

    def _open_at_adoption_start(self):
        with self._lock:
            self._raise_containment_locked()
            return (
                not self._closed
                and not self._invalid
                and self._process_handle is not None
                and self._adopted_by is None
            )

    def _adoption_preflight(self):
        with self._lock:
            self._raise_containment_locked()
            if (
                self._closed
                or self._invalid
                or self._process_handle is None
                or self._adopted_by is not None
            ):
                raise AdmissionContinuityError("CONTINUITY_INVALID")
            self._revalidate_locked()
            return True

    def _adopt(self, authority):
        with self._lock:
            self._raise_containment_locked()
            if type(authority) is not _AuthoritativePeerAdmission:
                raise AdmissionContinuityError("EXACT_AUTHORITY_REQUIRED")
            if authority._continuity is not self:
                raise AdmissionContinuityError("AUTHORITY_CONTINUITY_MISMATCH")
            if (
                self._closed
                or self._invalid
                or self._process_handle is None
                or self._adopted_by is not None
            ):
                raise AdmissionContinuityError("CONTINUITY_INVALID")
            self._adopted_by = authority
            return authority

    def _mint_use_token_locked(self, *, operation_id, kind, operation_deadline):
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

    def mint_use_token(self, *, operation_id, kind, operation_deadline):
        with self._lock:
            self._raise_containment_locked()
            if self._adopted_by is not None:
                raise AdmissionContinuityError("CONTINUITY_ADOPTED")
            return self._mint_use_token_locked(
                operation_id=operation_id,
                kind=kind,
                operation_deadline=operation_deadline,
            )

    def _mint_use_token_from_authority(
        self, authority, *, operation_id, kind, operation_deadline
    ):
        with self._lock:
            self._raise_containment_locked()
            if self._adopted_by is not authority:
                raise AdmissionContinuityError("AUTHORITY_OWNERSHIP_REQUIRED")
            if kind not in authority._allowed_kinds:
                raise AdmissionContinuityError("USE_KIND_NOT_ALLOWED")
            return self._mint_use_token_locked(
                operation_id=operation_id,
                kind=kind,
                operation_deadline=operation_deadline,
            )

    def _consume_use_token_locked(self, token, *, operation_id, kind):
        if type(token) is not ContinuityUseToken or token is not self._outstanding:
            raise AdmissionContinuityError("USE_TOKEN_MISMATCH")

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

    def consume_use_token(self, token, *, operation_id, kind):
        with self._lock:
            self._raise_containment_locked()
            if self._adopted_by is not None:
                raise AdmissionContinuityError("CONTINUITY_ADOPTED")
            return self._consume_use_token_locked(
                token,
                operation_id=operation_id,
                kind=kind,
            )

    def _consume_use_token_from_authority(self, authority, token, *, operation_id, kind):
        with self._lock:
            self._raise_containment_locked()
            if self._adopted_by is not authority:
                raise AdmissionContinuityError("AUTHORITY_OWNERSHIP_REQUIRED")
            if kind not in authority._allowed_kinds:
                raise AdmissionContinuityError("USE_KIND_NOT_ALLOWED")
            return self._consume_use_token_locked(
                token,
                operation_id=operation_id,
                kind=kind,
            )

    def _close_locked(self):
        self._burn_outstanding_locked()
        self._release_endpoint_claim_locked()
        self._release_process_locked()
        self._closed = True
        return True

    def close(self):
        with self._lock:
            self._raise_containment_locked()
            if self._closed:
                return False
            if self._adopted_by is not None:
                raise AdmissionContinuityError("CONTINUITY_ADOPTED")
            return self._close_locked()

    def _close_from_authority(self, authority):
        with self._lock:
            self._raise_containment_locked()
            if self._closed:
                return False
            if self._adopted_by is not authority:
                raise AdmissionContinuityError("AUTHORITY_OWNERSHIP_REQUIRED")
            return self._close_locked()


def prepare_continuity_from_live_lease(def prepare_continuity_from_live_lease(
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
        value._contained = False
        value._containment_reason = None
        value._adopted_by = None
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
