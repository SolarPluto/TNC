"""Native Windows peer-admission evaluator and live authority handoff."""
import json
import threading
from typing import Literal

from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Digest, Identifier, Model, canonical_bytes
from tnc.provenance.windows_peer_admission_continuity import (
    AdmissionContinuity,
    AdmissionContinuityContainment,
    AdmissionContinuityError,
    ContinuityUseKind,
    PeerAdmissionPolicySnapshot,
    _AuthoritativePeerAdmission,
)
from tnc.provenance.windows_peer_admission_evidence import PeerAdmissionEvidence
from tnc.provenance.windows_pipe_auth_bridge import (
    NATIVE_PEER_AUDIT_RESULT_PAIRS,
    NativePeerAuditResult,
)
from tnc.provenance.windows_pipe_process_lease import ProcessLeaseAudit


MAX_RECORD = 65536

TerminalPhase = Literal[
    "1",
    "2.1", "2.2", "2.3",
    "3.1", "3.2", "3.3",
    "4.1a", "4.1b", "4.2",
    "5.1a", "5.1b", "5.2",
    "6.1", "6.2", "6.3",
    "7.1",
]
AxisDisposition = Literal[
    "APPCONTAINER",
    "NON_APPCONTAINER",
    "CLASSIFICATION_CONFLICT",
    "UNAVAILABLE",
]

LEGAL_RESULT_PAIRS = frozenset({
    ("DENIED", "DESCRIPTOR_CHANGED"),
    ("DENIED", "DESCRIPTOR_MISMATCH"),
    ("DENIED", "ENDPOINT_CORRELATION_MISMATCH"),
    ("DENIED", "INTEGRITY_LEVEL_DENIED"),
    ("DENIED", "PIPE_CONTEXT_APP_CONTAINER_DENIED"),
    ("DENIED", "PROCESS_CORRELATION_MISMATCH"),
    ("DENIED", "PROCESS_LEASE_NOT_CORRELATED"),
    ("DENIED", "PROCESS_LIFETIME_MISMATCH"),
    ("DENIED", "PROCESS_PRIMARY_APP_CONTAINER_DENIED"),
    ("DENIED", "READ_BINDING_MISMATCH"),
    ("DENIED", "RESTRICTED_CONTEXT_DENIED"),
    ("DENIED", "SCOPE_MISMATCH"),
    ("DENIED", "TIME_MISMATCH"),
    ("DENIED", "TOKEN_IDENTITY_MISMATCH"),
    ("DENIED", "TOKEN_PROFILE_DENIED"),
    ("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE"),
    ("INDETERMINATE", "AUTHORITY_CONSTRUCTION_FAILED"),
    ("INDETERMINATE", "INVALID_ADMISSION_EVIDENCE"),
    ("INDETERMINATE", "INVALID_RECORD"),
    ("INDETERMINATE", "NATIVE_CAPTURE_REQUIRED"),
    ("INDETERMINATE", "NATIVE_PROCESS_LEASE_REQUIRED"),
    ("INDETERMINATE", "PEER_AUDIT_CONTRACT_VIOLATION"),
    ("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE"),
    ("INDETERMINATE", "PIPE_CONTEXT_CLASSIFICATION_CONFLICT"),
    ("INDETERMINATE", "POLICY_BINDING_UNAVAILABLE"),
    ("INDETERMINATE", "PROCESS_LEASE_CONTRACT_VIOLATION"),
    ("INDETERMINATE", "PROCESS_PRIMARY_CLASSIFICATION_CONFLICT"),
    ("ADMITTED", "ADMISSION_REQUIREMENTS_MET"),
})

_AUTHORITY_BRIDGE_PAIRS = frozenset(
    pair for pair in NATIVE_PEER_AUDIT_RESULT_PAIRS
    if pair != ("VIOLATIONS", "APP_CONTAINER_DENIED")
)
_V1_ALLOWED_USE_KINDS = frozenset()
_AUTHORITY_CONSTRUCTION_UNAVAILABLE_REASONS = frozenset({
    "CONTINUITY_UNAVAILABLE_AT_ADOPTION",
})
_STATE_SEAL = object()

_PROJECTION_FIELDS = (
    "pipe_context_classification",
    "process_primary_classification",
    "connection_operation_id",
    "pipe_lease_id",
    "process_lease_operation_id",
    "process_pid",
    "process_creation_filetime",
    "capture_ordinal",
    "evaluated_policy_revision",
    "evaluated_policy_digest",
)


class AdmissionEvaluatorInvariantError(RuntimeError):
    """Evaluator mapping/construction bug; never an operational peer outcome."""


class AuthorityConstructionUnavailable(RuntimeError):
    """Closed-vocabulary recoverable adoption refusal.

    V1 permits only CONTINUITY_UNAVAILABLE_AT_ADOPTION. Raising this certifies that
    no authority exists and continuity is either still valid/IDLE/orchestrator-owned
    or has been completely and successfully closed. Cleanup uncertainty must raise
    containment instead.
    """

    def __init__(self, reason):
        if reason not in _AUTHORITY_CONSTRUCTION_UNAVAILABLE_REASONS:
            raise ValueError("UNKNOWN_AUTHORITY_CONSTRUCTION_UNAVAILABLE_REASON")
        self.reason = reason
        super().__init__(reason)


class AdmissionHandoffFailure(BaseExceptionGroup):
    """Audit/tuple handoff failed and authority cleanup also failed."""

    def __new__(cls, exceptions):
        return super().__new__(
            cls,
            "admission handoff and authority cleanup both failed",
            exceptions,
        )

    def derive(self, exceptions):
        return type(self)(exceptions)


class PeerAdmissionAuditRecord(Model):
    profile: Literal["tnc-native-peer-admission-audit-v1"] = (
        "tnc-native-peer-admission-audit-v1"
    )
    status: Literal["DENIED", "INDETERMINATE", "ADMITTED"]
    reason: Identifier
    terminal_phase: TerminalPhase
    admission_granted: Literal[False] = False
    authorization_granted: Literal[False] = False
    grants_evaluated: Literal[False] = False
    signing_evaluated: Literal[False] = False
    pipe_context_classification: AxisDisposition | None = None
    process_primary_classification: AxisDisposition | None = None
    connection_operation_id: Identifier | None = None
    pipe_lease_id: Identifier | None = None
    process_lease_operation_id: Identifier | None = None
    process_pid: int | None = Field(default=None, strict=True, ge=1, le=2**32 - 1)
    process_creation_filetime: int | None = Field(
        default=None, strict=True, ge=1, le=2**64 - 1
    )
    capture_ordinal: Literal[1] | None = None
    evaluated_policy_revision: int | None = Field(default=None, strict=True, gt=0)
    evaluated_policy_digest: Digest | None = None

    @model_validator(mode="after")
    def terminal_contract(self):
        pair = (self.status, self.reason)
        if pair not in LEGAL_RESULT_PAIRS:
            raise ValueError(
                f"illegal admission result pair {pair!r}; "
                f"legal pairs={sorted(LEGAL_RESULT_PAIRS)!r}"
            )
        projection = tuple(getattr(self, name) for name in _PROJECTION_FIELDS)
        if self.terminal_phase == "1":
            if pair != ("INDETERMINATE", "INVALID_ADMISSION_EVIDENCE"):
                raise ValueError("PHASE_1_TERMINAL_REQUIRED")
            if any(value is not None for value in projection):
                raise ValueError("PHASE_1_PROJECTION_MUST_BE_EMPTY")
        elif any(value is None for value in projection):
            raise ValueError("VALIDATED_PROJECTION_REQUIRED")

        if self.status == "ADMITTED" and self.terminal_phase != "7.1":
            raise ValueError("ADMITTED_REQUIRES_PHASE_7_1")
        if self.terminal_phase == "7.1" and pair not in {
            ("ADMITTED", "ADMISSION_REQUIREMENTS_MET"),
            ("INDETERMINATE", "AUTHORITY_CONSTRUCTION_FAILED"),
        }:
            raise ValueError("PHASE_7_1_PAIR_INVALID")
        return self


class _ValidatedAdmissionState:
    __slots__ = ("_projection", "_continuity", "_evaluated_policy", "_seal")

    def __init__(self):
        raise TypeError("Evaluator-produced only")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("Validated admission state cannot be subclassed")

    def __reduce__(self):
        raise TypeError("Validated admission state cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise TypeError("Validated admission state cannot be serialized")

    def __getstate__(self):
        raise TypeError("Validated admission state cannot be serialized")

    def __copy__(self):
        raise TypeError("Validated admission state cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Validated admission state cannot be copied")


def _record_bound(value):
    raw = canonical_bytes(value)
    if len(raw) > MAX_RECORD:
        raise ValueError("RECORD_BOUND")
    return raw


def _validated_copy(kind, value):
    if type(value) is not kind:
        raise ValueError("EXACT_RECORD_REQUIRED")
    raw = _record_bound(value)
    copied = kind.model_validate_json(raw)
    if type(copied) is not kind:
        raise ValueError("EXACT_RECORD_REQUIRED")
    return copied


def _exact_contract_record(kind, value):
    """Snapshot exact record shape/bound without re-running phase-specific semantics.

    ProcessLeaseAudit and NativePeerAuditResult deliberately carry contract
    invariants that belong to phases 2.3 and 3.1/3.2. Revalidating those Literals
    here would collapse those phases into phase 1 and make their terminals
    unreachable. Exact concrete type, complete field shape, JSON-serializability,
    and the evaluator record bound are phase-1 concerns.
    """
    if type(value) is not kind:
        raise ValueError("EXACT_RECORD_REQUIRED")
    try:
        payload = value.model_dump(mode="json", warnings=False)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("EXACT_RECORD_REQUIRED") from exc
    if set(payload) != set(kind.model_fields):
        raise ValueError("EXACT_RECORD_REQUIRED")
    try:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("EXACT_RECORD_REQUIRED") from exc
    if len(raw) > MAX_RECORD:
        raise ValueError("RECORD_BOUND")
    return value


def _axis_disposition(axis):
    if axis.status == "CAPTURED_APPCONTAINER":
        return "APPCONTAINER"
    if axis.status == "CAPTURED_NON_APPCONTAINER":
        return "NON_APPCONTAINER"
    if axis.status == "CAPTURED_CLASSIFICATION_CONFLICT":
        return "CLASSIFICATION_CONFLICT"
    if axis.status in {"CAPTURED_CLASSIFICATION_UNAVAILABLE", "CAPTURE_UNAVAILABLE"}:
        return "UNAVAILABLE"
    raise AdmissionEvaluatorInvariantError(f"unhandled evidence status: {axis.status!r}")


def _capture_projection(peer_evidence, evaluated_policy):
    pipe = peer_evidence.pipe_context
    return (
        _axis_disposition(pipe),
        _axis_disposition(peer_evidence.process_primary),
        pipe.connection_operation_id,
        pipe.pipe_lease_id,
        pipe.process_lease_operation_id,
        pipe.process_pid,
        pipe.process_creation_filetime,
        pipe.capture_ordinal,
        evaluated_policy.revision,
        evaluated_policy.policy_digest,
    )


def _projection_kwargs(projection):
    if projection is None:
        return {name: None for name in _PROJECTION_FIELDS}
    return dict(zip(_PROJECTION_FIELDS, projection, strict=True))


def _build_audit(projection, *, status, reason, terminal_phase):
    try:
        return PeerAdmissionAuditRecord(
            status=status,
            reason=reason,
            terminal_phase=terminal_phase,
            **_projection_kwargs(projection),
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise AdmissionEvaluatorInvariantError(
            f"illegal evaluator audit {(status, reason, terminal_phase)!r}"
        ) from exc


def _make_validated_admission_state(projection, continuity, evaluated_policy):
    """Sole supported construction site for the private phase-7 state."""
    value = object.__new__(_ValidatedAdmissionState)
    value._projection = projection
    value._continuity = continuity
    value._evaluated_policy = evaluated_policy
    value._seal = _STATE_SEAL
    return value


def _require_validated_admission_state(state):
    if (
        type(state) is not _ValidatedAdmissionState
        or getattr(state, "_seal", None) is not _STATE_SEAL
    ):
        raise AdmissionEvaluatorInvariantError("VALIDATED_ADMISSION_STATE_REQUIRED")
    return state


def _build_phase_7_audit(state, *, status, reason):
    state = _require_validated_admission_state(state)
    return _build_audit(
        state._projection,
        status=status,
        reason=reason,
        terminal_phase="7.1",
    )


def _adopt_and_build_authority_from_state(state):
    state = _require_validated_admission_state(state)
    continuity = state._continuity
    if type(continuity) is not AdmissionContinuity:
        raise AdmissionEvaluatorInvariantError("EXACT_CONTINUITY_REQUIRED")

    authority = object.__new__(_AuthoritativePeerAdmission)
    authority._continuity = continuity
    authority._lock = threading.Lock()
    authority._allowed_kinds = _V1_ALLOWED_USE_KINDS
    authority._closed = False
    authority._contained = False
    authority._containment_reason = None

    try:
        return continuity._adopt(authority)
    except AdmissionContinuityError as exc:
        # Every operational adoption refusal occurs before the single adoption
        # assignment. Normalize it only after proving cleanup/ownership is known.
        try:
            continuity.close()
        except AdmissionContinuityContainment:
            raise
        except AdmissionContinuityError as cleanup_exc:
            raise AdmissionEvaluatorInvariantError(
                "adoption refusal left ambiguous continuity ownership"
            ) from cleanup_exc
        raise AuthorityConstructionUnavailable(
            "CONTINUITY_UNAVAILABLE_AT_ADOPTION"
        ) from exc


def evaluate_native_peer_admission(
    *,
    lease,
    peer,
    peer_evidence,
    continuity,
    evaluated_policy,
):
    """Evaluate phases 1-7 and return durable audit plus optional live authority."""

    def invalid_input():
        return (
            _build_audit(
                None,
                status="INDETERMINATE",
                reason="INVALID_ADMISSION_EVIDENCE",
                terminal_phase="1",
            ),
            None,
        )

    try:
        lease = _exact_contract_record(ProcessLeaseAudit, lease)
        peer = _exact_contract_record(NativePeerAuditResult, peer)
        peer_evidence = _validated_copy(PeerAdmissionEvidence, peer_evidence)
        if type(continuity) is not AdmissionContinuity:
            raise ValueError("EXACT_CONTINUITY_REQUIRED")
        evaluated_policy = _validated_copy(
            PeerAdmissionPolicySnapshot,
            evaluated_policy,
        )
    except (ValueError, TypeError, AttributeError):
        return invalid_input()

    projection = _capture_projection(peer_evidence, evaluated_policy)

    def terminal(status, reason, phase):
        return (
            _build_audit(
                projection,
                status=status,
                reason=reason,
                terminal_phase=phase,
            ),
            None,
        )

    # Phase 2: process lease.
    if lease.source != "NATIVE_PROCESS_API":
        return terminal("INDETERMINATE", "NATIVE_PROCESS_LEASE_REQUIRED", "2.1")
    if (lease.status, lease.reason) != ("CORRELATED", "AUDIT_MATCHED"):
        return terminal("DENIED", "PROCESS_LEASE_NOT_CORRELATED", "2.2")
    if not lease.audit_only or lease.authorization_granted:
        return terminal("INDETERMINATE", "PROCESS_LEASE_CONTRACT_VIOLATION", "2.3")

    # Phase 3: existing peer audit and its closed vocabulary.
    if peer.authorization_granted or peer.grants_evaluated or not peer.audit_only:
        return terminal("INDETERMINATE", "PEER_AUDIT_CONTRACT_VIOLATION", "3.1")
    bridge_pair = (peer.status, peer.reason)
    if bridge_pair not in _AUTHORITY_BRIDGE_PAIRS:
        raise AdmissionEvaluatorInvariantError(
            f"bridge result outside declared authority-compatible set: {bridge_pair!r}"
        )
    if peer.status == "VIOLATIONS":
        return terminal("DENIED", peer.reason, "3.2")
    if peer.reason == "CAPTURE_UNAVAILABLE":
        return terminal("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE", "3.3")
    if peer.reason != "APP_CONTAINER_EXCLUSION_UNPROVEN":
        return terminal("INDETERMINATE", peer.reason, "3.3")

    # Phase 4: exact pipe-client context.
    pipe = peer_evidence.pipe_context
    if pipe.status in {"CAPTURED_CLASSIFICATION_UNAVAILABLE", "CAPTURE_UNAVAILABLE"}:
        return terminal("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE", "4.1a")
    if pipe.status == "CAPTURED_CLASSIFICATION_CONFLICT":
        return terminal(
            "INDETERMINATE",
            "PIPE_CONTEXT_CLASSIFICATION_CONFLICT",
            "4.1b",
        )
    if pipe.status == "CAPTURED_APPCONTAINER":
        return terminal("DENIED", "PIPE_CONTEXT_APP_CONTAINER_DENIED", "4.2")
    if pipe.status != "CAPTURED_NON_APPCONTAINER":
        raise AdmissionEvaluatorInvariantError(f"unhandled pipe status: {pipe.status!r}")

    # Phase 5: process PRIMARY context.
    process = peer_evidence.process_primary
    if process.status == "CAPTURED_CLASSIFICATION_UNAVAILABLE":
        return terminal("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE", "5.1a")
    if process.status == "CAPTURED_CLASSIFICATION_CONFLICT":
        return terminal(
            "INDETERMINATE",
            "PROCESS_PRIMARY_CLASSIFICATION_CONFLICT",
            "5.1b",
        )
    if process.status == "CAPTURED_APPCONTAINER":
        return terminal("DENIED", "PROCESS_PRIMARY_APP_CONTAINER_DENIED", "5.2")
    if process.status != "CAPTURED_NON_APPCONTAINER":
        raise AdmissionEvaluatorInvariantError(
            f"unhandled process-primary status: {process.status!r}"
        )

    binding = projection[2:8]

    # Phase 6: continuity binding, policy, and open-at-adoption-start guard.
    if not continuity._evaluation_binding_available(binding):
        return terminal("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE", "6.1")
    if not continuity._evaluation_policy_matches(evaluated_policy):
        return terminal("INDETERMINATE", "POLICY_BINDING_UNAVAILABLE", "6.2")
    if not continuity._open_at_adoption_start():
        return terminal("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE", "6.3")

    state = _make_validated_admission_state(
        projection,
        continuity,
        evaluated_policy,
    )

    try:
        authority = _adopt_and_build_authority_from_state(state)
    except AuthorityConstructionUnavailable:
        # No authority exists on this path, so audit bugs propagate directly.
        return (
            _build_phase_7_audit(
                state,
                status="INDETERMINATE",
                reason="AUTHORITY_CONSTRUCTION_FAILED",
            ),
            None,
        )

    try:
        audit = _build_phase_7_audit(
            state,
            status="ADMITTED",
            reason="ADMISSION_REQUIREMENTS_MET",
        )
        outcome = (audit, authority)
    except BaseException as handoff_exc:
        try:
            authority.close()
        except BaseException as close_exc:
            # Both failures are explicit group members; from None only suppresses
            # the redundant active close-exception context in traceback display.
            raise AdmissionHandoffFailure([handoff_exc, close_exc]) from None
        raise

    return outcome


__all__ = [
    "AdmissionEvaluatorInvariantError",
    "AdmissionHandoffFailure",
    "AuthorityConstructionUnavailable",
    "LEGAL_RESULT_PAIRS",
    "PeerAdmissionAuditRecord",
    "TerminalPhase",
    "evaluate_native_peer_admission",
]
