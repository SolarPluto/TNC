"""Temporary contract-table evaluator for native peer-admission phases 1-6.

Delete this module when the real evaluator satisfies the same permanent contract tests.
It intentionally performs no native acquisition and never constructs authority.
"""
from dataclasses import dataclass
from inspect import Signature, signature

from tnc.provenance.windows_peer_admission_gate import AdmissionEvaluatorInvariantError
from tnc.provenance.windows_pipe_auth_bridge import NATIVE_PEER_AUDIT_RESULT_PAIRS

_FUTURE_BRIDGE_PAIRS = frozenset(
    pair for pair in NATIVE_PEER_AUDIT_RESULT_PAIRS
    if pair != ("VIOLATIONS", "APP_CONTAINER_DENIED")
)


@dataclass(frozen=True)
class StubLeaseAudit:
    source: str = "NATIVE_PROCESS_API"
    status: str = "CORRELATED"
    reason: str = "AUDIT_MATCHED"
    audit_only: bool = True
    authorization_granted: bool = False


@dataclass(frozen=True)
class StubPeerAudit:
    status: str = "INDETERMINATE"
    reason: str = "APP_CONTAINER_EXCLUSION_UNPROVEN"
    audit_only: bool = True
    authorization_granted: bool = False
    grants_evaluated: bool = False


@dataclass(frozen=True)
class StubDualAppContainerEvidence:
    pipe: str = "NON_APPCONTAINER"
    process_primary: str = "NON_APPCONTAINER"


@dataclass(frozen=True)
class StubPolicySnapshot:
    revision: int = 1
    policy_digest: str = "policy-digest"


@dataclass(frozen=True)
class StubContinuity:
    available: bool = True
    exact_binding: bool = True
    policy_snapshot: StubPolicySnapshot = StubPolicySnapshot()
    open_at_adoption_start: bool = True


@dataclass(frozen=True)
class StubAuditRecord:
    status: str
    reason: str
    admission_granted: bool = False
    authorization_granted: bool = False
    grants_evaluated: bool = False
    signing_evaluated: bool = False


class StubReachedPhase7(RuntimeError):
    """The temporary branch stub deliberately stops before authority construction."""


def evaluate_native_peer_admission(
    *,
    lease,
    peer,
    peer_evidence,
    continuity,
    evaluated_policy,
):
    """Exercise the normative phase table through phase 6 only."""
    def terminal(status, reason):
        return StubAuditRecord(status=status, reason=reason), None

    if (
        type(lease) is not StubLeaseAudit
        or type(peer) is not StubPeerAudit
        or type(peer_evidence) is not StubDualAppContainerEvidence
        or type(continuity) is not StubContinuity
        or type(evaluated_policy) is not StubPolicySnapshot
    ):
        return terminal("INDETERMINATE", "INVALID_ADMISSION_EVIDENCE")

    # Phase 2: process lease.
    if lease.source != "NATIVE_PROCESS_API":
        return terminal("INDETERMINATE", "NATIVE_PROCESS_LEASE_REQUIRED")
    if (lease.status, lease.reason) != ("CORRELATED", "AUDIT_MATCHED"):
        return terminal("DENIED", "PROCESS_LEASE_NOT_CORRELATED")
    if not lease.audit_only or lease.authorization_granted:
        return terminal("INDETERMINATE", "PROCESS_LEASE_CONTRACT_VIOLATION")

    # Phase 3: existing peer audit.
    if peer.authorization_granted or peer.grants_evaluated or not peer.audit_only:
        return terminal("INDETERMINATE", "PEER_AUDIT_CONTRACT_VIOLATION")

    pair = (peer.status, peer.reason)
    if pair not in _FUTURE_BRIDGE_PAIRS:
        raise AdmissionEvaluatorInvariantError(
            f"bridge result outside declared authority-compatible set: {pair!r}"
        )
    if peer.status == "VIOLATIONS":
        return terminal("DENIED", peer.reason)
    if peer.reason == "CAPTURE_UNAVAILABLE":
        return terminal("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")
    if peer.reason != "APP_CONTAINER_EXCLUSION_UNPROVEN":
        return terminal("INDETERMINATE", peer.reason)

    # Phase 4: exact pipe-client context.
    if peer_evidence.pipe == "UNAVAILABLE":
        return terminal("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")
    if peer_evidence.pipe == "CONFLICT":
        return terminal("INDETERMINATE", "PIPE_CONTEXT_CLASSIFICATION_CONFLICT")
    if peer_evidence.pipe == "APPCONTAINER":
        return terminal("DENIED", "PIPE_CONTEXT_APP_CONTAINER_DENIED")
    if peer_evidence.pipe != "NON_APPCONTAINER":
        return terminal("INDETERMINATE", "INVALID_ADMISSION_EVIDENCE")

    # Phase 5: correlated process PRIMARY token.
    if peer_evidence.process_primary == "UNAVAILABLE":
        return terminal("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")
    if peer_evidence.process_primary == "CONFLICT":
        return terminal("INDETERMINATE", "PROCESS_PRIMARY_CLASSIFICATION_CONFLICT")
    if peer_evidence.process_primary == "APPCONTAINER":
        return terminal("DENIED", "PROCESS_PRIMARY_APP_CONTAINER_DENIED")
    if peer_evidence.process_primary != "NON_APPCONTAINER":
        return terminal("INDETERMINATE", "INVALID_ADMISSION_EVIDENCE")

    # Phase 6: continuity and evaluated-policy binding.
    if not continuity.available or not continuity.exact_binding:
        return terminal("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE")
    if continuity.policy_snapshot != evaluated_policy:
        return terminal("INDETERMINATE", "POLICY_BINDING_UNAVAILABLE")
    if not continuity.open_at_adoption_start:
        return terminal("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE")

    raise StubReachedPhase7("PHASE_7_REQUIRES_REAL_EVALUATOR")


def pinned_signature() -> Signature:
    return signature(evaluate_native_peer_admission)
