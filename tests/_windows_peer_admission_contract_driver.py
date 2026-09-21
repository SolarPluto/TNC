"""Production-backed driver for the permanent peer-admission contract tests."""
from hashlib import sha256
import threading

from pydantic import TypeAdapter

from tnc.provenance.windows_peer_admission_continuity import (
    AdmissionContinuity,
    PeerAdmissionPolicyProviderForTesting,
    PeerAdmissionPolicySnapshot,
)
from tnc.provenance.windows_peer_admission_evidence import PeerAdmissionEvidence
from tnc.provenance.windows_peer_admission_gate import evaluate_native_peer_admission
from tnc.provenance.windows_pipe_auth_bridge import NativePeerAuditResult
from tnc.provenance.windows_pipe_process_lease import ProcessLeaseAudit


evaluator_under_contract = evaluate_native_peer_admission
_EVIDENCE = TypeAdapter(PeerAdmissionEvidence)


def make_lease(**changes):
    data = {
        "status": "CORRELATED",
        "reason": "AUDIT_MATCHED",
        "source": "NATIVE_PROCESS_API",
        "audit_only": True,
        "authorization_granted": False,
    }
    data.update(changes)
    # model_construct deliberately permits contract-invariant tests to create the
    # exact production type with impossible internal fields for phase 2.3.
    return ProcessLeaseAudit.model_construct(**data)


def make_peer(**changes):
    data = {
        "status": "INDETERMINATE",
        "reason": "APP_CONTAINER_EXCLUSION_UNPROVEN",
        "audit_only": True,
        "authorization_granted": False,
        "grants_evaluated": False,
    }
    data.update(changes)
    # Same reason as make_lease: phase 3 explicitly owns these invariant checks.
    return NativePeerAuditResult.model_construct(**data)


def _digest(value):
    if (
        type(value) is str
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    ):
        return value
    return sha256(str(value).encode("utf-8")).hexdigest()


def make_policy(**changes):
    revision = changes.pop("revision", 1)
    digest = _digest(changes.pop("policy_digest", "policy-digest"))
    if changes:
        raise TypeError(f"unknown policy changes: {sorted(changes)!r}")
    return PeerAdmissionPolicySnapshot(revision=revision, policy_digest=digest)


_BINDING = {
    "connection_operation_id": "connect",
    "pipe_lease_id": "connectp",
    "process_lease_operation_id": "lease",
    "process_pid": 1,
    "process_creation_filetime": 100,
    "capture_ordinal": 1,
}


def _axis(kind, status):
    binding = dict(_BINDING)
    source = "PIPE_TOKEN" if kind == "pipe" else "PROCESS_PRIMARY_TOKEN"
    if status == "NON_APPCONTAINER":
        evidence = {
            "source": "NATIVE_TOKEN_API",
            "token_type": "IMPERSONATION" if kind == "pipe" else "PRIMARY",
            "level": "IMPERSONATION" if kind == "pipe" else None,
            "token_is_app_container": False,
            "app_container_sid": None,
            "capability_sids": (),
        }
        return {
            **binding,
            "status": "CAPTURED_NON_APPCONTAINER",
            "classification_source": source,
            "evidence": evidence,
        }
    if status == "APPCONTAINER":
        evidence = {
            "source": "NATIVE_TOKEN_API",
            "token_type": "IMPERSONATION" if kind == "pipe" else "PRIMARY",
            "level": "IMPERSONATION" if kind == "pipe" else None,
            "token_is_app_container": True,
            "app_container_sid": None,
            "capability_sids": (),
        }
        return {
            **binding,
            "status": "CAPTURED_APPCONTAINER",
            "classification_source": source,
            "evidence": evidence,
        }
    if status == "CONFLICT":
        return {
            **binding,
            "status": "CAPTURED_CLASSIFICATION_CONFLICT",
            "classification_source": source,
            "reason": "APPCONTAINER_SIGNAL_CONFLICT",
        }
    if status == "UNAVAILABLE":
        if kind == "pipe":
            return {
                **binding,
                "status": "CAPTURED_CLASSIFICATION_UNAVAILABLE",
                "classification_source": source,
                "failure_scope": "SERVER_CLASSIFICATION",
                "information_class": 29,
                "failure_reason": "QUERY_29_FAILED_5",
                "winerror": 5,
            }
        return {
            **binding,
            "status": "CAPTURED_CLASSIFICATION_UNAVAILABLE",
            "classification_source": source,
            "failed_stage": "GET_TOKEN_INFORMATION",
            "information_class": 29,
            "failure_reason": "QUERY_FAILED",
            "winerror": 5,
        }
    raise ValueError(f"unknown axis status {status!r}")


def make_evidence(**changes):
    pipe = changes.pop("pipe", "NON_APPCONTAINER")
    process = changes.pop("process_primary", "NON_APPCONTAINER")
    if changes:
        raise TypeError(f"unknown evidence changes: {sorted(changes)!r}")
    return _EVIDENCE.validate_python({
        "pipe_context": _axis("pipe", pipe),
        "process_primary": _axis("process", process),
    })


class _Endpoint:
    def __init__(self):
        self._continuity_claim_lock = threading.Lock()
        self._continuity_owner = None
        self._continuity_active = True
        self._handle = 700
        self._closed = False
        self._connected = True
        self._fatal = False


class _ProcessAPI:
    def __init__(self):
        self.wait = 258
        self.pid = 1
        self.birth = 100
        self.close_ok = True
        self.calls = []

    def wait_process(self, handle, timeout):
        self.calls.append(("wait", handle, timeout))
        return self.wait

    def process_id(self, handle):
        self.calls.append(("pid", handle))
        return self.pid

    def creation_filetime(self, handle):
        self.calls.append(("birth", handle))
        return self.birth

    def client_process_id(self, pipe):
        self.calls.append(("pipe_pid", pipe))
        return self.pid

    def close(self, handle):
        self.calls.append(("close", handle))
        return self.close_ok


def make_continuity(*, policy=None, **changes):
    available = changes.pop("available", True)
    exact_binding = changes.pop("exact_binding", True)
    open_at_adoption_start = changes.pop("open_at_adoption_start", True)
    if changes:
        raise TypeError(f"unknown continuity changes: {sorted(changes)!r}")

    snapshot = policy or make_policy()
    endpoint = _Endpoint()
    api = _ProcessAPI()
    value = object.__new__(AdmissionContinuity)
    value._endpoint = endpoint
    value._api = api
    value._clock = lambda: 10
    value._process_handle = 600 if available else None
    value._pipe = 700
    value._pid = 1
    value._creation_filetime = 100
    value._binding = (
        "connect" if exact_binding else "other-connect",
        "connectp",
        "lease",
        1,
        100,
        1,
    )
    value._provider = PeerAdmissionPolicyProviderForTesting(snapshot)
    value._policy_snapshot = PeerAdmissionPolicySnapshot.model_validate(snapshot.model_dump())
    value._deadline = 100
    value._lock = threading.Lock()
    value._closed = not open_at_adoption_start
    value._invalid = False
    value._contained = False
    value._containment_reason = None
    value._adopted_by = None
    value._outstanding = None
    endpoint._continuity_owner = value
    return value


def evaluate_case(
    *,
    lease=None,
    peer=None,
    evidence=None,
    continuity=None,
    evaluated_policy=None,
):
    policy = evaluated_policy or make_policy()
    return evaluator_under_contract(
        lease=lease or make_lease(),
        peer=peer or make_peer(),
        peer_evidence=evidence or make_evidence(),
        continuity=continuity or make_continuity(policy=policy),
        evaluated_policy=policy,
    )
