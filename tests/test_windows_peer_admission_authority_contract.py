"""Permanent contract tests for native peer-admission phases 1-6."""
import inspect

import pytest

from tnc.provenance.windows_peer_admission_gate import AdmissionEvaluatorInvariantError
from tnc.provenance.windows_pipe_auth_bridge import NATIVE_PEER_AUDIT_RESULT_PAIRS
from _windows_peer_admission_contract_driver import (
    evaluate_case,
    evaluator_under_contract,
    make_continuity,
    make_evidence,
    make_lease,
    make_peer,
    make_policy,
)


def pair(result):
    audit, authority = result
    assert authority is None
    return audit.status, audit.reason


def test_evaluator_keyword_interface_is_pinned():
    signature = inspect.signature(evaluator_under_contract)
    assert tuple(signature.parameters) == (
        "lease",
        "peer",
        "peer_evidence",
        "continuity",
        "evaluated_policy",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )


def test_phase_1_rejects_wrong_exact_input_type():
    assert pair(evaluate_case(lease=object())) == (
        "INDETERMINATE",
        "INVALID_ADMISSION_EVIDENCE",
    )


def test_phase_2_1_requires_native_process_lease():
    assert pair(evaluate_case(lease=make_lease(source="FAKE_PROCESS_API"))) == (
        "INDETERMINATE",
        "NATIVE_PROCESS_LEASE_REQUIRED",
    )


@pytest.mark.parametrize(
    "status,reason",
    [
        ("INDETERMINATE", "ABORTED"),
        ("INDETERMINATE", "PROCESS_CORRELATION_FAILED"),
    ],
)
def test_phase_2_2_requires_exact_correlated_pair(status, reason):
    assert pair(evaluate_case(lease=make_lease(status=status, reason=reason))) == (
        "DENIED",
        "PROCESS_LEASE_NOT_CORRELATED",
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"audit_only": False},
        {"authorization_granted": True},
    ],
)
def test_phase_2_3_enforces_lease_contract(changes):
    assert pair(evaluate_case(lease=make_lease(**changes))) == (
        "INDETERMINATE",
        "PROCESS_LEASE_CONTRACT_VIOLATION",
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"audit_only": False},
        {"authorization_granted": True},
        {"grants_evaluated": True},
    ],
)
def test_phase_3_1_enforces_peer_audit_contract(changes):
    assert pair(evaluate_case(peer=make_peer(**changes))) == (
        "INDETERMINATE",
        "PEER_AUDIT_CONTRACT_VIOLATION",
    )


@pytest.mark.parametrize(
    "reason",
    sorted(
        reason
        for status, reason in NATIVE_PEER_AUDIT_RESULT_PAIRS
        if status == "VIOLATIONS" and reason != "APP_CONTAINER_DENIED"
    ),
)
def test_phase_3_2_preserves_authority_compatible_bridge_violation(reason):
    assert pair(evaluate_case(peer=make_peer(status="VIOLATIONS", reason=reason))) == (
        "DENIED",
        reason,
    )


def test_phase_3_2_rejects_retired_bridge_appcontainer_verdict_as_invariant():
    with pytest.raises(AdmissionEvaluatorInvariantError):
        evaluate_case(peer=make_peer(status="VIOLATIONS", reason="APP_CONTAINER_DENIED"))


def test_phase_3_2_rejects_unknown_bridge_pair_as_invariant():
    with pytest.raises(AdmissionEvaluatorInvariantError):
        evaluate_case(peer=make_peer(status="VIOLATIONS", reason="UNKNOWN_BRIDGE_REASON"))


def test_phase_3_3_capture_unavailable_maps_to_peer_evidence_unavailable():
    assert pair(
        evaluate_case(
            peer=make_peer(status="INDETERMINATE", reason="CAPTURE_UNAVAILABLE")
        )
    ) == ("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")


def test_phase_3_3_appcontainer_unproven_hands_off_to_phase_4():
    assert pair(evaluate_case(evidence=make_evidence(pipe="APPCONTAINER"))) == (
        "DENIED",
        "PIPE_CONTEXT_APP_CONTAINER_DENIED",
    )


@pytest.mark.parametrize("reason", ["INVALID_RECORD", "NATIVE_CAPTURE_REQUIRED"])
def test_phase_3_3_other_indeterminate_reasons_propagate(reason):
    assert pair(
        evaluate_case(peer=make_peer(status="INDETERMINATE", reason=reason))
    ) == ("INDETERMINATE", reason)


@pytest.mark.parametrize(
    "pipe_status,process_status,expected",
    [
        ("APPCONTAINER", "NON_APPCONTAINER", ("DENIED", "PIPE_CONTEXT_APP_CONTAINER_DENIED")),
        ("NON_APPCONTAINER", "APPCONTAINER", ("DENIED", "PROCESS_PRIMARY_APP_CONTAINER_DENIED")),
        ("APPCONTAINER", "APPCONTAINER", ("DENIED", "PIPE_CONTEXT_APP_CONTAINER_DENIED")),
        ("APPCONTAINER", "UNAVAILABLE", ("DENIED", "PIPE_CONTEXT_APP_CONTAINER_DENIED")),
        ("UNAVAILABLE", "APPCONTAINER", ("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")),
        ("UNAVAILABLE", "UNAVAILABLE", ("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")),
        ("NON_APPCONTAINER", "UNAVAILABLE", ("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")),
        ("CONFLICT", "NON_APPCONTAINER", ("INDETERMINATE", "PIPE_CONTEXT_CLASSIFICATION_CONFLICT")),
        ("NON_APPCONTAINER", "CONFLICT", ("INDETERMINATE", "PROCESS_PRIMARY_CLASSIFICATION_CONFLICT")),
    ],
)
def test_phases_4_and_5_dual_classification_matrix(
    pipe_status,
    process_status,
    expected,
):
    assert pair(
        evaluate_case(
            evidence=make_evidence(
                pipe=pipe_status,
                process_primary=process_status,
            )
        )
    ) == expected


def test_phase_2_1_precedes_phase_2_2():
    assert pair(
        evaluate_case(
            lease=make_lease(
                source="FAKE_PROCESS_API",
                status="INDETERMINATE",
                reason="ABORTED",
            )
        )
    ) == ("INDETERMINATE", "NATIVE_PROCESS_LEASE_REQUIRED")


def test_phase_2_2_precedes_phase_2_3():
    assert pair(
        evaluate_case(
            lease=make_lease(
                status="INDETERMINATE",
                reason="ABORTED",
                audit_only=False,
            )
        )
    ) == ("DENIED", "PROCESS_LEASE_NOT_CORRELATED")


def test_phase_2_precedes_later_pipe_denial():
    assert pair(
        evaluate_case(
            lease=make_lease(status="INDETERMINATE", reason="ABORTED"),
            evidence=make_evidence(pipe="APPCONTAINER"),
        )
    ) == ("DENIED", "PROCESS_LEASE_NOT_CORRELATED")


def test_phase_3_1_precedes_phase_3_2():
    assert pair(
        evaluate_case(
            peer=make_peer(
                status="VIOLATIONS",
                reason="TOKEN_IDENTITY_MISMATCH",
                audit_only=False,
            )
        )
    ) == ("INDETERMINATE", "PEER_AUDIT_CONTRACT_VIOLATION")


def test_phase_3_precedes_later_pipe_denial():
    assert pair(
        evaluate_case(
            peer=make_peer(status="VIOLATIONS", reason="TOKEN_IDENTITY_MISMATCH"),
            evidence=make_evidence(pipe="APPCONTAINER"),
        )
    ) == ("DENIED", "TOKEN_IDENTITY_MISMATCH")


def test_phase_4_precedes_process_primary_denial():
    assert pair(
        evaluate_case(
            evidence=make_evidence(
                pipe="UNAVAILABLE",
                process_primary="APPCONTAINER",
            )
        )
    ) == ("INDETERMINATE", "PEER_EVIDENCE_UNAVAILABLE")


@pytest.mark.parametrize(
    "continuity,expected",
    [
        (
            make_continuity(available=False),
            ("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE"),
        ),
        (
            make_continuity(exact_binding=False),
            ("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE"),
        ),
    ],
)
def test_phase_6_1_requires_matching_live_continuity(continuity, expected):
    assert pair(evaluate_case(continuity=continuity)) == expected


def test_phase_6_2_requires_exact_evaluated_policy_binding():
    evaluated = make_policy(revision=2, policy_digest="evaluated")
    continuity_policy = make_policy(revision=1, policy_digest="captured")
    assert pair(
        evaluate_case(
            evaluated_policy=evaluated,
            continuity=make_continuity(policy=continuity_policy),
        )
    ) == ("INDETERMINATE", "POLICY_BINDING_UNAVAILABLE")


def test_phase_6_3_requires_continuity_open_at_adoption_start():
    assert pair(
        evaluate_case(continuity=make_continuity(open_at_adoption_start=False))
    ) == ("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE")


def test_phase_6_2_precedes_phase_6_3():
    evaluated = make_policy(revision=2, policy_digest="evaluated")
    continuity = make_continuity(
        policy=make_policy(revision=1, policy_digest="captured"),
        open_at_adoption_start=False,
    )
    assert pair(
        evaluate_case(evaluated_policy=evaluated, continuity=continuity)
    ) == ("INDETERMINATE", "POLICY_BINDING_UNAVAILABLE")


def test_phase_6_subcheck_precedence_binding_before_policy_before_open():
    evaluated = make_policy(revision=2, policy_digest="evaluated")
    continuity = make_continuity(
        policy=make_policy(revision=1, policy_digest="captured"),
        exact_binding=False,
        open_at_adoption_start=False,
    )
    assert pair(
        evaluate_case(evaluated_policy=evaluated, continuity=continuity)
    ) == ("INDETERMINATE", "ADMISSION_CONTINUITY_UNAVAILABLE")



def test_phase_7_1_returns_exact_live_authority_with_inert_audit_flags():
    from tnc.provenance.windows_peer_admission_continuity import _AuthoritativePeerAdmission
    from tnc.provenance.windows_peer_admission_gate import LEGAL_RESULT_PAIRS

    audit, authority = evaluate_case()
    assert (audit.status, audit.reason) == (
        "ADMITTED",
        "ADMISSION_REQUIREMENTS_MET",
    )
    assert audit.terminal_phase == "7.1"
    assert (audit.status, audit.reason) in LEGAL_RESULT_PAIRS
    assert audit.admission_granted is False
    assert audit.authorization_granted is False
    assert audit.grants_evaluated is False
    assert audit.signing_evaluated is False
    assert type(authority) is _AuthoritativePeerAdmission
    assert authority._continuity._adopted_by is authority
    assert authority.close() is True
    assert authority.close() is False
    assert audit.admission_granted is False


def test_phase_1_audit_projection_is_all_none():
    audit, authority = evaluate_case(lease=object())
    assert authority is None
    assert audit.terminal_phase == "1"
    for name in (
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
    ):
        assert getattr(audit, name) is None


def test_early_phase_2_terminal_keeps_complete_validated_projection():
    policy = make_policy()
    evidence = make_evidence(pipe="APPCONTAINER", process_primary="UNAVAILABLE")
    continuity = make_continuity(policy=policy)
    audit, authority = evaluate_case(
        lease=make_lease(source="FAKE_PROCESS_API"),
        evidence=evidence,
        continuity=continuity,
        evaluated_policy=policy,
    )
    assert authority is None
    assert audit.terminal_phase == "2.1"
    assert audit.pipe_context_classification == "APPCONTAINER"
    assert audit.process_primary_classification == "UNAVAILABLE"
    assert audit.connection_operation_id == "connect"
    assert audit.capture_ordinal == 1
    assert audit.evaluated_policy_revision == policy.revision
    assert audit.evaluated_policy_digest == policy.policy_digest
    assert continuity.close() is True


def test_validated_unavailable_axis_is_not_none_in_audit():
    policy = make_policy()
    continuity = make_continuity(policy=policy)
    audit, authority = evaluate_case(
        evidence=make_evidence(pipe="UNAVAILABLE"),
        continuity=continuity,
        evaluated_policy=policy,
    )
    assert authority is None
    assert audit.terminal_phase == "4.1a"
    assert audit.pipe_context_classification == "UNAVAILABLE"
    assert audit.process_primary_classification == "NON_APPCONTAINER"
    assert continuity.close() is True


def test_authority_construction_barrier_runtime():
    import copy
    import pickle

    from tnc.provenance.windows_peer_admission_continuity import _AuthoritativePeerAdmission

    audit, authority = evaluate_case()
    with pytest.raises(TypeError):
        _AuthoritativePeerAdmission()
    with pytest.raises(TypeError):
        _AuthoritativePeerAdmission(audit)
    assert not hasattr(_AuthoritativePeerAdmission, "_from_continuity")
    with pytest.raises(TypeError):
        copy.copy(authority)
    with pytest.raises(TypeError):
        copy.deepcopy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)
    authority.close()


def test_authority_construction_barrier_rejects_fabricated_state():
    from tnc.provenance.windows_peer_admission_gate import (
        _ValidatedAdmissionState,
        _adopt_and_build_authority_from_state,
    )

    with pytest.raises(TypeError):
        _ValidatedAdmissionState()
    fabricated = object.__new__(_ValidatedAdmissionState)
    with pytest.raises(AdmissionEvaluatorInvariantError):
        _adopt_and_build_authority_from_state(fabricated)


def test_bare_continuity_is_not_a_use_or_close_path_after_adoption():
    from tnc.provenance.windows_peer_admission_continuity import (
        AdmissionContinuityError,
        ContinuityUseKind,
    )

    continuity = make_continuity()
    audit, authority = evaluate_case(continuity=continuity)
    assert audit.status == "ADMITTED"
    with pytest.raises(AdmissionContinuityError, match="CONTINUITY_ADOPTED"):
        continuity.close()
    with pytest.raises(AdmissionContinuityError, match="CONTINUITY_ADOPTED"):
        continuity.mint_use_token(
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
            operation_deadline=50,
        )
    with pytest.raises(AdmissionContinuityError, match="USE_KIND_NOT_ALLOWED"):
        authority.mint_use_token(
            operation_id="op",
            kind=ContinuityUseKind.RESERVED_FOR_TESTING,
            operation_deadline=50,
        )
    authority.close()


def test_adoption_preflight_refusal_returns_phase_7_indeterminate_and_closes():
    continuity = make_continuity()
    continuity._api.wait = 0
    audit, authority = evaluate_case(continuity=continuity)
    assert authority is None
    assert (audit.status, audit.reason, audit.terminal_phase) == (
        "INDETERMINATE",
        "AUTHORITY_CONSTRUCTION_FAILED",
        "7.1",
    )
    assert continuity._closed is True
    assert continuity._adopted_by is None


def test_post_adoption_audit_failure_closes_authority_and_reraises(monkeypatch):
    import tnc.provenance.windows_peer_admission_gate as gate

    continuity = make_continuity()
    real = gate._build_audit

    def broken(projection, *, status, reason, terminal_phase):
        if status == "ADMITTED":
            raise RuntimeError("audit projection bug")
        return real(
            projection,
            status=status,
            reason=reason,
            terminal_phase=terminal_phase,
        )

    monkeypatch.setattr(gate, "_build_audit", broken)
    with pytest.raises(RuntimeError, match="audit projection bug"):
        evaluate_case(continuity=continuity)
    assert continuity._closed is True
    assert sum(1 for call in continuity._api.calls if call[0] == "close") == 1


def test_handoff_and_cleanup_failure_preserve_both_and_poison_authority(monkeypatch):
    import tnc.provenance.windows_peer_admission_gate as gate
    from tnc.provenance.windows_peer_admission_continuity import (
        AdmissionContinuityContainment,
    )
    from tnc.provenance.windows_peer_admission_gate import AdmissionHandoffFailure

    continuity = make_continuity()
    continuity._api.close_ok = False
    real = gate._build_audit

    def broken(projection, *, status, reason, terminal_phase):
        if status == "ADMITTED":
            raise RuntimeError("audit projection bug")
        return real(
            projection,
            status=status,
            reason=reason,
            terminal_phase=terminal_phase,
        )

    monkeypatch.setattr(gate, "_build_audit", broken)
    with pytest.raises(AdmissionHandoffFailure) as captured:
        evaluate_case(continuity=continuity)

    failure = captured.value
    assert len(failure.exceptions) == 2
    assert isinstance(failure.exceptions[0], RuntimeError)
    assert isinstance(failure.exceptions[1], AdmissionContinuityContainment)
    assert continuity._contained is True
    authority = continuity._adopted_by
    close_calls = sum(1 for call in continuity._api.calls if call[0] == "close")
    assert close_calls == 1
    with pytest.raises(AdmissionContinuityContainment):
        authority.close()
    assert sum(1 for call in continuity._api.calls if call[0] == "close") == close_calls
