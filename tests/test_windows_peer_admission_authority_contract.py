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
    assert pair(evaluate_case(evidence=make_evidence(pipe="UNAVAILABLE"))) == (
        "INDETERMINATE",
        "PEER_EVIDENCE_UNAVAILABLE",
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


def test_phase_2_precedes_later_pipe_denial():
    assert pair(
        evaluate_case(
            lease=make_lease(status="INDETERMINATE", reason="ABORTED"),
            evidence=make_evidence(pipe="APPCONTAINER"),
        )
    ) == ("DENIED", "PROCESS_LEASE_NOT_CORRELATED")


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
