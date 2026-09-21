"""Contract-test driver.

The permanent test file imports only this driver. When the real evaluator lands,
replace these synthetic factories with production objects; the contract tests stay
unchanged.
"""
from dataclasses import replace

from _windows_peer_admission_contract_stub import (
    StubContinuity,
    StubDualAppContainerEvidence,
    StubLeaseAudit,
    StubPeerAudit,
    StubPolicySnapshot,
    evaluate_native_peer_admission,
)

evaluator_under_contract = evaluate_native_peer_admission


def make_lease(**changes):
    return replace(StubLeaseAudit(), **changes)


def make_peer(**changes):
    return replace(StubPeerAudit(), **changes)


def make_evidence(**changes):
    return replace(StubDualAppContainerEvidence(), **changes)


def make_policy(**changes):
    return replace(StubPolicySnapshot(), **changes)


def make_continuity(*, policy=None, **changes):
    value = StubContinuity(policy_snapshot=policy or StubPolicySnapshot())
    return replace(value, **changes)


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
