"""Temporary tests for the phase-table stub itself.

Delete with the stub when the real evaluator lands.
"""
import pytest

from tests._windows_peer_admission_contract_driver import evaluate_case
from tests._windows_peer_admission_contract_stub import StubReachedPhase7


def test_stub_does_not_invent_a_phase_7_terminal_or_authority():
    with pytest.raises(StubReachedPhase7, match="PHASE_7_REQUIRES_REAL_EVALUATOR"):
        evaluate_case()
