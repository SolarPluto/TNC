"""Focused schema, layering, and handoff tests for the production admission gate."""
import inspect

import pytest

import tnc.provenance.windows_peer_admission_gate as gate
from tnc.provenance.windows_peer_admission_gate import (
    AdmissionHandoffFailure,
    LEGAL_RESULT_PAIRS,
    PeerAdmissionAuditRecord,
)


def projection():
    return {
        "pipe_context_classification": "NON_APPCONTAINER",
        "process_primary_classification": "NON_APPCONTAINER",
        "connection_operation_id": "connect",
        "pipe_lease_id": "connectp",
        "process_lease_operation_id": "lease",
        "process_pid": 1,
        "process_creation_filetime": 100,
        "capture_ordinal": 1,
        "evaluated_policy_revision": 1,
        "evaluated_policy_digest": "a" * 64,
    }


def test_positive_pair_is_legal_and_placeholder_pairs_are_retired():
    assert ("ADMITTED", "ADMISSION_REQUIREMENTS_MET") in LEGAL_RESULT_PAIRS
    assert ("INDETERMINATE", "PEER_ADMISSION_NOT_IMPLEMENTED") not in LEGAL_RESULT_PAIRS
    assert ("DENIED", "APP_CONTAINER_DENIED") not in LEGAL_RESULT_PAIRS


def test_admitted_audit_is_durable_but_all_grant_flags_are_inert():
    audit = PeerAdmissionAuditRecord(
        status="ADMITTED",
        reason="ADMISSION_REQUIREMENTS_MET",
        terminal_phase="7.1",
        **projection(),
    )
    assert audit.admission_granted is False
    assert audit.authorization_granted is False
    assert audit.grants_evaluated is False
    assert audit.signing_evaluated is False
    with pytest.raises(ValueError):
        PeerAdmissionAuditRecord(
            status="ADMITTED",
            reason="ADMISSION_REQUIREMENTS_MET",
            terminal_phase="7.1",
            admission_granted=True,
            **projection(),
        )


def test_audit_terminal_phase_is_closed_and_phase_1_projection_is_empty():
    with pytest.raises(ValueError):
        PeerAdmissionAuditRecord(
            status="ADMITTED",
            reason="ADMISSION_REQUIREMENTS_MET",
            terminal_phase="8",
            **projection(),
        )
    audit = PeerAdmissionAuditRecord(
        status="INDETERMINATE",
        reason="INVALID_ADMISSION_EVIDENCE",
        terminal_phase="1",
    )
    assert audit.pipe_context_classification is None


def test_illegal_pair_is_rejected():
    with pytest.raises(ValueError, match="illegal admission result pair"):
        PeerAdmissionAuditRecord(
            status="ADMITTED",
            reason="INVALID_RECORD",
            terminal_phase="7.1",
            **projection(),
        )


def test_handoff_group_subclass_is_not_demoted_to_exception_group():
    failure = AdmissionHandoffFailure(
        [ValueError("audit"), RuntimeError("close")]
    )
    assert type(failure) is AdmissionHandoffFailure
    assert isinstance(failure, BaseExceptionGroup)
    assert not isinstance(failure, Exception)


def test_evaluator_layer_does_not_import_native_producer_module():
    source = inspect.getsource(gate)
    assert "windows_pipe_context_producer" not in source
    assert "PipeContextProducer" not in source


def test_legacy_result_type_is_retired():
    assert not hasattr(gate, "NativePeerAdmissionResult")



def test_authority_construction_unavailable_reason_vocabulary_is_closed():
    from tnc.provenance.windows_peer_admission_gate import (
        AuthorityConstructionUnavailable,
    )

    value = AuthorityConstructionUnavailable(
        "CONTINUITY_UNAVAILABLE_AT_ADOPTION"
    )
    assert value.reason == "CONTINUITY_UNAVAILABLE_AT_ADOPTION"
    with pytest.raises(
        ValueError,
        match="UNKNOWN_AUTHORITY_CONSTRUCTION_UNAVAILABLE_REASON",
    ):
        AuthorityConstructionUnavailable("OTHER")
