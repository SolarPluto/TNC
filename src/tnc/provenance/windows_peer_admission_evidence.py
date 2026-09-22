"""Immutable dual-axis evidence schemas for native peer admission.

This module contains no acquisition logic. Native producers construct these exact
records; evaluators consume them without importing native producer implementations.
"""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Identifier, Model
from tnc.provenance.windows_appcontainer_evidence import AppContainerTokenEvidence


MAX_WINERROR = 2**32 - 1

_BINDING_FIELDS = (
    "connection_operation_id",
    "pipe_lease_id",
    "process_lease_operation_id",
    "process_pid",
    "process_creation_filetime",
    "capture_ordinal",
)


class _Binding(Model):
    connection_operation_id: Identifier
    pipe_lease_id: Identifier
    process_lease_operation_id: Identifier
    process_pid: int = Field(strict=True, ge=1, le=MAX_WINERROR)
    process_creation_filetime: int = Field(strict=True, ge=1, le=2**64 - 1)
    capture_ordinal: Literal[1] = 1


class _CapturedAppContainer(_Binding):
    status: Literal["CAPTURED_APPCONTAINER"] = "CAPTURED_APPCONTAINER"
    classification_source: Literal["PIPE_TOKEN"] = "PIPE_TOKEN"
    evidence: AppContainerTokenEvidence


class _CapturedNonAppContainer(_Binding):
    status: Literal["CAPTURED_NON_APPCONTAINER"] = "CAPTURED_NON_APPCONTAINER"
    classification_source: Literal["PIPE_TOKEN"] = "PIPE_TOKEN"
    evidence: AppContainerTokenEvidence


class _CapturedClassificationConflict(_Binding):
    status: Literal["CAPTURED_CLASSIFICATION_CONFLICT"] = "CAPTURED_CLASSIFICATION_CONFLICT"
    classification_source: Literal["PIPE_TOKEN"] = "PIPE_TOKEN"
    reason: Identifier


class _CapturedClassificationUnavailable(_Binding):
    status: Literal["CAPTURED_CLASSIFICATION_UNAVAILABLE"] = (
        "CAPTURED_CLASSIFICATION_UNAVAILABLE"
    )
    classification_source: Literal["PIPE_TOKEN"] = "PIPE_TOKEN"
    failure_scope: Literal["SERVER_CLASSIFICATION"] = "SERVER_CLASSIFICATION"
    information_class: Literal[29, 31]
    failure_reason: Identifier
    winerror: int | None = Field(default=None, strict=True, ge=0, le=MAX_WINERROR)


class _CaptureUnavailable(_Binding):
    status: Literal["CAPTURE_UNAVAILABLE"] = "CAPTURE_UNAVAILABLE"
    failure_scope: Literal["CAPTURE"] = "CAPTURE"
    failed_stage: Literal["IMPERSONATE", "OPEN_THREAD_TOKEN"]
    winerror: int = Field(strict=True, ge=0, le=MAX_WINERROR)


PipePeerAdmissionEvidence = Annotated[
    _CapturedAppContainer
    | _CapturedNonAppContainer
    | _CapturedClassificationConflict
    | _CapturedClassificationUnavailable
    | _CaptureUnavailable,
    Field(discriminator="status"),
]


ProcessPrimaryFailureReason = Literal[
    "OPEN_PROCESS_TOKEN_FAILED",
    "QUERY_FAILED",
    "QUERY_LENGTH_INVALID",
    "QUERY_BOOLEAN_INVALID",
    "QUERY_SIZE_PROBE_FAILED",
    "QUERY_BOUND_INVALID",
    "QUERY_RETURN_LENGTH_INVALID",
    "APPCONTAINER_INFO_HEADER_INVALID",
    "APPCONTAINER_SID_INVALID",
]


class _ProcessPrimaryCapturedAppContainer(_Binding):
    status: Literal["CAPTURED_APPCONTAINER"] = "CAPTURED_APPCONTAINER"
    classification_source: Literal["PROCESS_PRIMARY_TOKEN"] = "PROCESS_PRIMARY_TOKEN"
    evidence: AppContainerTokenEvidence


class _ProcessPrimaryCapturedNonAppContainer(_Binding):
    status: Literal["CAPTURED_NON_APPCONTAINER"] = "CAPTURED_NON_APPCONTAINER"
    classification_source: Literal["PROCESS_PRIMARY_TOKEN"] = "PROCESS_PRIMARY_TOKEN"
    evidence: AppContainerTokenEvidence


class _ProcessPrimaryClassificationConflict(_Binding):
    status: Literal["CAPTURED_CLASSIFICATION_CONFLICT"] = "CAPTURED_CLASSIFICATION_CONFLICT"
    classification_source: Literal["PROCESS_PRIMARY_TOKEN"] = "PROCESS_PRIMARY_TOKEN"
    reason: Literal["APPCONTAINER_SIGNAL_CONFLICT"] = "APPCONTAINER_SIGNAL_CONFLICT"


class _ProcessPrimaryClassificationUnavailable(_Binding):
    status: Literal["CAPTURED_CLASSIFICATION_UNAVAILABLE"] = (
        "CAPTURED_CLASSIFICATION_UNAVAILABLE"
    )
    classification_source: Literal["PROCESS_PRIMARY_TOKEN"] = "PROCESS_PRIMARY_TOKEN"
    failed_stage: Literal["OPEN_PROCESS_TOKEN", "GET_TOKEN_INFORMATION"]
    information_class: Literal[29, 31] | None = None
    failure_reason: ProcessPrimaryFailureReason
    winerror: int | None = Field(default=None, strict=True, ge=0, le=MAX_WINERROR)

    @model_validator(mode="after")
    def stage_matches_information_class(self):
        if self.failed_stage == "OPEN_PROCESS_TOKEN":
            if self.information_class is not None:
                raise ValueError("OPEN_PROCESS_TOKEN_HAS_NO_INFORMATION_CLASS")
            if self.failure_reason != "OPEN_PROCESS_TOKEN_FAILED":
                raise ValueError("OPEN_PROCESS_TOKEN_FAILURE_REASON_REQUIRED")
        else:
            if self.information_class not in (29, 31):
                raise ValueError("GET_TOKEN_INFORMATION_CLASS_REQUIRED")
            if self.failure_reason == "OPEN_PROCESS_TOKEN_FAILED":
                raise ValueError("QUERY_FAILURE_REASON_REQUIRED")
        return self


ProcessPrimaryAppContainerEvidence = Annotated[
    _ProcessPrimaryCapturedAppContainer
    | _ProcessPrimaryCapturedNonAppContainer
    | _ProcessPrimaryClassificationConflict
    | _ProcessPrimaryClassificationUnavailable,
    Field(discriminator="status"),
]


class PeerAdmissionEvidence(Model):
    """Two-axis evidence from one exact connection/process capture transaction."""

    pipe_context: PipePeerAdmissionEvidence
    process_primary: ProcessPrimaryAppContainerEvidence

    @model_validator(mode="after")
    def exact_cross_axis_binding(self):
        pipe_binding = tuple(getattr(self.pipe_context, name) for name in _BINDING_FIELDS)
        process_binding = tuple(getattr(self.process_primary, name) for name in _BINDING_FIELDS)
        if pipe_binding != process_binding:
            raise ValueError("CROSS_AXIS_BINDING_MISMATCH")
        return self


__all__ = [
    "PeerAdmissionEvidence",
    "PipePeerAdmissionEvidence",
    "ProcessPrimaryAppContainerEvidence",
    "ProcessPrimaryFailureReason",
]
