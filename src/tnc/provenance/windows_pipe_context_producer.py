"""Bound pipe-client AppContainer evidence producer for native Windows admission.

The snapshot exists because PR #37 / Windows Server 2025 build 26100 produced a
bound THREAD_TOKEN counterexample: a non-AppContainer process primary token did
not describe the AppContainer token carried by the thread that connected to the
pipe. The producer therefore classifies the exact captured pipe-client token.

This module produces immutable facts only. It does not evaluate admission.
"""
import ctypes as c
import os
import threading
import weakref
from typing import Annotated, Literal

from pydantic import Field

from tnc.provenance.authorization_models import Identifier, Model
from tnc.provenance.windows_appcontainer_evidence import (
    AppContainerTokenEvidence,
    evaluate_appcontainer_exclusion,
)
from tnc.provenance.windows_appcontainer_probe import (
    AppContainerProbeError,
    NativeAppContainerProbe,
)
from tnc.provenance.windows_pipe_operation_logic import PipeOperationPlan
from tnc.provenance.windows_pipe_process_lease import OwnedProcessLease
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI, TokenCaptureError

EXIT_REVERT_FAILED = 0xE401
TOKEN_QUERY = 0x0008
MAX_WINERROR = 2**32 - 1

_CLAIMED = weakref.WeakKeyDictionary()
_CLAIM_LOCK = threading.Lock()


class PipeContextProducerError(RuntimeError):
    """Caller misuse, producer invariant failure, or upstream contract violation."""


class _Binding(Model):
    connection_operation_id: Identifier
    pipe_lease_id: Identifier
    process_lease_operation_id: Identifier
    process_pid: int = Field(strict=True, ge=1, le=MAX_WINERROR)
    process_creation_filetime: int = Field(strict=True, ge=1, le=2**64 - 1)
    capture_ordinal: Literal[1] = 1


class _CapturedAppContainer(_Binding):
    """Producer-only variant. Do not construct from caller-supplied facts."""
    status: Literal['CAPTURED_APPCONTAINER'] = 'CAPTURED_APPCONTAINER'
    classification_source: Literal['PIPE_TOKEN'] = 'PIPE_TOKEN'
    evidence: AppContainerTokenEvidence


class _CapturedNonAppContainer(_Binding):
    """Producer-only variant. Do not construct from caller-supplied facts."""
    status: Literal['CAPTURED_NON_APPCONTAINER'] = 'CAPTURED_NON_APPCONTAINER'
    classification_source: Literal['PIPE_TOKEN'] = 'PIPE_TOKEN'
    evidence: AppContainerTokenEvidence


class _CapturedClassificationConflict(_Binding):
    """Captured pipe-token facts were valid but produced a classifier conflict."""
    status: Literal['CAPTURED_CLASSIFICATION_CONFLICT'] = 'CAPTURED_CLASSIFICATION_CONFLICT'
    classification_source: Literal['PIPE_TOKEN'] = 'PIPE_TOKEN'
    reason: Identifier


class _CapturedClassificationUnavailable(_Binding):
    """Post-revert server-side classification failure on a captured pipe token."""
    status: Literal['CAPTURED_CLASSIFICATION_UNAVAILABLE'] = (
        'CAPTURED_CLASSIFICATION_UNAVAILABLE'
    )
    classification_source: Literal['PIPE_TOKEN'] = 'PIPE_TOKEN'
    failure_scope: Literal['SERVER_CLASSIFICATION'] = 'SERVER_CLASSIFICATION'
    information_class: Literal[29, 31]
    failure_reason: Identifier
    winerror: int | None = Field(default=None, strict=True, ge=0, le=MAX_WINERROR)


class _CaptureUnavailable(_Binding):
    """No pipe token handle was captured; binding still identifies the failed attempt."""
    status: Literal['CAPTURE_UNAVAILABLE'] = 'CAPTURE_UNAVAILABLE'
    failure_scope: Literal['CAPTURE'] = 'CAPTURE'
    failed_stage: Literal['IMPERSONATE', 'OPEN_THREAD_TOKEN']
    winerror: int = Field(strict=True, ge=0, le=MAX_WINERROR)


PipePeerAdmissionEvidence = Annotated[
    _CapturedAppContainer
    | _CapturedNonAppContainer
    | _CapturedClassificationConflict
    | _CapturedClassificationUnavailable
    | _CaptureUnavailable,
    Field(discriminator='status'),
]

__all__ = [
    'EXIT_REVERT_FAILED',
    'PipeContextProducer',
    'PipeContextProducerError',
    'PipePeerAdmissionEvidence',
]


def _winerror(api):
    value = api._error()  # NativePipeTokenAPI owns the last-error reader.
    return value if type(value) is int and 0 <= value <= MAX_WINERROR else 0


def _probe_failure(probe, error):
    reason = str(error)
    if reason.startswith('QUERY_29_'):
        information_class = 29
    elif reason.startswith('QUERY_31_') or reason.startswith('APPCONTAINER_'):
        information_class = 31
    else:
        raise PipeContextProducerError('UNEXPECTED_PROBE_FAILURE') from error
    raw_error = probe._error()
    winerror = raw_error if type(raw_error) is int and 0 < raw_error <= MAX_WINERROR else None
    return information_class, reason, winerror


def _binding_from_live_lease(lease):
    if type(lease) is not OwnedProcessLease:
        raise PipeContextProducerError('OWNED_PROCESS_LEASE_REQUIRED')
    lease._owner_check()
    if lease._fatal or lease._consumed or lease._handle is None:
        raise PipeContextProducerError('LIVE_PROCESS_LEASE_REQUIRED')
    endpoint = lease._endpoint
    endpoint._guard()
    if endpoint._handle != lease._pipe or not endpoint._connected or endpoint._active is not None:
        raise PipeContextProducerError('CONNECTED_IDLE_ENDPOINT_REQUIRED')

    connect_plans = [
        operation._plan
        for operation in endpoint._operations.values()
        if type(operation._plan) is PipeOperationPlan and operation._plan.kind == 'CONNECT'
    ]
    if len(connect_plans) != 1:
        raise PipeContextProducerError('EXACT_CONNECTION_BINDING_REQUIRED')
    connection = connect_plans[0]
    return dict(
        connection_operation_id=connection.operation_id,
        pipe_lease_id=connection.pipe_lease_id,
        process_lease_operation_id=lease._plan.operation_id,
        process_pid=lease._pin.pid,
        process_creation_filetime=lease._pin.creation_filetime,
    )


class PipeContextProducer:
    """One-capture-per-connection producer; capture_ordinal is always 1 in v1.

    Substitution resistance comes from the internally read connection/lease/process
    binding. The ordinal is an explicit v1 invariant and reserves schema space for
    a future multi-capture design; it is not the current substitution mechanism.
    A lease is claimed once on entry and remains claimed after every later failure,
    including token-close failure; the producer never retries the same connection.
    """

    def __init__(self, *, api, probe):
        if type(api) is not NativePipeTokenAPI or type(probe) is not NativeAppContainerProbe:
            raise TypeError('EXACT_NATIVE_COMPONENTS_REQUIRED')
        # The real API explicitly binds OpenThreadToken(..., TOKEN_QUERY, TRUE, ...).
        # Bind fatal-revert calls here so the failure branch itself performs only
        # the required native termination statement.
        api.kernel.GetCurrentProcess.argtypes = []
        api.kernel.GetCurrentProcess.restype = c.c_void_p
        api.kernel.TerminateProcess.argtypes = [c.c_void_p, c.c_uint32]
        api.kernel.TerminateProcess.restype = c.c_int32
        self._self_process = api.kernel.GetCurrentProcess()
        self._api, self._probe = api, probe

    def produce(self, lease) -> PipePeerAdmissionEvidence:
        binding = _binding_from_live_lease(lease)
        with _CLAIM_LOCK:
            if lease in _CLAIMED:
                raise PipeContextProducerError('CONNECTION_ALREADY_CAPTURED')
            binding['capture_ordinal'] = 1
            # Claims are one-shot: failed capture does not permit retry on this lease.
            _CLAIMED[lease] = True

        owner = threading.get_ident()
        pipe = lease._pipe
        if not self._api.impersonate(pipe):
            return _CaptureUnavailable(
                **binding, failed_stage='IMPERSONATE', winerror=_winerror(self._api)
            )

        token = None
        capture_error = None
        try:
            if threading.get_ident() != owner:
                raise PipeContextProducerError('THREAD_AFFINITY_VIOLATION')
            try:
                token = self._api.open_thread_token()
                if token is None:
                    capture_error = _winerror(self._api)
            except TokenCaptureError:
                capture_error = _winerror(self._api)
        finally:
            # Microsoft: after RevertToSelf failure execution remains in the
            # client's context; terminate immediately rather than run Python
            # cleanup/logging. https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
            if not self._api.revert():
                self._api.kernel.TerminateProcess(self._self_process, EXIT_REVERT_FAILED)

        if token is None:
            return _CaptureUnavailable(
                **binding,
                failed_stage='OPEN_THREAD_TOKEN',
                winerror=capture_error,
            )

        try:
            try:
                evidence = self._probe.probe(
                    token, token_type='IMPERSONATION', level='IMPERSONATION'
                )
            except AppContainerProbeError as error:
                kind, reason, winerror = _probe_failure(self._probe, error)
                return _CapturedClassificationUnavailable(
                    **binding,
                    information_class=kind,
                    failure_reason=reason,
                    winerror=winerror,
                )

            result = evaluate_appcontainer_exclusion(evidence)
            if result.status == 'APPCONTAINER':
                return _CapturedAppContainer(**binding, evidence=evidence)
            if result.status == 'PROVEN_NON_APPCONTAINER':
                return _CapturedNonAppContainer(**binding, evidence=evidence)
            if result.status == 'INDETERMINATE':
                return _CapturedClassificationConflict(**binding, reason=result.reason)
            raise PipeContextProducerError('UNEXPECTED_CLASSIFIER_OUTCOME')
        finally:
            if not self._api.close(token):
                raise PipeContextProducerError('TOKEN_CLOSE_FAILED')
