"""Bound dual AppContainer evidence producer for native Windows admission.

The pipe axis classifies the exact token carried by the thread that established the
named-pipe connection. The process-primary axis independently classifies the PRIMARY
token of the correlated process instance retained by OwnedProcessLease.

This module produces immutable facts only. It does not evaluate admission.
"""
import ctypes as c
from contextlib import ExitStack
import os
import threading
import weakref

from pydantic import ValidationError

from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import (
    AppContainerProbeError,
    NativeAppContainerProbe,
)
from tnc.provenance.windows_peer_admission_evidence import (
    PeerAdmissionEvidence,
    PipePeerAdmissionEvidence,
    ProcessPrimaryAppContainerEvidence,
    ProcessPrimaryFailureReason,
    _CapturedAppContainer,
    _CapturedClassificationConflict,
    _CapturedClassificationUnavailable,
    _CapturedNonAppContainer,
    _CaptureUnavailable,
    _ProcessPrimaryCapturedAppContainer,
    _ProcessPrimaryCapturedNonAppContainer,
    _ProcessPrimaryClassificationConflict,
    _ProcessPrimaryClassificationUnavailable,
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


__all__ = [
    "EXIT_REVERT_FAILED",
    "PeerAdmissionEvidence",
    "PipeContextProducer",
    "PipeContextProducerError",
    "PipePeerAdmissionEvidence",
    "ProcessPrimaryAppContainerEvidence",
    "ProcessPrimaryFailureReason",
]


def _winerror(api):
    value = api._error()  # NativePipeTokenAPI owns the last-error reader.
    return value if type(value) is int and 0 <= value <= MAX_WINERROR else 0


def _optional_winerror(value):
    return value if type(value) is int and 0 < value <= MAX_WINERROR else None


def _required_probe_failure(error, *, axis):
    raw = str(error)
    if raw.startswith('QUERY_29_'):
        information_class = 29
        detail = raw[len('QUERY_29_'):]
    elif raw.startswith('QUERY_31_'):
        information_class = 31
        detail = raw[len('QUERY_31_'):]
    elif raw == 'APPCONTAINER_INFO_HEADER':
        return raw, 31, 'APPCONTAINER_INFO_HEADER_INVALID', None
    elif raw == 'APPCONTAINER_SID_INVALID':
        return raw, 31, 'APPCONTAINER_SID_INVALID', None
    else:
        raise PipeContextProducerError(f'UNEXPECTED_{axis}_PROBE_FAILURE') from error

    if detail.startswith('FAILED_'):
        try:
            winerror = int(detail[len('FAILED_'):])
        except ValueError as exc:
            raise PipeContextProducerError(f'MALFORMED_{axis}_PROBE_FAILURE') from exc
        reason = 'QUERY_FAILED'
    else:
        winerror = None
        reason = {
            'LENGTH': 'QUERY_LENGTH_INVALID',
            'BOOLEAN': 'QUERY_BOOLEAN_INVALID',
            'SIZE_PROBE': 'QUERY_SIZE_PROBE_FAILED',
            'BOUND': 'QUERY_BOUND_INVALID',
            'RETURN_LENGTH': 'QUERY_RETURN_LENGTH_INVALID',
        }.get(detail)
        if reason is None:
            raise PipeContextProducerError(f'UNMAPPED_{axis}_PROBE_FAILURE') from error
    return raw, information_class, reason, _optional_winerror(winerror)


def _probe_failure(probe, error):
    raw, information_class, _reason, parsed_winerror = _required_probe_failure(
        error,
        axis='PIPE',
    )
    observed_winerror = _optional_winerror(probe._error())
    return information_class, raw, parsed_winerror or observed_winerror


def _process_probe_failure(probe, error):
    _raw, information_class, reason, winerror = _required_probe_failure(
        error,
        axis='PROCESS_PRIMARY',
    )
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
        capture_ordinal=1,
    )


def _classify_pipe_axis(probe, token, binding):
    try:
        evidence = probe.probe(token, token_type='IMPERSONATION', level='IMPERSONATION')
    except AppContainerProbeError as error:
        kind, reason, winerror = _probe_failure(probe, error)
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
    if (
        result.status == 'INDETERMINATE'
        and result.reason == 'APPCONTAINER_SIGNAL_CONFLICT'
    ):
        return _CapturedClassificationConflict(**binding, reason=result.reason)
    raise PipeContextProducerError('UNEXPECTED_CLASSIFIER_OUTCOME')


def _classify_process_primary_axis(probe, token, binding):
    try:
        evidence = probe.probe(token, token_type='PRIMARY', level=None)
    except AppContainerProbeError as error:
        kind, reason, winerror = _process_probe_failure(probe, error)
        return _ProcessPrimaryClassificationUnavailable(
            **binding,
            failed_stage='GET_TOKEN_INFORMATION',
            information_class=kind,
            failure_reason=reason,
            winerror=winerror,
        )

    result = evaluate_appcontainer_exclusion(evidence)
    if result.status == 'APPCONTAINER':
        return _ProcessPrimaryCapturedAppContainer(**binding, evidence=evidence)
    if result.status == 'PROVEN_NON_APPCONTAINER':
        return _ProcessPrimaryCapturedNonAppContainer(**binding, evidence=evidence)
    if (
        result.status == 'INDETERMINATE'
        and result.reason == 'APPCONTAINER_SIGNAL_CONFLICT'
    ):
        return _ProcessPrimaryClassificationConflict(**binding)
    raise PipeContextProducerError('UNEXPECTED_PROCESS_PRIMARY_CLASSIFIER_OUTCOME')


class PipeContextProducer:
    """One dual-axis evidence transaction per live connection/lease."""

    def __init__(self, *, api, probe):
        if type(api) is not NativePipeTokenAPI or type(probe) is not NativeAppContainerProbe:
            raise TypeError('EXACT_NATIVE_COMPONENTS_REQUIRED')

        # Fatal-revert calls are pre-bound so the failure branch itself performs
        # only the required native termination statement.
        api.kernel.GetCurrentProcess.argtypes = []
        api.kernel.GetCurrentProcess.restype = c.c_void_p
        api.kernel.TerminateProcess.argtypes = [c.c_void_p, c.c_uint32]
        api.kernel.TerminateProcess.restype = c.c_int32
        self._self_process = api.kernel.GetCurrentProcess()

        # The process PRIMARY token is opened from the already-retained lease
        # process handle. Binding it here keeps token acquisition in this producer.
        process_token = api.security.OpenProcessToken
        process_token.argtypes = [c.c_void_p, c.c_uint32, c.POINTER(c.c_void_p)]
        process_token.restype = c.c_int32
        self._api, self._probe = api, probe

    def _close_token(self, token):
        if not self._api.close(token):
            raise PipeContextProducerError('TOKEN_CLOSE_FAILED')

    def _open_process_primary_token(self, lease, binding):
        token = c.c_void_p()
        try:
            ok = self._api.security.OpenProcessToken(
                lease._handle,
                TOKEN_QUERY,
                c.byref(token),
            )
        except OSError as error:
            return None, _ProcessPrimaryClassificationUnavailable(
                **binding,
                failed_stage='OPEN_PROCESS_TOKEN',
                information_class=None,
                failure_reason='OPEN_PROCESS_TOKEN_FAILED',
                winerror=_optional_winerror(getattr(error, 'winerror', None)),
            )
        if not ok:
            return None, _ProcessPrimaryClassificationUnavailable(
                **binding,
                failed_stage='OPEN_PROCESS_TOKEN',
                information_class=None,
                failure_reason='OPEN_PROCESS_TOKEN_FAILED',
                winerror=_optional_winerror(_winerror(self._api)),
            )
        value = token.value
        if type(value) is not int or not 0 < value < c.c_void_p(-1).value:
            raise PipeContextProducerError('INVALID_PROCESS_PRIMARY_TOKEN_HANDLE')
        return value, None

    def produce(self, lease) -> PeerAdmissionEvidence:
        binding = _binding_from_live_lease(lease)
        with _CLAIM_LOCK:
            if lease in _CLAIMED:
                raise PipeContextProducerError('CONNECTION_ALREADY_CAPTURED')
            _CLAIMED[lease] = True

        owner = threading.get_ident()
        pipe_token = None
        pipe_axis = None

        if not self._api.impersonate(lease._pipe):
            pipe_axis = _CaptureUnavailable(
                **binding,
                failed_stage='IMPERSONATE',
                winerror=_winerror(self._api),
            )
        else:
            capture_error = None
            try:
                if threading.get_ident() != owner:
                    raise PipeContextProducerError('THREAD_AFFINITY_VIOLATION')
                try:
                    pipe_token = self._api.open_thread_token()
                    if pipe_token is None:
                        capture_error = _winerror(self._api)
                except TokenCaptureError:
                    capture_error = _winerror(self._api)
            finally:
                # After RevertToSelf failure execution remains in the client's
                # context. Terminate immediately: no ExitStack or Python cleanup.
                if not self._api.revert():
                    self._api.kernel.TerminateProcess(
                        self._self_process,
                        EXIT_REVERT_FAILED,
                    )
            if pipe_token is None:
                pipe_axis = _CaptureUnavailable(
                    **binding,
                    failed_stage='OPEN_THREAD_TOKEN',
                    winerror=capture_error,
                )

        try:
            with ExitStack() as cleanup:
                if pipe_token is not None:
                    cleanup.callback(self._close_token, pipe_token)
                    pipe_axis = _classify_pipe_axis(self._probe, pipe_token, binding)

                process_token, process_axis = self._open_process_primary_token(lease, binding)
                if process_token is not None:
                    cleanup.callback(self._close_token, process_token)
                    process_axis = _classify_process_primary_axis(
                        self._probe,
                        process_token,
                        binding,
                    )

                try:
                    return PeerAdmissionEvidence(
                        pipe_context=pipe_axis,
                        process_primary=process_axis,
                    )
                except ValidationError as error:
                    raise PipeContextProducerError(
                        'PEER_ADMISSION_EVIDENCE_VALIDATION_FAILED'
                    ) from error
        except PipeContextProducerError:
            raise
