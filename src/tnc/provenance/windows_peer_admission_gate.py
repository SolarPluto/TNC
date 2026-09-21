"""Fail-closed native Windows peer admission gate.

Phase 1 intentionally has no admitted state. It composes already-produced native
process-lease, peer-audit, and pipe-context evidence. Positive AppContainer status
is an unconditional hard exclusion; established lease/peer denials then retain
their specific reasons before pipe-context epistemic failures are considered.
No token acquisition, handle ownership, grants, custody, or signing occur here.
"""
from typing import Literal

from pydantic import TypeAdapter, model_validator

from tnc.provenance.authorization_models import Model, Identifier, canonical_bytes, decode_canonical
from tnc.provenance.windows_pipe_auth_bridge import NativePeerAuditResult
from tnc.provenance.windows_pipe_context_producer import PipePeerAdmissionEvidence
from tnc.provenance.windows_pipe_process_lease import ProcessLeaseAudit

MAX_RECORD = 65536

LEGAL_RESULT_PAIRS = frozenset({
    ('DENIED', 'APP_CONTAINER_DENIED'),
    ('DENIED', 'DESCRIPTOR_CHANGED'),
    ('DENIED', 'DESCRIPTOR_MISMATCH'),
    ('DENIED', 'ENDPOINT_CORRELATION_MISMATCH'),
    ('DENIED', 'INTEGRITY_LEVEL_DENIED'),
    ('DENIED', 'PEER_CLASS_UNSUPPORTED'),
    ('DENIED', 'PROCESS_CORRELATION_MISMATCH'),
    ('DENIED', 'PROCESS_LEASE_NOT_CORRELATED'),
    ('DENIED', 'PROCESS_LIFETIME_MISMATCH'),
    ('DENIED', 'READ_BINDING_MISMATCH'),
    ('DENIED', 'RESTRICTED_CONTEXT_DENIED'),
    ('DENIED', 'SCOPE_MISMATCH'),
    ('DENIED', 'TIME_MISMATCH'),
    ('DENIED', 'TOKEN_IDENTITY_MISMATCH'),
    ('DENIED', 'TOKEN_PROFILE_DENIED'),
    ('INDETERMINATE', 'INVALID_ADMISSION_EVIDENCE'),
    ('INDETERMINATE', 'INVALID_RECORD'),
    ('INDETERMINATE', 'NATIVE_CAPTURE_REQUIRED'),
    ('INDETERMINATE', 'NATIVE_PROCESS_LEASE_REQUIRED'),
    ('INDETERMINATE', 'PEER_ADMISSION_NOT_IMPLEMENTED'),
    ('INDETERMINATE', 'PEER_AUDIT_CONTRACT_VIOLATION'),
    ('INDETERMINATE', 'PEER_EVIDENCE_UNAVAILABLE'),
    ('INDETERMINATE', 'PIPE_CONTEXT_CLASSIFICATION_CONFLICT'),
    ('INDETERMINATE', 'PROCESS_LEASE_CONTRACT_VIOLATION'),
})

_PIPE_CONTEXT_ADAPTER = TypeAdapter(PipePeerAdmissionEvidence)


class AdmissionEvaluatorInvariantError(RuntimeError):
    """Evaluator mapping bug; never a malformed-evidence classification."""


class NativePeerAdmissionResult(Model):
    profile: Literal['tnc-native-peer-admission-v1'] = 'tnc-native-peer-admission-v1'
    status: Literal['DENIED', 'INDETERMINATE']
    reason: Identifier
    admission_granted: Literal[False] = False
    authorization_granted: Literal[False] = False
    grants_evaluated: Literal[False] = False
    signing_evaluated: Literal[False] = False

    @model_validator(mode='after')
    def legal_pair(self):
        pair = (self.status, self.reason)
        if pair not in LEGAL_RESULT_PAIRS:
            raise ValueError(
                f'illegal admission result pair {pair!r}; legal pairs={sorted(LEGAL_RESULT_PAIRS)!r}'
            )
        return self


def _exact_copy(kind, value):
    if type(value) is not kind:
        raise ValueError('EXACT_RECORD_REQUIRED')
    raw = canonical_bytes(value)
    if len(raw) > MAX_RECORD:
        raise ValueError('RECORD_BOUND')
    return decode_canonical(kind, raw)


def _exact_pipe_context(value):
    if not isinstance(value, Model):
        raise ValueError('EXACT_PIPE_CONTEXT_REQUIRED')
    raw = canonical_bytes(value)
    if len(raw) > MAX_RECORD:
        raise ValueError('RECORD_BOUND')
    copied = _PIPE_CONTEXT_ADAPTER.validate_json(raw)
    if type(copied) is not type(value):
        raise ValueError('EXACT_PIPE_CONTEXT_REQUIRED')
    return copied


def evaluate_native_peer_admission(*, lease, peer, pipe_context):
    """Compose native evidence without manufacturing a successful admission.

    Precedence after exact input validation is deliberate: positive AppContainer
    context denies first; established lease/peer violations retain their specific
    reasons next; pipe-context conflict/unavailability is considered only after
    those checks pass. A proven non-AppContainer context can reach only the
    procedural PEER_ADMISSION_NOT_IMPLEMENTED terminal state in this phase.

    The evaluator does not verify that lease and pipe_context originate from the
    same underlying connection. Callers must pair them. This is a caller contract,
    not an evaluator check: ProcessLeaseAudit carries no serializable connection or
    process identity, while the producer establishes pipe_context binding against
    the live OwnedProcessLease before finish(). A future audit-schema extension may
    make this pairing independently checkable here.
    """
    def result(reason, status='DENIED'):
        try:
            return NativePeerAdmissionResult(status=status, reason=reason)
        except ValueError as exc:
            raise AdmissionEvaluatorInvariantError(
                f'illegal evaluator output {(status, reason)!r}'
            ) from exc

    try:
        lease = _exact_copy(ProcessLeaseAudit, lease)
        peer = _exact_copy(NativePeerAuditResult, peer)
        pipe_context = _exact_pipe_context(pipe_context)

        if pipe_context.status == 'CAPTURED_APPCONTAINER':
            return result('APP_CONTAINER_DENIED')

        if lease.source != 'NATIVE_PROCESS_API':
            return result('NATIVE_PROCESS_LEASE_REQUIRED', 'INDETERMINATE')
        if lease.status != 'CORRELATED' or lease.reason != 'AUDIT_MATCHED':
            return result('PROCESS_LEASE_NOT_CORRELATED')
        if not lease.audit_only or lease.authorization_granted:
            return result('PROCESS_LEASE_CONTRACT_VIOLATION', 'INDETERMINATE')

        if peer.authorization_granted or peer.grants_evaluated or not peer.audit_only:
            return result('PEER_AUDIT_CONTRACT_VIOLATION', 'INDETERMINATE')
        if peer.status == 'VIOLATIONS':
            return result(peer.reason)
        if peer.reason == 'CAPTURE_UNAVAILABLE':
            return result('PEER_EVIDENCE_UNAVAILABLE', 'INDETERMINATE')
        if peer.reason != 'APP_CONTAINER_EXCLUSION_UNPROVEN':
            return result(peer.reason, 'INDETERMINATE')

        if pipe_context.status == 'CAPTURED_CLASSIFICATION_CONFLICT':
            return result('PIPE_CONTEXT_CLASSIFICATION_CONFLICT', 'INDETERMINATE')
        if pipe_context.status in {
            'CAPTURED_CLASSIFICATION_UNAVAILABLE',
            'CAPTURE_UNAVAILABLE',
        }:
            return result('PEER_EVIDENCE_UNAVAILABLE', 'INDETERMINATE')
        if pipe_context.status == 'CAPTURED_NON_APPCONTAINER':
            return result('PEER_ADMISSION_NOT_IMPLEMENTED', 'INDETERMINATE')

        raise AdmissionEvaluatorInvariantError(
            f'unhandled pipe_context status: {pipe_context.status}'
        )
    except (ValueError, TypeError, AttributeError):
        return result('INVALID_ADMISSION_EVIDENCE', 'INDETERMINATE')
