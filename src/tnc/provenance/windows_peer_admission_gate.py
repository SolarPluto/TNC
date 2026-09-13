"""Fail-closed native Windows peer admission gate.

Phase 1 intentionally has no admitted state. It composes already-produced native
process-lease evidence with the native peer audit bridge and preserves the current
AppContainer exclusion blocker. No token acquisition, handle ownership, grants,
custody, or signing occur here.
"""
from typing import Literal

from tnc.provenance.authorization_models import Model, Identifier, canonical_bytes, decode_canonical
from tnc.provenance.windows_pipe_auth_bridge import NativePeerAuditResult
from tnc.provenance.windows_pipe_process_lease import ProcessLeaseAudit

MAX_RECORD = 65536


class NativePeerAdmissionResult(Model):
    profile: Literal['tnc-native-peer-admission-v1'] = 'tnc-native-peer-admission-v1'
    status: Literal['DENIED', 'INDETERMINATE']
    reason: Identifier
    admission_granted: Literal[False] = False
    authorization_granted: Literal[False] = False
    grants_evaluated: Literal[False] = False
    signing_evaluated: Literal[False] = False


def _exact_copy(kind, value):
    if type(value) is not kind:
        raise ValueError('EXACT_RECORD_REQUIRED')
    raw = canonical_bytes(value)
    if len(raw) > MAX_RECORD:
        raise ValueError('RECORD_BOUND')
    return decode_canonical(kind, raw)


def evaluate_native_peer_admission(*, lease, peer):
    """Compose native evidence without manufacturing a successful admission.

    A native process lease must have completed correlation successfully. The peer
    bridge must then have reached its single current all-other-checks-passed blocker:
    APP_CONTAINER_EXCLUSION_UNPROVEN. Any other state fails closed with a more
    specific reason. This function cannot return an admitted result by construction.
    """
    def result(reason, status='DENIED'):
        return NativePeerAdmissionResult(status=status, reason=reason)

    try:
        lease = _exact_copy(ProcessLeaseAudit, lease)
        peer = _exact_copy(NativePeerAuditResult, peer)

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
        if peer.reason != 'APP_CONTAINER_EXCLUSION_UNPROVEN':
            return result(peer.reason, 'INDETERMINATE')

        # Deliberate Phase 1 terminal state. Microsoft documents that a zero
        # TokenIsAppContainer result is insufficient for identification-level
        # impersonation tokens, which is the current TNC native peer profile.
        return result('APP_CONTAINER_EXCLUSION_UNPROVEN', 'INDETERMINATE')
    except (ValueError, TypeError, AttributeError):
        return result('INVALID_ADMISSION_EVIDENCE', 'INDETERMINATE')
