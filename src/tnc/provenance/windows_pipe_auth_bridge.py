"""Pure native-shaped audit comparison. No acquisition, grants, or signing.

Caller-supplied records (including source labels) are not native attestations.
Current capture records cannot prove AppContainer exclusion; no allow path exists.
"""
from typing import Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Identifier, Digest
from tnc.provenance.windows_custody_peer import (
    WindowsPeerPolicy, PeerProcess, PeerToken, PipeEndpoint,
    PipeSecurityObservation, Tick, _copy, _identity_mismatch,
)
from tnc.provenance.windows_pipe_token import TokenCaptureResult


class PeerReadBinding(Model):
    operation_id: Identifier
    preamble_digest: Digest


class PeerCorrelationAudit(Model):
    """Host-supplied observations, not proof of retained native process handles."""
    profile: Literal['tnc-native-peer-correlation-audit-v1'] = 'tnc-native-peer-correlation-audit-v1'
    deployment_id: Identifier
    store_instance_id: Identifier
    process_before: PeerProcess
    process_after: PeerProcess
    endpoint_before: PipeEndpoint
    endpoint_after: PipeEndpoint
    security_before: PipeSecurityObservation
    security_after: PipeSecurityObservation
    observed_at: Tick


class NativePeerAuditPolicy(Model):
    profile: Literal['tnc-native-peer-audit-v1'] = 'tnc-native-peer-audit-v1'
    identity: WindowsPeerPolicy
    minimum_integrity_rid: int = Field(default=0x2000, strict=True, ge=0x2000, le=2**32-1)


NATIVE_PEER_AUDIT_RESULT_PAIRS = frozenset({
    ('VIOLATIONS', 'APP_CONTAINER_DENIED'),
    ('VIOLATIONS', 'DESCRIPTOR_CHANGED'),
    ('VIOLATIONS', 'DESCRIPTOR_MISMATCH'),
    ('VIOLATIONS', 'ENDPOINT_CORRELATION_MISMATCH'),
    ('VIOLATIONS', 'INTEGRITY_LEVEL_DENIED'),
    ('VIOLATIONS', 'PROCESS_CORRELATION_MISMATCH'),
    ('VIOLATIONS', 'PROCESS_LIFETIME_MISMATCH'),
    ('VIOLATIONS', 'READ_BINDING_MISMATCH'),
    ('VIOLATIONS', 'RESTRICTED_CONTEXT_DENIED'),
    ('VIOLATIONS', 'SCOPE_MISMATCH'),
    ('VIOLATIONS', 'TIME_MISMATCH'),
    ('VIOLATIONS', 'TOKEN_IDENTITY_MISMATCH'),
    ('VIOLATIONS', 'TOKEN_PROFILE_DENIED'),
    ('INDETERMINATE', 'APP_CONTAINER_EXCLUSION_UNPROVEN'),
    ('INDETERMINATE', 'CAPTURE_UNAVAILABLE'),
    ('INDETERMINATE', 'INVALID_RECORD'),
    ('INDETERMINATE', 'NATIVE_CAPTURE_REQUIRED'),
})


class NativePeerAuditResult(Model):
    status: Literal['VIOLATIONS', 'INDETERMINATE']
    reason: Identifier
    audit_only: Literal[True] = True
    authorization_granted: Literal[False] = False
    grants_evaluated: Literal[False] = False

    @model_validator(mode='after')
    def legal_pair(self):
        pair = (self.status, self.reason)
        if pair not in NATIVE_PEER_AUDIT_RESULT_PAIRS:
            raise ValueError(
                f'illegal peer-audit result pair {pair!r}; '
                f'legal pairs={sorted(NATIVE_PEER_AUDIT_RESULT_PAIRS)!r}'
            )
        return self


class WindowsPipeAuthBridge:
    """Compare immutable audit inputs against independent host pins.

    This bridge deliberately has no successful admission result. A later native
    acquisition boundary must prove correlation and resolve sandbox uncertainty.
    """
    def __init__(self, policy):
        self._policy = _copy(NativePeerAuditPolicy, policy)

    def evaluate_native_peer(self, capture, correlation, *, retained_read, now):
        def result(reason, status='VIOLATIONS'):
            return NativePeerAuditResult(status=status, reason=reason)
        try:
            policy = _copy(NativePeerAuditPolicy, self._policy)
            capture = _copy(TokenCaptureResult, capture)
            correlation = _copy(PeerCorrelationAudit, correlation)
            retained_read = _copy(PeerReadBinding, retained_read)
            if type(now) is not int or not 0 <= now <= 2**63-1:
                raise ValueError('Exact epoch required')
            if capture.source != 'NATIVE_TOKEN_API':
                return result('NATIVE_CAPTURE_REQUIRED', 'INDETERMINATE')
            if capture.status != 'CAPTURED' or capture.reason != 'AUDIT_CAPTURE_ONLY' or capture.facts is None:
                return result('CAPTURE_UNAVAILABLE', 'INDETERMINATE')
            if (capture.operation_id, capture.preamble_digest) != (retained_read.operation_id, retained_read.preamble_digest):
                return result('READ_BINDING_MISMATCH')
            if (correlation.process_before != correlation.process_after
                    or not correlation.process_after.running):
                return result('PROCESS_CORRELATION_MISMATCH')
            endpoint = correlation.endpoint_after
            if (correlation.endpoint_before != endpoint or not endpoint.local or not endpoint.server_end):
                return result('ENDPOINT_CORRELATION_MISMATCH')
            if correlation.security_before != correlation.security_after:
                return result('DESCRIPTOR_CHANGED')
            facts = capture.facts
            # A filtered token and restricting SIDs are distinct captured facts;
            # either is conservatively denied by this explicit profile.
            if facts.app_container_reported:
                return result('APP_CONTAINER_DENIED')
            if facts.has_restrictions or facts.restricted_sids_present:
                return result('RESTRICTED_CONTEXT_DENIED')
            if facts.integrity_rid < policy.minimum_integrity_rid:
                return result('INTEGRITY_LEVEL_DENIED')
            if facts.level != 'IDENTIFICATION':
                return result('TOKEN_PROFILE_DENIED')
            token = PeerToken(user_sid=facts.user_sid, logon_sid=facts.logon_sid,
                authentication_id=facts.authentication_id, session_id=facts.session_id,
                token_type=facts.token_type, level=facts.level, logon_enabled=True,
                restricted=False, app_container=False)
            # Reuse identity comparisons only. Do not create a fake observation
            # or invoke the v1 fake-only acceptance path with native claims.
            reason = _identity_mismatch(policy.identity,
                scope=(correlation.deployment_id, correlation.store_instance_id, endpoint.name),
                observed_at=correlation.observed_at, process=correlation.process_after,
                token=token, security=correlation.security_after, now=now)
            if reason:
                return result(reason)
            return result('APP_CONTAINER_EXCLUSION_UNPROVEN', 'INDETERMINATE')
        except (ValueError, TypeError, AttributeError):
            return result('INVALID_RECORD', 'INDETERMINATE')
