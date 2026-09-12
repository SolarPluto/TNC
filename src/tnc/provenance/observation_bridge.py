"""Authenticated handoff to a temporary test authority; unsigned audit candidates only."""
from typing import Literal
from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Digest, canonical_bytes, record_digest
from tnc.provenance.provisioning_models import Interval
from tnc.provenance.mtls import MtlsConnection
from tnc.provenance.observation_handoff import ObservationHandoff
from tnc.provenance.observation_request_binding import ObservationRequestBinding
from tnc.provenance.observation_request_transport import ObservationRequestTransport, _check
from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter
from tnc.provenance.reconciliation_models import ReconciliationEnvelope
from tnc.provenance.reconciliation_simulation import SyntheticAuthorityCaller
from tnc.provenance.reconciliation_verifier import ObservationRequest, decode_v2_record


class UnsignedObservationCandidate(Interval):
    source: Literal['SYNTHETIC_TEST_AUTHORITY'] = 'SYNTHETIC_TEST_AUTHORITY'
    unsigned: Literal[True] = True
    request: ObservationRequest
    request_digest: Digest
    binding: ObservationRequestBinding
    envelope: ReconciliationEnvelope
    envelope_digest: Digest
    policy_revision: int = Field(strict=True, gt=0)
    policy_digest: Digest

    @model_validator(mode='after')
    def bindings(self):
        r, b, e = self.request, self.binding, self.envelope
        if (self.request_digest != record_digest(r) or self.request_digest != b.request_digest
                or self.envelope_digest != record_digest(e)
                or (r.principal_id, r.deployment_id, r.store_instance_id, r.issuer_id) !=
                   (b.principal_id, b.deployment_id, b.store_instance_id, b.issuer_id)
                or (e.deployment_id, e.store_instance_id) != (r.deployment_id, r.store_instance_id)
                or not b.valid_from <= self.valid_from < self.valid_until <= b.valid_until):
            raise ValueError('Invalid candidate binding')
        return self


class ObservationBridgeResult(Model):
    status: Literal['CANDIDATE', 'DENIED']
    reason_code: Literal['ACCESS_DENIED'] | None = None
    candidate: UnsignedObservationCandidate | None = None
    @model_validator(mode='after')
    def shape(self):
        ok = self.status == 'CANDIDATE'
        if (self.candidate is not None) != ok or (self.reason_code is None) != ok:
            raise ValueError('Invalid bridge result')
        return self


class TestObservationBridge:
    """Host-owned adapter for the existing synthetic temporary authority store.

    This does not turn its synthetic policy into production authorization.
    Serializable audit records cannot enter this API as handoffs.
    """
    __test__ = False

    def __init__(self, transport, reader):
        if type(transport) is not ObservationRequestTransport or type(reader) is not ReadOnlyAuthorityAdapter:
            raise ValueError('Host adapters required')
        self._transport, self._reader = transport, reader

    def observe(self, connection, handoff):
        denied = ObservationBridgeResult(status='DENIED', reason_code='ACCESS_DENIED')
        try:
            if type(connection) is not MtlsConnection or type(handoff) is not ObservationHandoff:
                return denied
            raw, prior, deadline = handoff._take(self._transport, connection)
            live = self._transport._revalidate(raw, prior, connection, deadline)
            request = decode_v2_record(ObservationRequest, raw)
            # Explicit test-store compatibility context, derived only from live binding.
            caller = SyntheticAuthorityCaller(principal_id=live.principal_id,
                deployment_id=live.deployment_id, store_instance_id=live.store_instance_id,
                valid_from=live.valid_from, valid_until=live.valid_until)
            _check(deadline)
            snapshot = self._reader.observe_current_snapshot(request.challenge, caller=caller, now=live.valid_from)
            # Suppress output if host authorization changed during the read.
            final = self._transport._revalidate(raw, live, connection, deadline)
            observation, policy = snapshot.observation, snapshot.policy
            if (observation.principal_id != request.principal_id or observation.challenge != request.challenge
                    or (policy.deployment_id, policy.store_instance_id) != (request.deployment_id, request.store_instance_id)):
                return denied
            candidate = UnsignedObservationCandidate(request=request, request_digest=record_digest(request),
                binding=final, envelope=observation.envelope, envelope_digest=record_digest(observation.envelope),
                policy_revision=policy.revision, policy_digest=record_digest(policy), valid_from=final.valid_from,
                valid_until=min(final.valid_until, observation.valid_until))
            if len(canonical_bytes(candidate)) > 131072:
                return denied
            _check(deadline)
            return ObservationBridgeResult(status='CANDIDATE', candidate=candidate)
        except Exception:
            return denied
