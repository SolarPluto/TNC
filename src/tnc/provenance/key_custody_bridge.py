"""Test-only live observation handoff to ephemeral custody; no publication."""
import math
from uuid import uuid4

from tnc.provenance.authorization_models import Model, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.key_custody_logic import (
    KeyHandleRecord, CustodyCapabilities, CustodyTrustAnchor, CustodySignRequest,
    evaluate_custody_request,
)
from tnc.provenance.key_custody_provider import TestCustodyProvider, CustodyProviderResult
from tnc.provenance.mtls import MtlsConnection
from tnc.provenance.observation_bridge import TestObservationBridge
from tnc.provenance.observation_signer_adapter import (
    _SigningHandoff, _seconds, _copy, ObservationSigningError, CandidateAlreadyConsumedError,
)
from tnc.provenance.reconciliation_verifier import (
    ObservationRequest, ObservationPayload, ObservationTrustStore, ObservationTrustCheckpoint,
    observation_preimage, verify_observation,
)
from time import monotonic


class CustodyObservationConfiguration(Model):
    """Independent host inputs, never supplied by the network request."""
    signer_id: Identifier
    handle: KeyHandleRecord
    capabilities: CustodyCapabilities
    anchor: CustodyTrustAnchor
    trust_store: ObservationTrustStore
    trusted_checkpoint: ObservationTrustCheckpoint


class TestCustodyObservationBridge:
    """Uses the existing transient signing handoff and live transport checks.

    Configuration is a trusted host callback, read at each gate. It must return
    one coherent snapshot. This is not production configuration authentication.
    """
    __test__ = False

    def __init__(self, bridge, provider, *, configuration):
        if type(bridge) is not TestObservationBridge or type(provider) is not TestCustodyProvider:
            raise ValueError('Test bridge and provider required')
        if not callable(configuration):
            raise ValueError('Host configuration callback required')
        self._bridge, self._provider, self._configuration = bridge, provider, configuration

    def __reduce_ex__(self, protocol):
        raise TypeError('Custody bridge serialization forbidden')

    def _snapshot(self):
        config = self._configuration()
        if type(config) is not CustodyObservationConfiguration:
            raise ValueError('Exact host configuration required')
        raw = canonical_bytes(config)
        if len(raw) > 1048576:
            raise ValueError('Configuration bound exceeded')
        return decode_canonical(CustodyObservationConfiguration, raw)

    def sign(self, connection, handoff, *, expected_request, mode='SUCCESS'):
        """Burn once, preserve deadline, dispatch once, independently verify release."""
        try:
            if type(handoff) is not _SigningHandoff:
                raise ObservationSigningError('Signing denied')
            candidate, deadline = handoff._take(self._bridge, connection)
            if type(connection) is not MtlsConnection:
                raise ObservationSigningError('Signing denied')
            request = _copy(expected_request, ObservationRequest)
            if request != candidate.request:
                raise ObservationSigningError('Signing denied')
            config = self._snapshot()
            config_bytes = canonical_bytes(config)
            start = monotonic()

            def check():
                tick = monotonic()
                if not math.isfinite(tick) or not start <= tick < deadline:
                    raise ObservationSigningError('Signing denied')
                if canonical_bytes(self._snapshot()) != config_bytes:
                    raise ObservationSigningError('Signing denied')

            check()
            live = self._bridge._transport._revalidate(canonical_bytes(request), candidate.binding, connection, deadline)
            now = live.valid_from
            issued = _seconds(now)
            trust, cp, handle = config.trust_store, config.trusted_checkpoint, config.handle
            raw_public = self._provider.public_key_bytes
            key = next((k for k in trust.keys if k.key_id == handle.key_id), None)
            scope = lambda v: (v.deployment_id, v.store_instance_id)
            if (raw_public.hex() != handle.public_key_hex or key is None
                    or key.public_key_hex != handle.public_key_hex or key.status != 'active'
                    or scope(trust) != scope(request) or scope(cp) != scope(request)
                    or cp.revision != trust.revision or cp.trust_store_digest != record_digest(trust)
                    or key.issuer_id != request.issuer_id or key.envelope_issuer_id != candidate.envelope.issuer_id
                    or 'AUTHORITY_OBSERVE_CURRENT' not in key.permissions):
                raise ObservationSigningError('Signing denied')
            if any(type(v) is not int or not 0 <= v <= 2**63-1
                   for item in (request, trust, cp, key) for v in (item.timestamp, item.expiry)):
                raise ObservationSigningError('Signing denied')
            lower = max(request.timestamp, _seconds(candidate.valid_from, upper=True),
                _seconds(candidate.envelope.valid_from, upper=True), key.timestamp, trust.timestamp, cp.timestamp,
                handle.timestamp, config.capabilities.timestamp, config.anchor.timestamp)
            expiry = min(request.expiry, _seconds(candidate.valid_until), _seconds(live.valid_until),
                _seconds(candidate.envelope.valid_until), key.expiry, trust.expiry, cp.expiry,
                handle.expiry, config.capabilities.expiry, config.anchor.expiry,
                issued + math.floor(deadline - monotonic()))
            if not lower <= issued < expiry:
                raise ObservationSigningError('Signing denied')
            payload = ObservationPayload(**{**request.model_dump(), 'timestamp':issued, 'expiry':expiry},
                request_digest=candidate.request_digest, signing_key_id=handle.key_id,
                trust_revision=cp.revision, trust_store_digest=cp.trust_store_digest,
                policy_revision=candidate.policy_revision, policy_digest=candidate.policy_digest,
                authority_revision=candidate.envelope.authority_revision,
                envelope_digest=candidate.envelope_digest, envelope=candidate.envelope)
            attempt_id = uuid4().hex
            custody_request = CustodySignRequest(attempt_id=attempt_id, signer_id=config.signer_id,
                handle_digest=record_digest(handle), timestamp=issued, expiry=expiry,
                payload=payload, preimage_hex=observation_preimage(payload).hex())
            custody_args = dict(handle=handle, capabilities=config.capabilities, trusted_anchor=config.anchor,
                expected_request=request, signer_id=config.signer_id)
            if evaluate_custody_request(custody_request, now=issued, **custody_args).status != 'READY':
                raise ObservationSigningError('Signing denied')
            # Recheck immediately before creating the provider handoff and dispatch.
            check()
            before = self._bridge._transport._revalidate(canonical_bytes(request), live, connection, deadline)
            if before.valid_from < now or _seconds(before.valid_until) < expiry:
                raise ObservationSigningError('Signing denied')
            check()
            provider_handoff = self._provider.mint_handoff_for_testing(attempt_id, custody_request, deadline=deadline)
            returned = self._provider.sign(provider_handoff, **custody_args, mode=mode)
            check()
            if (type(returned) is not CustodyProviderResult or returned.status != 'VERIFIED'
                    or returned.response is None or returned.response.payload != payload):
                raise ObservationSigningError('Signing denied')
            final = self._bridge._transport._revalidate(canonical_bytes(request), before, connection, deadline)
            if final.valid_from < before.valid_from or _seconds(final.valid_until) < expiry:
                raise ObservationSigningError('Signing denied')
            verified = verify_observation(returned.response, expected_request=request, trust_store=trust,
                trusted_checkpoint=cp, now=_seconds(final.valid_from))
            if verified.status != 'VERIFIED':
                raise ObservationSigningError('Signing denied')
            released = self._bridge._transport._revalidate(canonical_bytes(request), final, connection, deadline)
            if released.valid_from < final.valid_from or not _seconds(released.valid_from) < expiry <= _seconds(released.valid_until):
                raise ObservationSigningError('Signing denied')
            check()
            return returned.response
        except CandidateAlreadyConsumedError:
            raise
        except Exception:
            raise ObservationSigningError('Signing denied') from None
