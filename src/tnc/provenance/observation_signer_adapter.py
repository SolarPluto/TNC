"""Ephemeral test signing only. No imported private keys, secret stores or publication."""
from datetime import datetime, timezone
from hashlib import sha256
import math
import os
from threading import Lock, get_ident
from time import monotonic

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from tnc.provenance.authorization_models import canonical_bytes, decode_canonical, record_digest
from tnc.provenance.observation_bridge import TestObservationBridge, UnsignedObservationCandidate
from tnc.provenance.mtls import MtlsConnection
from tnc.provenance.reconciliation_verifier import (
    ObservationRequest, ObservationTrustStore, ObservationTrustCheckpoint,
    ObservationPayload, SignedObservation, decode_v2_record, observation_preimage,
    verify_observation,
)

_MINT = object()
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_TIME = 2**63 - 1


class ObservationSigningError(ValueError):
    pass


class CandidateAlreadyConsumedError(ObservationSigningError):
    pass


def _seconds(value, *, upper=False):
    """Exact nonnegative epoch arithmetic, without floating timestamp rounding."""
    if type(value) is not datetime or value.utcoffset() is None:
        raise ValueError('Aware clock required')
    delta = value.astimezone(timezone.utc) - _EPOCH
    micros = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    result = (micros + (999999 if upper else 0)) // 1000000
    if micros < 0 or not 0 <= result <= _MAX_TIME:
        raise ValueError('Invalid epoch')
    return result


def _check(deadline):
    if monotonic() >= deadline:
        raise ObservationSigningError('Signing denied')


class _SigningHandoff:
    __slots__ = ('_owner', '_connection', '_raw', '_digest', '_deadline', '_pid', '_thread', '_used', '_lock')

    def __init__(self, key, owner, connection, raw, deadline):
        if key is not _MINT:
            raise TypeError('Bridge-created handoff required')
        for name, value in dict(_owner=owner, _connection=connection, _raw=raw,
                _digest=sha256(raw).hexdigest(), _deadline=deadline, _pid=os.getpid(),
                _thread=get_ident(), _used=False, _lock=Lock()).items():
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise TypeError('Immutable signing handoff')

    def __reduce_ex__(self, protocol):
        raise TypeError('Signing handoff serialization forbidden')

    def __copy__(self):
        raise TypeError('Signing handoff copying forbidden')

    def __deepcopy__(self, memo):
        raise TypeError('Signing handoff copying forbidden')

    def _take(self, owner, connection):
        with self._lock:
            if self._used:
                raise CandidateAlreadyConsumedError('Candidate already consumed')
            object.__setattr__(self, '_used', True)
            if (self._owner is not owner or self._connection is not connection
                    or self._pid != os.getpid() or self._thread != get_ident()):
                raise ObservationSigningError('Signing denied')
            _check(self._deadline)
            if (type(self._raw) is not bytes or not 0 < len(self._raw) <= 131072
                    or sha256(self._raw).hexdigest() != self._digest):
                raise ObservationSigningError('Signing denied')
            return decode_canonical(UnsignedObservationCandidate, self._raw), self._deadline


def _mint_signing(owner, connection, candidate, deadline):
    _check(deadline)
    if type(candidate) is not UnsignedObservationCandidate:
        raise ValueError('Invalid candidate')
    raw = canonical_bytes(candidate)
    if not 0 < len(raw) <= 131072:
        raise ValueError('Invalid candidate')
    decode_canonical(UnsignedObservationCandidate, raw)
    return _SigningHandoff(_MINT, owner, connection, raw, deadline)


def _copy(value, kind):
    if type(value) is not kind:
        raise ValueError('Exact record required')
    return decode_v2_record(kind, canonical_bytes(value))


class TestObservationSignerAdapter:
    """Generates its own in-memory key; host supplies independent PUBLIC trust records.

    Private attributes are not a hostile-process security boundary. Keys are
    never exported by this API, but Python object lifetime is not secure erasure.
    """
    __test__ = False

    def __init__(self, bridge):
        if type(bridge) is not TestObservationBridge:
            raise ValueError('Host test bridge required')
        self._bridge = bridge
        self._private = Ed25519PrivateKey.generate()

    @property
    def public_key_bytes(self):
        if self._private is None:
            raise ObservationSigningError('Signing denied')
        return self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def close(self):
        self._private = None

    def __reduce_ex__(self, protocol):
        raise TypeError('Signer serialization forbidden')

    def sign(self, connection, handoff, *, expected_request, trust_store, trusted_checkpoint):
        """Consume first, recheck host context, sign once, and self-verify before return.

        A failure burns the handoff. No retry cache, network send, or storage write.
        """
        try:
            if type(handoff) is not _SigningHandoff:
                raise ObservationSigningError('Signing denied')
            candidate, deadline = handoff._take(self._bridge, connection)
            if type(connection) is not MtlsConnection or self._private is None:
                raise ObservationSigningError('Signing denied')
            request = _copy(expected_request, ObservationRequest)
            trust = _copy(trust_store, ObservationTrustStore)
            cp = _copy(trusted_checkpoint, ObservationTrustCheckpoint)
            if request != candidate.request:
                raise ObservationSigningError('Signing denied')
            live = self._bridge._transport._revalidate(canonical_bytes(request), candidate.binding, connection, deadline)
            now = live.valid_from
            issued = _seconds(now)
            scope = lambda v: (v.deployment_id, v.store_instance_id)
            raw_public = self.public_key_bytes
            key_id = sha256(raw_public).hexdigest()
            key = next((k for k in trust.keys if k.key_id == key_id), None)
            if (scope(trust) != scope(request) or scope(cp) != scope(request)
                    or cp.revision != trust.revision or cp.trust_store_digest != record_digest(trust)
                    or key is None or key.public_key_hex != raw_public.hex() or key.status != 'active'
                    or key.issuer_id != request.issuer_id or key.envelope_issuer_id != candidate.envelope.issuer_id
                    or 'AUTHORITY_OBSERVE_CURRENT' not in key.permissions):
                raise ObservationSigningError('Signing denied')
            if any(type(v) is not int or not 0 <= v <= _MAX_TIME
                    for item in (request, trust, cp, key) for v in (item.timestamp, item.expiry)):
                raise ObservationSigningError('Signing denied')
            lower = max(request.timestamp, _seconds(candidate.valid_from, upper=True),
                _seconds(candidate.envelope.valid_from, upper=True), key.timestamp, trust.timestamp, cp.timestamp)
            # Round the remaining monotonic lease down, never reset it at signing.
            remaining = math.floor(deadline - monotonic())
            expiry = min(request.expiry, _seconds(candidate.valid_until), _seconds(live.valid_until),
                _seconds(candidate.envelope.valid_until), key.expiry, trust.expiry, cp.expiry,
                issued + remaining)
            if not lower <= issued < expiry or request.expiry - request.timestamp > 60:
                raise ObservationSigningError('Signing denied')
            payload = ObservationPayload(**{**request.model_dump(), 'timestamp': issued, 'expiry': expiry},
                request_digest=candidate.request_digest, signing_key_id=key_id,
                trust_revision=cp.revision, trust_store_digest=cp.trust_store_digest,
                policy_revision=candidate.policy_revision, policy_digest=candidate.policy_digest,
                authority_revision=candidate.envelope.authority_revision,
                envelope_digest=candidate.envelope_digest, envelope=candidate.envelope)
            preimage = observation_preimage(payload)
            _check(deadline)
            response = SignedObservation(payload=payload, signature_hex=self._private.sign(preimage).hex())
            final = self._bridge._transport._revalidate(canonical_bytes(request), live, connection, deadline)
            if final.valid_from < now:
                raise ObservationSigningError('Signing denied')
            verified = verify_observation(response, expected_request=request, trust_store=trust,
                trusted_checkpoint=cp, now=_seconds(final.valid_from))
            _check(deadline)
            if verified.status != 'VERIFIED':
                raise ObservationSigningError('Signing denied')
            return response
        except CandidateAlreadyConsumedError:
            raise
        except Exception:
            raise ObservationSigningError('Signing denied') from None
