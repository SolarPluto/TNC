"""Test-only ephemeral raw Ed25519 provider; no production signing authority."""
from dataclasses import dataclass
from hashlib import sha256
import math
import os
from threading import RLock, get_ident
from time import monotonic, time

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.key_custody_logic import CustodySignRequest, decode_custody_record, evaluate_custody_request
from tnc.provenance.reconciliation_verifier import SignedObservation

_MINT = object()
_MODES = frozenset(('SUCCESS', 'WRONG_KEY', 'TAMPERED_SIGNATURE', 'INVALID_SIGNATURE',
    'UNSUPPORTED_MECHANISM', 'DEADLINE_EXPIRED', 'AMBIGUOUS_OUTCOME',
    'LATE_RESULT_REJECTION', 'PROVIDER_FAILURE'))


class _DefinitiveFailure(Exception):
    pass


@dataclass(frozen=True)
class CustodyProviderResult:
    status: str
    response: SignedObservation | None = None

    @property
    def signature_verified(self):
        return self.status == 'VERIFIED' and self.response is not None


class _TestHandoff:
    __slots__ = ('_id',)

    def __init__(self, mint, handoff_id):
        if mint is not _MINT:
            raise TypeError('Provider-minted test handoff required')
        object.__setattr__(self, '_id', handoff_id)

    def __setattr__(self, name, value):
        raise TypeError('Immutable test handoff')

    def __reduce_ex__(self, protocol):
        raise TypeError('Handoff serialization forbidden')

    def __copy__(self):
        raise TypeError('Handoff copying forbidden')

    def __deepcopy__(self, memo):
        raise TypeError('Handoff copying forbidden')


def _mono(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('Invalid monotonic clock')
    return value


class TestCustodyProvider:
    """Bounded, process-local test custody. Public pins are supplied independently.

    Minting is fixture plumbing, not authorization. Private Python attributes are
    not a hostile-process boundary; close does not promise secure key erasure.
    """
    __test__ = False
    MAX_HANDOFFS = 256

    def __init__(self, *, monotonic_clock=monotonic, epoch_clock=lambda: int(time())):
        self._clock, self._epoch = monotonic_clock, epoch_clock
        self._private = Ed25519PrivateKey.generate()
        self._public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._lock = RLock()
        self._pid = os.getpid()
        self._handoffs = {}
        self._ids = set()
        self._dispatch_count = 0

    @property
    def public_key_bytes(self):
        return self._public

    @property
    def dispatch_count(self):
        return self._dispatch_count

    def __reduce_ex__(self, protocol):
        raise TypeError('Provider serialization forbidden')

    def __copy__(self):
        raise TypeError('Provider copying forbidden')

    def __deepcopy__(self, memo):
        raise TypeError('Provider copying forbidden')

    def close(self):
        with self._lock:
            self._private = None

    def mint_handoff_for_testing(self, handoff_id, request, *, deadline):
        """Capture exact bytes and original deadline. IDs never evicted or reused."""
        with self._lock:
            if self._private is None or self._pid != os.getpid():
                raise ValueError('Provider unavailable')
            if (type(handoff_id) is not str or not 1 <= len(handoff_id) <= 128
                    or not handoff_id.isascii() or not all(c.isalnum() or c in '-_' for c in handoff_id)):
                raise ValueError('Invalid handoff ID')
            if handoff_id in self._ids or len(self._ids) >= self.MAX_HANDOFFS:
                raise ValueError('Handoff ID unavailable')
            if type(request) is not CustodySignRequest:
                raise ValueError('Exact request required')
            raw = canonical_bytes(request)
            decode_custody_record(CustodySignRequest, raw)
            start, deadline = _mono(self._clock()), _mono(deadline)
            if not start < deadline <= start + 5:
                raise ValueError('Bounded live deadline required')
            handoff = _TestHandoff(_MINT, handoff_id)
            self._ids.add(handoff_id)
            self._handoffs[handoff] = [raw, deadline, start, get_ident(), False]
            return handoff

    def _dispatch(self, preimage, mode):
        self._dispatch_count += 1
        if mode == 'PROVIDER_FAILURE':
            raise _DefinitiveFailure()
        key = Ed25519PrivateKey.generate() if mode == 'WRONG_KEY' else self._private
        signature = key.sign(preimage)
        if mode == 'TAMPERED_SIGNATURE':
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        if mode == 'INVALID_SIGNATURE':
            signature = signature[:-1]
        return signature

    def sign(self, handoff, *, handle, capabilities, trusted_anchor, expected_request,
             signer_id, mode='SUCCESS'):
        """Consume before all checks; dispatch at most once; never release late output.

        A valid signature proves only the bytes/key binding. Observation trust,
        live transport grants and release authorization remain outside this fake.
        """
        result = lambda status: CustodyProviderResult(status)
        with self._lock:
            if type(handoff) is not _TestHandoff or handoff not in self._handoffs:
                return result('INVALID_HANDOFF')
            entry = self._handoffs[handoff]
            if entry[4]:
                return result('HANDOFF_ALREADY_CONSUMED')
            entry[4] = True
            dispatched = False
            try:
                raw, deadline, minted, thread, _ = entry
                if self._pid != os.getpid() or thread != get_ident():
                    return result('CONTEXT_MISMATCH')
                if self._private is None:
                    return result('KEY_DISABLED')
                if type(mode) is not str or mode not in _MODES:
                    return result('INVALID_MODE')
                started = _mono(self._clock())
                if started < minted:
                    return result('CLOCK_REGRESSION')
                if started >= deadline or mode == 'DEADLINE_EXPIRED':
                    return result('DEADLINE_EXCEEDED')
                request = decode_custody_record(CustodySignRequest, raw)
                now = self._epoch()
                kwargs = dict(handle=handle, capabilities=capabilities, trusted_anchor=trusted_anchor,
                    expected_request=expected_request, signer_id=signer_id)
                assessment = evaluate_custody_request(request, now=now, **kwargs)
                if assessment.status != 'READY':
                    return result(assessment.reason)
                if handle.public_key_hex != self._public.hex() or handle.key_id != sha256(self._public).hexdigest():
                    return result('KEY_MISMATCH')
                if mode == 'UNSUPPORTED_MECHANISM':
                    return result('ALGORITHM_UNSUPPORTED')
                before = _mono(self._clock())
                if before < started:
                    return result('CLOCK_REGRESSION')
                if before >= deadline:
                    return result('DEADLINE_EXCEEDED')
                dispatched = True
                preimage = bytes.fromhex(request.preimage_hex)
                signature = self._dispatch(preimage, mode)
                if mode == 'AMBIGUOUS_OUTCOME':
                    return result('OUTCOME_UNKNOWN')
                finished, final_now = _mono(self._clock()), self._epoch()
                if finished < before or type(final_now) is not int or final_now < now:
                    return result('RESULT_DISCARDED')
                if finished >= deadline or mode == 'LATE_RESULT_REJECTION':
                    return result('RESULT_DISCARDED')
                final = evaluate_custody_request(request, now=final_now, **kwargs)
                if final.status != 'READY':
                    return result('RESULT_DISCARDED')
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(handle.public_key_hex)).verify(signature, preimage)
                except (InvalidSignature, ValueError, TypeError):
                    return result('SIGNATURE_INVALID')
                released = _mono(self._clock())
                if released < finished or released >= deadline:
                    return result('RESULT_DISCARDED')
                return CustodyProviderResult('VERIFIED', SignedObservation(
                    payload=request.payload, signature_hex=signature.hex()))
            except _DefinitiveFailure:
                return result('PROVIDER_FAILED')
            except Exception:
                return result('OUTCOME_UNKNOWN' if dispatched else 'INVALID_INPUT')
