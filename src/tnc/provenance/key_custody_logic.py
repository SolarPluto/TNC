"""Pure observation-v2 custody compatibility and synthetic attempt simulation.

Pins and signer identity are independently supplied fixture/host inputs. No key
generation, signatures, device access, clocks, handoffs or executable permissions.
"""
from hashlib import sha256
from typing import Annotated, Literal

from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.reconciliation_verifier import ObservationPayload, ObservationRequest, observation_preimage, DOMAIN_PREFIX

MAX_PREIMAGE = 65536 + len(DOMAIN_PREFIX)
RECORD_LIMIT = 524288
IMAGE_LIMIT = 1048576
HISTORY_LIMIT = 32
Time = Annotated[int, Field(strict=True, ge=0, le=2**63-1)]
Revision = Annotated[int, Field(strict=True, ge=1, le=2**63-1)]


class Window(Model):
    timestamp: Time
    expiry: Time

    @model_validator(mode='after')
    def interval(self):
        if self.timestamp >= self.expiry: raise ValueError('Positive interval required')
        return self


class KeyHandleRecord(Window):
    profile: Literal['tnc-key-custody-v1'] = 'tnc-key-custody-v1'
    deployment_id: Identifier
    store_instance_id: Identifier
    issuer_id: Identifier
    provider_id: Identifier
    resource_id: Identifier
    key_version: Identifier
    key_id: Digest
    public_key_hex: Digest
    algorithm: Literal['ED25519_RAW'] = 'ED25519_RAW'
    purpose: Literal['OBSERVATION_V2'] = 'OBSERVATION_V2'
    revision: Revision
    created_at: Time
    status: Literal['ACTIVE', 'ROTATING', 'REVOKED', 'DISABLED']
    allowed_signers: tuple[Identifier, ...] = Field(max_length=32)

    @model_validator(mode='after')
    def bindings(self):
        if (self.key_id != sha256(bytes.fromhex(self.public_key_hex)).hexdigest()
                or self.created_at > self.timestamp
                or self.allowed_signers != tuple(sorted(set(self.allowed_signers)))):
            raise ValueError('Invalid key binding or signer inventory')
        return self


class CustodyCapabilities(Window):
    """Pinned compatibility declarations, not hardware attestation."""
    provider_id: Identifier
    revision: Revision
    mechanism: Literal['ED25519_RAW', 'ED25519_PH', 'ECDSA']
    max_message_bytes: int = Field(strict=True, ge=1, le=MAX_PREIMAGE)
    signature_format: Literal['RAW_64', 'DER']
    state: Literal['AVAILABLE', 'LOCKED', 'UNAVAILABLE']


class CustodyTrustAnchor(Window):
    """Independent pin. Never accepted from the request as its own authority."""
    deployment_id: Identifier
    store_instance_id: Identifier
    issuer_id: Identifier
    revision: Revision
    handle_digest: Digest
    capabilities_digest: Digest


class CustodySignRequest(Window):
    profile: Literal['tnc-custody-request-v1'] = 'tnc-custody-request-v1'
    attempt_id: Identifier
    signer_id: Identifier
    handle_digest: Digest
    payload: ObservationPayload
    preimage_hex: str = Field(strict=True, min_length=2, max_length=2*MAX_PREIMAGE, pattern=r'^[0-9a-f]+$')

    @model_validator(mode='after')
    def bounds(self):
        if len(self.preimage_hex) % 2 or self.expiry-self.timestamp > 60:
            raise ValueError('Bounded preimage and request interval required')
        return self


class CustodyAssessment(Model):
    status: Literal['READY', 'DENIED']
    reason: Identifier
    audit_only: Literal[True] = True
    signature_verified: Literal[False] = False


class SimulatedCustodyReceipt(Model):
    sequence: int = Field(strict=True, ge=1, le=HISTORY_LIMIT)
    attempt_id: Identifier
    request_digest: Digest
    anchor_digest: Digest
    previous_receipt_digest: Digest
    started_at: Time
    completed_at: Time
    outcome: Literal['DENIED', 'SIMULATED_COMPLETION', 'PROVIDER_FAILED', 'SIGNING_OUTCOME_UNKNOWN', 'RESULT_DISCARDED']
    reason: Identifier
    audit_only: Literal[True] = True
    signature_verified: Literal[False] = False

    @model_validator(mode='after')
    def order(self):
        if self.completed_at < self.started_at: raise ValueError('Clock regression')
        return self


class CustodySimulationState(Model):
    receipts: tuple[SimulatedCustodyReceipt, ...] = Field(max_length=HISTORY_LIMIT)

    @model_validator(mode='after')
    def chain(self):
        previous, seen, last = '0'*64, set(), 0
        for index, receipt in enumerate(self.receipts, 1):
            if (receipt.sequence != index or receipt.previous_receipt_digest != previous
                    or receipt.attempt_id in seen or receipt.started_at < last):
                raise ValueError('Invalid simulation history')
            previous, last = record_digest(receipt), receipt.completed_at
            seen.add(receipt.attempt_id)
        return self


class CustodySimulationResult(Model):
    status: Identifier
    proposed_state: CustodySimulationState | None = None
    receipt: SimulatedCustodyReceipt | None = None
    audit_only: Literal[True] = True
    signature_verified: Literal[False] = False


def decode_custody_record(kind, raw):
    kinds = (KeyHandleRecord, CustodyCapabilities, CustodyTrustAnchor, CustodySignRequest,
             CustodyAssessment, SimulatedCustodyReceipt, CustodySimulationState, CustodySimulationResult)
    limit = IMAGE_LIMIT if kind in (CustodySimulationState, CustodySimulationResult) else RECORD_LIMIT
    if kind not in kinds or type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError('Invalid bounded custody record')
    record = decode_canonical(kind, raw)
    def numbers(value):
        if type(value) is int and not 0 <= value <= 2**63-1: raise ValueError('Integer out of range')
        if type(value) is float: raise ValueError('Floating scalars forbidden')
        if isinstance(value, dict):
            for child in value.values(): numbers(child)
        elif isinstance(value, (tuple, list)):
            for child in value: numbers(child)
    numbers(record.model_dump())
    return record


def _copy(record, kind):
    if type(record) is not kind: raise ValueError('Exact custody record required')
    return decode_custody_record(kind, canonical_bytes(record))


def _time(now):
    if type(now) is not int or not 0 <= now <= 2**63-1: raise ValueError('Exact epoch seconds required')


def _active(value, now):
    return value.timestamp <= now < value.expiry


def evaluate_custody_request(request, *, handle, capabilities, trusted_anchor, expected_request, signer_id, now):
    """READY is a compatibility finding, never a signing capability."""
    def deny(reason): return CustodyAssessment(status='DENIED', reason=reason)
    try:
        _time(now)
        request = _copy(request, CustodySignRequest)
        handle = _copy(handle, KeyHandleRecord)
        capabilities = _copy(capabilities, CustodyCapabilities)
        anchor = _copy(trusted_anchor, CustodyTrustAnchor)
        if type(expected_request) is not ObservationRequest: return deny('REQUEST_MISMATCH')
        expected_request = decode_canonical(ObservationRequest, canonical_bytes(expected_request))
        if type(signer_id) is not str or request.signer_id != signer_id or signer_id not in handle.allowed_signers:
            return deny('UNAUTHORIZED_SIGNER')
        scope = lambda v: (v.deployment_id, v.store_instance_id, v.issuer_id)
        if (anchor.handle_digest != record_digest(handle) or request.handle_digest != anchor.handle_digest
                or anchor.capabilities_digest != record_digest(capabilities)
                or capabilities.provider_id != handle.provider_id): return deny('TRUST_MISMATCH')
        if scope(handle) != scope(anchor) or scope(handle) != scope(expected_request): return deny('SCOPE_MISMATCH')
        if handle.status != 'ACTIVE': return deny('KEY_DISABLED')
        if capabilities.mechanism != 'ED25519_RAW' or capabilities.signature_format != 'RAW_64':
            return deny('ALGORITHM_UNSUPPORTED')
        if capabilities.state != 'AVAILABLE':
            return deny('HSM_LOCKED' if capabilities.state == 'LOCKED' else 'PROVIDER_UNAVAILABLE')
        if not all(_active(x, now) for x in (request, handle, capabilities, anchor)):
            return deny('EXPIRED_OR_NOT_YET_VALID')
        payload = request.payload
        preimage = bytes.fromhex(request.preimage_hex)
        if preimage != observation_preimage(payload): return deny('PREIMAGE_MISMATCH')
        if len(preimage) > capabilities.max_message_bytes: return deny('PAYLOAD_TOO_LARGE')
        if (payload.signing_key_id != handle.key_id or scope(payload) != scope(expected_request)
                or payload.request_digest != record_digest(expected_request)
                or (payload.principal_id, payload.challenge) != (expected_request.principal_id, expected_request.challenge)):
            return deny('REQUEST_MISMATCH')
        if (not 0 <= expected_request.timestamp <= payload.timestamp <= request.timestamp <= now
                < request.expiry <= payload.expiry <= expected_request.expiry <= 2**63-1
                or expected_request.expiry-expected_request.timestamp > 60
                or any(x.timestamp > payload.timestamp or payload.expiry > x.expiry
                       for x in (handle, capabilities, anchor))): return deny('INTERVAL_INVALID')
        return CustodyAssessment(status='READY', reason='COMPATIBLE')
    except (ValueError, TypeError, AttributeError): return deny('INVALID_RECORD')


def simulate_custody_attempt(state, request, *, handle, capabilities, trusted_anchor,
                            expected_request, signer_id, now, completed_at, provider_outcome='SUCCESS'):
    """Explicit synthetic outcomes; no signature or provider call is produced.

    Every modeled attempt, including denial, consumes its ID in the proposed state.
    The caller chooses state application; this is not a durable single-use guard.
    """
    try:
        _time(now); _time(completed_at)
        state = _copy(state, CustodySimulationState)
        request = _copy(request, CustodySignRequest)
        anchor = _copy(trusted_anchor, CustodyTrustAnchor)
        if provider_outcome not in ('SUCCESS', 'FAILURE', 'UNKNOWN'): raise ValueError('Invalid fixture outcome')
        if completed_at < now or (state.receipts and now < state.receipts[-1].completed_at):
            return CustodySimulationResult(status='CLOCK_REGRESSION')
        digest = record_digest(request)
        for receipt in state.receipts:
            if receipt.attempt_id == request.attempt_id:
                return CustodySimulationResult(status='ATTEMPT_ALREADY_USED' if receipt.request_digest == digest else 'ATTEMPT_CONFLICT')
        if len(state.receipts) >= HISTORY_LIMIT: return CustodySimulationResult(status='CAPACITY_EXCEEDED')
        kwargs = dict(handle=handle, capabilities=capabilities, trusted_anchor=anchor,
                      expected_request=expected_request, signer_id=signer_id)
        assessment = evaluate_custody_request(request, now=now, **kwargs)
        outcome, reason = 'DENIED', assessment.reason
        if assessment.status == 'READY':
            if provider_outcome == 'UNKNOWN': outcome, reason = 'SIGNING_OUTCOME_UNKNOWN', 'PROVIDER_TIMEOUT'
            elif provider_outcome == 'FAILURE': outcome, reason = 'PROVIDER_FAILED', 'SYNTHETIC_PROVIDER_FAILURE'
            else:
                final = evaluate_custody_request(request, now=completed_at, **kwargs)
                outcome, reason = ('SIMULATED_COMPLETION', 'NO_SIGNATURE_PRODUCED') if final.status == 'READY' else ('RESULT_DISCARDED', final.reason)
        receipt = SimulatedCustodyReceipt(sequence=len(state.receipts)+1, attempt_id=request.attempt_id,
            request_digest=digest, anchor_digest=record_digest(anchor), started_at=now, completed_at=completed_at,
            previous_receipt_digest=record_digest(state.receipts[-1]) if state.receipts else '0'*64,
            outcome=outcome, reason=reason)
        proposed = CustodySimulationState(receipts=state.receipts+(receipt,))
        return CustodySimulationResult(status=outcome, receipt=receipt, proposed_state=proposed)
    except (ValueError, TypeError, AttributeError): return CustodySimulationResult(status='INVALID_RECORD')
