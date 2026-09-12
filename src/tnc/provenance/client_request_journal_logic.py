"""Pure test-only client journal proposals. No storage, clock, or caller authentication."""
from hashlib import sha256
from typing import Literal
from pydantic import Field, model_validator
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.reconciliation_verifier import (
    Time, ObservationRequest, ObservationTrustStore, ObservationTrustCheckpoint,
    SignedObservation, decode_v2_record, verify_observation,
)
from tnc.provenance.client_high_water_logic import (
    ClientAnchor, ClientHighWaterState, ClientReceipt, AdvancementRequest,
    decode_client_record, _validate as validate_high_water,
)

DOMAIN = b'TNC-CLIENT-JOURNAL-INTENT-v1:'
IMAGE_LIMIT = 16 * 1024 * 1024
INTENT_LIMIT = 2 * 1024 * 1024
RESPONSE_LIMIT = 32768


class JournalModel(Model):
    profile: Literal['tnc-client-journal-v1'] = 'tnc-client-journal-v1'


class ClientJournalIntent(JournalModel):
    operation_id: Identifier
    client_anchor_digest: Digest
    principal_id: Identifier
    request: ObservationRequest
    trust_store: ObservationTrustStore
    trusted_checkpoint: ObservationTrustCheckpoint
    created_at: Time
    expires_at: Time

    @model_validator(mode='after')
    def bindings(self):
        r, t, c = self.request, self.trust_store, self.trusted_checkpoint
        scope = lambda x: (x.deployment_id, x.store_instance_id)
        if (self.principal_id != r.principal_id or scope(r) != scope(t) or scope(t) != scope(c)
                or t.revision != c.revision or record_digest(t) != c.trust_store_digest
                or not self.created_at < self.expires_at or r.expiry-r.timestamp > 60
                or any(not v.timestamp <= self.created_at < self.expires_at <= v.expiry for v in (r,t,c))
                or len(canonical_bytes(r)) > 16384):
            raise ValueError('Invalid intent binding')
        return self


class RetainedClientResponse(JournalModel):
    intent_digest: Digest
    response_canonical_json: str = Field(strict=True, min_length=1, max_length=RESPONSE_LIMIT)
    response_digest: Digest
    retained_at: Time

    @model_validator(mode='after')
    def canonical(self):
        raw = self.response_canonical_json.encode('utf-8')
        if len(raw) > RESPONSE_LIMIT or sha256(raw).hexdigest() != self.response_digest:
            raise ValueError('Invalid response bytes')
        decode_v2_record(SignedObservation, raw)
        return self


class JournalReceiptBinding(JournalModel):
    intent_digest: Digest
    advancement_request_digest: Digest
    response_digest: Digest
    receipt_canonical_json: str = Field(strict=True, min_length=1, max_length=65536)
    reconciled_at: Time
    # Synthetic full replay evidence, not a caller-supplied committed flag.
    high_water_evidence: ClientHighWaterState

    @model_validator(mode='after')
    def canonical(self):
        decode_client_record(ClientReceipt, self.receipt_canonical_json.encode('utf-8'))
        return self


class ClientJournalEntry(JournalModel):
    intent: ClientJournalIntent
    intent_digest: Digest
    local_sequence: int = Field(strict=True, ge=1, le=3)
    last_event_at: Time
    state: Literal['AWAITING_RESPONSE','RETAINED_RESPONSE','COMMITTED_RECEIPT']
    retained_response: RetainedClientResponse | None = None
    receipt_binding: JournalReceiptBinding | None = None

    @model_validator(mode='after')
    def shape(self):
        phase = ('AWAITING_RESPONSE','RETAINED_RESPONSE','COMMITTED_RECEIPT').index(self.state)+1
        if (self.local_sequence != phase or (self.retained_response is not None) != (phase>=2)
                or (self.receipt_binding is not None) != (phase==3)):
            raise ValueError('Invalid lifecycle shape')
        return self


class ClientJournalImage(JournalModel):
    entries: tuple[ClientJournalEntry,...] = Field(default=(), max_length=64)

    @model_validator(mode='after')
    def ordered(self):
        ids = tuple(e.intent.operation_id for e in self.entries)
        if ids != tuple(sorted(set(ids))): raise ValueError('Sorted unique operations required')
        return self


class JournalOutcome(JournalModel):
    audit_only: bool = Field(default=True, strict=True)
    status: Literal['REGISTERED','RETAINED','COMMITTED','RECOVERED','UNCHANGED',
                    'READY_TO_APPLY','AWAITING_RESPONSE','REJECTED','INDETERMINATE']
    reason_code: Literal['INVALID_STATE','INVALID_INPUT','ANCHOR_MISMATCH','ACCESS_DENIED',
        'OPERATION_CONFLICT','INVALID_RECEIPT','CLOCK_REGRESSION','CAPACITY_EXCEEDED',
        'INVALID_REGISTRATION_TIME','INVALID_RESPONSE','RESPONSE_EXPIRED',
        'VERIFICATION_FAILED','HIGH_WATER_UNAVAILABLE'] | None = None
    proposed_image: ClientJournalImage | None = None
    advancement_request: AdvancementRequest | None = None
    receipt: ClientReceipt | None = None

    @model_validator(mode='after')
    def shape(self):
        if (not self.audit_only or (self.proposed_image is not None) != (self.status in ('REGISTERED','RETAINED','COMMITTED'))
                or (self.advancement_request is not None) != (self.status=='READY_TO_APPLY')
                or (self.receipt is not None) != (self.status in ('COMMITTED','RECOVERED'))
                or (self.reason_code is not None) != (self.status in ('REJECTED','INDETERMINATE'))):
            raise ValueError('Invalid outcome shape')
        return self


KINDS = (ClientJournalIntent,RetainedClientResponse,JournalReceiptBinding,
         ClientJournalEntry,ClientJournalImage,JournalOutcome)


def decode_journal_record(kind, raw):
    limit = INTENT_LIMIT if kind is ClientJournalIntent else IMAGE_LIMIT
    if kind not in KINDS or type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError('Invalid record bound')
    return decode_canonical(kind, raw)


def _copy(value, kind):
    if type(value) is not kind: raise ValueError('Exact record required')
    return decode_journal_record(kind, canonical_bytes(value))


def intent_digest(intent):
    return sha256(DOMAIN + canonical_bytes(_copy(intent, ClientJournalIntent))).hexdigest()


class _Denied(ValueError): pass


def _require(ok, reason='INVALID_STATE'):
    if not ok: raise _Denied(reason)


def _bound_intent(intent, anchor):
    _copy(intent, ClientJournalIntent)
    _require(intent.client_anchor_digest == record_digest(anchor), 'ANCHOR_MISMATCH')
    _require((intent.request.deployment_id,intent.request.store_instance_id,intent.principal_id) ==
             (anchor.deployment_id,anchor.store_instance_id,anchor.principal_id), 'ACCESS_DENIED')
    _require(intent.created_at >= anchor.accepted_timestamp)


def _request(entry):
    i, r = entry.intent, entry.retained_response
    return AdvancementRequest(operation_id=i.operation_id,
        response=decode_v2_record(SignedObservation,r.response_canonical_json.encode('utf-8')),
        retained_request=i.request, trust_store=i.trust_store, trusted_checkpoint=i.trusted_checkpoint)


def _verify(request, now):
    return verify_observation(request.response, expected_request=request.retained_request,
        trust_store=request.trust_store, trusted_checkpoint=request.trusted_checkpoint, now=now).status=='VERIFIED'


def _receipt_from(evidence, anchor, entry, now):
    if type(evidence) is not ClientHighWaterState: raise ValueError('Invalid evidence')
    checked = decode_client_record(ClientHighWaterState, canonical_bytes(evidence))
    validate_high_water(checked, anchor, now)
    found = next((e for e in checked.history if e.request.operation_id==entry.intent.operation_id),None)
    if found is None: return None
    _require(canonical_bytes(found.request)==canonical_bytes(_request(entry)), 'OPERATION_CONFLICT')
    _require(found.receipt.accepted_timestamp >= entry.retained_response.retained_at, 'INVALID_RECEIPT')
    return found.receipt


def _validate(image, anchor, now):
    for e in image.entries:
        _bound_intent(e.intent, anchor)
        _require(e.intent_digest==intent_digest(e.intent))
        last = e.intent.created_at
        if e.retained_response is not None:
            r=e.retained_response
            _require(r.intent_digest==e.intent_digest and last<=r.retained_at<e.intent.expires_at)
            _require(_verify(_request(e),r.retained_at))
            last=r.retained_at
        if e.receipt_binding is not None:
            b=e.receipt_binding
            _require(last<=b.reconciled_at<=now)
            receipt=_receipt_from(b.high_water_evidence,anchor,e,b.reconciled_at)
            _require(receipt is not None and b.intent_digest==e.intent_digest
                and b.advancement_request_digest==record_digest(_request(e))
                and b.response_digest==e.retained_response.response_digest
                and canonical_bytes(receipt)==b.receipt_canonical_json.encode('utf-8'))
            last=b.reconciled_at
        _require(e.last_event_at==last)
        _require(last<=now, 'CLOCK_REGRESSION')


def _start(image, anchor, principal, now):
    _require(type(now) is int and now>=0, 'INVALID_INPUT')
    _require(type(anchor) is ClientAnchor, 'INVALID_INPUT')
    anchor=decode_client_record(ClientAnchor,canonical_bytes(anchor))
    _require(type(principal) is str and principal==anchor.principal_id, 'ACCESS_DENIED')
    image=_copy(image,ClientJournalImage)
    _require(now>=anchor.accepted_timestamp,'CLOCK_REGRESSION')
    _validate(image,anchor,now)
    return image,anchor


def _entry(image, operation_id):
    _require(type(operation_id) is str, 'ACCESS_DENIED')
    e=next((e for e in image.entries if e.intent.operation_id==operation_id),None)
    _require(e is not None,'ACCESS_DENIED')
    return e


def _propose(image, entry, anchor, now, status, receipt=None):
    entries=tuple(e for e in image.entries if e.intent.operation_id!=entry.intent.operation_id)+(entry,)
    _require(len(entries)<=64,'CAPACITY_EXCEEDED')
    image=ClientJournalImage(entries=tuple(sorted(entries,key=lambda e:e.intent.operation_id)))
    _require(len(canonical_bytes(image))<=IMAGE_LIMIT,'CAPACITY_EXCEEDED')
    image=_copy(image,ClientJournalImage); _validate(image,anchor,now)
    return _copy(JournalOutcome(status=status,proposed_image=image,receipt=receipt),JournalOutcome)


def _failure(exc):
    return JournalOutcome(status='REJECTED',reason_code=str(exc) if isinstance(exc,_Denied) else 'INVALID_INPUT')


def register_intent(image, intent, *, trusted_client_anchor, caller_principal, now):
    try:
        image,anchor=_start(image,trusted_client_anchor,caller_principal,now)
        intent=_copy(intent,ClientJournalIntent); _bound_intent(intent,anchor)
        found=next((e for e in image.entries if e.intent.operation_id==intent.operation_id),None)
        if found:
            _require(canonical_bytes(found.intent)==canonical_bytes(intent),'OPERATION_CONFLICT')
            return JournalOutcome(status='UNCHANGED')
        _require(now==intent.created_at,'INVALID_REGISTRATION_TIME')
        e=ClientJournalEntry(intent=intent,intent_digest=intent_digest(intent),local_sequence=1,
            last_event_at=now,state='AWAITING_RESPONSE')
        return _propose(image,e,anchor,now,'REGISTERED')
    except Exception as exc: return _failure(exc)


def retain_response(image, operation_id, response_bytes, *, trusted_client_anchor, caller_principal, now):
    try:
        image,anchor=_start(image,trusted_client_anchor,caller_principal,now)
        e=_entry(image,operation_id)
        _require(type(response_bytes) is bytes and 0<len(response_bytes)<=RESPONSE_LIMIT,'INVALID_RESPONSE')
        if e.retained_response is not None:
            _require(e.retained_response.response_canonical_json.encode('utf-8')==response_bytes,'OPERATION_CONFLICT')
            return JournalOutcome(status='UNCHANGED')
        _require(now<e.intent.expires_at,'RESPONSE_EXPIRED')
        r=RetainedClientResponse(intent_digest=e.intent_digest,response_canonical_json=response_bytes.decode('utf-8'),
            response_digest=sha256(response_bytes).hexdigest(),retained_at=now)
        e=e.model_copy(update={'retained_response':r,'local_sequence':2,'last_event_at':now,'state':'RETAINED_RESPONSE'})
        _require(_verify(_request(e),now),'VERIFICATION_FAILED')
        return _propose(image,e,anchor,now,'RETAINED')
    except Exception as exc: return _failure(exc)


def evaluate_recovery(image, operation_id, *, trusted_client_anchor, caller_principal, checked_high_water_state, now):
    try:
        image,anchor=_start(image,trusted_client_anchor,caller_principal,now)
        e=_entry(image,operation_id)
        if e.state=='COMMITTED_RECEIPT':
            return JournalOutcome(status='RECOVERED',receipt=decode_client_record(ClientReceipt,
                e.receipt_binding.receipt_canonical_json.encode('utf-8')))
        if e.state=='AWAITING_RESPONSE': return JournalOutcome(status='AWAITING_RESPONSE')
        try: receipt=_receipt_from(checked_high_water_state,anchor,e,now)
        except _Denied: raise
        except Exception: return JournalOutcome(status='INDETERMINATE',reason_code='HIGH_WATER_UNAVAILABLE')
        if receipt is not None:
            b=JournalReceiptBinding(intent_digest=e.intent_digest,advancement_request_digest=record_digest(_request(e)),
                response_digest=e.retained_response.response_digest,receipt_canonical_json=canonical_bytes(receipt).decode('utf-8'),
                reconciled_at=now,high_water_evidence=checked_high_water_state)
            e=e.model_copy(update={'receipt_binding':b,'local_sequence':3,'last_event_at':now,'state':'COMMITTED_RECEIPT'})
            return _propose(image,e,anchor,now,'COMMITTED',receipt)
        _require(now<e.intent.expires_at and now<_request(e).response.payload.expiry,'RESPONSE_EXPIRED')
        request=_request(e)
        _require(_verify(request,now),'VERIFICATION_FAILED')
        return JournalOutcome(status='READY_TO_APPLY',advancement_request=request)
    except Exception as exc: return _failure(exc)
