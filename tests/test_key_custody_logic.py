"""Pure custody records and simulation with deterministic public fixture records."""
from datetime import datetime, timezone, timedelta
from hashlib import sha256

import pytest

from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.key_custody_logic import *
from tnc.provenance.reconciliation_models import ReconciliationEnvelope
from tnc.provenance.update_storage_models import UpdateStorageCheckpoint


def change(record, **values):
    return type(record).model_validate({**record.model_dump(), **values})


@pytest.fixture
def custody():
    now = 1_800_000_000
    expected = ObservationRequest(deployment_id='deployment', store_instance_id='store', issuer_id='observer',
        principal_id='caller', challenge='c'*64, timestamp=now, expiry=now+60)
    public = '12'*32  # Structural public bytes only; no key is generated.
    handle = KeyHandleRecord(deployment_id=expected.deployment_id, store_instance_id=expected.store_instance_id,
        issuer_id=expected.issuer_id, provider_id='test-provider', resource_id='key-resource', key_version='version-1',
        key_id=sha256(bytes.fromhex(public)).hexdigest(), public_key_hex=public, revision=1, created_at=now-200,
        timestamp=now-100, expiry=now+100, status='ACTIVE', allowed_signers=('host-signer',))
    checkpoint = UpdateStorageCheckpoint(deployment_id='deployment', image_hash='a'*64, event_count=0,
                                         event_head_hash='0'*64, authority_head_hash='b'*64)
    moment = datetime.fromtimestamp(now, timezone.utc)
    envelope = ReconciliationEnvelope(deployment_id='deployment', store_instance_id='store', authority_revision=1,
        previous_envelope_hash='0'*64, issuer_id='authority', key_id='a'*64, checkpoint=checkpoint,
        valid_from=moment-timedelta(seconds=100), valid_until=moment+timedelta(seconds=100))
    payload = ObservationPayload(**expected.model_dump(), request_digest=record_digest(expected),
        signing_key_id=handle.key_id, trust_revision=1, trust_store_digest='d'*64,
        policy_revision=1, policy_digest='e'*64, authority_revision=1,
        envelope_digest=record_digest(envelope), envelope=envelope)
    caps = CustodyCapabilities(provider_id=handle.provider_id, revision=1, timestamp=now-100, expiry=now+100,
        mechanism='ED25519_RAW', max_message_bytes=MAX_PREIMAGE, signature_format='RAW_64', state='AVAILABLE')
    anchor = CustodyTrustAnchor(deployment_id=handle.deployment_id, store_instance_id=handle.store_instance_id,
        issuer_id=handle.issuer_id, revision=1, timestamp=now-100, expiry=now+100,
        handle_digest=record_digest(handle), capabilities_digest=record_digest(caps))
    request = CustodySignRequest(attempt_id='attempt-1', signer_id='host-signer', handle_digest=record_digest(handle),
        timestamp=now, expiry=now+60, payload=payload, preimage_hex=observation_preimage(payload).hex())
    return request, handle, caps, anchor, expected, now


def repin(c, *, handle=None, caps=None):
    request, old_handle, old_caps, anchor, expected, now = c
    handle, caps = handle or old_handle, caps or old_caps
    anchor = change(anchor, handle_digest=record_digest(handle), capabilities_digest=record_digest(caps))
    request = change(request, handle_digest=record_digest(handle))
    return request, handle, caps, anchor, expected, now


def assess(c, **kw):
    request, handle, caps, anchor, expected, now = c
    values = dict(handle=handle, capabilities=caps, trusted_anchor=anchor,
                  expected_request=expected, signer_id='host-signer', now=now)
    values.update(kw)
    return evaluate_custody_request(request, **values)


def simulate(c, state=None, **kw):
    request, handle, caps, anchor, expected, now = c
    values = dict(handle=handle, capabilities=caps, trusted_anchor=anchor, expected_request=expected,
                  signer_id='host-signer', now=now, completed_at=now)
    values.update(kw)
    return simulate_custody_attempt(state or CustodySimulationState(receipts=()), request, **values)


def test_ready_is_non_authorizing_and_exact_preimage(custody):
    result = assess(custody)
    assert result.status == 'READY' and result.audit_only and not result.signature_verified
    assert bytes.fromhex(custody[0].preimage_hex) == b'TNC-SIGNED-OBSERVATION-v2:' + canonical_bytes(custody[0].payload)
    assert len(bytes.fromhex(custody[0].preimage_hex)) == 1541
    assert sha256(bytes.fromhex(custody[0].preimage_hex)).hexdigest() == '1792be56a432cb102dcacff9d8697fe3e49644d982e6114c984bea31702ad43b'
    assert record_digest(custody[0]) == 'ec57d5c0954c01d41330e7cd1f15b68996382225f3722fc1ed09f966cd0686f9'
    assert result == assess(custody)


@pytest.mark.parametrize('delta,expected', [(-1,'PAYLOAD_TOO_LARGE'),(0,'COMPATIBLE'),(1,'COMPATIBLE')])
def test_exact_raw_byte_limit(custody, delta, expected):
    length = len(bytes.fromhex(custody[0].preimage_hex))
    c = repin(custody, caps=change(custody[2], max_message_bytes=length+delta))
    assert assess(c).reason == expected


def test_4096_is_provider_capability_not_global_protocol(custody):
    c = repin(custody, caps=change(custody[2], max_message_bytes=4096))
    length = len(bytes.fromhex(c[0].preimage_hex))
    assert assess(c).reason == ('COMPATIBLE' if length <= 4096 else 'PAYLOAD_TOO_LARGE')
    assert custody[2].max_message_bytes > 4096


@pytest.mark.parametrize('mode', ['sha256','sha512','v1','checkpoint','padding'])
def test_no_hashing_domain_swap_or_padding(custody, mode):
    raw = bytes.fromhex(custody[0].preimage_hex)
    if mode == 'sha256': raw = sha256(raw).digest()
    if mode == 'sha512':
        from hashlib import sha512
        raw = sha512(raw).digest()
    if mode == 'v1': raw = raw.replace(b'v2:', b'v1:', 1)
    if mode == 'checkpoint': raw = b'TNC-TRUST-DISTRIBUTION-v1:' + canonical_bytes(custody[0].payload)
    if mode == 'padding': raw += b' '
    c = (change(custody[0], preimage_hex=raw.hex()), *custody[1:])
    assert assess(c).reason == 'PREIMAGE_MISMATCH'


@pytest.mark.parametrize('mechanism,format', [('ED25519_PH','RAW_64'),('ECDSA','RAW_64'),('ED25519_RAW','DER')])
def test_algorithm_no_fallback(custody, mechanism, format):
    c = repin(custody, caps=change(custody[2], mechanism=mechanism, signature_format=format))
    assert assess(c).reason == 'ALGORITHM_UNSUPPORTED'


@pytest.mark.parametrize('status', ['ROTATING','REVOKED','DISABLED'])
def test_only_explicit_active_key(custody, status):
    assert assess(repin(custody, handle=change(custody[1], status=status))).reason == 'KEY_DISABLED'


@pytest.mark.parametrize('status,reason', [('LOCKED','HSM_LOCKED'),('UNAVAILABLE','PROVIDER_UNAVAILABLE')])
def test_provider_status(custody, status, reason):
    assert assess(repin(custody, caps=change(custody[2], state=status))).reason == reason


@pytest.mark.parametrize('field', ['resource_id','key_version','provider_id','revision'])
def test_unpinned_handle_change(custody, field):
    value = 2 if field == 'revision' else 'other'
    assert assess(custody, handle=change(custody[1], **{field:value})).reason == 'TRUST_MISMATCH'


@pytest.mark.parametrize('field', ['deployment_id','store_instance_id','issuer_id'])
def test_scope_binding(custody, field):
    assert assess(custody, expected_request=change(custody[4], **{field:'other'})).reason == 'SCOPE_MISMATCH'


def test_signer_permission_not_a_key_identifier(custody):
    assert assess(custody, signer_id=custody[1].key_id).reason == 'UNAUTHORIZED_SIGNER'
    assert assess(repin(custody, handle=change(custody[1], allowed_signers=()))).reason == 'UNAUTHORIZED_SIGNER'


@pytest.mark.parametrize('field,value', [('principal_id','other'),('challenge','f'*64),('request_digest','f'*64),('signing_key_id','f'*64)])
def test_payload_context_even_when_preimage_rebuilt(custody, field, value):
    payload = change(custody[0].payload, **{field:value})
    request = change(custody[0], payload=payload, preimage_hex=observation_preimage(payload).hex())
    assert assess((request,*custody[1:])).reason == 'REQUEST_MISMATCH'


@pytest.mark.parametrize('index', [1,2,3])
def test_dual_temporal_bounds(custody, index):
    # A pin valid only after issuance must not bless the earlier payload.
    changed = change(custody[index], timestamp=custody[5]+1)
    c = list(custody)
    if index == 1: c = list(repin(custody, handle=changed))
    elif index == 2: c = list(repin(custody, caps=changed))
    else: c[index] = changed
    assert assess(tuple(c), now=custody[5]+2).reason == 'INTERVAL_INVALID'


@pytest.mark.parametrize('delta,status', [(-1,'DENIED'),(0,'READY'),(59,'READY'),(60,'DENIED')])
def test_request_time_boundaries(custody, delta, status):
    assert assess(custody, now=custody[5]+delta).status == status


@pytest.mark.parametrize('now', [True,-1,'1',1.5,2**63])
def test_strict_clock(custody, now):
    assert assess(custody, now=now).reason == 'INVALID_RECORD'


def test_public_key_digest_and_creation_bounds(custody):
    with pytest.raises(ValueError): change(custody[1], key_id='f'*64)
    with pytest.raises(ValueError): change(custody[1], created_at=custody[1].timestamp+1)
    with pytest.raises(ValueError): change(custody[1], allowed_signers=('b','a'))
    with pytest.raises(ValueError): change(custody[1], algorithm='ED25519_PH')


@pytest.mark.parametrize('raw', ['a', 'AA', '00'*(MAX_PREIMAGE+1)], ids=['odd-length','uppercase','oversize'])
def test_preimage_encoding_bounds(custody, raw):
    with pytest.raises(ValueError): change(custody[0], preimage_hex=raw)


def test_canonical_records(custody):
    for record in custody[:4]:
        raw = canonical_bytes(record)
        assert decode_custody_record(type(record), raw) == record
        with pytest.raises(ValueError): decode_custody_record(type(record), raw+b' ')
    with pytest.raises(ValueError): decode_custody_record(KeyHandleRecord, b'{"x":1,"x":2}')
    with pytest.raises(ValueError): decode_custody_record(KeyHandleRecord, b'{"x":NaN}')
    with pytest.raises(ValueError): decode_custody_record(KeyHandleRecord, b'x'*(RECORD_LIMIT+1))
    with pytest.raises(ValueError): change(custody[1], unknown=True)
    with pytest.raises(ValueError): custody[1].status = 'ACTIVE'


def test_nested_integer_bounds(custody):
    payload = change(custody[0].payload, policy_revision=2**63)
    request = change(custody[0], payload=payload, preimage_hex=observation_preimage(payload).hex())
    assert assess((request,*custody[1:])).reason == 'INVALID_RECORD'


def test_simulation_only_proposes_and_consumes_attempt_id(custody):
    state = CustodySimulationState(receipts=())
    result = simulate(custody, state)
    assert state.receipts == () and result.status == 'SIMULATED_COMPLETION'
    assert result.receipt.reason == 'NO_SIGNATURE_PRODUCED'
    assert result.receipt.signature_verified is False
    assert not hasattr(result.receipt,'signature')
    assert simulate(custody, result.proposed_state).status == 'ATTEMPT_ALREADY_USED'
    changed = (change(custody[0], expiry=custody[0].expiry-1),*custody[1:])
    assert simulate(changed, result.proposed_state).status == 'ATTEMPT_CONFLICT'


@pytest.mark.parametrize('outcome,status', [('SUCCESS','SIMULATED_COMPLETION'),('FAILURE','PROVIDER_FAILED'),('UNKNOWN','SIGNING_OUTCOME_UNKNOWN')])
def test_provider_outcomes(custody, outcome, status):
    result = simulate(custody, provider_outcome=outcome)
    assert result.status == status and len(result.proposed_state.receipts) == 1


def test_late_result_is_discarded(custody):
    result = simulate(custody, completed_at=custody[5]+60)
    assert result.status == 'RESULT_DISCARDED'
    assert simulate(custody, result.proposed_state, now=custody[5]+60, completed_at=custody[5]+60).status == 'ATTEMPT_ALREADY_USED'


def test_denial_burns_only_proposed_id(custody):
    result = simulate(custody, signer_id='unauthorized')
    assert result.status == 'DENIED'
    assert simulate(custody, result.proposed_state).status == 'ATTEMPT_ALREADY_USED'
    assert simulate(custody).status == 'SIMULATED_COMPLETION'  # caller did not apply proposal


def test_simulation_clock_and_history_integrity(custody):
    assert simulate(custody, completed_at=custody[5]-1).status == 'CLOCK_REGRESSION'
    receipt = simulate(custody).receipt
    with pytest.raises(ValueError): CustodySimulationState(receipts=(change(receipt, previous_receipt_digest='f'*64),))
    with pytest.raises(ValueError): CustodySimulationState(receipts=(receipt, receipt))


def test_simulation_capacity(custody):
    state = CustodySimulationState(receipts=())
    for index in range(HISTORY_LIMIT):
        c = (change(custody[0], attempt_id=f'attempt-{index}'),*custody[1:])
        state = simulate(c, state).proposed_state
    c = (change(custody[0], attempt_id='overflow'),*custody[1:])
    assert simulate(c, state).status == 'CAPACITY_EXCEEDED'


def test_no_hardware_crypto_io_or_clock(custody, monkeypatch):
    import builtins
    import socket
    import sqlite3
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    def forbidden(*args, **kw): raise AssertionError('Unexpected side effect')
    for obj,name in ((builtins,'open'),(socket,'socket'),(sqlite3,'connect'),(time,'time'),(time,'monotonic'),(Ed25519PrivateKey,'generate')):
        monkeypatch.setattr(obj,name,forbidden)
    assert assess(custody).status == 'READY'
    assert simulate(custody).status == 'SIMULATED_COMPLETION'


def test_short_internal_request_does_not_extend_signed_key_window(custody):
    c = list(repin(custody, handle=change(custody[1], expiry=custody[5]+30)))
    c[0] = change(c[0], expiry=custody[5]+20)
    assert assess(tuple(c)).reason == 'INTERVAL_INVALID'
