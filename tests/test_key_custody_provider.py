"""Ephemeral provider faults; no devices, cloud clients or persistent secrets."""
import copy
import pickle
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from test_key_custody_logic import custody, change
from tnc.provenance.authorization_models import record_digest
from tnc.provenance.key_custody_logic import *
from tnc.provenance.key_custody_provider import TestCustodyProvider
from tnc.provenance.reconciliation_verifier import (
    ObservationKey, ObservationTrustStore, ObservationTrustCheckpoint, verify_observation)


@pytest.fixture
def harness(custody):
    clock = [100.0, custody[-1]]
    provider = TestCustodyProvider(monotonic_clock=lambda: clock[0], epoch_clock=lambda: clock[1])
    request, handle, caps, anchor, expected, now = custody
    public = provider.public_key_bytes
    handle = change(handle, public_key_hex=public.hex(), key_id=sha256(public).hexdigest())
    key = ObservationKey(deployment_id=handle.deployment_id, store_instance_id=handle.store_instance_id,
        timestamp=handle.timestamp, expiry=handle.expiry, key_id=handle.key_id, public_key_hex=handle.public_key_hex,
        issuer_id=handle.issuer_id, envelope_issuer_id='authority', permissions=('AUTHORITY_OBSERVE_CURRENT',), status='active')
    trust = ObservationTrustStore(deployment_id=handle.deployment_id, store_instance_id=handle.store_instance_id,
        timestamp=handle.timestamp, expiry=handle.expiry, revision=1, keys=(key,))
    cp = ObservationTrustCheckpoint(deployment_id=handle.deployment_id, store_instance_id=handle.store_instance_id,
        timestamp=handle.timestamp, expiry=handle.expiry, revision=1, trust_store_digest=record_digest(trust))
    payload = change(request.payload, signing_key_id=handle.key_id, trust_store_digest=record_digest(trust))
    request = change(request, handle_digest=record_digest(handle), payload=payload,
                     preimage_hex=observation_preimage(payload).hex())
    anchor = change(anchor, handle_digest=record_digest(handle))
    kwargs = dict(handle=handle, capabilities=caps, trusted_anchor=anchor, expected_request=expected, signer_id='host-signer')
    yield provider, request, kwargs, clock, trust, cp
    provider.close()


def attempt(harness, mode='SUCCESS', **overrides):
    provider, request, kwargs, clock, *_ = harness
    handoff = provider.mint_handoff_for_testing('handoff', request, deadline=105)
    result = provider.sign(handoff, **{**kwargs, **overrides}, mode=mode)
    count = provider.dispatch_count
    assert provider.sign(handoff, **kwargs).status == 'HANDOFF_ALREADY_CONSUMED'
    assert provider.dispatch_count == count
    return result


def test_round_trip_and_independent_v2_verification(harness):
    provider, request, kwargs, clock, trust, cp = harness
    result = attempt(harness)
    assert result.status == 'VERIFIED' and result.signature_verified
    Ed25519PublicKey.from_public_bytes(provider.public_key_bytes).verify(
        bytes.fromhex(result.response.signature_hex), bytes.fromhex(request.preimage_hex))
    assert verify_observation(result.response, expected_request=kwargs['expected_request'],
        trust_store=trust, trusted_checkpoint=cp, now=clock[1]).status == 'VERIFIED'
    assert provider.dispatch_count == 1


@pytest.mark.parametrize('mode,status,count', [
    ('WRONG_KEY','SIGNATURE_INVALID',1), ('TAMPERED_SIGNATURE','SIGNATURE_INVALID',1),
    ('INVALID_SIGNATURE','SIGNATURE_INVALID',1), ('UNSUPPORTED_MECHANISM','ALGORITHM_UNSUPPORTED',0),
    ('DEADLINE_EXPIRED','DEADLINE_EXCEEDED',0), ('AMBIGUOUS_OUTCOME','OUTCOME_UNKNOWN',1),
    ('LATE_RESULT_REJECTION','RESULT_DISCARDED',1), ('PROVIDER_FAILURE','PROVIDER_FAILED',1),
    ('not-a-mode','INVALID_MODE',0)])
def test_faults_burn_handoff_without_output_or_fallback(harness, mode, status, count):
    result = attempt(harness, mode)
    assert result.status == status and result.response is None and not result.signature_verified
    assert harness[0].dispatch_count == count


@pytest.mark.parametrize('field,value,status', [('signer_id','intruder','UNAUTHORIZED_SIGNER'),
    ('trusted_anchor',None,'INVALID_RECORD'), ('expected_request',None,'REQUEST_MISMATCH')])
def test_invalid_inputs_consumed_before_dispatch(harness, field, value, status):
    assert attempt(harness, **{field:value}).status == status
    assert harness[0].dispatch_count == 0


@pytest.mark.parametrize('mechanism,format', [('ED25519_PH','RAW_64'),('ECDSA','RAW_64'),('ED25519_RAW','DER')])
def test_pinned_unsupported_capabilities(harness, mechanism, format):
    p,r,k,*_ = harness
    caps = change(k['capabilities'], mechanism=mechanism, signature_format=format)
    anchor = change(k['trusted_anchor'], capabilities_digest=record_digest(caps))
    assert attempt(harness, capabilities=caps, trusted_anchor=anchor).status == 'ALGORITHM_UNSUPPORTED'
    assert p.dispatch_count == 0


def test_oversize_has_no_prehash_fallback(harness):
    p,r,k,*_ = harness
    caps = change(k['capabilities'], max_message_bytes=len(bytes.fromhex(r.preimage_hex))-1)
    anchor = change(k['trusted_anchor'], capabilities_digest=record_digest(caps))
    assert attempt(harness, capabilities=caps, trusted_anchor=anchor).status == 'PAYLOAD_TOO_LARGE'
    assert p.dispatch_count == 0


@pytest.mark.parametrize('mutation', ['hash','prefix','payload'])
def test_exact_captured_preimage(harness, mutation):
    p,r,k,clock,*_ = harness
    if mutation == 'hash': r = change(r, preimage_hex=sha256(bytes.fromhex(r.preimage_hex)).hexdigest())
    elif mutation == 'prefix': r = change(r, preimage_hex=(b'wrong:' + bytes.fromhex(r.preimage_hex)).hex())
    else: r = change(r, payload=change(r.payload, policy_digest='1'*64))
    h = p.mint_handoff_for_testing('bad',r,deadline=105)
    assert p.sign(h,**k).status == 'PREIMAGE_MISMATCH'
    assert p.sign(h,**k).status == 'HANDOFF_ALREADY_CONSUMED'
    assert p.dispatch_count == 0


@pytest.mark.parametrize('clock_value,status', [(105,'DEADLINE_EXCEEDED'),(106,'DEADLINE_EXCEEDED'),
    (99,'CLOCK_REGRESSION'),(float('nan'),'INVALID_INPUT')])
def test_pre_dispatch_clock(harness, clock_value, status):
    p,r,k,clock,*_ = harness
    h = p.mint_handoff_for_testing('clock',r,deadline=105)
    clock[0] = clock_value
    assert p.sign(h,**k).status == status
    assert p.sign(h,**k).status == 'HANDOFF_ALREADY_CONSUMED'
    assert p.dispatch_count == 0


@pytest.mark.parametrize('which,value', [(0,105),(0,99),(1,1_800_000_060),(1,1_799_999_999)])
def test_real_post_dispatch_clock_changes_discard(harness, monkeypatch, which, value):
    p,r,k,clock,*_ = harness
    dispatch = p._dispatch
    def delayed(raw, mode):
        signature = dispatch(raw, mode)
        clock[which] = value
        return signature
    monkeypatch.setattr(p,'_dispatch',delayed)
    assert attempt(harness).status == 'RESULT_DISCARDED'
    assert p.dispatch_count == 1


def test_unexpected_dispatch_exception_is_unknown(harness, monkeypatch):
    def broken(*args): raise RuntimeError('sensitive diagnostic')
    monkeypatch.setattr(harness[0],'_dispatch',broken)
    assert attempt(harness).status == 'OUTCOME_UNKNOWN'


def test_closed_provider_burns_existing_handoff(harness):
    p,r,k,*_ = harness
    h = p.mint_handoff_for_testing('closed',r,deadline=105)
    p.close()
    assert p.sign(h,**k).status == 'KEY_DISABLED'
    assert p.sign(h,**k).status == 'HANDOFF_ALREADY_CONSUMED'
    with pytest.raises(ValueError): p.mint_handoff_for_testing('new',r,deadline=105)


def test_other_provider_cannot_take_handoff(harness):
    p,r,k,*_ = harness
    h = p.mint_handoff_for_testing('foreign',r,deadline=105)
    other = TestCustodyProvider()
    try: assert other.sign(h,**k).status == 'INVALID_HANDOFF'
    finally: other.close()
    assert p.sign(h,**k).status == 'VERIFIED'


def test_thread_misuse_consumes_once(harness):
    p,r,k,*_ = harness
    h = p.mint_handoff_for_testing('thread',r,deadline=105)
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _:p.sign(h,**k).status,range(2)))
    assert sorted(results) == ['CONTEXT_MISMATCH','HANDOFF_ALREADY_CONSUMED']
    assert p.dispatch_count == 0


@pytest.mark.parametrize('method',[copy.copy,copy.deepcopy,pickle.dumps])
def test_noncopyable_nonserializable(harness, method):
    p,r,*_ = harness
    h = p.mint_handoff_for_testing('opaque',r,deadline=105)
    for obj in (p,h):
        with pytest.raises(TypeError): method(obj)
    with pytest.raises(TypeError): h._id = 'changed'


@pytest.mark.parametrize('deadline',[100,106,True,float('inf'),float('nan')])
def test_mint_deadline_bounds(harness, deadline):
    p,r,*_ = harness
    with pytest.raises(ValueError): p.mint_handoff_for_testing('bad',r,deadline=deadline)


def test_id_reuse_and_bounded_inventory(harness):
    p,r,k,*_ = harness
    p.MAX_HANDOFFS = 2
    h = p.mint_handoff_for_testing('one',r,deadline=105)
    p.sign(h,**k)
    with pytest.raises(ValueError): p.mint_handoff_for_testing('one',r,deadline=105)
    p.mint_handoff_for_testing('two',r,deadline=105)
    with pytest.raises(ValueError): p.mint_handoff_for_testing('three',r,deadline=105)


def test_unknown_cannot_recover_signature_but_fresh_handoff_can_sign(harness):
    p,r,k,*_ = harness
    assert attempt(harness,'AMBIGUOUS_OUTCOME').response is None
    h = p.mint_handoff_for_testing('fresh',change(r,attempt_id='attempt-2'),deadline=105)
    assert p.sign(h,**k).status == 'VERIFIED'
    assert p.dispatch_count == 2


def test_pinned_wrong_instance_key_rejected_before_dispatch(harness, custody):
    p,r,k,*_ = harness
    handle = custody[1]
    payload = change(r.payload,signing_key_id=handle.key_id)
    r = change(r,handle_digest=record_digest(handle),payload=payload,preimage_hex=observation_preimage(payload).hex())
    anchor = change(k['trusted_anchor'],handle_digest=record_digest(handle))
    h = p.mint_handoff_for_testing('mismatch',r,deadline=105)
    assert p.sign(h,**{**k,'handle':handle,'trusted_anchor':anchor}).status == 'KEY_MISMATCH'
    assert p.dispatch_count == 0


def test_process_context_change_burns_handoff(harness, monkeypatch):
    p,r,k,*_ = harness
    h = p.mint_handoff_for_testing('process',r,deadline=105)
    monkeypatch.setattr('tnc.provenance.key_custody_provider.os.getpid',lambda:p._pid+1)
    assert p.sign(h,**k).status == 'CONTEXT_MISMATCH'
    assert p.sign(h,**k).status == 'HANDOFF_ALREADY_CONSUMED'
    assert p.dispatch_count == 0


def test_deadline_passes_during_verification(harness, monkeypatch):
    p,r,k,clock,*_ = harness
    values = iter((100,100,100,100,105))  # mint, start, pre-dispatch, completion, release
    p._clock = lambda:next(values)
    assert attempt(harness).status == 'RESULT_DISCARDED'


@pytest.mark.parametrize('state,status',[('LOCKED','HSM_LOCKED'),('UNAVAILABLE','PROVIDER_UNAVAILABLE')])
def test_provider_availability_is_checked(harness, state, status):
    p,r,k,*_ = harness
    caps = change(k['capabilities'],state=state)
    anchor = change(k['trusted_anchor'],capabilities_digest=record_digest(caps))
    assert attempt(harness,capabilities=caps,trusted_anchor=anchor).status == status
    assert p.dispatch_count == 0


def test_no_io_during_signing(harness, monkeypatch):
    def forbidden(*args,**kwargs): raise AssertionError('Unexpected I/O')
    monkeypatch.setattr('builtins.open',forbidden)
    monkeypatch.setattr('socket.socket',forbidden)
    monkeypatch.setattr('sqlite3.connect',forbidden)
    assert attempt(harness).status == 'VERIFIED'
