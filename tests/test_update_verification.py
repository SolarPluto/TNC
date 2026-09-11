from datetime import timedelta
from hashlib import sha256
import builtins
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.update_models import UpdateReceipt
from tnc.provenance.update_verification import (
    SIGNING_DOMAIN, InstallerKeyRecord, InstallerTrustStore, InstallerTrustCheckpoint,
    SignatureEnvelope, CommittedSignatureBinding, UpdateSignatureResult,
    installer_key_hash, update_signature_preimage, decode_verification_record,
    verify_update_intent_signature, verify_committed_update_signature,
)


@pytest.fixture
def signed(update):
    private = Ed25519PrivateKey.generate()  # Test-only, in memory; never persisted.
    public_hex = private.public_key().public_bytes_raw().hex()
    key = InstallerKeyRecord(key_id=installer_key_hash(public_hex), public_key_hex=public_hex,
        principal_id='installer', state='ACTIVE', permissions=('UPDATE_PUBLISH',), minimum_generation=1,
        valid_from=NOW-timedelta(days=1), valid_until=NOW+timedelta(minutes=30))
    store = InstallerTrustStore(deployment_id=update['intent'].deployment_id, revision=1, keys=(key,), revoked_key_ids=(),
        valid_from=NOW-timedelta(days=1), valid_until=NOW+timedelta(days=1))
    checkpoint = InstallerTrustCheckpoint(deployment_id=store.deployment_id, revision=1, trust_store_hash=record_digest(store),
        valid_from=store.valid_from, valid_until=store.valid_until)
    intent = update['intent'].model_copy(update={'signer_key_hash':key.key_id})
    envelope = SignatureEnvelope(deployment_id=intent.deployment_id, key_id=key.key_id,
        signature_hex=private.sign(update_signature_preimage(intent)).hex())
    return dict(private=private, key=key, store=store, checkpoint=checkpoint, intent=intent, envelope=envelope)


def verify(s, now=NOW):
    return verify_update_intent_signature(s['intent'], s['envelope'], s['store'], trusted_checkpoint=s['checkpoint'], now=now)


def changed_store(s, **changes):
    store = s['store'].model_copy(update=changes)
    checkpoint = s['checkpoint'].model_copy(update={'revision':store.revision, 'trust_store_hash':record_digest(store)})
    return s | {'store':store, 'checkpoint':checkpoint}


def history(s):
    intent = s['intent']
    receipt = UpdateReceipt(operation_id=intent.operation_id, deployment_id=intent.deployment_id,
        publisher_id=intent.publisher_id, intent_hash=record_digest(intent), checkpoint_hash=record_digest(intent.candidate.checkpoint),
        authority_sequence=intent.expected_head_sequence+1, generation=intent.candidate.envelope.generation, committed_at=NOW)
    binding = CommittedSignatureBinding(deployment_id=intent.deployment_id, receipt_hash=record_digest(receipt),
        signature_envelope_hash=record_digest(s['envelope']), trust_checkpoint_hash=record_digest(s['checkpoint']))
    return receipt, binding


def historical(s, receipt, binding):
    return verify_committed_update_signature(s['intent'], s['envelope'], s['store'], s['checkpoint'], receipt, trusted_binding=binding)


def test_real_signature_verifies_with_bound_identity(signed):
    result = verify(signed)
    assert result.status=='VERIFIED' and result.mode=='CURRENT'
    assert result.intent_hash==record_digest(signed['intent']) and result.key_id==signed['key'].key_id
    assert result.principal_id=='installer' and result.trust_revision==1


def test_preimage_and_key_id_match_independent_construction(signed):
    payload = canonical_bytes(signed['intent'])
    deployment = signed['intent'].deployment_id.encode()
    expected = b'TNC-INSTALLER-UPDATE\x00v1\x00'+len(deployment).to_bytes(4,'big')+deployment+len(payload).to_bytes(8,'big')+payload
    assert update_signature_preimage(signed['intent'])==expected
    public = signed['private'].public_key()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert sha256(der).hexdigest()==signed['key'].key_id
    public.verify(bytes.fromhex(signed['envelope'].signature_hex), expected)


@pytest.mark.parametrize('field,value', [('operation_id','another'), ('expected_head_sequence',99),
    ('expected_checkpoint_hash','f'*64)])
def test_payload_tampering(signed, field, value):
    result = verify(signed | {'intent':signed['intent'].model_copy(update={field:value})})
    assert result.reason_code=='SIGNATURE_INVALID' and result.principal_id is None


@pytest.mark.parametrize('mode', ['raw-json','wrong-domain','digest-only','other-key','bitflip'])
def test_invalid_signature_preimages(signed, mode):
    private = signed['private']
    payload = update_signature_preimage(signed['intent'])
    if mode=='raw-json': payload=canonical_bytes(signed['intent'])
    if mode=='wrong-domain': payload=payload.replace(SIGNING_DOMAIN,b'OTHER-DOMAIN\x00')
    if mode=='digest-only': payload=sha256(payload).digest()
    if mode=='other-key': private=Ed25519PrivateKey.generate()
    signature = private.sign(payload)
    if mode=='bitflip': signature=bytes((signature[0]^1,))+signature[1:]
    envelope = signed['envelope'].model_copy(update={'signature_hex':signature.hex()})
    assert verify(signed | {'envelope':envelope}).reason_code=='SIGNATURE_INVALID'


def test_deployment_header_mismatch(signed):
    envelope = signed['envelope'].model_copy(update={'deployment_id':'other-deployment'})
    assert verify(signed | {'envelope':envelope}).reason_code=='DEPLOYMENT_MISMATCH'


def test_unknown_signer(signed):
    private = Ed25519PrivateKey.generate()
    intent = signed['intent'].model_copy(update={'signer_key_hash':installer_key_hash(private.public_key().public_bytes_raw().hex())})
    envelope = SignatureEnvelope(deployment_id=intent.deployment_id, key_id=intent.signer_key_hash,
        signature_hex=private.sign(update_signature_preimage(intent)).hex())
    assert verify(signed | {'intent':intent,'envelope':envelope}).reason_code=='UNKNOWN_SIGNER'


@pytest.mark.parametrize('field,value,reason', [('state','RETIRED','KEY_RETIRED'),
    ('permissions',(),'PUBLISH_PERMISSION_DENIED'), ('principal_id','another','PUBLISH_PERMISSION_DENIED'),
    ('minimum_generation',3,'GENERATION_DENIED'), ('maximum_generation',1,'GENERATION_DENIED'),
    ('valid_from',NOW+timedelta(seconds=1),'KEY_NOT_YET_VALID'), ('valid_until',NOW,'KEY_EXPIRED')])
def test_key_authority_constraints(signed, field, value, reason):
    key = signed['key'].model_copy(update={field:value})
    assert verify(changed_store(signed, keys=(key,))).reason_code==reason


def test_revocation_blocks_previously_valid_signature(signed):
    revoked = changed_store(signed, revision=2, revoked_key_ids=(signed['key'].key_id,))
    assert verify(revoked).reason_code=='KEY_REVOKED'


def test_new_rotation_key_can_sign_new_intent(signed):
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes_raw().hex()
    key = InstallerKeyRecord(key_id=installer_key_hash(public_hex), public_key_hex=public_hex,
        principal_id='installer', state='ACTIVE', permissions=('UPDATE_PUBLISH',), minimum_generation=2,
        valid_from=NOW, valid_until=NOW+timedelta(hours=1))
    old = signed['key'].model_copy(update={'state':'RETIRED'})
    rotated = changed_store(signed, revision=2, keys=tuple(sorted((old,key), key=lambda k:k.key_id)))
    intent = signed['intent'].model_copy(update={'signer_key_hash':key.key_id, 'operation_id':'rotation-update'})
    envelope = SignatureEnvelope(deployment_id=intent.deployment_id, key_id=key.key_id,
        signature_hex=private.sign(update_signature_preimage(intent)).hex())
    assert verify(rotated | {'intent':intent, 'envelope':envelope}).status=='VERIFIED'


def test_signature_header_key_must_match_intent(signed):
    envelope = signed['envelope'].model_copy(update={'key_id':'f'*64})
    assert verify(signed | {'envelope':envelope}).reason_code=='SIGNATURE_INVALID'


def test_expired_current_trust_cannot_be_used_as_historical_override(signed):
    assert verify(signed, NOW+timedelta(days=2)).reason_code=='TRUST_INTERVAL_INVALID'
    assert historical(signed, *history(signed)).mode=='HISTORICAL'


@pytest.mark.parametrize('field,value', [('keys',()), ('keys','not-a-key-list'), ('revoked_key_ids',('f'*64,))])
def test_invalid_trust_inventories(signed, field, value):
    with pytest.raises(ValueError):
        InstallerTrustStore.model_validate(signed['store'].model_dump() | {field:value})


def test_revoked_key_at_commit_cannot_verify_historically(signed):
    revoked = changed_store(signed, revision=2, revoked_key_ids=(signed['key'].key_id,))
    assert historical(revoked, *history(revoked)).reason_code=='KEY_REVOKED'


@pytest.mark.parametrize('field,value', [('revision',2), ('trust_store_hash','f'*64)])
def test_checkpoint_mismatch(signed, field, value):
    assert verify(signed | {'checkpoint':signed['checkpoint'].model_copy(update={field:value})}).reason_code=='TRUST_CHECKPOINT_MISMATCH'


def test_rolled_back_store_cannot_match_current_checkpoint(signed):
    current = changed_store(signed, revision=2, revoked_key_ids=(signed['key'].key_id,))
    assert verify(signed | {'checkpoint':current['checkpoint']}).reason_code=='TRUST_CHECKPOINT_MISMATCH'


@pytest.mark.parametrize('which', ['store','checkpoint'])
def test_expired_trust_snapshot(signed, which):
    if which=='store':
        changed = changed_store(signed, valid_until=NOW)
    else: changed=signed | {'checkpoint':signed['checkpoint'].model_copy(update={'valid_until':NOW})}
    assert verify(changed).reason_code=='TRUST_INTERVAL_INVALID'


def test_expired_key_checked_at_now_not_claimed_signing_time(signed):
    assert verify(signed, NOW+timedelta(minutes=30)).reason_code=='KEY_EXPIRED'


def test_intent_cannot_begin_before_key_activation(signed):
    key = signed['key'].model_copy(update={'valid_from':NOW+timedelta(seconds=1)})
    assert verify(changed_store(signed, keys=(key,)), NOW+timedelta(seconds=2)).reason_code=='KEY_ACTIVATION_MISMATCH'


@pytest.mark.parametrize('field,value', [('valid_from',NOW+timedelta(seconds=1)), ('valid_until',NOW)])
def test_intent_validity(signed, field, value):
    updates={field:value}
    if field=='valid_until': updates['valid_from']=NOW-timedelta(seconds=1)
    intent = signed['intent'].model_copy(update=updates)
    assert verify(signed | {'intent':intent}).reason_code=='INTENT_INTERVAL_INVALID'


def test_historical_verification_does_not_grant_current_authority(signed):
    receipt, binding = history(signed)
    retired = changed_store(signed, revision=2, keys=(signed['key'].model_copy(update={'state':'RETIRED'}),))
    assert verify(retired).reason_code=='KEY_RETIRED'
    result = historical(signed, receipt, binding)
    assert result.status=='VERIFIED' and result.mode=='HISTORICAL' and result.evaluated_at==NOW


def test_revoked_current_key_does_not_rewrite_archival_binding(signed):
    receipt, binding = history(signed)
    current = changed_store(signed, revision=2, revoked_key_ids=(signed['key'].key_id,))
    assert verify(current).reason_code=='KEY_REVOKED'
    assert historical(signed, receipt, binding).status=='VERIFIED'


@pytest.mark.parametrize('field,value', [('committed_at',NOW-timedelta(hours=1)), ('intent_hash','f'*64),
    ('authority_sequence',99), ('publisher_id','other')])
def test_historical_receipt_tampering(signed, field, value):
    receipt, binding = history(signed)
    assert historical(signed, receipt.model_copy(update={field:value}), binding).reason_code=='HISTORICAL_BINDING_MISMATCH'


def test_archival_association_still_checked_with_bound_receipt(signed):
    receipt, binding = history(signed)
    receipt = receipt.model_copy(update={'intent_hash':'f'*64})
    binding = binding.model_copy(update={'receipt_hash':record_digest(receipt)})
    assert historical(signed, receipt, binding).reason_code=='HISTORICAL_BINDING_MISMATCH'


def test_replacing_historical_signature_is_blocked(signed):
    receipt, binding = history(signed)
    replacement = signed['envelope'].model_copy(update={'signature_hex':'00'*64})
    assert historical(signed | {'envelope':replacement}, receipt, binding).reason_code=='HISTORICAL_BINDING_MISMATCH'


@pytest.mark.parametrize('mutation', [lambda b:b+b' ', lambda b:b'\xff', lambda b:b'{}',
    lambda b:b.replace(b'"codec_version":1', b'"codec_version":true'),
    lambda b:b.replace(b'"profile":', b'"signed_at":"2010-01-01T00:00:00.000000Z","profile":'),
    lambda b:b.replace(b'"profile":', b'"profile":"dup","profile":'),
    lambda b:b.replace(b'tnc-update-ed25519-v1', b'none'), lambda b:bytearray(b), lambda b:b' '*(1024*1024+1)])
def test_signature_envelope_canonical_rejection(signed, mutation):
    with pytest.raises(ValueError): decode_verification_record(SignatureEnvelope, mutation(canonical_bytes(signed['envelope'])))


def test_key_id_cannot_be_detached_from_public_key(signed):
    with pytest.raises(ValueError):
        InstallerKeyRecord.model_validate(signed['key'].model_dump() | {'key_id':'f'*64})


def test_result_cannot_claim_identity_on_failure():
    with pytest.raises(ValueError):
        UpdateSignatureResult(status='REJECTED', mode='CURRENT', reason_code='SIGNATURE_INVALID', principal_id='installer')


def test_naive_time_rejected(signed):
    assert verify(signed, NOW.replace(tzinfo=None)).reason_code=='INVALID_RECORD'


def test_no_io_and_no_production_signing(signed, monkeypatch):
    def forbidden(*a, **k): pytest.fail('Verifier attempted I/O')
    monkeypatch.setattr(builtins,'open',forbidden)
    monkeypatch.setattr(sqlite3,'connect',forbidden)
    assert verify(signed).status=='VERIFIED'
    assert historical(signed, *history(signed)).status=='VERIFIED'
