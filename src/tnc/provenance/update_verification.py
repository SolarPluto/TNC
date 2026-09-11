"""Read-only Ed25519 verification. No private keys, signing, I/O, or activation."""
from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.provisioning_models import Interval
from tnc.provenance.update_models import UpdateIntent, UpdateReceipt, UPDATE_RECORD_LIMIT

PublicKeyHex = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
SignatureHex = Annotated[str, Field(pattern=r'^[0-9a-f]{128}$')]
SIGNING_DOMAIN = b'TNC-INSTALLER-UPDATE\x00v1\x00'


def installer_key_hash(public_key_hex):
    """SHA-256 of Ed25519 DER SubjectPublicKeyInfo, not a certificate fingerprint."""
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    return sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


class InstallerKeyRecord(Interval):
    key_id: Digest
    public_key_hex: PublicKeyHex
    principal_id: Identifier
    algorithm: Literal['Ed25519'] = 'Ed25519'
    state: Literal['ACTIVE', 'RETIRED']
    permissions: tuple[Literal['UPDATE_PUBLISH'], ...] = Field(max_length=1)
    minimum_generation: int = Field(strict=True, gt=0)
    maximum_generation: int | None = Field(default=None, strict=True, gt=0)

    @model_validator(mode='after')
    def binding(self):
        if self.key_id != installer_key_hash(self.public_key_hex):
            raise ValueError('Public key binding mismatch')
        if self.maximum_generation is not None and self.maximum_generation < self.minimum_generation:
            raise ValueError('Reversed generation bounds')
        return self


class InstallerTrustStore(Interval):
    codec_version: Literal[1] = 1
    deployment_id: Identifier
    revision: int = Field(strict=True, gt=0)
    keys: tuple[InstallerKeyRecord, ...] = Field(min_length=1, max_length=64)
    revoked_key_ids: tuple[Digest, ...] = Field(max_length=64)

    @model_validator(mode='after')
    def canonical_inventory(self):
        ids = tuple(k.key_id for k in self.keys)
        if ids != tuple(sorted(set(ids))) or self.revoked_key_ids != tuple(sorted(set(self.revoked_key_ids))):
            raise ValueError('Sorted unique keys required')
        if not set(self.revoked_key_ids) <= set(ids):
            raise ValueError('Revoked key history must be retained')
        return self


class InstallerTrustCheckpoint(Interval):
    """Independently provisioned current trust-store binding, never request-supplied."""
    deployment_id: Identifier
    revision: int = Field(strict=True, gt=0)
    trust_store_hash: Digest


class SignatureEnvelope(Model):
    codec_version: Literal[1] = 1
    profile: Literal['tnc-update-ed25519-v1'] = 'tnc-update-ed25519-v1'
    deployment_id: Identifier
    key_id: Digest
    signature_hex: SignatureHex


class CommittedSignatureBinding(Model):
    """Independent archival attestation binding the signature seen at commit."""
    deployment_id: Identifier
    receipt_hash: Digest
    signature_envelope_hash: Digest
    trust_checkpoint_hash: Digest


class UpdateSignatureResult(Model):
    status: Literal['VERIFIED', 'REJECTED']
    mode: Literal['CURRENT', 'HISTORICAL']
    reason_code: Literal['INVALID_RECORD', 'SIGNATURE_INVALID', 'UNKNOWN_SIGNER', 'KEY_EXPIRED',
        'KEY_NOT_YET_VALID', 'KEY_REVOKED', 'KEY_RETIRED', 'DEPLOYMENT_MISMATCH',
        'TRUST_CHECKPOINT_MISMATCH', 'TRUST_INTERVAL_INVALID', 'PUBLISH_PERMISSION_DENIED',
        'GENERATION_DENIED', 'INTENT_INTERVAL_INVALID', 'KEY_ACTIVATION_MISMATCH',
        'HISTORICAL_BINDING_MISMATCH'] | None = None
    intent_hash: Digest | None = None
    key_id: Digest | None = None
    principal_id: Identifier | None = None
    deployment_id: Identifier | None = None
    trust_revision: int | None = Field(default=None, strict=True, gt=0)
    evaluated_at: datetime | None = None

    @model_validator(mode='after')
    def shape(self):
        facts = (self.intent_hash, self.key_id, self.principal_id, self.deployment_id, self.trust_revision, self.evaluated_at)
        if self.status == 'VERIFIED':
            if self.reason_code is not None or any(v is None for v in facts):
                raise ValueError('Incomplete verification result')
        elif self.reason_code is None or any(v is not None for v in facts):
            raise ValueError('Rejected result exposes no verified identity')
        return self


_KINDS = (InstallerKeyRecord, InstallerTrustStore, InstallerTrustCheckpoint, SignatureEnvelope,
          CommittedSignatureBinding, UpdateSignatureResult, UpdateIntent, UpdateReceipt)


def decode_verification_record(kind, data):
    if kind not in _KINDS or type(data) is not bytes or not 0 < len(data) <= UPDATE_RECORD_LIMIT:
        raise ValueError('Invalid verification record')
    return decode_canonical(kind, data)


def _copy(record, kind):
    if type(record) is not kind:
        raise ValueError('Exact typed record required')
    return decode_verification_record(kind, canonical_bytes(record))


def update_signature_preimage(intent):
    """Fixed domain || uint32 deployment length || deployment || uint64 JSON length || JSON."""
    intent = _copy(intent, UpdateIntent)
    deployment, payload = intent.deployment_id.encode('utf-8'), canonical_bytes(intent)
    return SIGNING_DOMAIN + len(deployment).to_bytes(4, 'big') + deployment + len(payload).to_bytes(8, 'big') + payload


class _Rejected(ValueError):
    def __init__(self, reason): self.reason = reason


def _require(condition, reason):
    if not condition: raise _Rejected(reason)


def _verify(intent, envelope, store, checkpoint, at, mode):
    _require(isinstance(at, datetime) and at.utcoffset() is not None, 'INVALID_RECORD')
    _require(intent.deployment_id == envelope.deployment_id == store.deployment_id == checkpoint.deployment_id,
             'DEPLOYMENT_MISMATCH')
    _require(checkpoint.revision == store.revision and checkpoint.trust_store_hash == record_digest(store),
             'TRUST_CHECKPOINT_MISMATCH')
    _require(all(v.valid_from <= at < v.valid_until for v in (checkpoint, store)), 'TRUST_INTERVAL_INVALID')
    _require(envelope.key_id == intent.signer_key_hash, 'SIGNATURE_INVALID')
    key = next((k for k in store.keys if k.key_id == envelope.key_id), None)
    _require(key is not None, 'UNKNOWN_SIGNER')
    _require(key.key_id not in store.revoked_key_ids, 'KEY_REVOKED')
    _require(key.state == 'ACTIVE', 'KEY_RETIRED')
    _require(at >= key.valid_from, 'KEY_NOT_YET_VALID')
    _require(at < key.valid_until, 'KEY_EXPIRED')
    _require('UPDATE_PUBLISH' in key.permissions and key.principal_id == intent.publisher_id, 'PUBLISH_PERMISSION_DENIED')
    generation = intent.candidate.envelope.generation
    _require(generation >= key.minimum_generation and (key.maximum_generation is None or generation <= key.maximum_generation),
             'GENERATION_DENIED')
    _require(intent.valid_from <= at < intent.valid_until, 'INTENT_INTERVAL_INVALID')
    # This prevents declaring an intent active before its nominated key. It does
    # not establish a signature creation time or provide trusted timestamping.
    _require(intent.valid_from >= key.valid_from, 'KEY_ACTIVATION_MISMATCH')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(
            bytes.fromhex(envelope.signature_hex), update_signature_preimage(intent))
    except InvalidSignature:
        raise _Rejected('SIGNATURE_INVALID') from None
    return UpdateSignatureResult(status='VERIFIED', mode=mode, intent_hash=record_digest(intent), key_id=key.key_id,
        principal_id=key.principal_id, deployment_id=intent.deployment_id, trust_revision=store.revision, evaluated_at=at)


def verify_update_intent_signature(intent, signature_envelope, trust_store, *, trusted_checkpoint, now):
    """Current validity/permission check; does not authenticate the live caller or commit."""
    try:
        return _verify(_copy(intent, UpdateIntent), _copy(signature_envelope, SignatureEnvelope),
            _copy(trust_store, InstallerTrustStore), _copy(trusted_checkpoint, InstallerTrustCheckpoint), now, 'CURRENT')
    except _Rejected as exc:
        reason = exc.reason
    except Exception:
        reason = 'INVALID_RECORD'
    return UpdateSignatureResult(status='REJECTED', mode='CURRENT', reason_code=reason)


def verify_committed_update_signature(intent, signature_envelope, historical_trust_store, historical_checkpoint,
                                     receipt, *, trusted_binding):
    """Archival signature check only. Never authorize a current receipt lookup or update.

    Receipt/signature/checkpoint binding must be supplied by an independent trusted
    commit archive; accepting a caller-created binding would permit backdating.
    """
    try:
        intent, envelope = _copy(intent, UpdateIntent), _copy(signature_envelope, SignatureEnvelope)
        store = _copy(historical_trust_store, InstallerTrustStore)
        checkpoint = _copy(historical_checkpoint, InstallerTrustCheckpoint)
        receipt, binding = _copy(receipt, UpdateReceipt), _copy(trusted_binding, CommittedSignatureBinding)
        _require(binding.deployment_id == receipt.deployment_id == intent.deployment_id
                 and binding.receipt_hash == record_digest(receipt)
                 and binding.signature_envelope_hash == record_digest(envelope)
                 and binding.trust_checkpoint_hash == record_digest(checkpoint), 'HISTORICAL_BINDING_MISMATCH')
        _require(receipt.intent_hash == record_digest(intent) and receipt.operation_id == intent.operation_id
                 and receipt.publisher_id == intent.publisher_id
                 and receipt.checkpoint_hash == record_digest(intent.candidate.checkpoint)
                 and receipt.generation == intent.candidate.envelope.generation
                 and receipt.authority_sequence == intent.expected_head_sequence + 1, 'HISTORICAL_BINDING_MISMATCH')
        return _verify(intent, envelope, store, checkpoint, receipt.committed_at, 'HISTORICAL')
    except _Rejected as exc:
        reason = exc.reason
    except Exception:
        reason = 'INVALID_RECORD'
    return UpdateSignatureResult(status='REJECTED', mode='HISTORICAL', reason_code=reason)
