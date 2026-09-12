"""Pure authenticated public trust distribution checks; no signing or storage.

Policy/checkpoint and retained head are independent host inputs. A successful
result proposes audit state; it neither publishes trust nor proves unseen freshness.
"""
from hashlib import sha256
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Digest, Identifier, ZERO, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.reconciliation_verifier import ObservationTrustStore, ObservationTrustCheckpoint

CHECKPOINT_DOMAIN = b'TNC-TRUST-DISTRIBUTION-v1:'
TRANSITION_DOMAIN = b'TNC-TRUST-EPOCH-TRANSITION-v1:'
RECORD_LIMIT = 131072
Time = Annotated[int, Field(strict=True, ge=0, le=2**63-1)]
Revision = Annotated[int, Field(strict=True, gt=0, le=2**63-1)]
Age = Annotated[int, Field(strict=True, ge=1, le=3600)]
Signature = Annotated[str, Field(strict=True, pattern=r'^[0-9a-f]{128}$')]


class DistributionInterval(Model):
    issued_at: Time
    expires_at: Time

    @model_validator(mode='after')
    def interval(self):
        if self.issued_at >= self.expires_at: raise ValueError('Positive interval required')
        return self


class DistributionScope(Model):
    deployment_id: Identifier
    store_instance_id: Identifier


class DistributionKey(DistributionScope, DistributionInterval):
    issuer_id: Identifier
    key_id: Digest
    public_key_hex: Digest
    algorithm: Literal['Ed25519'] = 'Ed25519'
    status: Literal['active', 'retired', 'revoked']
    permission: Literal['DISTRIBUTE_OBSERVATION_TRUST', 'AUTHORIZE_DISTRIBUTION_EPOCH']

    @model_validator(mode='after')
    def key_binding(self):
        if self.key_id != sha256(bytes.fromhex(self.public_key_hex)).hexdigest():
            raise ValueError('Raw public-key digest required')
        return self


class DistributionPolicy(DistributionScope, DistributionInterval):
    profile: Literal['tnc-trust-distribution-policy-v1'] = 'tnc-trust-distribution-policy-v1'
    revision: Revision
    issuer_id: Identifier
    max_age_seconds: Age
    bootstrap_checkpoint_revision: Revision
    bootstrap_epoch: Revision
    bootstrap_epoch_id: Identifier
    bootstrap_signing_key_id: Digest
    keys: tuple[DistributionKey, ...] = Field(min_length=1, max_length=8)
    root_key: DistributionKey

    @model_validator(mode='after')
    def inventory(self):
        ids = tuple(k.key_id for k in self.keys)
        if ids != tuple(sorted(set(ids))) or self.root_key.key_id in ids:
            raise ValueError('Distinct sorted distribution and root keys required')
        if self.bootstrap_signing_key_id not in ids: raise ValueError('Bootstrap key missing')
        if self.root_key.permission != 'AUTHORIZE_DISTRIBUTION_EPOCH': raise ValueError('Root permission required')
        for key in self.keys:
            if key.permission != 'DISTRIBUTE_OBSERVATION_TRUST' or key.issuer_id != self.issuer_id:
                raise ValueError('Distribution permission/issuer mismatch')
        if any((k.deployment_id, k.store_instance_id) != (self.deployment_id, self.store_instance_id)
               for k in self.keys+(self.root_key,)):
            raise ValueError('Key scope mismatch')
        return self


class DistributionPolicyCheckpoint(DistributionScope, DistributionInterval):
    """Independently authenticated host pin; never nominated by the bundle."""
    policy_revision: Revision
    policy_digest: Digest


class TrustDistributionPayload(DistributionScope, DistributionInterval):
    profile: Literal['tnc-trust-distribution-v1'] = 'tnc-trust-distribution-v1'
    issuer_id: Identifier
    signing_key_id: Digest
    checkpoint_revision: Revision
    previous_checkpoint_digest: Digest
    epoch: Revision
    epoch_id: Identifier
    trust_store_revision: Revision
    trust_store_digest: Digest
    max_age_seconds: Age
    transition_digest: Digest | None = None


class EpochTransition(DistributionScope, DistributionInterval):
    profile: Literal['tnc-trust-epoch-transition-v1'] = 'tnc-trust-epoch-transition-v1'
    root_issuer_id: Identifier
    root_key_id: Digest
    distribution_issuer_id: Identifier
    from_epoch: Revision
    from_epoch_id: Identifier
    from_signing_key_id: Digest
    previous_checkpoint_revision: Revision
    previous_checkpoint_digest: Digest
    to_epoch: Revision
    to_epoch_id: Identifier
    to_signing_key_id: Digest
    checkpoint_revision: Revision
    trust_store_revision: Revision
    trust_store_digest: Digest

    @model_validator(mode='after')
    def progression(self):
        if (self.to_epoch != self.from_epoch+1 or self.from_epoch_id == self.to_epoch_id
                or self.to_signing_key_id == self.from_signing_key_id
                or self.checkpoint_revision != self.previous_checkpoint_revision+1):
            raise ValueError('Direct epoch/key/checkpoint successor required')
        return self


class SignedEpochTransition(Model):
    payload: EpochTransition
    signature_hex: Signature


class TrustDistributionBundle(Model):
    payload: TrustDistributionPayload
    trust_store: ObservationTrustStore
    signature_hex: Signature
    transition: SignedEpochTransition | None = None


class DistributionHead(DistributionScope):
    """Trusted retained audit state; no local persistence or self-authentication."""
    checkpoint_revision: Revision
    checkpoint_digest: Digest
    epoch: Revision
    epoch_id: Identifier
    signing_key_id: Digest
    trust_store_revision: Revision
    trust_store_digest: Digest
    policy_revision: Revision
    policy_digest: Digest
    issued_at: Time
    accepted_at: Time
    checked_at: Time

    @model_validator(mode='after')
    def times(self):
        if not self.issued_at <= self.accepted_at <= self.checked_at: raise ValueError('Invalid head times')
        return self


Reason = Literal['INVALID_RECORD', 'POLICY_MISMATCH', 'POLICY_REGRESSION', 'POLICY_FORK',
    'SCOPE_MISMATCH', 'KEY_DENIED', 'SIGNATURE_INVALID', 'CHECKPOINT_STALE', 'NOT_YET_VALID',
    'CHECKPOINT_REGRESSION', 'CHECKPOINT_FORK', 'PREDECESSOR_MISMATCH', 'MISSING_CHAIN',
    'TRUST_STORE_MISMATCH', 'TRUST_STORE_REGRESSION', 'TRUST_STORE_FORK', 'EPOCH_MISMATCH',
    'TRANSITION_REQUIRED', 'TRANSITION_INVALID', 'ROOT_DENIED', 'CLOCK_REGRESSION']


class DistributionResult(Model):
    status: Literal['INITIAL', 'ADVANCE', 'UNCHANGED', 'REJECTED']
    audit_only: bool = Field(default=True, strict=True)
    signature_verified: bool = Field(strict=True)
    reason_code: Reason | None = None
    proposed_head: DistributionHead | None = None
    checked_store: ObservationTrustStore | None = None
    checked_checkpoint: ObservationTrustCheckpoint | None = None

    @model_validator(mode='after')
    def shape(self):
        ok = self.status != 'REJECTED'
        if (not self.audit_only or self.signature_verified != ok or (self.reason_code is None) != ok
                or any((v is not None) != ok for v in (self.proposed_head, self.checked_store, self.checked_checkpoint))):
            raise ValueError('Audit result shape mismatch')
        return self


KINDS = (DistributionKey, DistributionPolicy, DistributionPolicyCheckpoint, TrustDistributionPayload,
         EpochTransition, SignedEpochTransition, TrustDistributionBundle, DistributionHead, DistributionResult)


def decode_distribution(kind, raw):
    if kind not in KINDS or type(raw) is not bytes or not 0 < len(raw) <= RECORD_LIMIT:
        raise ValueError('Invalid record bound')
    return decode_canonical(kind, raw)


def _copy(value, kind):
    if type(value) is not kind: raise ValueError('Exact record required')
    return decode_distribution(kind, canonical_bytes(value))


def checkpoint_preimage(payload):
    return CHECKPOINT_DOMAIN+canonical_bytes(_copy(payload, TrustDistributionPayload))


def transition_preimage(payload):
    return TRANSITION_DOMAIN+canonical_bytes(_copy(payload, EpochTransition))


class _Denied(ValueError): pass


def _require(condition, reason):
    if not condition: raise _Denied(reason)


def _scope(value): return value.deployment_id, value.store_instance_id


def _signature(key, signature, preimage, reason='SIGNATURE_INVALID'):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(bytes.fromhex(signature), preimage)
    except InvalidSignature:
        raise _Denied(reason) from None


def _active(key, issued, now, reason):
    _require(key.status == 'active' and key.issued_at <= issued <= now < key.expires_at, reason)


def verify_trust_distribution(bundle, *, policy, trusted_policy_checkpoint, retained_head, now):
    """Propose trust/head records under current independent host pins.

    Exact current retries still require fresh intervals and current signing-key
    permission. They never refresh the signed issuance time or expiry.
    """
    try:
        _require(type(now) is int and 0 <= now <= 2**63-1, 'INVALID_RECORD')
        b = _copy(bundle, TrustDistributionBundle)
        policy = _copy(policy, DistributionPolicy)
        pin = _copy(trusted_policy_checkpoint, DistributionPolicyCheckpoint)
        head = None if retained_head is None else _copy(retained_head, DistributionHead)
        p, store = b.payload, b.trust_store
        _require(_scope(p) == _scope(store) == _scope(policy) == _scope(pin), 'SCOPE_MISMATCH')
        _require((pin.policy_revision, pin.policy_digest) == (policy.revision, record_digest(policy)), 'POLICY_MISMATCH')
        _require(p.issuer_id == policy.issuer_id, 'POLICY_MISMATCH')
        _require(policy.issued_at <= now and pin.issued_at <= now and p.issued_at <= now, 'NOT_YET_VALID')
        _require(now < min(policy.expires_at, pin.expires_at, p.expires_at,
                           p.issued_at+min(p.max_age_seconds, policy.max_age_seconds)), 'CHECKPOINT_STALE')
        _require(p.checkpoint_revision >= policy.bootstrap_checkpoint_revision, 'CHECKPOINT_REGRESSION')
        _require(p.trust_store_revision == store.revision and p.trust_store_digest == record_digest(store), 'TRUST_STORE_MISMATCH')
        _require(0 <= store.timestamp <= p.issued_at <= now < store.expiry <= 2**63-1, 'TRUST_STORE_MISMATCH')
        # Existing store models have unbounded integer times; impose this profile's
        # 64-bit bounds without altering v2 records or requiring all keys active.
        _require(all(0 <= k.timestamp < k.expiry <= 2**63-1 for k in store.keys), 'INVALID_RECORD')
        key = next((k for k in policy.keys if k.key_id == p.signing_key_id), None)
        _require(key is not None, 'KEY_DENIED')
        _active(key, p.issued_at, now, 'KEY_DENIED')
        _signature(key, b.signature_hex, checkpoint_preimage(p))

        digest = record_digest(p)
        if head is None:
            _require(p.checkpoint_revision == policy.bootstrap_checkpoint_revision and p.previous_checkpoint_digest == ZERO
                and (p.epoch, p.epoch_id, p.signing_key_id) ==
                    (policy.bootstrap_epoch, policy.bootstrap_epoch_id, policy.bootstrap_signing_key_id), 'EPOCH_MISMATCH')
            _require(p.transition_digest is None and b.transition is None, 'TRANSITION_INVALID')
            status = 'INITIAL'
        else:
            _require(_scope(head) == _scope(p), 'SCOPE_MISMATCH')
            _require(now >= head.checked_at, 'CLOCK_REGRESSION')
            _require(policy.revision >= head.policy_revision, 'POLICY_REGRESSION')
            _require(policy.revision != head.policy_revision or record_digest(policy) == head.policy_digest, 'POLICY_FORK')
            _require(p.checkpoint_revision >= head.checkpoint_revision, 'CHECKPOINT_REGRESSION')
            if p.checkpoint_revision == head.checkpoint_revision:
                _require(digest == head.checkpoint_digest, 'CHECKPOINT_FORK')
                _require((p.epoch,p.epoch_id,p.signing_key_id,p.trust_store_revision,p.trust_store_digest,p.issued_at) ==
                         (head.epoch,head.epoch_id,head.signing_key_id,head.trust_store_revision,head.trust_store_digest,head.issued_at),
                         'CHECKPOINT_FORK')
                status = 'UNCHANGED'
            else:
                _require(p.checkpoint_revision == head.checkpoint_revision+1, 'MISSING_CHAIN')
                _require(p.previous_checkpoint_digest == head.checkpoint_digest, 'PREDECESSOR_MISMATCH')
                _require(p.issued_at >= head.issued_at, 'CLOCK_REGRESSION')
                _require(p.trust_store_revision >= head.trust_store_revision, 'TRUST_STORE_REGRESSION')
                _require(p.trust_store_revision != head.trust_store_revision or p.trust_store_digest == head.trust_store_digest,
                         'TRUST_STORE_FORK')
                if p.epoch == head.epoch:
                    _require((p.epoch_id,p.signing_key_id) == (head.epoch_id,head.signing_key_id), 'EPOCH_MISMATCH')
                    _require(p.transition_digest is None and b.transition is None, 'TRANSITION_INVALID')
                else:
                    _require(p.epoch == head.epoch+1 and p.epoch_id != head.epoch_id, 'EPOCH_MISMATCH')
                    _require(b.transition is not None and p.transition_digest is not None, 'TRANSITION_REQUIRED')
                status = 'ADVANCE'

        root_upper = 2**63-1
        if p.transition_digest is not None or b.transition is not None:
            _require(b.transition is not None and p.transition_digest == record_digest(b.transition.payload), 'TRANSITION_INVALID')
            t = b.transition.payload
            root = policy.root_key
            _require(_scope(t) == _scope(p) and (t.root_key_id,t.root_issuer_id) == (root.key_id,root.issuer_id)
                     and t.distribution_issuer_id == p.issuer_id, 'TRANSITION_INVALID')
            _require((t.to_epoch,t.to_epoch_id,t.to_signing_key_id,t.checkpoint_revision,t.previous_checkpoint_digest,
                      t.trust_store_revision,t.trust_store_digest) ==
                     (p.epoch,p.epoch_id,p.signing_key_id,p.checkpoint_revision,p.previous_checkpoint_digest,
                      p.trust_store_revision,p.trust_store_digest), 'TRANSITION_INVALID')
            if status == 'ADVANCE':
                _require((t.from_epoch,t.from_epoch_id,t.from_signing_key_id,t.previous_checkpoint_revision) ==
                         (head.epoch,head.epoch_id,head.signing_key_id,head.checkpoint_revision), 'TRANSITION_INVALID')
            _active(root, t.issued_at, now, 'ROOT_DENIED')
            _require(t.issued_at <= p.issued_at <= now < min(t.expires_at,t.issued_at+policy.max_age_seconds), 'TRANSITION_INVALID')
            _signature(root, b.transition.signature_hex, transition_preimage(t), 'TRANSITION_INVALID')
            root_upper = min(root.expires_at,t.expires_at,t.issued_at+policy.max_age_seconds)

        upper = min(p.expires_at,p.issued_at+min(p.max_age_seconds,policy.max_age_seconds),
                    policy.expires_at,pin.expires_at,key.expires_at,store.expiry,root_upper)
        checked = ObservationTrustCheckpoint(deployment_id=p.deployment_id,store_instance_id=p.store_instance_id,
            revision=store.revision,trust_store_digest=p.trust_store_digest,timestamp=p.issued_at,expiry=upper)
        proposed = DistributionHead(deployment_id=p.deployment_id,store_instance_id=p.store_instance_id,
            checkpoint_revision=p.checkpoint_revision,checkpoint_digest=digest,epoch=p.epoch,epoch_id=p.epoch_id,
            signing_key_id=p.signing_key_id,trust_store_revision=p.trust_store_revision,trust_store_digest=p.trust_store_digest,
            policy_revision=policy.revision,policy_digest=record_digest(policy),issued_at=p.issued_at,
            accepted_at=head.accepted_at if status == 'UNCHANGED' else now,checked_at=now)
        return DistributionResult(status=status,signature_verified=True,proposed_head=proposed,
                                  checked_store=store,checked_checkpoint=checked)
    except Exception as exc:
        return DistributionResult(status='REJECTED',signature_verified=False,
                                  reason_code=str(exc) if isinstance(exc,_Denied) else 'INVALID_RECORD')
