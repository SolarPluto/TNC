"""Pure external-witness simulation. Fixture evidence is NOT authentication.

No signing, clocks, I/O, publication, or execution authorization. Callers choose
whether to apply a proposed image. The independently retained initial record and
synthetic policy/evidence are harness trust inputs, never client credentials.
"""
from hashlib import sha256
from typing import Annotated, Literal

from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical

DOMAIN = b'TNC-WITNESS-BINDING-v1:'
RECORD_LIMIT = 262144
IMAGE_LIMIT = 1048576
HISTORY_LIMIT = 64
Counter = Annotated[int, Field(strict=True, ge=0, le=2**63-1)]
Positive = Annotated[int, Field(strict=True, ge=1, le=2**63-1)]


class WitnessStoreContext(Model):
    deployment_id: Identifier
    store_instance_id: Identifier
    local_store_id: Identifier
    bootstrap_anchor_digest: Digest


class WitnessLocalHead(Model):
    """Stable distribution acceptance frontier, excluding mutable check times.

    history_digest covers canonical accepted ingestion/receipt history only.
    This does not cover client high-water stores or later checked_at updates.
    """
    local_sequence: Counter
    history_digest: Digest
    checkpoint_revision: Positive
    checkpoint_digest: Digest
    epoch_counter: Positive
    epoch_id: Identifier
    trust_store_revision: Positive
    trust_store_digest: Digest
    policy_revision: Positive
    policy_digest: Digest


class WitnessStateRecord(Model):
    profile: Literal['tnc-external-witness-v1'] = 'tnc-external-witness-v1'
    context: WitnessStoreContext
    witness_sequence: Counter
    head: WitnessLocalHead
    last_updated_at: Counter


class Window(Model):
    issued_at: Counter
    expires_at: Counter

    @model_validator(mode='after')
    def positive_window(self):
        if not 0 < self.expires_at - self.issued_at <= 300:
            raise ValueError('Window must be positive and at most 300 seconds')
        return self


class WitnessAdvanceRequest(Window):
    context: WitnessStoreContext
    request_id: Identifier
    principal_id: Identifier
    predecessor_witness_sequence: Counter
    predecessor_state_digest: Digest
    target_witness_sequence: Positive
    target_head: WitnessLocalHead

    @model_validator(mode='after')
    def successor(self):
        if self.target_witness_sequence != self.predecessor_witness_sequence + 1:
            raise ValueError('Direct witness successor required')
        return self


class SyntheticWitnessPolicy(Window):
    context: WitnessStoreContext
    revision: Positive
    advance_principals: tuple[Identifier, ...] = Field(max_length=32)
    recovery_principals: tuple[Identifier, ...] = Field(max_length=32)
    observation_principals: tuple[Identifier, ...] = Field(max_length=32)

    @model_validator(mode='after')
    def unique_principals(self):
        for values in (self.advance_principals, self.recovery_principals, self.observation_principals):
            if values != tuple(sorted(set(values))):
                raise ValueError('Sorted unique principals required')
        return self


class SyntheticCallerEvidence(Window):
    """Host fixture assertion, not proof of client possession."""
    context: WitnessStoreContext
    principal_id: Identifier
    request_digest: Digest
    policy_digest: Digest


class SyntheticLineageEvidence(Window):
    """Fixture stands for independently checked complete local transition proof."""
    request_digest: Digest
    predecessor_state_digest: Digest
    target_head_digest: Digest
    root_transition_authorized: bool = Field(strict=True)


class WitnessReceipt(Model):
    request: WitnessAdvanceRequest
    policy: SyntheticWitnessPolicy
    caller: SyntheticCallerEvidence
    evidence: SyntheticLineageEvidence
    accepted_at: Counter
    resulting_state: WitnessStateRecord


class WitnessImage(Model):
    initial: WitnessStateRecord
    receipts: tuple[WitnessReceipt, ...] = Field(max_length=HISTORY_LIMIT)


class WitnessObservationRequest(Window):
    context: WitnessStoreContext
    principal_id: Identifier
    challenge: Digest


class SyntheticWitnessObservation(Window):
    request_digest: Digest
    challenge: Digest
    principal_id: Identifier
    state: WitnessStateRecord


class SyntheticObservationEvidence(Window):
    """Independent fixture binding; never an issuer-controlled verified flag."""
    observation_digest: Digest
    request_digest: Digest
    context: WitnessStoreContext


class WitnessResult(Model):
    status: Literal['SUCCESS', 'HISTORICAL_RECEIPT', 'CAS_MISMATCH', 'STATE_FORK',
                    'OPERATION_CONFLICT', 'UNAUTHORIZED_CLIENT', 'INDETERMINATE',
                    'CAPACITY_EXCEEDED', 'INVALID_LINEAGE', 'MATCHED',
                    'LOCAL_EXTENSION_PENDING', 'ROLLBACK_OR_STATE_LOSS']
    audit_only: Literal[True] = True
    signature_verified: Literal[False] = False
    proposed_image: WitnessImage | None = None
    receipt: WitnessReceipt | None = None
    observation: SyntheticWitnessObservation | None = None


def checked(record):
    data = canonical_bytes(record)
    if len(data) > (IMAGE_LIMIT if isinstance(record, WitnessImage) else RECORD_LIMIT):
        raise ValueError('Bounded witness record required')
    return decode_canonical(type(record), data)


def witness_digest(record) -> str:
    return sha256(DOMAIN + canonical_bytes(checked(record))).hexdigest()


def active(record, now):
    return record.issued_at <= now < record.expires_at


def valid_time(now):
    if type(now) is not int or not 0 <= now <= 2**63-1:
        raise ValueError('Exact epoch seconds required')


def lineage(old, new):
    if new.local_sequence != old.local_sequence + 1 or new.history_digest == old.history_digest:
        return False
    if new.checkpoint_revision not in (old.checkpoint_revision, old.checkpoint_revision + 1):
        return False
    for revision, digest in (('checkpoint_revision', 'checkpoint_digest'),
                             ('trust_store_revision', 'trust_store_digest'),
                             ('policy_revision', 'policy_digest')):
        if getattr(new, revision) < getattr(old, revision): return False
        if getattr(new, revision) == getattr(old, revision) and getattr(new, digest) != getattr(old, digest):
            return False
    if new.epoch_counter == old.epoch_counter:
        return new.epoch_id == old.epoch_id
    return (new.epoch_counter == old.epoch_counter + 1 and new.epoch_id != old.epoch_id
            and new.checkpoint_revision == old.checkpoint_revision + 1)


def validate_witness_image(image, *, trusted_initial):
    image, trusted_initial = checked(image), checked(trusted_initial)
    if image.initial != trusted_initial: raise ValueError('Independent initial binding mismatch')
    head, seen, prior_policy = image.initial, set(), None
    for receipt in image.receipts:
        request = receipt.request
        if (not policy_progress(prior_policy, receipt.policy)
                or request.request_id in seen or request.context != head.context
                or request.predecessor_witness_sequence != head.witness_sequence
                or request.predecessor_state_digest != witness_digest(head)
                or not head.last_updated_at <= receipt.accepted_at
                or not active(request, receipt.accepted_at)
                or not authorized(request, receipt.caller, receipt.policy, 'advance', receipt.accepted_at)
                or not valid_evidence(head, request, receipt.evidence, receipt.accepted_at)):
            raise ValueError('Invalid historical chain')
        expected = WitnessStateRecord(context=head.context, witness_sequence=request.target_witness_sequence,
                                      head=request.target_head, last_updated_at=receipt.accepted_at)
        if receipt.resulting_state != expected: raise ValueError('Invalid receipt state')
        seen.add(request.request_id)
        prior_policy = receipt.policy
        head = expected
    return head


def authorized(request, caller, policy, action, now):
    return (active(caller, now) and active(policy, now)
            and request.context == caller.context == policy.context
            and request.principal_id == caller.principal_id
            and caller.request_digest == witness_digest(request)
            and caller.policy_digest == witness_digest(policy)
            and caller.principal_id in getattr(policy, action + '_principals'))


def policy_progress(previous, current):
    return (previous is None or current.revision > previous.revision
            or (current.revision == previous.revision and current == previous))


def valid_evidence(head, request, evidence, now):
    return (active(evidence, now) and evidence.request_digest == witness_digest(request)
            and evidence.predecessor_state_digest == witness_digest(head)
            and evidence.target_head_digest == witness_digest(request.target_head)
            and lineage(head.head, request.target_head)
            and (request.target_head.epoch_counter == head.head.epoch_counter or evidence.root_transition_authorized))


def evaluate_witness_advance(image, request, *, trusted_initial, caller, policy, evidence, now):
    """Return a proposed successor or original receipt; never apply it."""
    valid_time(now)
    request, caller, policy = checked(request), checked(caller), checked(policy)
    # Authorize before looking up any operation or exposing state.
    if not authorized(request, caller, policy, 'recovery', now) and not authorized(request, caller, policy, 'advance', now):
        return WitnessResult(status='UNAUTHORIZED_CLIENT')
    head = validate_witness_image(image, trusted_initial=trusted_initial)
    if request.context != head.context: return WitnessResult(status='UNAUTHORIZED_CLIENT')
    if not policy_progress(image.receipts[-1].policy if image.receipts else None, policy):
        return WitnessResult(status='INDETERMINATE')
    if now < head.last_updated_at: return WitnessResult(status='INDETERMINATE')
    for receipt in image.receipts:
        if receipt.request.request_id == request.request_id:
            if (receipt.request.principal_id != request.principal_id
                    or not authorized(request, caller, policy, 'recovery', now)):
                return WitnessResult(status='UNAUTHORIZED_CLIENT')
            if receipt.request != request: return WitnessResult(status='OPERATION_CONFLICT')
            return WitnessResult(status='HISTORICAL_RECEIPT', receipt=receipt)
    if not authorized(request, caller, policy, 'advance', now):
        return WitnessResult(status='UNAUTHORIZED_CLIENT')
    if not active(request, now): return WitnessResult(status='INDETERMINATE')
    if request.predecessor_witness_sequence != head.witness_sequence:
        return WitnessResult(status='CAS_MISMATCH')
    if request.predecessor_state_digest != witness_digest(head):
        return WitnessResult(status='STATE_FORK')
    if evidence is None: return WitnessResult(status='INVALID_LINEAGE')
    evidence = checked(evidence)
    if not valid_evidence(head, request, evidence, now):
        return WitnessResult(status='INVALID_LINEAGE')
    if len(image.receipts) >= HISTORY_LIMIT: return WitnessResult(status='CAPACITY_EXCEEDED')
    successor = WitnessStateRecord(context=head.context, witness_sequence=request.target_witness_sequence,
                                   head=request.target_head, last_updated_at=now)
    receipt = WitnessReceipt(request=request, policy=policy, caller=caller, evidence=evidence,
                             accepted_at=now, resulting_state=successor)
    proposed = WitnessImage(initial=image.initial, receipts=image.receipts + (receipt,))
    validate_witness_image(proposed, trusted_initial=trusted_initial)
    return WitnessResult(status='SUCCESS', proposed_image=proposed, receipt=receipt)


def observe_witness_current(image, request, *, trusted_initial, caller, policy, now):
    valid_time(now)
    request, caller, policy = checked(request), checked(caller), checked(policy)
    if not authorized(request, caller, policy, 'observation', now):
        return WitnessResult(status='UNAUTHORIZED_CLIENT')
    head = validate_witness_image(image, trusted_initial=trusted_initial)
    if request.context != head.context: return WitnessResult(status='UNAUTHORIZED_CLIENT')
    if not policy_progress(image.receipts[-1].policy if image.receipts else None, policy):
        return WitnessResult(status='INDETERMINATE')
    if not active(request, now) or now < head.last_updated_at:
        return WitnessResult(status='INDETERMINATE')
    observation = SyntheticWitnessObservation(request_digest=witness_digest(request), challenge=request.challenge,
        principal_id=request.principal_id, state=head, issued_at=now,
        expires_at=min(request.expires_at, caller.expires_at, policy.expires_at))
    return WitnessResult(status='SUCCESS', observation=observation)


def compare_witness_observation(local, request, observation, *, evidence, now):
    """Audit relationship only. No result grants execution permission."""
    valid_time(now)
    local, request = checked(local), checked(request)
    if observation is None or evidence is None: return WitnessResult(status='INDETERMINATE')
    if type(observation) is not SyntheticWitnessObservation: return WitnessResult(status='INDETERMINATE')
    observation, evidence = checked(observation), checked(evidence)
    if (not all(active(x, now) for x in (request, observation, evidence))
            or local.context != request.context or observation.state.context != request.context
            or evidence.context != request.context or local.last_updated_at > now
            or observation.state.last_updated_at > observation.issued_at
            or observation.request_digest != witness_digest(request)
            or evidence.request_digest != witness_digest(request)
            or evidence.observation_digest != witness_digest(observation)
            or observation.challenge != request.challenge or observation.principal_id != request.principal_id):
        return WitnessResult(status='INDETERMINATE')
    remote = observation.state
    if local.witness_sequence < remote.witness_sequence:
        return WitnessResult(status='ROLLBACK_OR_STATE_LOSS')
    if local.witness_sequence > remote.witness_sequence:
        return WitnessResult(status='INDETERMINATE')
    if local == remote: return WitnessResult(status='MATCHED')
    if lineage(remote.head, local.head): return WitnessResult(status='LOCAL_EXTENSION_PENDING')
    return WitnessResult(status='STATE_FORK')
