"""Pure replay of a bounded storage image. Does not prove locks or durability."""
from tnc.provenance.authorization_models import ZERO, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.update_models import UpdateCommand, InstallerEvidenceClaims
from tnc.provenance.update_validation import _evaluate_checked_update_transition
from tnc.provenance.update_verification import verify_update_intent_signature, verify_committed_update_signature
from tnc.provenance.update_storage_models import (
    EVENT_LIMIT, IMAGE_LIMIT, RecordedUpdateAuthority, StoredUpdateRegistration, StoredUpdatePreparation,
    StoredUpdateCommit, StoredLocatorPublication, StoredUpdateEvent, UpdateStorageImage,
    UpdateStorageCheckpoint, UpdateStorageValidationResult,
)

_KINDS = (RecordedUpdateAuthority, StoredUpdateRegistration, StoredUpdatePreparation, StoredUpdateCommit,
          StoredLocatorPublication, StoredUpdateEvent, UpdateStorageImage, UpdateStorageCheckpoint, UpdateStorageValidationResult)


def decode_update_storage_record(kind, data):
    limit = IMAGE_LIMIT if kind is UpdateStorageImage else EVENT_LIMIT
    if kind not in _KINDS or type(data) is not bytes or not 0 < len(data) <= limit:
        raise ValueError('Invalid storage record')
    return decode_canonical(kind, data)


def update_storage_event_hash(event):
    return record_digest(event.model_copy(update={'entry_hash':ZERO}))


def _copy(value, kind):
    if type(value) is not kind:
        raise ValueError('Exact typed record required')
    return decode_update_storage_record(kind, canonical_bytes(value))


class _Invalid(ValueError):
    def __init__(self, reason): self.reason = reason


def _require(condition, reason):
    if not condition: raise _Invalid(reason)


def _authority(view, previous, deployment, at):
    store, cp = view.trust_store, view.trust_checkpoint
    _require(store.deployment_id == cp.deployment_id == deployment and store.revision == cp.revision
             and record_digest(store) == cp.trust_store_hash
             and all(v.valid_from <= at < v.valid_until for v in (store, cp)), 'AUTHORITY_INVALID')
    identities = {i.credential_id:i for i in view.identities}
    for identity in view.identities:
        _require(identity.verified_at <= at and identity.verified_at < identity.valid_until, 'AUTHORITY_INVALID')
    for grant in view.permissions:
        identity = identities.get(grant.credential_id)
        _require(identity is not None and grant.deployment_id == deployment
                 and grant.principal_id == identity.principal_id
                 and grant.registry_revision == identity.registry_revision, 'AUTHORITY_INVALID')
    if previous is not None:
        old = previous.trust_store
        _require(store.revision >= old.revision and
                 (record_digest(store) == record_digest(old) or store.revision > old.revision), 'AUTHORITY_INVALID')
        _require(set(old.revoked_key_ids) <= set(store.revoked_key_ids), 'AUTHORITY_INVALID')
        keys = {k.key_id:k for k in store.keys}
        for before in old.keys:
            after = keys.get(before.key_id)
            _require(after is not None and (after.public_key_hex, after.principal_id, after.valid_from) ==
                     (before.public_key_hex, before.principal_id, before.valid_from)
                     and (before.state != 'RETIRED' or after.state == 'RETIRED'), 'AUTHORITY_INVALID')


def _claims(view, credential_id, intent, at, recovery=False):
    _require(view is not None, 'AUTHORITY_INVALID')
    identity = next((i for i in view.identities if i.credential_id == credential_id), None)
    _require(identity is not None and identity.principal_id == intent.publisher_id
             and identity.verified_at <= at < identity.valid_until, 'AUTHORITY_INVALID')
    grants = [g for g in view.permissions if g.credential_id == credential_id and g.principal_id == intent.publisher_id
              and g.operation_id == intent.operation_id and g.deployment_id == intent.deployment_id
              and g.registry_revision == identity.registry_revision and g.valid_from <= at < g.valid_until]
    _require(len(grants) == 1 and 'UPDATE_EVALUATE' in grants[0].permissions
             and (not recovery or 'UPDATE_RECOVER_OWN' in grants[0].permissions), 'AUTHORITY_INVALID')
    store, cp = view.trust_store, view.trust_checkpoint
    _require(all(v.valid_from <= at < v.valid_until for v in (store, cp)), 'AUTHORITY_INVALID')
    return InstallerEvidenceClaims(principal_id=identity.principal_id, signer_key_hash=intent.signer_key_hash,
        deployment_id=intent.deployment_id, authenticated=True, may_publish=True, valid_from=at,
        valid_until=min(identity.valid_until, grants[0].valid_until, store.valid_until, cp.valid_until))


def validate_update_storage_image(image, *, trusted_checkpoint):
    """Validate an ordered logical history bound to an independent image checkpoint.

    AUTHORITY events are recorded trusted inputs, not authenticated administrative
    updates. No live credential verification or persistent transaction occurs.
    """
    try:
        image = _copy(image, UpdateStorageImage)
        cp = _copy(trusted_checkpoint, UpdateStorageCheckpoint)
        _require(image.deployment_id == cp.deployment_id == image.base_head.checkpoint.deployment_id
                 == image.head.checkpoint.deployment_id
                 and cp.image_hash == record_digest(image) and cp.event_count == len(image.events)
                 and cp.authority_head_hash == record_digest(image.head)
                 and cp.event_head_hash == (image.events[-1].entry_hash if image.events else ZERO), 'CHECKPOINT_MISMATCH')
        head, authority, authority_revision = image.base_head, None, 0
        previous_hash, last_time = ZERO, None
        operations, signatures, archives = {}, {}, {}
        for expected_sequence, event in enumerate(image.events, 1):
            event = _copy(event, StoredUpdateEvent)
            _require(event.sequence == expected_sequence and event.previous_hash == previous_hash
                     and event.entry_hash == update_storage_event_hash(event)
                     and (last_time is None or event.recorded_at >= last_time), 'CHAIN_INVALID')
            previous_hash, last_time = event.entry_hash, event.recorded_at
            payload, at = event.payload, event.recorded_at
            if type(payload) is RecordedUpdateAuthority:
                _authority(payload, authority, image.deployment_id, at)
                authority, authority_revision = payload, event.sequence
                continue
            if type(payload) is StoredUpdateRegistration:
                intent, operation_id = payload.intent, payload.intent.operation_id
                _require(operation_id not in operations and intent.deployment_id == image.deployment_id, 'OPERATION_INVALID')
                existing = None
                signature = payload.signature
                command = UpdateCommand(action='REGISTER', intent=intent)
            else:
                operation_id = payload.operation_id
                existing = operations.get(operation_id)
                _require(existing is not None, 'OPERATION_INVALID')
                intent, signature = existing.intent, signatures[operation_id]
                if type(payload) is StoredUpdatePreparation:
                    _require(existing.receipt is None, 'OPERATION_INVALID')
                    command = UpdateCommand(action='PREPARE', intent=intent, preparation=payload.preparation)
                elif type(payload) is StoredUpdateCommit:
                    _require(existing.receipt is None and payload.authority_revision == authority_revision, 'COMMIT_INVALID')
                    command = UpdateCommand(action='COMMIT', intent=intent, preparation=payload.preparation, drain=payload.drain)
                else:
                    _require(existing.receipt is not None and operation_id in archives, 'PUBLICATION_INVALID')
                    _require(existing.publication is None or payload.locator.observed_at >= existing.publication.observed_at,
                             'PUBLICATION_INVALID')
                    command = UpdateCommand(action='PUBLISH', intent=intent, locator=payload.locator)
            publishing = type(payload) is StoredLocatorPublication
            claims = _claims(authority, payload.credential_id, intent, at, recovery=publishing)
            if not publishing:
                verification = verify_update_intent_signature(intent, signature, authority.trust_store,
                    trusted_checkpoint=authority.trust_checkpoint, now=at)
                _require(verification.status == 'VERIFIED', 'AUTHORITY_INVALID')
            result = _evaluate_checked_update_transition(head=head, existing=existing, command=command, authority=claims, now=at)
            reason = 'COMMIT_INVALID' if type(payload) is StoredUpdateCommit else 'PUBLICATION_INVALID' if publishing else 'OPERATION_INVALID'
            _require(result.status in ('PROPOSED', 'UNCHANGED'), reason)
            if type(payload) is StoredUpdateCommit:
                _require(result.proposed_head is not None and canonical_bytes(result.operation.receipt) == canonical_bytes(payload.receipt)
                         and canonical_bytes(result.proposed_head) == canonical_bytes(payload.head), 'COMMIT_INVALID')
                archive = payload.archive
                _require(canonical_bytes(archive.signature) == canonical_bytes(signature)
                         and canonical_bytes(archive.trust_store) == canonical_bytes(authority.trust_store)
                         and canonical_bytes(archive.trust_checkpoint) == canonical_bytes(authority.trust_checkpoint), 'ARCHIVE_INVALID')
                verified = verify_committed_update_signature(intent, archive.signature, archive.trust_store,
                    archive.trust_checkpoint, payload.receipt, trusted_binding=archive.binding)
                _require(verified.status == 'VERIFIED', 'ARCHIVE_INVALID')
                head, archives[operation_id] = payload.head, archive
            operations[operation_id], signatures[operation_id] = result.operation, signature
        _require(canonical_bytes(head) == canonical_bytes(image.head), 'HEAD_MISMATCH')
        return UpdateStorageValidationResult(status='CONSISTENT', event_count=len(image.events),
            operation_count=len(operations), commit_count=len(archives),
            unpublished_operation_ids=tuple(sorted(k for k,v in operations.items() if v.stage == 'COMMITTED')))
    except _Invalid as exc:
        reason = exc.reason
    except Exception:
        reason = 'INVALID_RECORD'
    return UpdateStorageValidationResult(status='INVALID', reason_code=reason)
