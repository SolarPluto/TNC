"""Pure relationship classification and synthetic acceptance binding checks.

No files, database, clock acquisition, signatures, authority advancement, or I/O.
"""
from datetime import datetime
from hashlib import sha256

from tnc.provenance.authorization_models import ZERO, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.update_storage_models import IMAGE_LIMIT, EVENT_LIMIT, UpdateStorageImage, UpdateStorageCheckpoint, StoredUpdateEvent
from tnc.provenance.update_storage_validation import validate_update_storage_image, decode_update_storage_record
from tnc.provenance.reconciliation_models import (
    RECONCILIATION_LIMIT, ReconciliationEnvelope, SyntheticCheckpointEvidence, ReconciliationRequest,
    ReconciliationAcceptance, SyntheticAcceptanceEvidence, ReconciliationRelationship, ReconciliationAcceptanceResult,
)

_KINDS = (ReconciliationEnvelope, SyntheticCheckpointEvidence, ReconciliationRequest,
          ReconciliationAcceptance, SyntheticAcceptanceEvidence, ReconciliationRelationship, ReconciliationAcceptanceResult)


def decode_reconciliation_record(kind, data):
    if kind not in _KINDS or type(data) is not bytes or not 0 < len(data) <= RECONCILIATION_LIMIT:
        raise ValueError('Invalid bounded record')
    return decode_canonical(kind, data)


def _copy(value, kind):
    if type(value) is not kind:
        raise ValueError('Exact typed record required')
    return decode_reconciliation_record(kind, canonical_bytes(value))


def _time(now):
    if type(now) is not datetime or now.utcoffset() is None:
        raise ValueError('Aware evaluation time required')


def _active(value, now):
    return value.valid_from <= now < value.valid_until


def _checkpoint(image):
    # Internal consistency comparison only; not returned as independent authority.
    return UpdateStorageCheckpoint(deployment_id=image.deployment_id, image_hash=record_digest(image),
        event_count=len(image.events), event_head_hash=image.events[-1].entry_hash if image.events else ZERO,
        authority_head_hash=record_digest(image.head))


def reconciliation_batch_digest(events):
    """v1 domain + uint32 count + (uint64 byte length + canonical event)*."""
    if type(events) is not tuple or not 0 < len(events) <= 256:
        raise ValueError('Bounded nonempty tuple required')
    digest = sha256(b'TNC-RECONCILIATION-EVENT-BATCH\x00v1\x00' + len(events).to_bytes(4,'big'))
    total = 0
    for event in events:
        if type(event) is not StoredUpdateEvent: raise ValueError('Exact event required')
        data = canonical_bytes(event)
        total += len(data)
        if len(data) > EVENT_LIMIT or total > IMAGE_LIMIT: raise ValueError('Batch too large')
        digest.update(len(data).to_bytes(8,'big'))
        digest.update(data)
    return digest.hexdigest()


def classify_checkpoint_relationship(image, envelope, *, observed_store_instance_id, evidence, now):
    """Classify logical observations only; never authorize acceptance or execution.

    observed_store_instance_id is host observation input, not authenticated here.
    """
    def result(relationship, reason, **facts):
        return ReconciliationRelationship(relationship=relationship, reason_code=reason, **facts)
    try:
        _time(now)
        envelope = _copy(envelope, ReconciliationEnvelope)
        evidence = _copy(evidence, SyntheticCheckpointEvidence)
        if not (_active(envelope,now) and _active(evidence,now) and
                (evidence.deployment_id,evidence.store_instance_id,evidence.current_authority_revision,evidence.current_envelope_hash) ==
                (envelope.deployment_id,envelope.store_instance_id,envelope.authority_revision,record_digest(envelope))):
            return result('INDETERMINATE','FRESHNESS_UNAVAILABLE')
        if type(image) is not UpdateStorageImage or type(observed_store_instance_id) is not str:
            raise ValueError('Invalid observation')
        image = decode_update_storage_record(UpdateStorageImage,canonical_bytes(image))
        if any(event.recorded_at > now for event in image.events):
            return result('INDETERMINATE','INVALID_INPUT')
        if (image.deployment_id,observed_store_instance_id) != (envelope.deployment_id,envelope.store_instance_id):
            return result('FORK_OR_MISMATCH','IDENTITY_MISMATCH')
        local = _checkpoint(image)
        if validate_update_storage_image(image,trusted_checkpoint=local).status != 'CONSISTENT':
            return result('FORK_OR_MISMATCH','IMAGE_INVALID')
        accepted = envelope.checkpoint
        if len(image.events) < accepted.event_count:
            return result('CHECKPOINT_AHEAD','DATABASE_BEHIND')
        prefix_events = image.events[:accepted.event_count]
        prefix_head = image.base_head
        for event in prefix_events:
            if event.payload.kind == 'COMMIT': prefix_head=event.payload.head
        prefix = image.model_copy(update={'events':prefix_events,'head':prefix_head})
        if canonical_bytes(_checkpoint(prefix)) != canonical_bytes(accepted):
            return result('FORK_OR_MISMATCH','PREFIX_MISMATCH')
        facts = dict(observed_event_count=len(image.events),observed_image_hash=local.image_hash)
        if len(image.events) == accepted.event_count:
            return result('MATCHED','EXACT_MATCH',**facts)
        return result('DATABASE_EXTENSION_PENDING','INDEPENDENT_ACCEPTANCE_REQUIRED',**facts,
                      suffix_batch_hash=reconciliation_batch_digest(image.events[accepted.event_count:]))
    except Exception:
        return result('INDETERMINATE','INVALID_INPUT')


def verify_reconciliation_acceptance(request, acceptance, *, evidence, now):
    """Check an exact historical acceptance binding with synthetic current access.

    VALID_BINDING is audit-only and never permits envelope publication. This does
    not check the image/prefix (use the classifier), nor authenticate the provider.
    """
    def reject(reason): return ReconciliationAcceptanceResult(status='REJECTED',reason_code=reason)
    try:
        _time(now)
        request = _copy(request, ReconciliationRequest)
        evidence = _copy(evidence, SyntheticAcceptanceEvidence)
        if not (_active(evidence,now) and evidence.may_recover and
                (evidence.deployment_id,evidence.store_instance_id,evidence.principal_id,evidence.request_id) ==
                (request.deployment_id,request.store_instance_id,request.principal_id,request.request_id)):
            return reject('ACCESS_DENIED')
        acceptance = _copy(acceptance, ReconciliationAcceptance)
        if not (
            evidence.request_hash == acceptance.request_hash == record_digest(request)
            and evidence.acceptance_hash == record_digest(acceptance)
            and evidence.independent_evidence_hash == acceptance.independent_evidence_hash
            and (acceptance.deployment_id,acceptance.store_instance_id,acceptance.principal_id,acceptance.request_id,
                 acceptance.predecessor_revision,acceptance.predecessor_hash,acceptance.event_batch_hash) ==
                (request.deployment_id,request.store_instance_id,request.principal_id,request.request_id,
                 request.expected_authority_revision,request.expected_envelope_hash,request.event_batch_hash)
            and canonical_bytes(acceptance.successor.checkpoint) == canonical_bytes(request.successor_checkpoint)
            and acceptance.accepted_at <= now and _active(request,acceptance.accepted_at)
            and _active(acceptance.successor,acceptance.accepted_at)
        ):
            return reject('BINDING_MISMATCH')
        return ReconciliationAcceptanceResult(status='VALID_BINDING',acceptance_hash=record_digest(acceptance))
    except Exception:
        return reject('INVALID_INPUT')
