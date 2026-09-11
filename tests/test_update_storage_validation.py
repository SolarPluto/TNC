from datetime import timedelta
import builtins
import sqlite3

import pytest

from test_provisioning_validation import case
from test_deployment_validation import inventory, NOW
from test_trusted_boundary import config
from test_update_validation import update, locator
from test_update_verification import signed
from test_update_integration import host, committed
from tnc.provenance.authorization_models import ZERO, canonical_bytes, record_digest
from tnc.provenance.update_storage_models import (
    EVENT_LIMIT, IMAGE_LIMIT, RecordedUpdateAuthority, StoredUpdateRegistration, StoredUpdatePreparation,
    StoredUpdateCommit, StoredLocatorPublication, StoredUpdateEvent, UpdateStorageImage,
    UpdateStorageCheckpoint, UpdateStorageValidationResult,
)
from tnc.provenance.update_storage_validation import (
    update_storage_event_hash, decode_update_storage_record, validate_update_storage_image,
)
from tnc.provenance.update_verification import SignatureEnvelope, update_signature_preimage


def checkpoint(image):
    return UpdateStorageCheckpoint(deployment_id=image.deployment_id, image_hash=record_digest(image),
        event_count=len(image.events), event_head_hash=image.events[-1].entry_hash if image.events else ZERO,
        authority_head_hash=record_digest(image.head))


def image_from(base, payloads, head=None):
    events, previous = [], ZERO
    final = base
    for sequence, payload in enumerate(payloads,1):
        event = StoredUpdateEvent(sequence=sequence, recorded_at=NOW, previous_hash=previous, entry_hash=ZERO, payload=payload)
        event = event.model_copy(update={'entry_hash':update_storage_event_hash(event)})
        previous = event.entry_hash
        events.append(event)
        if type(payload) is StoredUpdateCommit: final=payload.head
    return UpdateStorageImage(deployment_id=base.checkpoint.deployment_id, base_head=base, events=tuple(events), head=head or final)


@pytest.fixture
def stored(host, signed, update):
    result = committed(host,signed)
    authority = RecordedUpdateAuthority(trust_store=signed['store'], trust_checkpoint=signed['checkpoint'],
        identities=(host.identity.value,), permissions=(host.permissions.value,))
    registration = StoredUpdateRegistration(intent=signed['intent'], signature=signed['envelope'], credential_id='9'*64)
    preparation = StoredUpdatePreparation(operation_id=signed['intent'].operation_id,
        preparation=host.observations.preparation, credential_id='9'*64)
    commit = StoredUpdateCommit(operation_id=signed['intent'].operation_id, authority_revision=1, credential_id='9'*64,
        preparation=host.observations.preparation, drain=host.observations.drain,
        receipt=result.proposal.operation.receipt, head=result.proposal.proposed_head, archive=host.snapshots.value.archive)
    return update['head'], [authority,registration,preparation,commit]


def validate(stored, payloads=None, head=None):
    image = image_from(stored[0], stored[1] if payloads is None else payloads, head)
    return validate_update_storage_image(image, trusted_checkpoint=checkpoint(image))


def test_complete_commit_without_locator_is_consistent(stored):
    result = validate(stored)
    assert result.status=='CONSISTENT' and result.event_count==4 and result.commit_count==1
    assert result.unpublished_operation_ids==(stored[1][3].operation_id,)


def test_publication_is_separate_history(stored):
    commit = stored[1][3]
    publication = StoredLocatorPublication(operation_id=commit.operation_id, credential_id='9'*64,
        locator=locator(commit.head))
    result = validate(stored, stored[1]+[publication,publication])
    assert result.status=='CONSISTENT' and result.commit_count==1 and not result.unpublished_operation_ids


@pytest.mark.parametrize('count', [0,1,2,3])
def test_precommit_images_do_not_advance_head(stored, count):
    result = validate(stored, stored[1][:count])
    assert result.status=='CONSISTENT' and result.commit_count==0


@pytest.mark.parametrize('field,value', [('image_hash','f'*64),('event_count',0),('event_head_hash','f'*64),
    ('authority_head_hash','f'*64),('deployment_id','other')])
def test_independent_checkpoint_mismatch(stored, field, value):
    image=image_from(*stored)
    cp=checkpoint(image).model_copy(update={field:value})
    result=validate_update_storage_image(image,trusted_checkpoint=cp)
    assert result.reason_code=='CHECKPOINT_MISMATCH' and result.commit_count==0


@pytest.mark.parametrize('field,value', [('sequence',99),('previous_hash','f'*64),('entry_hash','f'*64),
    ('recorded_at',NOW-timedelta(seconds=1))])
def test_chain_corruption_even_with_rebound_checkpoint(stored, field, value):
    image=image_from(*stored)
    events=list(image.events)
    events[1]=events[1].model_copy(update={field:value})
    image=image.model_copy(update={'events':tuple(events)})
    result=validate_update_storage_image(image,trusted_checkpoint=checkpoint(image))
    assert result.reason_code=='CHAIN_INVALID'


def test_head_without_commit_is_invalid(stored):
    result=validate(stored,stored[1][:3],head=stored[1][3].head)
    assert result.reason_code=='HEAD_MISMATCH'


def test_commit_without_head_is_invalid(stored):
    assert validate(stored,head=stored[0]).reason_code=='HEAD_MISMATCH'


def test_orphan_commit_and_duplicate_commit(stored):
    assert validate(stored,[stored[1][0],stored[1][3]]).reason_code=='OPERATION_INVALID'
    assert validate(stored,stored[1]+[stored[1][3]]).reason_code=='COMMIT_INVALID'


def test_duplicate_registration_is_not_an_exact_retry_write(stored):
    assert validate(stored,stored[1][:2]+[stored[1][1]]).reason_code=='OPERATION_INVALID'


def test_preparation_before_registration_is_invalid(stored):
    assert validate(stored,[stored[1][0],stored[1][2],stored[1][1]]).reason_code=='OPERATION_INVALID'


@pytest.mark.parametrize('field',['archive','receipt','head'])
def test_missing_atomic_commit_component_rejected(stored,field):
    value=stored[1][3].model_dump()
    value.pop(field)
    with pytest.raises(ValueError): StoredUpdateCommit.model_validate(value)


@pytest.mark.parametrize('field,value', [('authority_revision',99),('credential_id','f'*64)])
def test_commit_binds_current_authority(stored, field, value):
    payloads=stored[1].copy()
    payloads[3]=payloads[3].model_copy(update={field:value})
    assert validate(stored,payloads).status=='INVALID'


@pytest.mark.parametrize('field,value', [('intent_hash','f'*64),('authority_sequence',99),('generation',99),
    ('checkpoint_hash','f'*64),('publisher_id','other')])
def test_receipt_mismatch(stored, field, value):
    payloads=stored[1].copy()
    payloads[3]=payloads[3].model_copy(update={'receipt':payloads[3].receipt.model_copy(update={field:value})})
    assert validate(stored,payloads).reason_code=='COMMIT_INVALID'


def test_archive_binding_mismatch(stored):
    payloads=stored[1].copy()
    archive=payloads[3].archive
    archive=archive.model_copy(update={'binding':archive.binding.model_copy(update={'receipt_hash':'f'*64})})
    payloads[3]=payloads[3].model_copy(update={'archive':archive})
    assert validate(stored,payloads).reason_code=='ARCHIVE_INVALID'


def revised_authority(view, *, revoke=False, deny=False):
    store=view.trust_store.model_copy(update={'revision':view.trust_store.revision+1,
        'revoked_key_ids':(view.trust_store.keys[0].key_id,) if revoke else view.trust_store.revoked_key_ids})
    cp=view.trust_checkpoint.model_copy(update={'revision':store.revision,'trust_store_hash':record_digest(store)})
    return view.model_copy(update={'trust_store':store,'trust_checkpoint':cp,'permissions':() if deny else view.permissions})


@pytest.mark.parametrize('kind', ['revoke','deny'])
def test_authority_change_before_commit_blocks_update(stored, kind):
    newer=revised_authority(stored[1][0],revoke=kind=='revoke',deny=kind=='deny')
    commit=stored[1][3].model_copy(update={'authority_revision':4})
    assert validate(stored,stored[1][:3]+[newer,commit]).reason_code=='AUTHORITY_INVALID'


def test_stale_authority_revision_blocks_commit_even_without_revocation(stored):
    newer=revised_authority(stored[1][0])
    assert validate(stored,stored[1][:3]+[newer,stored[1][3]]).reason_code=='COMMIT_INVALID'


def test_two_prepared_updates_cannot_both_commit_from_same_head(stored,signed):
    authority,registration,preparation,commit=stored[1]
    intent=registration.intent.model_copy(update={'operation_id':'second-update'})
    signature=SignatureEnvelope(deployment_id=intent.deployment_id,key_id=intent.signer_key_hash,
        signature_hex=signed['private'].sign(update_signature_preimage(intent)).hex())
    grant=authority.permissions[0].model_copy(update={'operation_id':intent.operation_id})
    authority=authority.model_copy(update={'permissions':tuple(sorted((*authority.permissions,grant),
        key=lambda p:(p.principal_id,p.operation_id,p.credential_id)))})
    second_registration=registration.model_copy(update={'intent':intent,'signature':signature})
    second_preparation=preparation.model_copy(update={'operation_id':intent.operation_id,
        'preparation':preparation.preparation.model_copy(update={'intent_hash':record_digest(intent)})})
    receipt=commit.receipt.model_copy(update={'operation_id':intent.operation_id,'intent_hash':record_digest(intent)})
    archive=commit.archive.model_copy(update={'signature':signature,'binding':commit.archive.binding.model_copy(update={
        'receipt_hash':record_digest(receipt),'signature_envelope_hash':record_digest(signature)})})
    second_commit=commit.model_copy(update={'operation_id':intent.operation_id,'receipt':receipt,'archive':archive,
        'preparation':second_preparation.preparation,'drain':commit.drain.model_copy(update={'intent_hash':record_digest(intent)})})
    history=[authority,registration,preparation,second_registration,second_preparation,commit,second_commit]
    assert validate(stored,history).reason_code=='COMMIT_INVALID'


def test_expired_transport_evidence_blocks_registration(stored):
    authority=stored[1][0]
    identity=authority.identities[0].model_copy(update={'verified_at':NOW-timedelta(hours=1),'valid_until':NOW})
    authority=authority.model_copy(update={'identities':(identity,)})
    assert validate(stored,[authority,*stored[1][1:]]).reason_code=='AUTHORITY_INVALID'


def test_missing_preparation_blocks_commit(stored):
    assert validate(stored,[stored[1][0],stored[1][1],stored[1][3]]).reason_code=='COMMIT_INVALID'


def test_revocation_after_commit_preserves_historical_receipt(stored):
    newer=revised_authority(stored[1][0],revoke=True)
    result=validate(stored,stored[1]+[newer])
    assert result.status=='CONSISTENT' and result.commit_count==1


def test_revoked_key_cannot_be_removed_from_history(stored):
    revoked=revised_authority(stored[1][0],revoke=True)
    cleared=revised_authority(revoked)
    store=cleared.trust_store.model_copy(update={'revoked_key_ids':()})
    cleared=cleared.model_copy(update={'trust_store':store,
        'trust_checkpoint':cleared.trust_checkpoint.model_copy(update={'trust_store_hash':record_digest(store)})})
    assert validate(stored,stored[1]+[revoked,cleared]).reason_code=='AUTHORITY_INVALID'


def test_authority_revision_rollback(stored):
    newer=revised_authority(stored[1][0])
    assert validate(stored,stored[1]+[newer,stored[1][0]]).reason_code=='AUTHORITY_INVALID'


def test_publication_before_commit_is_invalid(stored):
    publication=StoredLocatorPublication(operation_id=stored[1][3].operation_id,credential_id='9'*64,
        locator=locator(stored[1][3].head))
    assert validate(stored,stored[1][:3]+[publication]).reason_code=='PUBLICATION_INVALID'


@pytest.mark.parametrize('field,value', [('checkpoint_hash','f'*64),('target_state','INVALID'),('authority_sequence',99)])
def test_locator_mismatch_does_not_count_as_publication(stored,field,value):
    publication=StoredLocatorPublication(operation_id=stored[1][3].operation_id,credential_id='9'*64,
        locator=locator(stored[1][3].head,**{field:value}))
    assert validate(stored,stored[1]+[publication]).reason_code=='PUBLICATION_INVALID'


@pytest.mark.parametrize('mutation', [lambda b:b+b' ',lambda b:b'{}',lambda b:b'\xff',lambda b:bytearray(b),
    lambda b:b.replace(b'"codec_version":1',b'"codec_version":true'),
    lambda b:b.replace(b'"deployment_id":',b'"extra":1,"deployment_id":'),
    lambda b:b' '*(IMAGE_LIMIT+1)])
def test_canonical_image_rejection(stored,mutation):
    with pytest.raises(ValueError):
        decode_update_storage_record(UpdateStorageImage,mutation(canonical_bytes(image_from(*stored))))


def test_bounded_event_count(stored):
    image=image_from(*stored)
    with pytest.raises(ValueError):
        UpdateStorageImage.model_validate(image.model_dump() | {'events':(image.events[0],)*257})


def test_event_byte_limit():
    with pytest.raises(ValueError): decode_update_storage_record(StoredUpdateEvent,b' '*(EVENT_LIMIT+1))


def test_deterministic_no_io_and_immutable(stored,monkeypatch):
    def forbidden(*a,**k): pytest.fail('Pure storage validator attempted I/O')
    monkeypatch.setattr(builtins,'open',forbidden)
    monkeypatch.setattr(sqlite3,'connect',forbidden)
    image=image_from(*stored)
    before=canonical_bytes(image)
    first=validate_update_storage_image(image,trusted_checkpoint=checkpoint(image))
    second=validate_update_storage_image(image,trusted_checkpoint=checkpoint(image))
    assert first==second and first.status=='CONSISTENT' and canonical_bytes(image)==before
    with pytest.raises(ValueError): image.deployment_id='other'


def test_invalid_result_exposes_no_counts():
    with pytest.raises(ValueError):
        UpdateStorageValidationResult(status='INVALID',reason_code='CHAIN_INVALID',commit_count=1)
