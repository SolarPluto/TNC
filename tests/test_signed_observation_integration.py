"""Test-only snapshot assembly and ephemeral signing; no production signer."""
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from test_reconciliation_durable_writer import (
    case,inventory,config,update,signed,host,stored,reconciliation,sim,db,writer,NOW,submit,policy,
)
from tnc.provenance.authorization_models import canonical_bytes,record_digest
from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter,AuthorityReadError
from tnc.provenance.reconciliation_durable_store import TestCheckpointAuthorityStore
from tnc.provenance.reconciliation_verifier import (
    ObservationKey,ObservationTrustStore,ObservationTrustCheckpoint,ObservationRequest,
    ObservationPayload,SignedObservation,observation_preimage,verify_observation,
)


@dataclass(frozen=True)
class CapturedSnapshot:
    observation: object
    state: object


def capture(reader,sim,monkeypatch,after_snapshot=None):
    # Test seam captures the immutable state actually used by this reader call.
    # No second store read is used for policy assembly.
    original=TestCheckpointAuthorityStore._load
    captured=[]
    def load(store,connection,*,now):
        state=original(store,connection,now=now)
        if not captured:
            captured.append(state)
            if after_snapshot is not None: after_snapshot()
        return state
    with monkeypatch.context() as patch:
        patch.setattr(TestCheckpointAuthorityStore,'_load',load)
        observation=reader.observe_current('c'*64,caller=sim[2],now=NOW)
    assert len(captured)==1
    return CapturedSnapshot(observation,captured[0])


@pytest.fixture
def harness(db,sim):
    t=int(NOW.timestamp()); env=sim[4]
    private=Ed25519PrivateKey.generate()
    raw=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    scope=dict(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id)
    key=ObservationKey(**scope,timestamp=t-100,expiry=t+100,key_id=sha256(raw).hexdigest(),public_key_hex=raw.hex(),
        issuer_id='observer',envelope_issuer_id=env.issuer_id,permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active')
    trust=ObservationTrustStore(**scope,timestamp=t-100,expiry=t+100,revision=1,keys=(key,))
    checkpoint=ObservationTrustCheckpoint(**scope,timestamp=t-100,expiry=t+100,revision=1,trust_store_digest=record_digest(trust))
    request=ObservationRequest(**scope,timestamp=t,expiry=t+60,principal_id=sim[2].principal_id,issuer_id='observer',challenge='c'*64)
    reader=ReadOnlyAuthorityAdapter(db.path,trusted_initial_envelope=env)
    return reader,private,trust,checkpoint,request,t


def assemble(snapshot,h):
    _,_,trust,cp,request,t=h
    state=snapshot.state; observation=snapshot.observation
    if canonical_bytes(observation.envelope)!=canonical_bytes(state.current_envelope): raise ValueError('SNAPSHOT_MISMATCH')
    if observation.principal_id!=request.principal_id or observation.challenge!=request.challenge: raise ValueError('REQUEST_MISMATCH')
    expiry=min(request.expiry,int(observation.valid_until.timestamp()))
    return ObservationPayload(**{**request.model_dump(),'timestamp':t,'expiry':expiry},
        request_digest=record_digest(request),signing_key_id=trust.keys[0].key_id,
        trust_revision=cp.revision,trust_store_digest=cp.trust_store_digest,
        policy_revision=state.policy.revision,policy_digest=record_digest(state.policy),
        authority_revision=observation.envelope.authority_revision,envelope_digest=record_digest(observation.envelope),envelope=observation.envelope)


def sign(payload,h):
    return SignedObservation(payload=payload,signature_hex=h[1].sign(observation_preimage(payload)).hex())


def verify(response,h,**changes):
    args=dict(expected_request=h[4],trust_store=h[2],trusted_checkpoint=h[3],now=h[5]); args.update(changes)
    return verify_observation(response,**args)


def test_roundtrip(harness,sim,writer,monkeypatch):
    submit(writer,sim)
    snapshot=capture(harness[0],sim,monkeypatch)
    result=verify(sign(assemble(snapshot,harness),harness),harness)
    assert result.status=='VERIFIED' and result.audit_only
    assert result.checked_payload.policy_digest==record_digest(snapshot.state.policy)


def test_policy_change_during_read_uses_old_snapshot(harness,sim,writer,monkeypatch):
    prior=writer.load(now=NOW).policy
    replacement=prior.model_copy(update={'revision':2})
    old=capture(harness[0],sim,monkeypatch,lambda:policy(writer,sim,replacement))
    new=capture(harness[0],sim,monkeypatch)
    assert assemble(old,harness).policy_revision==1
    assert assemble(new,harness).policy_revision==2
    assert verify(sign(assemble(old,harness),harness),harness).status=='VERIFIED'
    # Same envelope can legitimately occur in different policy snapshots. The
    # safe assembler accepts only its captured state, not a second policy input.
    with pytest.raises(TypeError): assemble(old,harness,policy=new.state.policy)


def test_envelope_mixing_rejected_by_assembler(harness,sim,writer,monkeypatch):
    old=capture(harness[0],sim,monkeypatch)
    submit(writer,sim)
    new=capture(harness[0],sim,monkeypatch)
    with pytest.raises(ValueError,match='SNAPSHOT_MISMATCH'):
        assemble(CapturedSnapshot(old.observation,new.state),harness)


@pytest.mark.parametrize('field,value',[('envelope_digest','f'*64),('policy_digest','f'*64),('policy_revision',99)])
def test_post_signature_tampering(harness,sim,monkeypatch,field,value):
    response=sign(assemble(capture(harness[0],sim,monkeypatch),harness),harness)
    response=response.model_copy(update={'payload':response.payload.model_copy(update={field:value})})
    assert verify(response,harness).reason_code=='SIGNATURE_INVALID'


@pytest.mark.parametrize('offset,status',[(59,'VERIFIED'),(60,'REJECTED'),(61,'REJECTED')])
def test_expiry(harness,sim,monkeypatch,offset,status):
    response=sign(assemble(capture(harness[0],sim,monkeypatch),harness),harness)
    assert verify(response,harness,now=harness[5]+offset).status==status


def test_new_challenge_rejects_old_response(harness,sim,writer,monkeypatch):
    old=sign(assemble(capture(harness[0],sim,monkeypatch),harness),harness)
    submit(writer,sim)
    request=harness[4].model_copy(update={'challenge':'d'*64})
    assert verify(old,harness,expected_request=request).reason_code=='REQUEST_MISMATCH'
    # Unexpired old snapshot with its original request still verifies: not latestness.
    assert verify(old,harness).status=='VERIFIED'


def test_historical_receipt_is_not_current_response(harness,sim,writer):
    submit(writer,sim)
    raw=harness[0].recover_historical(sim[1].request,caller=sim[2],now=NOW)
    assert verify(raw,harness).reason_code=='INVALID_RECORD'


def test_trusted_signer_false_policy_claim_is_not_detectable(harness,sim,monkeypatch):
    payload=assemble(capture(harness[0],sim,monkeypatch),harness)
    malicious=payload.model_copy(update={'policy_digest':'f'*64})
    assert verify(sign(malicious,harness),harness).status=='VERIFIED'
    # Verification authenticates the issuer's assertion, not policy history.


def test_independent_checkpoint_required(harness,sim,monkeypatch):
    response=sign(assemble(capture(harness[0],sim,monkeypatch),harness),harness)
    cp=harness[3].model_copy(update={'trust_store_digest':'f'*64})
    assert verify(response,harness,trusted_checkpoint=cp).reason_code=='TRUST_MISMATCH'


def test_permission_removed_before_capture(harness,sim,writer,monkeypatch):
    policy(writer,sim)
    with pytest.raises(AuthorityReadError,match='ACCESS_DENIED'): capture(harness[0],sim,monkeypatch)


def test_no_application_writes(harness,sim,db,monkeypatch):
    with closing(sqlite3.connect(db.path)) as c: before=list(c.iterdump())
    response=sign(assemble(capture(harness[0],sim,monkeypatch),harness),harness)
    assert verify(response,harness).status=='VERIFIED'
    with closing(sqlite3.connect(db.path)) as c: assert list(c.iterdump())==before
