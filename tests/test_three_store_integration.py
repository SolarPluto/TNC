"""Runtime, authority and client temporary stores with explicit fixture handoffs."""
from contextlib import closing
from hashlib import sha256
from types import SimpleNamespace
import multiprocessing
import os
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from test_two_store_recovery import case,inventory,config,update,signed,host,stored,setup,NOW,harness,read,revoke,auth
from test_signed_observation_integration import capture,assemble,sign,verify
from tnc.provenance.authorization_models import record_digest,canonical_bytes
from tnc.provenance.reconciliation_reader import ReadOnlyAuthorityAdapter
from tnc.provenance.reconciliation_verifier import ObservationKey,ObservationTrustStore,ObservationTrustCheckpoint,ObservationRequest,verify_observation
from tnc.provenance.client_high_water_logic import ClientAnchor,AdvancementRequest
from tnc.provenance.client_high_water_store import TestClientHighWaterStore,ClientStoreError


@pytest.fixture
def three(harness,tmp_path):
    h=harness; env=h.authority.load(now=NOW).current_envelope; t=int(NOW.timestamp())
    private=Ed25519PrivateKey.generate()
    raw=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    scope=dict(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id)
    key=ObservationKey(**scope,timestamp=t-100,expiry=t+100,key_id=sha256(raw).hexdigest(),public_key_hex=raw.hex(),
        issuer_id='observer',envelope_issuer_id=env.issuer_id,permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active')
    trust=ObservationTrustStore(**scope,timestamp=t-100,expiry=t+100,revision=1,keys=(key,))
    cp=ObservationTrustCheckpoint(**scope,timestamp=t-100,expiry=t+100,revision=1,trust_store_digest=record_digest(trust))
    request=ObservationRequest(**scope,timestamp=t,expiry=t+60,principal_id=h.caller.principal_id,issuer_id='observer',challenge='c'*64)
    reader=ReadOnlyAuthorityAdapter(h.authority.path,trusted_initial_envelope=env)
    signer=(reader,private,trust,cp,request,t)
    anchor=ClientAnchor(**scope,principal_id=h.caller.principal_id,authority_revision=env.authority_revision,
        envelope_digest=record_digest(env),accepted_timestamp=t)
    client=TestClientHighWaterStore.create_for_testing(tmp_path/'client.sqlite',trusted_initial_anchor=anchor,now=t)
    client.clock=lambda:t
    return SimpleNamespace(stack=h,signer=signer,client=client,anchor=anchor,t=t)


def observation(s,monkeypatch,op='client-1'):
    snapshot=capture(s.signer[0],(None,None,s.stack.caller),monkeypatch)
    signed=sign(assemble(snapshot,s.signer),s.signer)
    assert verify(signed,s.signer).status=='VERIFIED'
    return AdvancementRequest(operation_id=op,response=signed,retained_request=s.signer[4],trust_store=s.signer[2],trusted_checkpoint=s.signer[3])


def advance_authority(s):
    s.stack.execute_runtime_commit()
    command=s.stack.retained_command()
    s.stack.submit(command,auth(command.request))


def apply(s,request): return s.client.apply(request,caller_principal=s.anchor.principal_id)
def client_state(s): return s.client.load(now=s.t)


def upstream(s):
    return canonical_bytes(read(s.stack.runtime)),canonical_bytes(s.stack.authority.load(now=NOW))


def test_full_lifecycle(three,monkeypatch):
    s=three; advance_authority(s); request=observation(s,monkeypatch); before=upstream(s)
    result=apply(s,request); state=client_state(s)
    assert result.status=='VALID_ADVANCE' and state.authority_revision==2 and state.local_sequence==1
    assert state.envelope_digest==record_digest(s.stack.authority.load(now=NOW).current_envelope)
    assert result.receipt_bytes==canonical_bytes(state.history[0].receipt)
    assert upstream(s)==before


def child(path,anchor,request,t,point):
    assert verify_observation(request.response,expected_request=request.retained_request,trust_store=request.trust_store,
        trusted_checkpoint=request.trusted_checkpoint,now=t).status=='VERIFIED'
    if point=='after_verification': os._exit(73)
    store=TestClientHighWaterStore(path,trusted_initial_anchor=anchor,clock=lambda:t)
    def hook(where):
        if where==point: os._exit(73)
    store._hook=hook
    store.apply(request,caller_principal=anchor.principal_id)


@pytest.mark.parametrize('point,committed',[('after_verification',False),('before_commit',False),('after_commit',True)])
def test_client_crash_gap(three,monkeypatch,point,committed):
    s=three; advance_authority(s); request=observation(s,monkeypatch); before=upstream(s)
    p=multiprocessing.get_context('spawn').Process(target=child,args=(str(s.client.path),s.anchor,request,s.t,point))
    try:
        p.start(); p.join(25); assert p.exitcode==73
        state=client_state(s); assert state.local_sequence==int(committed)
        result=apply(s,request)
        assert result.status==('RECOVERED' if committed else 'VALID_ADVANCE')
        if committed: assert result.receipt_bytes==canonical_bytes(state.history[0].receipt)
        assert upstream(s)==before
    finally:
        if p.is_alive(): p.terminate(); p.join(5)


def test_stale_new_operation_rejected(three,monkeypatch):
    s=three; old=observation(s,monkeypatch,'old')
    advance_authority(s); apply(s,observation(s,monkeypatch))
    before=client_state(s)
    assert apply(s,old).status=='STALE' and client_state(s)==before


def test_skipped_revision(three,monkeypatch):
    s=three; advance_authority(s)
    revoke(s.stack.runtime); s.stack.runtime.writer.record_authority(expected_revision=1)
    command=s.stack.retained_command('authority-2'); s.stack.submit(command,auth(command.request))
    before=client_state(s)
    assert apply(s,observation(s,monkeypatch)).status=='PREDECESSOR_MISMATCH'
    assert client_state(s)==before


def test_receipt_retry_after_later_head(three,monkeypatch):
    s=three; advance_authority(s); first=observation(s,monkeypatch); receipt=apply(s,first)
    revoke(s.stack.runtime); s.stack.runtime.writer.record_authority(expected_revision=1)
    command=s.stack.retained_command('authority-2'); s.stack.submit(command,auth(command.request))
    apply(s,observation(s,monkeypatch,'client-2')); before=client_state(s)
    assert apply(s,first).receipt_bytes==receipt.receipt_bytes and client_state(s)==before


def test_forked_signed_claim(three,monkeypatch):
    s=three; advance_authority(s); original=observation(s,monkeypatch); apply(s,original)
    p=original.response.payload
    env=p.envelope.model_copy(update={'key_id':'f'*64})
    p=p.model_copy(update={'envelope':env,'envelope_digest':record_digest(env)})
    fork=original.model_copy(update={'operation_id':'fork','response':sign(p,s.signer)})
    before=client_state(s)
    assert apply(s,fork).status=='CONFLICT_FORK' and client_state(s)==before


@pytest.mark.parametrize('kind',['expired','tampered','trust'])
def test_invalid_observation_no_writes(three,monkeypatch,kind):
    s=three; advance_authority(s); request=observation(s,monkeypatch)
    if kind=='expired': s.client.clock=lambda:s.t+60
    elif kind=='tampered': request=request.model_copy(update={'response':request.response.model_copy(update={'signature_hex':'0'*128})})
    else: request=request.model_copy(update={'trusted_checkpoint':request.trusted_checkpoint.model_copy(update={'trust_store_digest':'f'*64})})
    before=client_state(s); sources=upstream(s)
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'): apply(s,request)
    assert client_state(s)==before and upstream(s)==sources


def test_three_distinct_databases_no_publication(three,monkeypatch):
    s=three; advance_authority(s); apply(s,observation(s,monkeypatch))
    paths=(s.stack.runtime.writer.path,s.stack.authority.path,s.client.path)
    assert len(set(paths))==3
    ids=[]
    for path in paths:
        with closing(sqlite3.connect(path)) as c:
            ids.append(c.execute('PRAGMA application_id').fetchone()[0])
            assert len(c.execute('PRAGMA database_list').fetchall())==1
    assert len(set(ids))==3
    with closing(sqlite3.connect(paths[0])) as c:
        assert c.execute('SELECT count(*) FROM publications').fetchone()==(0,)
