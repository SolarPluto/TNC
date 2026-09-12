"""Real loopback mTLS handoffs to fake custody and independent v2 verification."""
from datetime import timedelta
from hashlib import sha256

import pytest
from test_observation_signer_adapter import (
    pki, case, inventory, config, update, signed, host, stored, reconciliation,
    sim, db, writer, NOW, bridge_case, exchange, prepare,
)
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.key_custody_logic import KeyHandleRecord, CustodyCapabilities, CustodyTrustAnchor
from tnc.provenance.key_custody_provider import TestCustodyProvider, CustodyProviderResult
from tnc.provenance.key_custody_bridge import TestCustodyObservationBridge, CustodyObservationConfiguration
from tnc.provenance.observation_signer_adapter import ObservationSigningError, CandidateAlreadyConsumedError
from tnc.provenance.reconciliation_verifier import (
    ObservationKey, ObservationTrustStore, ObservationTrustCheckpoint, verify_observation)
import tnc.provenance.key_custody_bridge as module


@pytest.fixture
def custody_bridge(bridge_case,sim):
    s=bridge_case; t=int(NOW.timestamp()); env=sim[4]
    s.provider=TestCustodyProvider(epoch_clock=lambda:int(s.now.timestamp()))
    raw=s.provider.public_key_bytes
    scope=dict(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id)
    key=ObservationKey(**scope,timestamp=t-100,expiry=t+100,key_id=sha256(raw).hexdigest(),public_key_hex=raw.hex(),
        issuer_id=s.request.issuer_id,envelope_issuer_id=env.issuer_id,permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active')
    s.trust=ObservationTrustStore(**scope,timestamp=t-100,expiry=t+100,revision=1,keys=(key,))
    s.checkpoint=ObservationTrustCheckpoint(**scope,timestamp=t-100,expiry=t+100,revision=1,trust_store_digest=record_digest(s.trust))
    handle=KeyHandleRecord(**scope,issuer_id=s.request.issuer_id,provider_id='fake',resource_id='test-key',
        key_version='v1',key_id=key.key_id,public_key_hex=raw.hex(),revision=1,created_at=t-100,
        timestamp=t-100,expiry=t+100,status='ACTIVE',allowed_signers=('host',))
    caps=CustodyCapabilities(provider_id='fake',revision=1,timestamp=t-100,expiry=t+100,
        mechanism='ED25519_RAW',max_message_bytes=4096,signature_format='RAW_64',state='AVAILABLE')
    anchor=CustodyTrustAnchor(**scope,issuer_id=s.request.issuer_id,revision=1,timestamp=t-100,expiry=t+100,
        handle_digest=record_digest(handle),capabilities_digest=record_digest(caps))
    s.custody=CustodyObservationConfiguration(signer_id='host',handle=handle,capabilities=caps,anchor=anchor,
        trust_store=s.trust,trusted_checkpoint=s.checkpoint)
    s.signer=TestCustodyObservationBridge(s.bridge,s.provider,configuration=lambda:s.custody)
    yield s
    s.provider.close()


def sign(s,c,ticket,**kw):
    return s.signer.sign(c,ticket,expected_request=s.request,**kw)


def denied(s, mutate=lambda s,t:None, **kw):
    def action(c):
        ticket=prepare(s,c)
        mutate(s,ticket)
        with pytest.raises(ObservationSigningError,match='^Signing denied$'):sign(s,c,ticket,**kw)
        count=s.provider.dispatch_count
        with pytest.raises(CandidateAlreadyConsumedError):sign(s,c,ticket)
        assert s.provider.dispatch_count==count
    exchange(s,action)


def test_round_trip_and_original_deadline(custody_bridge,monkeypatch):
    s=custody_bridge; captured=[]; mint=s.provider.mint_handoff_for_testing
    def capture(*args,**kw):
        captured.append(kw['deadline']);return mint(*args,**kw)
    monkeypatch.setattr(s.provider,'mint_handoff_for_testing',capture)
    def action(c):
        ticket=prepare(s,c); response=sign(s,c,ticket)
        assert captured==[ticket._deadline]
        with pytest.raises(CandidateAlreadyConsumedError):sign(s,c,ticket)
        return response
    response=exchange(s,action)
    assert verify_observation(response,expected_request=s.request,trust_store=s.trust,
        trusted_checkpoint=s.checkpoint,now=int(s.now.timestamp())).status=='VERIFIED'
    assert response.payload.expiry<=int(s.now.timestamp())+5
    assert s.provider.dispatch_count==1


@pytest.mark.parametrize('kind',['credential','grant','expiry'])
def test_revoked_after_intake_before_dispatch(custody_bridge,kind):
    s=custody_bridge
    def mutate(s,t):
        if kind=='credential':s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
        elif kind=='grant':s.policy=s.policy.model_copy(update={'grants':()})
        else:s.now+=timedelta(seconds=60)
    denied(s,mutate)
    assert s.provider.dispatch_count==0


@pytest.mark.parametrize('kind',['handle','anchor','capabilities','trust','signer'])
def test_descriptor_and_trust_substitution(custody_bridge,kind):
    s=custody_bridge
    def mutate(s,t):
        cfg=s.custody
        if kind=='handle':cfg=cfg.model_copy(update={'handle':cfg.handle.model_copy(update={'resource_id':'other'})})
        elif kind=='anchor':cfg=cfg.model_copy(update={'anchor':cfg.anchor.model_copy(update={'handle_digest':'f'*64})})
        elif kind=='capabilities':cfg=cfg.model_copy(update={'capabilities':cfg.capabilities.model_copy(update={'max_message_bytes':1})})
        elif kind=='trust':cfg=cfg.model_copy(update={'trusted_checkpoint':cfg.trusted_checkpoint.model_copy(update={'revision':2})})
        else:cfg=cfg.model_copy(update={'signer_id':'intruder'})
        s.custody=cfg
    denied(s,mutate);assert s.provider.dispatch_count==0


@pytest.mark.parametrize('mode',['WRONG_KEY','TAMPERED_SIGNATURE','INVALID_SIGNATURE','UNSUPPORTED_MECHANISM',
    'DEADLINE_EXPIRED','AMBIGUOUS_OUTCOME','LATE_RESULT_REJECTION','PROVIDER_FAILURE'])
def test_provider_faults_no_retry(custody_bridge,mode):
    s=custody_bridge;denied(s,mode=mode)
    assert s.provider.dispatch_count==(0 if mode in ('UNSUPPORTED_MECHANISM','DEADLINE_EXPIRED') else 1)


@pytest.mark.parametrize('kind',['credential','grant','config','clock'])
def test_post_dispatch_changes_discard(custody_bridge,monkeypatch,kind):
    s=custody_bridge;dispatch=s.provider._dispatch
    def changed(raw,mode):
        signature=dispatch(raw,mode)
        if kind=='credential':s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
        elif kind=='grant':s.policy=s.policy.model_copy(update={'grants':()})
        elif kind=='config':s.custody=s.custody.model_copy(update={'anchor':s.custody.anchor.model_copy(update={'revision':2})})
        else:s.now+=timedelta(seconds=60)
        return signature
    monkeypatch.setattr(s.provider,'_dispatch',changed)
    denied(s);assert s.provider.dispatch_count==1


def test_bridge_independently_checks_provider_claim(custody_bridge,monkeypatch):
    s=custody_bridge;provider_sign=s.provider.sign
    def corrupt(*args,**kw):
        result=provider_sign(*args,**kw)
        return CustodyProviderResult('VERIFIED',result.response.model_copy(update={'signature_hex':'0'*128}))
    monkeypatch.setattr(s.provider,'sign',corrupt)
    denied(s);assert s.provider.dispatch_count==1


def test_bridge_rejects_other_payload_even_if_provider_claims_verified(custody_bridge,monkeypatch):
    s=custody_bridge;provider_sign=s.provider.sign
    def corrupt(*args,**kw):
        result=provider_sign(*args,**kw)
        payload=result.response.payload.model_copy(update={'policy_digest':'f'*64})
        return CustodyProviderResult('VERIFIED',result.response.model_copy(update={'payload':payload}))
    monkeypatch.setattr(s.provider,'sign',corrupt)
    denied(s)


def test_late_completion_bridge_gate(custody_bridge,monkeypatch):
    s=custody_bridge;provider_sign=s.provider.sign
    def mutate(s,ticket):
        def late(*args,**kw):
            result=provider_sign(*args,**kw)
            monkeypatch.setattr(module,'monotonic',lambda:ticket._deadline)
            return result
        monkeypatch.setattr(s.provider,'sign',late)
    denied(s,mutate)
    assert s.provider.dispatch_count==1


def test_snapshot_change_before_dispatch(custody_bridge):
    s=custody_bridge;calls=[]
    def configuration():
        calls.append(1)
        if len(calls)==2:s.custody=s.custody.model_copy(update={'signer_id':'other'})
        return s.custody
    s.signer._configuration=configuration
    denied(s);assert s.provider.dispatch_count==0


def test_grant_change_between_live_gates(custody_bridge,monkeypatch):
    s=custody_bridge
    def mutate(s,ticket):
        original=s.transport._revalidate;calls=[]
        def changing(*args,**kw):
            result=original(*args,**kw);calls.append(1)
            if len(calls)==1:s.policy=s.policy.model_copy(update={'grants':()})
            return result
        monkeypatch.setattr(s.transport,'_revalidate',changing)
    denied(s,mutate);assert s.provider.dispatch_count==0


def test_expired_original_deadline_no_dispatch(custody_bridge,monkeypatch):
    s=custody_bridge
    def mutate(s,ticket):monkeypatch.setattr(module,'monotonic',lambda:ticket._deadline)
    denied(s,mutate);assert s.provider.dispatch_count==0


@pytest.mark.parametrize('kind',['missing','oversize','revoked','scope'])
def test_invalid_host_inputs(custody_bridge,kind):
    s=custody_bridge
    def mutate(s,ticket):
        if kind=='missing':s.signer._configuration=lambda:None;return
        if kind=='oversize':
            caps=s.custody.capabilities.model_copy(update={'max_message_bytes':1})
            s.custody=s.custody.model_copy(update={'capabilities':caps,
                'anchor':s.custody.anchor.model_copy(update={'capabilities_digest':record_digest(caps)})})
        else:
            h=s.custody.handle.model_copy(update={'status':'REVOKED'} if kind=='revoked' else {'store_instance_id':'other'})
            s.custody=s.custody.model_copy(update={'handle':h,
                'anchor':s.custody.anchor.model_copy(update={'handle_digest':record_digest(h)})})
    denied(s,mutate);assert s.provider.dispatch_count==0


def test_unsigned_report_cannot_authorize_provider(custody_bridge):
    s=custody_bridge
    def action(c):
        candidate=s.bridge.observe(c,s.transport.receive_handoff(c)).candidate
        for value in (candidate,canonical_bytes(candidate)):
            with pytest.raises(ObservationSigningError):sign(s,c,value)
    exchange(s,action);assert s.provider.dispatch_count==0


def test_expected_request_substitution_burns_ticket(custody_bridge):
    s=custody_bridge
    def action(c):
        ticket=prepare(s,c)
        with pytest.raises(ObservationSigningError):
            s.signer.sign(c,ticket,expected_request=s.request.model_copy(update={'challenge':'f'*64}))
        with pytest.raises(CandidateAlreadyConsumedError):sign(s,c,ticket)
    exchange(s,action);assert s.provider.dispatch_count==0


def test_offline_receipt_recovery(custody_bridge,sim,tmp_path,monkeypatch):
    from tnc.provenance.client_high_water_logic import ClientAnchor,AdvancementRequest
    from tnc.provenance.client_high_water_store import TestClientHighWaterStore
    s=custody_bridge;t=int(s.now.timestamp());env=sim[4]
    anchor=ClientAnchor(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id,
        principal_id=s.request.principal_id,authority_revision=env.authority_revision,
        envelope_digest=record_digest(env),accepted_timestamp=t)
    store=TestClientHighWaterStore.create_for_testing(tmp_path/'client.db',trusted_initial_anchor=anchor,now=t)
    store.clock=lambda:t
    response=exchange(s,lambda c:sign(s,c,prepare(s,c)))
    request=AdvancementRequest(operation_id='offline',response=response,retained_request=s.request,
        trust_store=s.trust,trusted_checkpoint=s.checkpoint)
    original=store.apply(request,caller_principal=anchor.principal_id)
    assert original.receipt_bytes
    s.provider.close()
    def forbidden(*args,**kw):pytest.fail('Offline recovery called upstream')
    monkeypatch.setattr(s.signer,'sign',forbidden)
    monkeypatch.setattr(s.provider,'sign',forbidden)
    monkeypatch.setattr(s.bridge,'prepare_signing',forbidden)
    monkeypatch.setattr(s.registry,'read',forbidden)
    store=TestClientHighWaterStore(store.path,trusted_initial_anchor=anchor,clock=lambda:t+1000)
    recovered=store.apply(request,caller_principal=anchor.principal_id)
    assert recovered.status=='RECOVERED' and recovered.receipt_bytes==original.receipt_bytes
