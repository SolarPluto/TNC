"""Real TLS-to-bridge-to-ephemeral-signature integration; no live key custody."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import builtins
import copy
import pickle
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_observation_bridge import (
    pki, case, inventory, config, update, signed, host, stored, reconciliation,
    sim, db, writer, NOW, bridge_case, exchange,
)
from tnc.provenance.authorization_models import canonical_bytes, record_digest
from tnc.provenance.observation_bridge import TestObservationBridge
from tnc.provenance.observation_signer_adapter import (
    TestObservationSignerAdapter, ObservationSigningError, CandidateAlreadyConsumedError, _seconds,
)
from tnc.provenance.reconciliation_verifier import ObservationKey, ObservationTrustStore, ObservationTrustCheckpoint, verify_observation
import tnc.provenance.observation_signer_adapter as signer_module


@pytest.fixture
def signing(bridge_case,sim):
    s=bridge_case; s.signer=TestObservationSignerAdapter(s.bridge)
    raw=s.signer.public_key_bytes; t=int(NOW.timestamp()); env=sim[4]
    scope=dict(deployment_id=env.deployment_id,store_instance_id=env.store_instance_id)
    key=ObservationKey(**scope,timestamp=t-100,expiry=t+100,key_id=sha256(raw).hexdigest(),public_key_hex=raw.hex(),
        issuer_id=s.request.issuer_id,envelope_issuer_id=env.issuer_id,permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active')
    s.trust=ObservationTrustStore(**scope,timestamp=t-100,expiry=t+100,revision=1,keys=(key,))
    s.checkpoint=ObservationTrustCheckpoint(**scope,timestamp=t-100,expiry=t+100,revision=1,trust_store_digest=record_digest(s.trust))
    return s


def prepare(s,conn):
    ticket=s.bridge.prepare_signing(conn,s.transport.receive_handoff(conn))
    assert ticket is not None
    return ticket


def sign(s,conn,ticket,**changes):
    args=dict(expected_request=s.request,trust_store=s.trust,trusted_checkpoint=s.checkpoint);args.update(changes)
    return s.signer.sign(conn,ticket,**args)


def verify(s,response,**changes):
    args=dict(expected_request=s.request,trust_store=s.trust,trusted_checkpoint=s.checkpoint,now=int(s.now.timestamp()))
    args.update(changes)
    return verify_observation(response,**args)


def test_full_path(signing,sim):
    s=signing; response=exchange(s,lambda c:sign(s,c,prepare(s,c)))
    result=verify(s,response)
    assert result.status=='VERIFIED' and result.audit_only
    assert response.payload.envelope==sim[4] and response.payload.policy_digest==record_digest(sim[0].policy)
    assert response.payload.request_digest==record_digest(s.request)
    assert response.payload.principal_id==s.request.principal_id and response.payload.challenge==s.request.challenge
    assert response.payload.expiry<=int(NOW.timestamp())+5


def test_replay_burned(signing):
    s=signing
    def action(conn):
        ticket=prepare(s,conn); first=sign(s,conn,ticket)
        with pytest.raises(CandidateAlreadyConsumedError):sign(s,conn,ticket)
        return first
    assert verify(s,exchange(s,action)).status=='VERIFIED'


def test_report_is_not_signing_permission(signing):
    s=signing
    def action(conn):
        report=s.bridge.observe(conn,s.transport.receive_handoff(conn)).candidate
        for value in (report,report.model_copy(),canonical_bytes(report)):
            with pytest.raises(ObservationSigningError):sign(s,conn,value)
    exchange(s,action)


@pytest.mark.parametrize('kind',['digest','revision','challenge','other-key'])
def test_bad_trust_or_request_burns_attempt(signing,kind):
    s=signing
    def action(conn):
        ticket=prepare(s,conn); changes={}
        if kind=='digest':changes['trusted_checkpoint']=s.checkpoint.model_copy(update={'trust_store_digest':'f'*64})
        elif kind=='revision':changes['trusted_checkpoint']=s.checkpoint.model_copy(update={'revision':2})
        elif kind=='challenge':changes['expected_request']=s.request.model_copy(update={'challenge':'e'*64})
        else:s.signer._private=TestObservationSignerAdapter(s.bridge)._private
        with pytest.raises(ObservationSigningError,match='^Signing denied$'):sign(s,conn,ticket,**changes)
        with pytest.raises(CandidateAlreadyConsumedError):sign(s,conn,ticket)
    exchange(s,action)


@pytest.mark.parametrize('change',[{'status':'revoked'},{'status':'retired'},{'permissions':()},
    {'issuer_id':'other'},{'envelope_issuer_id':'other'}, {'timestamp':int(NOW.timestamp())+1},
    {'expiry':int(NOW.timestamp())},{'expiry':2**63}],
    ids=['revoked','retired','missing-grant','issuer','envelope-issuer','future','expired','overflow'])
def test_key_checks_before_signing(signing,change):
    s=signing; key=s.trust.keys[0].model_copy(update=change)
    s.trust=s.trust.model_copy(update={'keys':(key,)})
    s.checkpoint=s.checkpoint.model_copy(update={'trust_store_digest':record_digest(s.trust)})
    original=s.signer._private
    class NoSign:
        def public_key(self):return original.public_key()
        def sign(self,data):pytest.fail('Unauthorized signature generated')
    s.signer._private=NoSign()
    def action(conn):
        with pytest.raises(ObservationSigningError):sign(s,conn,prepare(s,conn))
    exchange(s,action)


@pytest.mark.parametrize('kind',['monotonic','expired','backward','revoked','grant'])
def test_changed_context_cannot_sign(signing,monkeypatch,kind):
    s=signing
    def action(conn):
        ticket=prepare(s,conn)
        if kind=='monotonic':monkeypatch.setattr(signer_module,'monotonic',lambda:ticket._deadline)
        if kind=='expired':s.now+=timedelta(seconds=60)
        if kind=='backward':s.now-=timedelta(seconds=1)
        if kind=='revoked':s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
        if kind=='grant':s.policy=s.policy.model_copy(update={'grants':()})
        with pytest.raises(ObservationSigningError):sign(s,conn,ticket)
    exchange(s,action)


def test_single_use_failed_signature(signing):
    s=signing;original=s.signer._private
    class BadSigner:
        def public_key(self):return original.public_key()
        def sign(self,data):return bytes(64)
    s.signer._private=BadSigner()
    def action(conn):
        ticket=prepare(s,conn)
        with pytest.raises(ObservationSigningError):sign(s,conn,ticket)
        with pytest.raises(CandidateAlreadyConsumedError):sign(s,conn,ticket)
    exchange(s,action)


def test_revocation_during_sign_suppresses_output(signing):
    s=signing;original=s.signer._private; calls=[]
    class RevokingSigner:
        def public_key(self):return original.public_key()
        def sign(self,data):
            calls.append(1)
            signature=original.sign(data)
            s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
            return signature
    s.signer._private=RevokingSigner()
    def action(conn):
        with pytest.raises(ObservationSigningError):sign(s,conn,prepare(s,conn))
    exchange(s,action);assert calls==[1]


@pytest.mark.parametrize('kind',['copy','pickle','deepcopy','mutate','tamper'])
def test_ticket_integrity(signing,kind):
    s=signing
    def action(conn):
        ticket=prepare(s,conn)
        if kind=='tamper':
            # Deliberate in-process bypass exercises digest checking, not hostile-code isolation.
            object.__setattr__(ticket,'_raw',ticket._raw.replace(b'"observer"',b'"imposter"'))
            with pytest.raises(ObservationSigningError):sign(s,conn,ticket)
            return
        with pytest.raises(TypeError):
            if kind=='copy':copy.copy(ticket)
            elif kind=='deepcopy':copy.deepcopy(ticket)
            elif kind=='pickle':pickle.dumps(ticket)
            else:ticket._raw=b'forged'
        assert verify(s,sign(s,conn,ticket)).status=='VERIFIED'
    exchange(s,action)


@pytest.mark.parametrize('kind',['thread','bridge','connection'])
def test_confinement(signing,kind):
    s=signing
    def action(conn):
        ticket=prepare(s,conn)
        with pytest.raises(ObservationSigningError):
            if kind=='thread':
                with ThreadPoolExecutor(max_workers=1) as pool:pool.submit(sign,s,conn,ticket).result(timeout=5)
            elif kind=='bridge':
                other=TestObservationSignerAdapter(TestObservationBridge(s.transport,s.reader))
                other.sign(conn,ticket,expected_request=s.request,trust_store=s.trust,trusted_checkpoint=s.checkpoint)
            else:exchange(s,lambda other:sign(s,other,ticket))
    exchange(s,action)


def test_fractional_lower_bound_never_backdated(signing):
    s=signing;s.now=NOW+timedelta(microseconds=250000)
    def action(conn):
        ticket=prepare(s,conn)
        with pytest.raises(ObservationSigningError):sign(s,conn,ticket)
    exchange(s,action)


def test_fractional_candidate_signable_in_next_second(signing):
    s=signing;s.now=NOW+timedelta(microseconds=250000)
    def action(conn):
        ticket=prepare(s,conn);s.now=NOW+timedelta(seconds=1)
        return sign(s,conn,ticket)
    response=exchange(s,action)
    assert response.payload.timestamp==int(NOW.timestamp())+1 and verify(s,response).status=='VERIFIED'


def test_fractional_upper_bound_rounded_down(signing):
    s=signing
    short=s.registry.state.credentials[0].model_copy(update={'valid_until':NOW+timedelta(seconds=3,microseconds=750000)})
    s.registry.state=s.registry.state.model_copy(update={'credentials':(short,)})
    response=exchange(s,lambda c:sign(s,c,prepare(s,c)))
    assert response.payload.expiry==int(NOW.timestamp())+3
    assert verify(s,response,now=response.payload.expiry).status=='REJECTED'


@pytest.mark.parametrize('offset,lower,upper',[(0,0,0),(1,0,1),(999999,0,1),(1000000,1,1)])
def test_exact_epoch_rounding(offset,lower,upper):
    value=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=offset)
    assert _seconds(value)==lower and _seconds(value,upper=True)==upper


@pytest.mark.parametrize('value',[datetime(2026,1,1),datetime(1969,12,31,tzinfo=timezone.utc),0])
def test_bad_epochs(value):
    with pytest.raises(ValueError):_seconds(value)


def test_no_io_in_signing(signing,monkeypatch):
    s=signing
    def action(conn):
        ticket=prepare(s,conn)
        def fail(*a,**kw):pytest.fail('Signing I/O forbidden')
        with monkeypatch.context() as patch:
            patch.setattr(builtins,'open',fail);patch.setattr(sqlite3,'connect',fail)
            return sign(s,conn,ticket)
    assert verify(s,exchange(s,action)).status=='VERIFIED'


def test_closed_signer_and_no_private_key_import(signing):
    s=signing
    with pytest.raises(TypeError):TestObservationSignerAdapter(s.bridge,private_key=s.signer._private)
    s.signer.close()
    def action(conn):
        with pytest.raises(ObservationSigningError):sign(s,conn,prepare(s,conn))
    exchange(s,action)


def test_post_signature_tampering_rejected(signing):
    s=signing;response=exchange(s,lambda c:sign(s,c,prepare(s,c)))
    modified=response.model_copy(update={'payload':response.payload.model_copy(update={'policy_digest':'f'*64})})
    assert verify(s,modified).reason_code=='SIGNATURE_INVALID'


def test_original_deadline_is_not_reset(signing,monkeypatch):
    s=signing
    def action(conn):
        request_ticket=s.transport.receive_handoff(conn)
        ticket=s.bridge.prepare_signing(conn,request_ticket)
        assert ticket._deadline==request_ticket._deadline
        assert s.bridge.prepare_signing(conn,request_ticket) is None
        monkeypatch.setattr(signer_module,'monotonic',lambda:ticket._deadline-1.25)
        return sign(s,conn,ticket)
    response=exchange(s,action)
    assert response.payload.expiry==int(NOW.timestamp())+1


@pytest.mark.parametrize('target,field,value',[
    ('trust','timestamp',int(NOW.timestamp())+1),('trust','expiry',int(NOW.timestamp())),
    ('checkpoint','timestamp',int(NOW.timestamp())+1),('checkpoint','expiry',int(NOW.timestamp())),
])
def test_trust_intervals(signing,target,field,value):
    s=signing
    setattr(s,target,getattr(s,target).model_copy(update={field:value}))
    if target=='trust':s.checkpoint=s.checkpoint.model_copy(update={'trust_store_digest':record_digest(s.trust)})
    def action(conn):
        with pytest.raises(ObservationSigningError):sign(s,conn,prepare(s,conn))
    exchange(s,action)


def test_key_is_generated_per_adapter_and_signer_not_serializable(signing):
    s=signing;other=TestObservationSignerAdapter(s.bridge)
    assert len(other.public_key_bytes)==32 and other.public_key_bytes!=s.signer.public_key_bytes
    with pytest.raises(TypeError):pickle.dumps(s.signer)
    other.close()


def test_signature_deadline_overrun_suppresses_result(signing,monkeypatch):
    s=signing;original=s.signer._private;deadline=[]
    class SlowSigner:
        def public_key(self):return original.public_key()
        def sign(self,data):
            result=original.sign(data)
            monkeypatch.setattr(signer_module,'monotonic',lambda:deadline[0])
            return result
    s.signer._private=SlowSigner()
    def action(conn):
        ticket=prepare(s,conn);deadline.append(ticket._deadline)
        with pytest.raises(ObservationSigningError):sign(s,conn,ticket)
    exchange(s,action)
