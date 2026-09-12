"""Pure signature, fixed freshness, predecessor and root-authorized rotation tests."""
from hashlib import sha256
from types import SimpleNamespace
import builtins
import json
import socket
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from tnc.provenance.authorization_models import canonical_bytes, record_digest, ZERO
from tnc.provenance.reconciliation_verifier import ObservationTrustStore, ObservationKey
from tnc.provenance.protected_trust_distribution import *


def keypair(t, root=False):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = DistributionKey(deployment_id='deployment',store_instance_id='store',
        issuer_id='root-authority' if root else 'distributor', key_id=sha256(public).hexdigest(),
        public_key_hex=public.hex(),status='active',issued_at=t-10,expires_at=t+1000,
        permission='AUTHORIZE_DISTRIBUTION_EPOCH' if root else 'DISTRIBUTE_OBSERVATION_TRUST')
    return private,key


@pytest.fixture
def case():
    t=1800000000
    private,key=keypair(t);new_private,new_key=keypair(t);root_private,root=keypair(t,True)
    _,observer=keypair(t)
    observation_key=ObservationKey(deployment_id='deployment',store_instance_id='store',key_id=observer.key_id,
        public_key_hex=observer.public_key_hex,issuer_id='observer',envelope_issuer_id='authority',
        permissions=('AUTHORITY_OBSERVE_CURRENT',),status='active',timestamp=t-10,expiry=t+1000)
    store=ObservationTrustStore(deployment_id='deployment',store_instance_id='store',revision=3,
        keys=(observation_key,),timestamp=t-10,expiry=t+1000)
    policy=DistributionPolicy(deployment_id='deployment',store_instance_id='store',revision=7,
        issuer_id='distributor',issued_at=t-10,expires_at=t+1000,max_age_seconds=60,
        bootstrap_checkpoint_revision=10,bootstrap_epoch=1,bootstrap_epoch_id='epoch-one',
        bootstrap_signing_key_id=key.key_id,keys=tuple(sorted((key,new_key),key=lambda k:k.key_id)),root_key=root)
    pin=DistributionPolicyCheckpoint(deployment_id='deployment',store_instance_id='store',policy_revision=7,
        policy_digest=record_digest(policy),issued_at=t-10,expires_at=t+1000)
    p=TrustDistributionPayload(deployment_id='deployment',store_instance_id='store',issuer_id='distributor',
        signing_key_id=key.key_id,checkpoint_revision=10,previous_checkpoint_digest=ZERO,epoch=1,epoch_id='epoch-one',
        trust_store_revision=3,trust_store_digest=record_digest(store),issued_at=t,expires_at=t+120,max_age_seconds=60)
    c=SimpleNamespace(t=t,private=private,key=key,new_private=new_private,new_key=new_key,
        root_private=root_private,root=root,store=store,policy=policy,pin=pin,p=p)
    c.bundle=emit(c)
    return c


def emit(c,p=None,store=None,transition=None,private=None,domain=CHECKPOINT_DOMAIN):
    p=p or c.p
    return TrustDistributionBundle(payload=p,trust_store=store or c.store,transition=transition,
        signature_hex=(private or c.private).sign(domain+canonical_bytes(p)).hex())


def check(c,bundle=None,**kwargs):
    args=dict(policy=c.policy,trusted_policy_checkpoint=c.pin,retained_head=None,now=c.t)
    args.update(kwargs)
    return verify_trust_distribution(bundle or c.bundle,**args)


def policy_pin(policy):
    return DistributionPolicyCheckpoint(deployment_id=policy.deployment_id,store_instance_id=policy.store_instance_id,
        policy_revision=policy.revision,policy_digest=record_digest(policy),issued_at=policy.issued_at,expires_at=policy.expires_at)


def successor(c,**changes):
    return c.p.model_copy(update={'checkpoint_revision':11,'previous_checkpoint_digest':record_digest(c.p),**changes})


def rotated(c):
    head=check(c).proposed_head
    store=c.store.model_copy(update={'revision':4})
    transition=EpochTransition(deployment_id='deployment',store_instance_id='store',
        root_issuer_id=c.root.issuer_id,root_key_id=c.root.key_id,distribution_issuer_id='distributor',
        issued_at=c.t,expires_at=c.t+50,from_epoch=1,from_epoch_id='epoch-one',from_signing_key_id=c.key.key_id,
        previous_checkpoint_revision=10,previous_checkpoint_digest=head.checkpoint_digest,
        to_epoch=2,to_epoch_id='epoch-two',to_signing_key_id=c.new_key.key_id,checkpoint_revision=11,
        trust_store_revision=4,trust_store_digest=record_digest(store))
    signed=SignedEpochTransition(payload=transition,signature_hex=c.root_private.sign(transition_preimage(transition)).hex())
    p=successor(c,epoch=2,epoch_id='epoch-two',signing_key_id=c.new_key.key_id,trust_store_revision=4,
        trust_store_digest=record_digest(store),transition_digest=record_digest(transition))
    return emit(c,p,store,signed,c.new_private),head


def test_valid_initial_and_existing_v2_checkpoint_mapping(case):
    c=case;r=check(c)
    assert r.status=='INITIAL' and r.audit_only and r.signature_verified
    assert r.proposed_head.checkpoint_revision==10
    assert r.checked_checkpoint.revision==3 and r.checked_checkpoint.trust_store_digest==record_digest(c.store)
    assert r.checked_checkpoint.timestamp==c.t and r.checked_checkpoint.expiry==c.t+60
    assert r.checked_store==c.store


def test_exact_current_retry_does_not_slide_expiry_or_acceptance(case):
    c=case;first=check(c);head=first.proposed_head
    again=check(c,retained_head=head,now=c.t+20)
    assert again.status=='UNCHANGED' and again.checked_checkpoint==first.checked_checkpoint
    assert again.proposed_head.accepted_at==c.t and again.proposed_head.checked_at==c.t+20
    assert head.checked_at==c.t
    with pytest.raises(ValueError):head.epoch=2


@pytest.mark.parametrize('offset',[60,61,120])
def test_exact_freshness_upper_boundary(case,offset):
    c=case;head=check(c).proposed_head
    assert check(c,retained_head=head,now=c.t+offset).reason_code=='CHECKPOINT_STALE'


def test_local_max_age_overrides_signer_declared_age(case):
    c=case;b=emit(c,c.p.model_copy(update={'max_age_seconds':3600}))
    assert check(c,b,now=c.t+59).status=='INITIAL'
    assert check(c,b,now=c.t+60).reason_code=='CHECKPOINT_STALE'


def test_lower_signed_max_age_is_enforced(case):
    c=case;b=emit(c,c.p.model_copy(update={'max_age_seconds':5}))
    assert check(c,b).checked_checkpoint.expiry==c.t+5
    assert check(c,b,now=c.t+5).reason_code=='CHECKPOINT_STALE'


@pytest.mark.parametrize('kind',['payload','store','signature','domain','other_key'])
def test_tampering_and_domain_confusion(case,kind):
    c=case;b=c.bundle
    if kind=='payload':b=b.model_copy(update={'payload':c.p.model_copy(update={'epoch_id':'changed'})})
    elif kind=='store':b=b.model_copy(update={'trust_store':c.store.model_copy(update={'revision':4})})
    elif kind=='signature':b=b.model_copy(update={'signature_hex':'0'*128})
    elif kind=='domain':b=emit(c,domain=b'TNC-SIGNED-OBSERVATION-v2:')
    else:b=emit(c,private=c.new_private)
    r=check(c,b)
    assert r.status=='REJECTED' and not r.signature_verified and r.proposed_head is None and r.checked_store is None


@pytest.mark.parametrize('kind',['unknown','revoked','retired','expired','future'])
def test_current_distribution_key_permission_and_time(case,kind):
    c=case
    if kind=='unknown':return assert_denied(check(c,emit(c,c.p.model_copy(update={'signing_key_id':'f'*64}))), 'KEY_DENIED')
    key=c.key.model_copy(update={'status':kind} if kind in ('revoked','retired') else
        {'expires_at':c.t} if kind=='expired' else {'issued_at':c.t+1})
    policy=c.policy.model_copy(update={'keys':tuple(sorted((key,c.new_key),key=lambda k:k.key_id)),'revision':8})
    assert check(c,policy=policy,trusted_policy_checkpoint=policy_pin(policy)).reason_code=='KEY_DENIED'


def assert_denied(result,reason): assert result.status=='REJECTED' and result.reason_code==reason


@pytest.mark.parametrize('field,value',[('policy_revision',8),('policy_digest','f'*64),('store_instance_id','other')])
def test_independent_pin_mismatch(case,field,value):
    c=case;r=check(c,trusted_policy_checkpoint=c.pin.model_copy(update={field:value}))
    assert r.status=='REJECTED'


@pytest.mark.parametrize('field,value',[('issued_at',1800000001),('expires_at',1800000000)])
def test_pin_temporal_bounds(case,field,value):
    assert check(case,trusted_policy_checkpoint=case.pin.model_copy(update={field:value})).status=='REJECTED'


def test_signature_timestamp_is_not_freshness_authentication(case):
    c=case
    # A signer assertion about issuance does not prove when a private-key operation occurred.
    # Here a real signature over a future claimed timestamp must still fail now.
    b=emit(c,c.p.model_copy(update={'issued_at':c.t+1}))
    assert check(c,b).reason_code=='NOT_YET_VALID'


def test_direct_advance_with_same_store_renews_checkpoint_only(case):
    c=case;head=check(c).proposed_head
    b=emit(c,successor(c,issued_at=c.t+10))
    r=check(c,b,retained_head=head,now=c.t+10)
    assert r.status=='ADVANCE' and r.checked_checkpoint.revision==3
    assert r.proposed_head.checkpoint_revision==11 and r.checked_checkpoint.expiry==c.t+70


@pytest.mark.parametrize('kind',['stale','fork','skip','predecessor','epoch_id','key','epoch_reset'])
def test_checkpoint_lineage_rejections(case,kind):
    c=case;head=check(c).proposed_head;p=successor(c)
    if kind=='stale':
        newer=check(c,emit(c,p),retained_head=head).proposed_head
        return assert_denied(check(c,retained_head=newer),'CHECKPOINT_REGRESSION')
    changes={'fork':{'checkpoint_revision':10,'epoch_id':'fork'},'skip':{'checkpoint_revision':12},
        'predecessor':{'previous_checkpoint_digest':'f'*64},'epoch_id':{'epoch_id':'other'},
        'key':{'signing_key_id':c.new_key.key_id},'epoch_reset':{'epoch':3}}[kind]
    private=c.new_private if kind=='key' else c.private
    r=check(c,emit(c,p.model_copy(update=changes),private=private),retained_head=head)
    assert r.reason_code=={'fork':'CHECKPOINT_FORK','skip':'MISSING_CHAIN','predecessor':'PREDECESSOR_MISMATCH',
                          'epoch_id':'EPOCH_MISMATCH','key':'EPOCH_MISMATCH','epoch_reset':'EPOCH_MISMATCH'}[kind]


@pytest.mark.parametrize('kind',['regression','fork','advance'])
def test_observation_store_revision_separate_from_checkpoint(case,kind):
    c=case;head=check(c).proposed_head
    store=c.store.model_copy(update={'revision':2 if kind=='regression' else 4 if kind=='advance' else 3,'expiry':c.t+900})
    p=successor(c,trust_store_revision=store.revision,trust_store_digest=record_digest(store))
    r=check(c,emit(c,p,store),retained_head=head)
    assert r.status=='ADVANCE' if kind=='advance' else r.reason_code==('TRUST_STORE_REGRESSION' if kind=='regression' else 'TRUST_STORE_FORK')


def test_root_authorized_rotation_and_next_checkpoint(case):
    c=case;b,head=rotated(c);r=check(c,b,retained_head=head)
    assert r.status=='ADVANCE' and r.proposed_head.epoch==2 and r.checked_checkpoint.expiry==c.t+50
    assert check(c,b,retained_head=r.proposed_head,now=c.t+1).status=='UNCHANGED'
    p=b.payload.model_copy(update={'checkpoint_revision':12,'previous_checkpoint_digest':record_digest(b.payload),
                                  'transition_digest':None,'issued_at':c.t+1})
    follow=emit(c,p,b.trust_store,private=c.new_private)
    assert check(c,follow,retained_head=r.proposed_head,now=c.t+1).status=='ADVANCE'


def test_root_authorized_emergency_rotation_needs_no_retiring_key_signature(case):
    c=case;b,head=rotated(c)
    policy=c.policy.model_copy(update={'revision':8,'keys':tuple(sorted((c.key.model_copy(update={'status':'revoked'}),c.new_key),key=lambda k:k.key_id))})
    assert check(c,b,retained_head=head,policy=policy,trusted_policy_checkpoint=policy_pin(policy)).status=='ADVANCE'
    assert check(c,retained_head=head,policy=policy,trusted_policy_checkpoint=policy_pin(policy)).reason_code=='KEY_DENIED'


@pytest.mark.parametrize('kind',['absent','bad_signature','wrong_root','wrong_old_key','wrong_target','wrong_domain','expired','retired_root'])
def test_rotation_failure_matrix(case,kind):
    c=case;b,head=rotated(c);t=b.transition;p=b.payload;kwargs={}
    if kind=='absent':b=b.model_copy(update={'transition':None})
    elif kind=='retired_root':
        policy=c.policy.model_copy(update={'revision':8,'root_key':c.root.model_copy(update={'status':'retired'})})
        kwargs=dict(policy=policy,trusted_policy_checkpoint=policy_pin(policy))
    else:
        if kind in ('wrong_root','wrong_old_key','wrong_target','expired'):
            changes={'wrong_root':{'root_key_id':'f'*64},'wrong_old_key':{'from_signing_key_id':'f'*64},
                     'wrong_target':{'trust_store_digest':'f'*64},'expired':{'issued_at':c.t-10,'expires_at':c.t}}[kind]
            payload=t.payload.model_copy(update=changes)
            t=t.model_copy(update={'payload':payload,'signature_hex':c.root_private.sign(transition_preimage(payload)).hex()})
            p=p.model_copy(update={'transition_digest':record_digest(payload)})
        elif kind=='wrong_domain':t=t.model_copy(update={'signature_hex':c.root_private.sign(CHECKPOINT_DOMAIN+canonical_bytes(t.payload)).hex()})
        else:t=t.model_copy(update={'signature_hex':'0'*128})
        b=emit(c,p,b.trust_store,t,c.new_private)
    assert check(c,b,retained_head=head,**kwargs).status=='REJECTED'


def test_transition_manifest_cannot_be_stripped_or_reused_for_other_store(case):
    c=case;b,head=rotated(c)
    stripped=emit(c,b.payload.model_copy(update={'transition_digest':None}),b.trust_store,private=c.new_private)
    assert check(c,stripped,retained_head=head).reason_code=='TRANSITION_REQUIRED'
    store=b.trust_store.model_copy(update={'revision':5})
    changed=emit(c,b.payload.model_copy(update={'trust_store_revision':5,'trust_store_digest':record_digest(store)}),store,b.transition,c.new_private)
    assert check(c,changed,retained_head=head).reason_code=='TRANSITION_INVALID'


def test_policy_head_revision_and_digest_pins(case):
    c=case;head=check(c).proposed_head
    newer=c.policy.model_copy(update={'revision':8,'max_age_seconds':30});pin=policy_pin(newer)
    r=check(c,retained_head=head,policy=newer,trusted_policy_checkpoint=pin)
    assert r.status=='UNCHANGED' and r.proposed_head.policy_revision==8 and r.checked_checkpoint.expiry==c.t+30
    assert check(c,retained_head=r.proposed_head).reason_code=='POLICY_REGRESSION'
    fork=newer.model_copy(update={'max_age_seconds':20})
    assert check(c,retained_head=r.proposed_head,policy=fork,trusted_policy_checkpoint=policy_pin(fork)).reason_code=='POLICY_FORK'


def test_old_consistent_inputs_cannot_reveal_unseen_revocation(case):
    c=case;head=check(c).proposed_head
    revoked=c.policy.model_copy(update={'revision':8,'keys':tuple(sorted((c.key.model_copy(update={'status':'revoked'}),c.new_key),key=lambda k:k.key_id))})
    assert check(c,retained_head=head,policy=revoked,trusted_policy_checkpoint=policy_pin(revoked)).status=='REJECTED'
    assert check(c,retained_head=head).status=='UNCHANGED'  # Honest fixed-window limit, not latestness proof.
    assert check(c,retained_head=head,trusted_policy_checkpoint=policy_pin(revoked)).reason_code=='POLICY_MISMATCH'


def test_clock_regression_and_scope_before_proposal(case):
    c=case;head=check(c,now=c.t+10).proposed_head
    assert check(c,retained_head=head,now=c.t+9).reason_code=='CLOCK_REGRESSION'
    assert check(c,retained_head=head.model_copy(update={'store_instance_id':'other'}),now=c.t+10).reason_code=='SCOPE_MISMATCH'


@pytest.mark.parametrize('now',[True,1.0,-1,2**63,'1800000000'])
def test_strict_now(case,now):assert check(case,now=now).reason_code=='INVALID_RECORD'


@pytest.mark.parametrize('kind',['padding','duplicate','extra','bool','float','too_large'])
def test_strict_canonical_decode(case,kind):
    raw=canonical_bytes(case.p)
    if kind=='padding':raw+=b' '
    elif kind=='duplicate':raw=b'{"epoch":1,"epoch":1}'
    elif kind=='extra':raw=raw[:-1]+b',"extra":1}'
    elif kind=='bool':raw=raw.replace(b'"epoch":1',b'"epoch":true')
    elif kind=='float':raw=raw.replace(b'"epoch":1',b'"epoch":1.0')
    else:raw=b'x'*(RECORD_LIMIT+1)
    with pytest.raises(ValueError):decode_distribution(TrustDistributionPayload,raw)


def test_inventory_and_key_identity_bounds(case):
    c=case
    for changes in ({'keys':(c.key,c.key)}, {'root_key':c.key}, {'keys':(c.new_key,)*9}):
        with pytest.raises(ValueError):canonical_bytes(c.policy.model_copy(update=changes))
    with pytest.raises(ValueError):canonical_bytes(c.key.model_copy(update={'public_key_hex':'a'*64}))
    with pytest.raises(ValueError):canonical_bytes(c.p.model_copy(update={'max_age_seconds':3601}))


def test_fixed_canonical_preimage_vector():
    p=TrustDistributionPayload(deployment_id='d',store_instance_id='s',issuer_id='i',signing_key_id='a'*64,
        checkpoint_revision=1,previous_checkpoint_digest=ZERO,epoch=1,epoch_id='e',trust_store_revision=1,
        trust_store_digest='b'*64,issued_at=10,expires_at=20,max_age_seconds=5)
    expected=(b'{"checkpoint_revision":1,"deployment_id":"d","epoch":1,"epoch_id":"e","expires_at":20,'
        b'"issued_at":10,"issuer_id":"i","max_age_seconds":5,"previous_checkpoint_digest":"'+b'0'*64+
        b'","profile":"tnc-trust-distribution-v1","signing_key_id":"'+b'a'*64+b'","store_instance_id":"s",'
        b'"transition_digest":null,"trust_store_digest":"'+b'b'*64+b'","trust_store_revision":1}')
    assert canonical_bytes(p)==expected
    assert checkpoint_preimage(p)==b'TNC-TRUST-DISTRIBUTION-v1:'+expected


def test_no_io_wallclock_or_signing_during_verification(case,monkeypatch):
    c=case
    def forbidden(*a,**k):pytest.fail('Pure verification attempted side effect')
    for owner,name in ((builtins,'open'),(sqlite3,'connect'),(socket,'socket'),(time,'time'),
                       (time,'monotonic'),(Ed25519PrivateKey,'generate')):
        monkeypatch.setattr(owner,name,forbidden)
    assert check(c).status=='INITIAL'
