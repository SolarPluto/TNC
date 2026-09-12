"""Pure signed configuration, independent checkpoint and current-context tests."""
from datetime import datetime,timezone,timedelta
from hashlib import sha256
import builtins
import json
import socket
import sqlite3
import time
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from tnc.provenance.authenticated_caller_config import *
from tnc.provenance.authorization_models import canonical_bytes,record_digest
import tnc.provenance.authenticated_caller_config as module


@pytest.fixture
def case():
    t=1800000000
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    key=ConfigurationAuthorityKey(configuration_id='host-config',issuer_id='config-authority',
        key_id=sha256(public).hexdigest(),public_key_hex=public.hex(),status='active',
        permissions=('CALLER_CONFIG_SIGN',),effective_at=t-100,expires_at=t+100)
    enrollment=CallerEnrollmentRecord(certificate_sha256='e'*64,principal_id='alice',status='active',
        effective_at=t-10,expires_at=t+50)
    grant=CallerObservationGrant(grant_id='observe',principal_id='alice',deployment_id='deployment',
        store_instance_id='authority-store',observation_issuer_id='observer',observation_trust_digest='d'*64,
        effective_at=t-10,expires_at=t+50,max_requests=10,window_seconds=60)
    payload=CallerConfigPayload(configuration_id=key.configuration_id,issuer_id=key.issuer_id,
        signing_key_id=key.key_id,revision=7,registry_revision=3,effective_at=t-10,expires_at=t+60,
        enrollments=(enrollment,),grants=(grant,))
    cp=CallerConfigCheckpoint(configuration_id=key.configuration_id,issuer_id=key.issuer_id,
        signing_key_id=key.key_id,revision=payload.revision,configuration_digest=record_digest(payload),
        effective_at=t-10,expires_at=t+60)
    request=ObservationRequest(deployment_id=grant.deployment_id,store_instance_id=grant.store_instance_id,
        principal_id='alice',issuer_id='observer',challenge='c'*64,timestamp=t,expiry=t+60)
    oc=ObservationTrustCheckpoint(deployment_id=request.deployment_id,store_instance_id=request.store_instance_id,
        revision=11,trust_store_digest=grant.observation_trust_digest,timestamp=t-10,expiry=t+60)
    instant=datetime.fromtimestamp(t,timezone.utc)
    identity=VerifiedIdentity(principal_id='alice',credential_id=enrollment.certificate_sha256,
        connection_id='connection-1',audit_id='audit-1',verified_at=instant,
        valid_until=instant+timedelta(seconds=40),registry_revision=3)
    c=SimpleNamespace(t=t,private=private,key=key,payload=payload,cp=cp,request=request,oc=oc,identity=identity)
    c.doc=sign(c)
    return c


def sign(c,payload=None,domain=DOMAIN):
    p=payload or c.payload
    return CallerConfigDocument(payload=p,signature_hex=c.private.sign(domain+canonical_bytes(p)).hex())


def evaluate(c,**changes):
    args=dict(identity=c.identity,trusted_key=c.key,trusted_checkpoint=c.cp,observation_checkpoint=c.oc,
        retained_head=None,now=c.t)
    document=changes.pop('document',c.doc);raw=changes.pop('request_bytes',canonical_bytes(c.request))
    args.update(changes)
    return validate_caller_request(document,raw,**args)


def update(c,**changes):
    payload=c.payload.model_copy(update={'revision':c.payload.revision+1,**changes})
    return sign(c,payload),c.cp.model_copy(update={'revision':payload.revision,'configuration_digest':record_digest(payload)})


def test_valid_current_snapshot_and_exact_request(case):
    c=case;r=evaluate(c)
    assert r.status=='MATCHED' and r.binding.signature_verified and r.binding.audit_only
    assert r.binding.request_digest==sha256(canonical_bytes(c.request)).hexdigest()
    assert r.binding.configuration_revision==7 and r.binding.registry_revision==3
    assert r.binding.observation_trust_revision==11 and r.binding.configuration_key_id!=r.binding.certificate_sha256
    assert r.binding.expires_at==c.t+40
    assert r.binding.max_requests==10 and not r.binding.rate_limit_enforced


def test_fingerprint_string_or_dict_is_not_identity_evidence(case):
    assert evaluate(case,identity=case.identity.credential_id).reason_code=='IDENTITY_INVALID'
    assert evaluate(case,identity=case.identity.model_dump()).reason_code=='IDENTITY_INVALID'


@pytest.mark.parametrize('kind',['unknown','disabled','expired'])
def test_invalid_enrollment(case,kind):
    c=case;e=c.payload.enrollments[0]
    if kind=='unknown':return_value=evaluate(c,identity=c.identity.model_copy(update={'credential_id':'f'*64}))
    else:
        e=e.model_copy(update={'status':'disabled'} if kind=='disabled' else {'expires_at':c.t})
        doc,cp=update(c,enrollments=(e,))
        return_value=evaluate(c,document=doc,trusted_checkpoint=cp)
    assert return_value.reason_code=='CREDENTIAL_INVALID'


@pytest.mark.parametrize('field,value',[('principal_id','other'),('credential_id','f'*64),('registry_revision',4)])
def test_identity_binding(case,field,value):
    result=evaluate(case,identity=case.identity.model_copy(update={field:value}))
    assert result.status=='DENIED' and result.binding is None


@pytest.mark.parametrize('field,value',[('deployment_id','other'),('store_instance_id','other'),('issuer_id','other'),('principal_id','other')])
def test_request_scope(case,field,value):
    request=case.request.model_copy(update={field:value})
    assert evaluate(case,request_bytes=canonical_bytes(request)).status=='DENIED'


@pytest.mark.parametrize('field,value',[('store_instance_id','other'),('trust_store_digest','f'*64),('expiry',1800000000)])
def test_independent_observation_trust_scope(case,field,value):
    assert evaluate(case,observation_checkpoint=case.oc.model_copy(update={field:value})).status=='DENIED'


def test_duplicate_certificate_cannot_map_to_another_principal(case):
    p=case.payload;e=p.enrollments[0].model_copy(update={'principal_id':'other'})
    with pytest.raises(ValueError):CallerConfigPayload.model_validate({**p.model_dump(),'enrollments':(p.enrollments[0],e)})


def test_multiple_certificates_can_rotate_for_same_principal(case):
    c=case;e=c.payload.enrollments[0].model_copy(update={'certificate_sha256':'f'*64})
    doc,cp=update(c,enrollments=c.payload.enrollments+(e,))
    assert evaluate(c,document=doc,trusted_checkpoint=cp).status=='MATCHED'
    assert evaluate(c,document=doc,trusted_checkpoint=cp,identity=c.identity.model_copy(update={'credential_id':'f'*64})).status=='MATCHED'


def test_pinned_audit_does_not_override_new_revocation(case):
    c=case;original=evaluate(c).binding;raw=canonical_bytes(original)
    disabled=c.payload.enrollments[0].model_copy(update={'status':'disabled'})
    doc,cp=update(c,enrollments=(disabled,))
    assert evaluate(c,document=doc,trusted_checkpoint=cp).reason_code=='CREDENTIAL_INVALID'
    assert evaluate(c,trusted_checkpoint=cp).reason_code=='CONFIG_TRUST_MISMATCH'
    assert canonical_bytes(original)==raw
    # No old binding is accepted as identity or document authority.
    assert evaluate(c,identity=original).reason_code=='IDENTITY_INVALID'


@pytest.mark.parametrize('mode',['removed','revoked','expired','different-trust'])
def test_live_grant_change_does_not_mutate_old_audit(case,mode):
    c=case;old=evaluate(c).binding;before=canonical_bytes(old);g=c.payload.grants[0]
    if mode=='removed':grants=()
    else:
        changes={'revoked':{'status':'revoked'},'expired':{'expires_at':c.t},'different-trust':{'observation_trust_digest':'f'*64}}
        grants=(g.model_copy(update=changes[mode]),)
    doc,cp=update(c,grants=grants)
    denied=evaluate(c,document=doc,trusted_checkpoint=cp)
    assert denied.reason_code==('GRANT_REVOKED' if mode=='revoked' else 'GRANT_SCOPE_MISMATCH')
    assert denied.binding is None and canonical_bytes(old)==before


@pytest.mark.parametrize('kind',['signature','payload','v2-domain','wrong-key'])
def test_signature_and_domain_validation(case,kind):
    c=case;doc=c.doc;cp=c.cp
    if kind=='signature':doc=doc.model_copy(update={'signature_hex':'0'*128})
    if kind=='payload':
        p=c.payload.model_copy(update={'registry_revision':99})
        doc=doc.model_copy(update={'payload':p});cp=cp.model_copy(update={'configuration_digest':record_digest(p)})
    if kind=='v2-domain':doc=sign(c,domain=b'TNC-SIGNED-OBSERVATION-v2:')
    if kind=='wrong-key':doc=doc.model_copy(update={'signature_hex':Ed25519PrivateKey.generate().sign(caller_config_preimage(c.payload)).hex()})
    assert evaluate(c,document=doc,trusted_checkpoint=cp).reason_code=='CONFIG_SIGNATURE_INVALID'


@pytest.mark.parametrize('change',[{'status':'revoked'},{'status':'retired'},{'permissions':()},{'expires_at':1800000000}])
def test_configuration_key_current_authority(case,change):
    assert evaluate(case,trusted_key=case.key.model_copy(update=change)).reason_code=='CONFIG_KEY_DENIED'


@pytest.mark.parametrize('field,value',[('configuration_id','foreign'),('issuer_id','foreign'),('signing_key_id','f'*64),('revision',8),('configuration_digest','f'*64)])
def test_exogenous_checkpoint_pin(case,field,value):
    assert evaluate(case,trusted_checkpoint=case.cp.model_copy(update={field:value})).reason_code=='CONFIG_TRUST_MISMATCH'


def test_expired_configuration_and_checkpoint(case):
    c=case
    assert evaluate(c,now=c.payload.expires_at).reason_code=='CONFIG_EXPIRED'
    assert evaluate(c,trusted_checkpoint=c.cp.model_copy(update={'expires_at':c.t})).reason_code=='CONFIG_EXPIRED'
    assert evaluate(c,now=c.payload.effective_at-1).reason_code=='CONFIG_NOT_YET_VALID'


@pytest.mark.parametrize('offset',[-1,40,60])
def test_current_identity_and_request_time(case,offset):
    assert evaluate(case,now=case.t+offset).status=='DENIED'


def test_fractional_identity_upper_bound_never_widens(case):
    c=case;i=c.identity.model_copy(update={'valid_until':c.identity.verified_at+timedelta(seconds=1,microseconds=900000)})
    assert evaluate(c,identity=i).binding.expires_at==c.t+1
    i=i.model_copy(update={'valid_until':c.identity.verified_at+timedelta(microseconds=900000)})
    assert evaluate(c,identity=i).reason_code=='IDENTITY_INVALID'


def revision(c,head=None,**changes):
    args=dict(trusted_key=c.key,trusted_checkpoint=c.cp,retained_head=head,now=c.t)
    doc=changes.pop('document',c.doc);args.update(changes)
    return evaluate_config_revision(doc,**args)


def test_monotonic_revision_proposals_and_exact_retry(case):
    c=case;first=revision(c);assert first.status=='INITIAL'
    head=first.proposed_head;before=canonical_bytes(head)
    retry=revision(c,head,now=c.t+1)
    assert retry.status=='UNCHANGED' and retry.proposed_head is None and canonical_bytes(head)==before
    doc,cp=update(c,revision=9)
    advance=revision(c,head,document=doc,trusted_checkpoint=cp)
    assert advance.status=='ADVANCE' and advance.proposed_head.revision==9
    assert revision(c,advance.proposed_head).reason_code=='CONFIG_ROLLBACK'


def test_equal_revision_fork_and_clock_regression(case):
    c=case;head=revision(c).proposed_head
    p=c.payload.model_copy(update={'grants':()});doc=sign(c,p)
    cp=c.cp.model_copy(update={'configuration_digest':record_digest(p)})
    assert revision(c,head,document=doc,trusted_checkpoint=cp).reason_code=='CONFIG_FORK'
    assert revision(c,head.model_copy(update={'accepted_at':c.t+1})).reason_code=='CLOCK_REGRESSION'
    assert evaluate(c,retained_head=head.model_copy(update={'revision':8})).reason_code=='CONFIG_ROLLBACK'


@pytest.mark.parametrize('kind',['extra','duplicate','padding','bool','float','oversize'])
def test_noncanonical_configuration_rejected(case,kind):
    raw=canonical_bytes(case.doc)
    if kind=='extra':raw=raw[:-1]+b',"unknown":0}'
    if kind=='duplicate':raw=raw[:-1]+b',"signature_hex":"'+b'0'*128+b'"}'
    if kind=='padding':raw=b' '+raw
    if kind in ('bool','float'):
        obj=json.loads(raw);obj['payload']['revision']=True if kind=='bool' else 7.0
        raw=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
    if kind=='oversize':raw=b' '*(CONFIG_LIMIT+1)
    with pytest.raises(ValueError):decode_caller_config(CallerConfigDocument,raw)


@pytest.mark.parametrize('value',[True,-1,'1800000000',1800000000.0,2**63])
def test_strict_supplied_time(case,value):
    assert evaluate(case,now=value).reason_code=='INVALID_INPUT'


def test_rate_declarations_are_bounded_but_not_enforced(case):
    c=case;first=evaluate(c)
    assert all(evaluate(c)==first for _ in range(12))
    assert first.binding.max_requests==10 and not first.binding.rate_limit_enforced
    for change in ({'max_requests':0},{'max_requests':True},{'window_seconds':None},{'window_seconds':86401}):
        with pytest.raises(ValueError):CallerObservationGrant.model_validate({**c.payload.grants[0].model_dump(),**change})


def test_frozen_models_and_complete_inventory_checks(case):
    c=case
    with pytest.raises(ValueError):c.payload.revision=8
    with pytest.raises(ValueError):CallerConfigPayload.model_validate({**c.payload.model_dump(),'grants':c.payload.grants*2})
    with pytest.raises(ValueError):CallerConfigPayload.model_validate({**c.payload.model_dump(),'enrollments':c.payload.enrollments*65})
    with pytest.raises(ValueError):CallerConfigPayload.model_validate({**c.payload.model_dump(),'grants':(c.payload.grants[0].model_copy(update={'principal_id':'other'}),)})
    with pytest.raises(ValueError):ConfigurationAuthorityKey.model_validate({**c.key.model_dump(),'key_id':'f'*64})


def test_input_caps_and_host_only_diagnostics(case,monkeypatch):
    c=case;raw=canonical_bytes(c.doc)
    monkeypatch.setattr(module,'CONFIG_LIMIT',len(raw))
    assert decode_caller_config(CallerConfigDocument,raw)==c.doc
    monkeypatch.setattr(module,'CONFIG_LIMIT',len(raw)-1)
    assert evaluate(c).reason_code=='INVALID_INPUT'
    assert evaluate(c).binding is None


def test_no_io_clock_or_signing(case,monkeypatch):
    c=case
    def fail(*a,**kw):pytest.fail('Side effect forbidden')
    for obj,name in ((builtins,'open'),(socket,'socket'),(sqlite3,'connect'),(time,'time'),(time,'monotonic'),(Ed25519PrivateKey,'generate')):
        monkeypatch.setattr(obj,name,fail)
    assert evaluate(c).status=='MATCHED' and revision(c).status=='INITIAL'


def test_old_consistent_inputs_cannot_prove_latestness(case):
    c=case;old=evaluate(c).binding
    doc,cp=update(c,grants=())
    assert evaluate(c,document=doc,trusted_checkpoint=cp).status=='DENIED'
    assert evaluate(c,trusted_checkpoint=cp).reason_code=='CONFIG_TRUST_MISMATCH'
    # Pure code has no discovery channel: only the host can supply a fresh pin.
    assert evaluate(c).binding==old and old.audit_only


@pytest.mark.parametrize('raw',[b'',b'{}',b' '+b'{}',b' '*16385],ids=['empty','shape','padding','oversize'])
def test_request_canonical_shape_and_bounds(case,raw):
    assert evaluate(case,request_bytes=raw).reason_code=='INVALID_INPUT'


def test_fixed_signing_preimage_vector():
    payload=CallerConfigPayload(configuration_id='host',issuer_id='issuer',signing_key_id='a'*64,
        revision=1,registry_revision=2,effective_at=100,expires_at=200,enrollments=(),grants=())
    assert caller_config_preimage(payload)==(
        b'TNC-CALLER-CONFIG-v1:{"configuration_id":"host","effective_at":100,"enrollments":[],"expires_at":200,'
        b'"grants":[],"issuer_id":"issuer","profile":"tnc-caller-config-v1","registry_revision":2,"revision":1,'
        b'"signing_key_id":"'+b'a'*64+b'"}')


def test_outcome_cannot_claim_rate_enforcement(case):
    binding=evaluate(case).binding
    with pytest.raises(ValueError):CallerConfigAuditBinding.model_validate({**binding.model_dump(),'rate_limit_enforced':True})
    with pytest.raises(ValueError):CallerConfigAuditBinding.model_validate({**binding.model_dump(),'audit_only':False})
