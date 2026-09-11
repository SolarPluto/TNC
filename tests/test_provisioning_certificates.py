"""Temporary PKI acceptance tests; never install certificates in Windows stores."""
from datetime import timedelta
from hashlib import sha256
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

from test_mtls import pki
from test_provisioning_validation import case
from test_protected_provisioning import FakeAPI
from tnc.provenance.authorization_models import record_digest
from tnc.provenance.provisioning_models import ArtifactBinding, CertificateProfile
from tnc.provenance.protected_provisioning import _load
from tnc.provenance.provisioning_certificates import _verify, _parse, _supplied_crls, validate_nominated_certificate
from tnc.provenance.windows_certificate_chain import _WindowsChainAPI, CertificateVerificationError

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows certificate acceptance')


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def crl(pki, *, issuer=None, key=None, revoked=(), start=None, end=None, extension=None):
    issuer = issuer or pki.ca
    builder = x509.CertificateRevocationListBuilder().issuer_name(issuer[0].subject).last_update(
        start or pki.now-timedelta(hours=1)).next_update(end or pki.now+timedelta(hours=2))
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer[1].public_key()), False)
    if extension:
        builder = builder.add_extension(extension, True)
    for cert in revoked:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
            cert.serial_number).revocation_date(pki.now-timedelta(minutes=1)).build())
    return builder.sign(key or issuer[1], hashes.SHA256())


def snapshot(case, pki, *, leaf=None, roots=None, crls=None, intermediates=(), fingerprint=None):
    leaf = leaf or pki.client[0]
    roots = (pki.ca[0],) if roots is None else roots
    crls = (crl(pki),) if crls is None else crls
    data = {'leaf.der': der(leaf), 'roots.pem': b''.join(c.public_bytes(serialization.Encoding.PEM) for c in roots),
            'revocations.crl': b''.join(c.public_bytes(serialization.Encoding.PEM) for c in crls)}
    kinds = {'leaf.der':'leaf', 'roots.pem':'roots', 'revocations.crl':'crls'}
    if intermediates:
        data['intermediates.pem'] = b''.join(c.public_bytes(serialization.Encoding.PEM) for c in intermediates)
        kinds['intermediates.pem'] = 'intermediates'
    policy = case['policy'].model_copy(update={'artifacts': tuple(ArtifactBinding(name=n,kind=kinds[n],
        sha256=sha256(b).hexdigest(),length=len(b)) for n,b in sorted(data.items())),
        'certificate_profile': CertificateProfile(max_crl_age_seconds=86400)})
    enrollment = case['manifest'].initial_enrollment
    enrollment = enrollment.model_copy(update={'credential': enrollment.credential.model_copy(update={
        'credential_id': fingerprint or sha256(der(leaf)).hexdigest()})})
    manifest = case['manifest'].model_copy(update={'admin_policy_hash':record_digest(policy), 'initial_enrollment':enrollment})
    anchor = case['descriptor'].bootstrap_anchor.model_copy(update={'manifest_hash':record_digest(manifest)})
    descriptor = case['descriptor'].model_copy(update={'policy_hash':record_digest(policy), 'bootstrap_anchor':anchor})
    return _load(descriptor, FakeAPI(case | {'artifacts': data, 'policy': policy, 'manifest':manifest}))


def test_real_native_valid_chain(case, pki):
    with snapshot(case,pki) as value:
        result = _verify(value,pki.now,_WindowsChainAPI())
        assert result.chain_fingerprints == tuple(sha256(der(c)).hexdigest() for c in (pki.client[0],pki.ca[0]))
        assert result.valid_until == pki.now+timedelta(hours=2)
        assert len(result.crl_digests) == 1


@pytest.mark.parametrize('kind', ['wrong_root','wrong_fingerprint','expired','future','server_eku','revoked',
    'stale_crl','future_crl','wrong_crl_signature','delta_crl','unknown_crl_extension'])
def test_native_rejections(case,pki,kind):
    options = {}
    if kind == 'wrong_root': options['roots'] = (pki.issue('foreign',ca=True)[0],)
    if kind == 'wrong_fingerprint': options['fingerprint'] = 'f'*64
    if kind == 'expired': options['leaf'] = pki.issue('expired',end=pki.now-timedelta(seconds=1))[0]
    if kind == 'future': options['leaf'] = pki.issue('future',start=pki.now+timedelta(seconds=1))[0]
    if kind == 'server_eku': options['leaf'] = pki.server[0]
    if kind == 'revoked': options['crls'] = (crl(pki,revoked=(pki.client[0],)),)
    if kind == 'stale_crl': options['crls'] = (crl(pki,end=pki.now-timedelta(seconds=1)),)
    if kind == 'future_crl': options['crls'] = (crl(pki,start=pki.now+timedelta(seconds=1)),)
    if kind == 'wrong_crl_signature': options['crls'] = (crl(pki,key=ec.generate_private_key(ec.SECP256R1())),)
    if kind == 'delta_crl': options['crls'] = (crl(pki,extension=x509.DeltaCRLIndicator(1)),)
    if kind == 'unknown_crl_extension': options['crls'] = (crl(pki,extension=x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\x00')),)
    with snapshot(case,pki,**options) as value, pytest.raises(CertificateVerificationError):
        validate_nominated_certificate(value,now=pki.now)


@pytest.mark.parametrize('data', [b'', b'junk', b'\xff', b' '*(4*1024*1024+1)], ids=['empty','junk','invalid-utf8','oversize'])
def test_invalid_bundles(data):
    with pytest.raises(ValueError): _parse(data)


def test_der_trailing_bytes_and_duplicate_pem(pki):
    for data in (der(pki.client[0])+b'junk', pki.client[0].public_bytes(serialization.Encoding.PEM)*2):
        with pytest.raises(ValueError): _parse(data)


def test_closed_snapshot_denied(case,pki):
    value = snapshot(case,pki)
    value.close()
    with pytest.raises(CertificateVerificationError): validate_nominated_certificate(value,now=pki.now)


def test_supplied_revocation_not_rescued_by_successful_backend(case,pki):
    class WarmBackend:
        def verify(self,*args): return (der(pki.client[0]),der(pki.ca[0]))
    with snapshot(case,pki,crls=(crl(pki,revoked=(pki.client[0],)),)) as value:
        with pytest.raises(ValueError,match='revoked'): _verify(value,pki.now,WarmBackend())


def test_missing_crl_not_rescued_by_success():
    # Required independently of native backend success or any cached CRL.
    class Cert:
        issuer = 'issuer'
        subject = 'issuer'
    with pytest.raises(ValueError,match='supplied full CRL'):
        _supplied_crls((Cert(),Cert()),(),None,None)


def issue(pki, name, *, issuer=None, ca=False, key=None, path_length=2, unknown=False, eku=True):
    from cryptography.x509.oid import NameOID
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    signing_key = issuer[1] if issuer else key
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer[0].subject if issuer else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(pki.now-timedelta(hours=1)).not_valid_after(pki.now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca,path_length=path_length if ca else None),True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,
            data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=False,decipher_only=False),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),False))
    if not ca and eku: builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False)
    if unknown: builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\x00'),True)
    return builder.sign(signing_key,hashes.SHA256()), key


def test_native_intermediate_and_missing_evidence(case,pki):
    root = issue(pki,'root2',ca=True)
    intermediate = issue(pki,'intermediate',issuer=root,ca=True,path_length=0)
    leaf = issue(pki,'leaf2',issuer=intermediate)
    root_crl, leaf_crl = crl(pki,issuer=root), crl(pki,issuer=intermediate)
    options = dict(leaf=leaf[0],roots=(root[0],),intermediates=(intermediate[0],),crls=(root_crl,leaf_crl))
    with snapshot(case,pki,**options) as value:
        assert len(validate_nominated_certificate(value,now=pki.now).chain_fingerprints) == 3
    # A preceding valid call may have warmed native caches; supplied evidence is still mandatory.
    for changed in ({'intermediates':()}, {'crls':(leaf_crl,)},
                    {'crls':(crl(pki,issuer=root,revoked=(intermediate[0],)),leaf_crl)}):
        with snapshot(case,pki,**(options|changed)) as value, pytest.raises(CertificateVerificationError):
            validate_nominated_certificate(value,now=pki.now)


@pytest.mark.parametrize('kind', ['rsa1024','p521','unknown_critical','missing_eku','bad_path_length'])
def test_algorithm_and_extension_constraints(case,pki,kind):
    root = issue(pki,'strict-root',ca=True,path_length=0 if kind=='bad_path_length' else 2)
    options = {}
    if kind == 'rsa1024': options['key'] = rsa.generate_private_key(public_exponent=65537,key_size=1024)
    if kind == 'p521': options['key'] = ec.generate_private_key(ec.SECP521R1())
    if kind == 'unknown_critical': options['unknown'] = True
    if kind == 'missing_eku': options['eku'] = False
    issuer, middle, crls = root, (), (crl(pki,issuer=root),)
    if kind == 'bad_path_length':
        issuer = issue(pki,'middle',issuer=root,ca=True,path_length=0)
        middle, crls = (issuer[0],), (*crls,crl(pki,issuer=issuer))
    leaf = issue(pki,'strict-leaf',issuer=issuer,**options)
    with snapshot(case,pki,leaf=leaf[0],roots=(root[0],),intermediates=middle,crls=crls) as value:
        with pytest.raises(CertificateVerificationError): validate_nominated_certificate(value,now=pki.now)


@pytest.mark.parametrize('key', ['rsa2048','p384'])
def test_supported_keys(case,pki,key):
    private = rsa.generate_private_key(public_exponent=65537,key_size=2048) if key=='rsa2048' else ec.generate_private_key(ec.SECP384R1())
    root = issue(pki,'supported-root',ca=True,key=private)
    leaf_key = rsa.generate_private_key(public_exponent=65537,key_size=2048) if key=='rsa2048' else ec.generate_private_key(ec.SECP384R1())
    leaf = issue(pki,'supported-leaf',issuer=root,key=leaf_key)
    with snapshot(case,pki,leaf=leaf[0],roots=(root[0],),crls=(crl(pki,issuer=root),)) as value:
        assert validate_nominated_certificate(value,now=pki.now).leaf_fingerprint == sha256(der(leaf[0])).hexdigest()


@pytest.mark.parametrize('oid', ['1.2.840.113549.1.1.5','1.2.840.113549.1.1.4','1.2.840.10045.4.1'])
def test_sha1_md5_signature_policy(oid):
    from types import SimpleNamespace
    from tnc.provenance.provisioning_certificates import _algorithm
    with pytest.raises(ValueError): _algorithm(SimpleNamespace(signature_algorithm_oid=ObjectIdentifier(oid)))


@pytest.mark.parametrize('kind', ['missing','wrong_signature','stale','authority','scope','revoked_reason'])
def test_independent_crl_checks_after_backend_success(case,pki,kind):
    class Success:
        def verify(self,*args): return der(pki.client[0]),der(pki.ca[0])
    value = crl(pki)
    if kind=='wrong_signature': value=crl(pki,key=ec.generate_private_key(ec.SECP256R1()))
    if kind=='stale': value=crl(pki,start=pki.now-timedelta(days=2))
    if kind=='authority':
        # Valid signature, wrong AKI: independently rejected even with backend success.
        value=(x509.CertificateRevocationListBuilder().issuer_name(pki.ca[0].subject)
            .last_update(pki.now-timedelta(hours=1)).next_update(pki.now+timedelta(hours=1))
            .add_extension(x509.AuthorityKeyIdentifier(b'x'*20,None,None),False).sign(pki.ca[1],hashes.SHA256()))
    if kind=='scope': value=crl(pki,extension=x509.DeltaCRLIndicator(1))
    if kind=='revoked_reason':
        entry=(x509.RevokedCertificateBuilder().serial_number(pki.client[0].serial_number)
            .revocation_date(pki.now-timedelta(minutes=1)).add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise),False).build())
        value=(x509.CertificateRevocationListBuilder().issuer_name(pki.ca[0].subject)
            .last_update(pki.now-timedelta(hours=1)).next_update(pki.now+timedelta(hours=1))
            .add_revoked_certificate(entry).sign(pki.ca[1],hashes.SHA256()))
    if kind=='missing':
        value=crl(pki,issuer=issue(pki,'unrelated',ca=True))
    with snapshot(case,pki,crls=(value,)) as snap, pytest.raises(ValueError):
        _verify(snap,pki.now,Success())


def test_chain_cannot_use_unsupplied_root(case,pki):
    foreign = issue(pki,'cached-root',ca=True)[0]
    class Success:
        def verify(self,*args): return der(pki.client[0]),der(foreign)
    with snapshot(case,pki) as value, pytest.raises(ValueError,match='unsupplied'):
        _verify(value,pki.now,Success())


@pytest.mark.parametrize('failure', ['CertOpenStore','CertAddEncodedCertificateToStore','CertAddEncodedCRLToStore',
    'CertCreateCertificateChainEngine','CertCreateCertificateContext','CertGetCertificateChain',
    'CertVerifyCertificateChainPolicy'])
def test_native_failure_cleanup(case,pki,failure):
    api = _WindowsChainAPI()
    real = api.lib
    opened, closed, engines, freed_engines, certs, freed_certs, chains, freed_chains = [], [], [], [], [], [], [], []
    class Proxy:
        def __getattr__(self,name):
            def call(*args):
                if name == failure: return 0
                result = getattr(real,name)(*args)
                if name=='CertOpenStore' and result: opened.append(result)
                if name=='CertCloseStore': closed.append(args[0])
                if name=='CertCreateCertificateChainEngine' and result: engines.append(1)
                if name=='CertFreeCertificateChainEngine': freed_engines.append(1)
                if name=='CertCreateCertificateContext' and result: certs.append(1)
                if name=='CertFreeCertificateContext': freed_certs.append(1)
                if name=='CertGetCertificateChain' and result: chains.append(1)
                if name=='CertFreeCertificateChain': freed_chains.append(1)
                return result
            return call
    api.lib = Proxy()
    with snapshot(case,pki) as value, pytest.raises(CertificateVerificationError): _verify(value,pki.now,api)
    assert sorted(opened)==sorted(closed)
    assert engines==freed_engines and certs==freed_certs and chains==freed_chains


def test_native_offline_and_client_policy_flags(case,pki):
    import ctypes as c
    from tnc.provenance.windows_certificate_chain import _Engine,_Policy,_SSL
    api = _WindowsChainAPI()
    real, checked = api.lib, set()
    class Proxy:
        def __getattr__(self,name):
            def call(*args):
                if name=='CertCreateCertificateChainEngine':
                    config=c.cast(args[0],c.POINTER(_Engine)).contents
                    assert config.exclusive_root and not config.exclusive_people and not config.exclusive_flags
                    assert config.flags == 0x2004
                    checked.add('engine')
                if name=='CertGetCertificateChain':
                    assert args[5]==0xc0002004
                    checked.add('offline')
                if name=='CertVerifyCertificateChainPolicy':
                    policy=c.cast(args[2],c.POINTER(_Policy)).contents
                    ssl=c.cast(policy.extra,c.POINTER(_SSL)).contents
                    assert args[0]==4 and not policy.flags and ssl.auth_type==1 and not ssl.checks
                    checked.add('client')
                return getattr(real,name)(*args)
            return call
    api.lib=Proxy()
    with snapshot(case,pki) as value: _verify(value,pki.now,api)
    assert checked=={'engine','offline','client'}


@pytest.mark.parametrize('offset', [-1,0,1])
def test_crl_expiry_boundary(case,pki,offset):
    supplied=crl(pki,end=pki.now+timedelta(seconds=offset))
    with snapshot(case,pki,crls=(supplied,)) as value:
        if offset<=0:
            with pytest.raises(CertificateVerificationError): validate_nominated_certificate(value,now=pki.now)
        else:
            assert validate_nominated_certificate(value,now=pki.now).valid_until==pki.now+timedelta(seconds=1)


def test_tls_and_provisioning_agree_on_valid_and_revoked(case,pki):
    from test_mtls import Reader,server,client,exchange
    for revoked in (False,True):
        supplied=crl(pki,revoked=(pki.client[0],) if revoked else ())
        path=pki.path/'parity-crl.pem'
        path.write_bytes(supplied.public_bytes(serialization.Encoding.PEM))
        accepted, response, error, _=exchange(server(pki,Reader(pki),crl_file=path),client(pki))
        with snapshot(case,pki,crls=(supplied,)) as value:
            if revoked:
                assert not accepted and error is not None
                with pytest.raises(CertificateVerificationError): validate_nominated_certificate(value,now=pki.now)
            else:
                assert accepted and response==b'ok'
                validate_nominated_certificate(value,now=pki.now)
