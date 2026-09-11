"""Explicit-bundle Windows chain verification plus attributable supplied CRLs."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, CRLEntryExtensionOID

from tnc.provenance.authorization_models import record_digest
from tnc.provenance.provisioning_models import CertificateValidationEvidence, BUNDLE_LIMIT
from tnc.provenance.provisioning_validation import validate_provisioning_snapshot
from tnc.provenance.protected_provisioning import ProtectedProvisioningSnapshot
from tnc.provenance.windows_certificate_chain import _WindowsChainAPI, CertificateVerificationError


def _der(value):
    return value.public_bytes(serialization.Encoding.DER)


def _fingerprint(value):
    return sha256(_der(value)).hexdigest()


def _parse(data, crl=False):
    if type(data) is not bytes or not 0 < len(data) <= BUNDLE_LIMIT:
        raise ValueError('Invalid bundle size')
    label = b'X509 CRL' if crl else b'CERTIFICATE'
    if data.lstrip().startswith(b'-----BEGIN'):
        pattern = rb'-----BEGIN '+label+rb'-----\s+[A-Za-z0-9+/=\s]+?-----END '+label+rb'-----'
        matches = list(re.finditer(pattern, data))
        if not 1 <= len(matches) <= 32 or re.sub(pattern, b'', data).strip():
            raise ValueError('Invalid PEM bundle')
        loader = x509.load_pem_x509_crl if crl else x509.load_pem_x509_certificate
        values = tuple(loader(m.group()) for m in matches)
    else:
        loader = x509.load_der_x509_crl if crl else x509.load_der_x509_certificate
        value = loader(data)
        if _der(value) != data:
            raise ValueError('Noncanonical DER')
        values = (value,)
    if len({_fingerprint(v) for v in values}) != len(values):
        raise ValueError('Duplicate bundle entry')
    return values


def _algorithm(value):
    # Deliberately bounded first profile: RSA PKCS#1 v1.5 or ECDSA, SHA-256/384/512.
    if value.signature_algorithm_oid.dotted_string not in {
        '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13',
        '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4'}:
        raise ValueError('Unsupported signature algorithm')
    if value.signature_hash_algorithm.name not in ('sha256', 'sha384', 'sha512'):
        raise ValueError('Weak signature digest')


def _extension(value, kind):
    return value.extensions.get_extension_for_class(kind).value


def _certificate(cert, now, ca):
    _algorithm(cert)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048 or key.key_size > 8192:
            raise ValueError('Unsupported RSA key size')
    elif not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name not in ('secp256r1', 'secp384r1'):
        raise ValueError('Unsupported public key')
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError('Certificate outside validity')
    constraints, usage = _extension(cert, x509.BasicConstraints), _extension(cert, x509.KeyUsage)
    if constraints.ca != ca or (ca and not (usage.key_cert_sign and usage.crl_sign)):
        raise ValueError('Invalid CA usage')
    if not ca and (not usage.digital_signature or usage.key_cert_sign or usage.crl_sign
                   or ExtendedKeyUsageOID.CLIENT_AUTH not in _extension(cert, x509.ExtendedKeyUsage)):
        raise ValueError('Invalid client usage')
    understood = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
        ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    for ext in cert.extensions:
        if ext.critical and ext.oid not in understood:
            raise ValueError('Unsupported critical certificate extension')
        if isinstance(ext.value, x509.CRLDistributionPoints):
            for point in ext.value:
                if point.relative_name or point.reasons or point.crl_issuer:
                    raise ValueError('Unsupported CRL distribution scope')


def _supplied_crls(chain, crls, now, profile):
    used, starts, ends = set(), [], []
    for cert, issuer in zip(chain, chain[1:]):
        candidates = [crl for crl in crls if crl.issuer == issuer.subject]
        if len(candidates) != 1:
            raise ValueError('One supplied full CRL per issuer required')
        crl = candidates[0]
        _algorithm(crl)
        if (crl.next_update_utc is None or not crl.last_update_utc <= now < crl.next_update_utc
                or not now < crl.last_update_utc + timedelta(seconds=profile.max_crl_age_seconds)):
            raise ValueError('Stale or unavailable CRL')
        if not crl.is_signature_valid(issuer.public_key()):
            raise ValueError('CRL signature mismatch')
        for ext in crl.extensions:
            if ext.oid not in (ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.CRL_NUMBER):
                raise ValueError('Unsupported full CRL extension')
            if isinstance(ext.value, x509.AuthorityKeyIdentifier):
                if (ext.value.key_identifier != _extension(issuer, x509.SubjectKeyIdentifier).digest
                        or ext.value.authority_cert_issuer is not None
                        or ext.value.authority_cert_serial_number is not None):
                    raise ValueError('CRL authority mismatch')
        serials = set()
        for entry in crl:
            if entry.serial_number in serials:
                raise ValueError('Duplicate CRL serial')
            serials.add(entry.serial_number)
            for ext in entry.extensions:
                if ext.oid not in (CRLEntryExtensionOID.CRL_REASON, CRLEntryExtensionOID.INVALIDITY_DATE) or ext.critical:
                    raise ValueError('Unsupported CRL entry extension')
                if isinstance(ext.value, x509.CRLReason) and ext.value.reason == x509.ReasonFlags.remove_from_crl:
                    raise ValueError('Delta-only CRL entry')
        if cert.serial_number in serials:
            raise ValueError('Certificate revoked')
        used.add(_fingerprint(crl))
        starts.append(crl.last_update_utc)
        ends.append(min(crl.next_update_utc, crl.last_update_utc+timedelta(seconds=profile.max_crl_age_seconds)))
    if used != {_fingerprint(crl) for crl in crls}:
        raise ValueError('Extraneous CRL evidence')
    return tuple(sorted(used)), starts, ends


def _verify(snapshot, now, backend):
    if type(snapshot) is not ProtectedProvisioningSnapshot:
        raise ValueError('Open host snapshot required')
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError('Aware current host time required')
    now = now.astimezone(timezone.utc)
    artifacts = dict(snapshot.artifacts)  # Access fails after close.
    record = validate_provisioning_snapshot(descriptor=snapshot.descriptor, policy=snapshot.policy,
        manifest=snapshot.manifest, artifacts=artifacts, observations=snapshot.record.artifacts)
    if record != snapshot.record:
        raise ValueError('Snapshot mismatch')
    groups = {a.kind: _parse(artifacts[a.name], a.kind == 'crls') for a in snapshot.policy.artifacts}
    if len(groups['leaf']) != 1 or sum(len(v) for k,v in groups.items() if k != 'crls') > 32:
        raise ValueError('Certificate count exceeded')
    leaf, roots, intermediates, crls = groups['leaf'][0], groups['roots'], groups.get('intermediates', ()), groups['crls']
    certificates = (leaf, *roots, *intermediates)
    if len({_fingerprint(v) for v in certificates}) != len(certificates):
        raise ValueError('Duplicate certificate roles')
    if _fingerprint(leaf) != snapshot.manifest.initial_enrollment.credential.credential_id:
        raise ValueError('Nominated fingerprint mismatch')
    for cert in certificates:
        _certificate(cert, now, cert is not leaf)
    for root in roots:
        if root.subject != root.issuer:
            raise ValueError('Self-signed root required')
        root.verify_directly_issued_by(root)
    encoded = backend.verify(_der(leaf), tuple(map(_der, roots)), tuple(map(_der, intermediates)),
        tuple(map(_der, crls)), now)
    supplied = {_der(cert): cert for cert in certificates}
    if (not 2 <= len(encoded) <= 32 or encoded[0] != _der(leaf)
            or encoded[-1] not in {_der(root) for root in roots}
            or len(set(encoded)) != len(encoded) or any(data not in supplied for data in encoded)):
        raise ValueError('Native chain used unsupplied evidence')
    if any(data not in {_der(cert) for cert in intermediates} for data in encoded[1:-1]):
        raise ValueError('Invalid intermediate role')
    chain = tuple(supplied[data] for data in encoded)
    used, starts, ends = _supplied_crls(chain, crls, now, snapshot.policy.certificate_profile)
    return CertificateValidationEvidence(leaf_fingerprint=_fingerprint(leaf),
        chain_fingerprints=tuple(map(_fingerprint, chain)), root_fingerprint=_fingerprint(chain[-1]),
        crl_digests=used, profile_hash=record_digest(snapshot.policy.certificate_profile),
        snapshot_hash=record_digest(record), validated_at=now,
        valid_from=max(*(cert.not_valid_before_utc for cert in chain), *starts),
        valid_until=min(*(cert.not_valid_after_utc for cert in chain), *ends))


def validate_nominated_certificate(snapshot, *, now):
    """Host-only current-time check; no provisioning proof or private-key possession."""
    try:
        return _verify(snapshot, now, _WindowsChainAPI())
    except Exception:
        raise CertificateVerificationError('Nominated certificate unavailable') from None
