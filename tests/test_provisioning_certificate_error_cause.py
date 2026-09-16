import pytest

from tnc.provenance import provisioning_certificates as certificates
from tnc.provenance.windows_certificate_chain import CertificateVerificationError


def test_validate_nominated_certificate_preserves_cause(monkeypatch):
    cause = ValueError('inner certificate diagnostic')

    def fail(*args):
        raise cause

    monkeypatch.setattr(certificates, '_WindowsChainAPI', lambda: object())
    monkeypatch.setattr(certificates, '_verify', fail)

    with pytest.raises(CertificateVerificationError, match='Nominated certificate unavailable') as caught:
        certificates.validate_nominated_certificate(object(), now=object())

    assert caught.value.__cause__ is cause
