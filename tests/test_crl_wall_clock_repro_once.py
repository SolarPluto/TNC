"""Throwaway one-run reproduction for the Windows CRL +1s boundary."""
from datetime import timedelta
import sys
import time

import pytest

from test_mtls import pki
from test_provisioning_validation import case
from test_provisioning_certificates import crl, snapshot
from tnc.provenance.provisioning_certificates import validate_nominated_certificate


pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows certificate acceptance')


def test_crl_wall_clock_repro_offset_1(case, pki):
    supplied = crl(pki, end=pki.now + timedelta(seconds=1))
    with snapshot(case, pki, crls=(supplied,)) as value:
        time.sleep(3)
        result = validate_nominated_certificate(value, now=pki.now)
        assert result.valid_until == pki.now + timedelta(seconds=1)
