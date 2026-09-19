"""Native smoke for process-token AppContainer queries under lease rights."""
import ctypes as c
import os
import sys

import pytest

from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_process_native import (
    HANDLE,
    NativeProcessAPI,
    PROCESS_LEASE_RIGHTS,
)
from tnc.provenance.windows_pipe_token import TOKEN_QUERY


@pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows process-token rights smoke')
def test_process_lease_rights_allow_primary_appcontainer_probe(capsys):
    """Lease rights must permit TOKEN_QUERY plus classes 29/30/31 on PRIMARY."""
    process_api = NativeProcessAPI()
    process = process_api.open_process(os.getpid(), PROCESS_LEASE_RIGHTS, False)

    advapi = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
    kernel = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    advapi.OpenProcessToken.argtypes = [HANDLE, c.c_uint32, c.POINTER(HANDLE)]
    advapi.OpenProcessToken.restype = c.c_int32
    kernel.CloseHandle.argtypes = [HANDLE]
    kernel.CloseHandle.restype = c.c_int32

    token = HANDLE()
    try:
        assert advapi.OpenProcessToken(
            HANDLE(process), TOKEN_QUERY, c.byref(token)
        ), c.get_last_error()
        assert token.value

        evidence = NativeAppContainerProbe().probe(
            int(token.value), token_type='PRIMARY', level=None
        )
        result = evaluate_appcontainer_exclusion(evidence)

        # The hosted test runner is an ordinary non-AppContainer process. More
        # importantly, reaching this point proves TOKEN_QUERY supports all three
        # AppContainer information classes used by NativeAppContainerProbe.
        assert evidence.source == 'NATIVE_TOKEN_API'
        assert evidence.token_is_app_container is False
        assert evidence.app_container_sid is None
        assert isinstance(evidence.capability_sids, tuple)
        assert result.status == 'PROVEN_NON_APPCONTAINER'
        print(
            'TNC process-token limited-rights smoke: '
            f'is_appcontainer={evidence.token_is_app_container!r} '
            f'appcontainer_sid={evidence.app_container_sid!r} '
            f'capability_count={len(evidence.capability_sids)} '
            f'status={result.status} reason={result.reason}',
            flush=True,
        )
    finally:
        if token.value:
            assert kernel.CloseHandle(token), c.get_last_error()
        assert process_api.close(process)
