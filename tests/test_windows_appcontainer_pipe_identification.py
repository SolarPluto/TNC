"""Windows-only diagnostic for AppContainer queries on a named-pipe identification token.

This test grants no admission or authorization. It creates a local disposable named
pipe, connects a client with SECURITY_IDENTIFICATION SQOS, verifies the resulting
server thread token is identification-level, runs the audit-only AppContainer probe,
and then closes/reverts deterministically.
"""
import ctypes as c
import os
import threading
import uuid

import pytest

from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows named-pipe token diagnostic only')

HANDLE = c.c_void_p
DWORD = c.c_uint32
BOOL = c.c_int32
INVALID_HANDLE_VALUE = c.c_void_p(-1).value
ERROR_PIPE_CONNECTED = 535

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
SECURITY_IDENTIFICATION = 0x00010000
SECURITY_SQOS_PRESENT = 0x00100000


def _kernel32():
    k = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    k.CreateNamedPipeW.argtypes = [c.c_wchar_p, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, c.c_void_p]
    k.CreateNamedPipeW.restype = HANDLE
    k.ConnectNamedPipe.argtypes = [HANDLE, c.c_void_p]
    k.ConnectNamedPipe.restype = BOOL
    k.DisconnectNamedPipe.argtypes = [HANDLE]
    k.DisconnectNamedPipe.restype = BOOL
    k.WaitNamedPipeW.argtypes = [c.c_wchar_p, DWORD]
    k.WaitNamedPipeW.restype = BOOL
    k.CreateFileW.argtypes = [c.c_wchar_p, DWORD, DWORD, c.c_void_p, DWORD, DWORD, HANDLE]
    k.CreateFileW.restype = HANDLE
    k.WriteFile.argtypes = [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p]
    k.WriteFile.restype = BOOL
    k.ReadFile.argtypes = [HANDLE, c.c_void_p, DWORD, c.POINTER(DWORD), c.c_void_p]
    k.ReadFile.restype = BOOL
    k.CloseHandle.argtypes = [HANDLE]
    k.CloseHandle.restype = BOOL
    return k


def test_named_pipe_identification_token_appcontainer_diagnostic():
    k = _kernel32()
    name = rf'\\.\pipe\tnc-appcontainer-ident-{os.getpid()}-{uuid.uuid4().hex}'
    server = k.CreateNamedPipeW(
        name,
        PIPE_ACCESS_DUPLEX,
        PIPE_REJECT_REMOTE_CLIENTS,
        1,
        4096,
        4096,
        0,
        None,
    )
    assert server not in (None, 0, INVALID_HANDLE_VALUE)

    release_client = threading.Event()
    client_done = threading.Event()
    client_errors = []

    def client():
        handle = None
        try:
            assert k.WaitNamedPipeW(name, 5000), c.get_last_error()
            handle = k.CreateFileW(
                name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                None,
            )
            assert handle not in (None, 0, INVALID_HANDLE_VALUE), c.get_last_error()
            payload = c.create_string_buffer(b'X')
            written = DWORD()
            assert k.WriteFile(handle, payload, 1, c.byref(written), None), c.get_last_error()
            assert written.value == 1
            assert release_client.wait(10)
        except BaseException as exc:
            client_errors.append(exc)
        finally:
            if handle not in (None, 0, INVALID_HANDLE_VALUE):
                k.CloseHandle(handle)
            client_done.set()

    thread = threading.Thread(target=client, name='tnc-identification-client', daemon=True)
    thread.start()

    api = NativePipeTokenAPI()
    token = None
    impersonated = False
    try:
        connected = bool(k.ConnectNamedPipe(server, None))
        if not connected:
            assert c.get_last_error() == ERROR_PIPE_CONNECTED

        byte = c.create_string_buffer(1)
        read = DWORD()
        assert k.ReadFile(server, byte, 1, c.byref(read), None), c.get_last_error()
        assert read.value == 1 and byte.raw == b'X'

        assert api.open_thread_token() is None
        assert api.impersonate(server)
        impersonated = True
        token = api.open_thread_token()
        assert token is not None

        # Independently verify Windows minted the exact profile under study.
        facts = api.capture(token, lambda: None)
        assert facts.token_type == 'IMPERSONATION'
        assert facts.level == 'IDENTIFICATION'

        evidence = NativeAppContainerProbe().probe(
            token,
            token_type='IMPERSONATION',
            level='IDENTIFICATION',
        )
        result = evaluate_appcontainer_exclusion(evidence)

        # Even if classes 29/30/31 are fully queryable and internally consistent,
        # Microsoft guidance forbids converting TokenIsAppContainer==0 on an
        # identification-level impersonation token into exclusion proof.
        assert result.status in {'UNPROVEN', 'APPCONTAINER', 'INDETERMINATE'}
        if evidence.token_is_app_container is False and evidence.app_container_sid is None:
            assert result.status == 'UNPROVEN'
            assert result.reason == 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN'
        assert not result.authorization_granted
        assert not result.admission_granted
    finally:
        if token is not None:
            assert api.close(token)
        if impersonated:
            assert api.revert()
        release_client.set()
        assert client_done.wait(10)
        thread.join(timeout=1)
        k.DisconnectNamedPipe(server)
        assert k.CloseHandle(server)

    if client_errors:
        raise client_errors[0]
    assert api.open_thread_token() is None
