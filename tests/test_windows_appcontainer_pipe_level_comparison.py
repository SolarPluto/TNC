"""Same ordinary process, two pipe SQOS levels, independently anchored first.

Both endpoints belong to this process: this is self-impersonation, not evidence
of equivalence with an external-process pipe client.
"""
from contextlib import ExitStack
import ctypes as c
import os
import uuid

import pytest

import _native_harness as harness
from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance.windows_appcontainer_probe import NativeAppContainerProbe
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows pipe SQOS comparison only')
SECURITY_SQOS_PRESENT = 0x00100000
PIPE_LEVELS = [('IDENTIFICATION', 0x00010000), ('IMPERSONATION', 0x00020000)]


_checked_cleanup = harness._checked_cleanup


def _raw_ordinary_primary_oracle(advapi, token):
    """Use raw Win32 queries, never the TNC probe, to establish the client."""
    returned = harness.DWORD()
    flag = harness.DWORD()
    assert advapi.GetTokenInformation(
        token, harness.TOKEN_IS_APPCONTAINER, c.byref(flag), c.sizeof(flag), c.byref(returned)
    ), c.get_last_error()
    assert returned.value == c.sizeof(flag)
    assert flag.value == 0, 'PRIMARY oracle: this runner is not an ordinary client'
    # This oracle requires class 31 to succeed with a pointer-sized structure
    # containing NULL for the ordinary token, as observed locally. A build that
    # rejects this query or returns another size fails oracle setup here, before
    # either pipe observation; that is not an exclusion-classifier result.
    # sizeof(info) follows pointer width and is not hard-coded to eight bytes.
    info = harness.TOKEN_APPCONTAINER_INFORMATION()
    assert advapi.GetTokenInformation(
        token, harness.TOKEN_APPCONTAINER_SID, c.byref(info), c.sizeof(info), c.byref(returned)
    ), c.get_last_error()
    assert returned.value == c.sizeof(info)
    assert not info.TokenAppContainer, 'PRIMARY oracle: unexpected AppContainer SID'


def test_same_ordinary_client_at_both_pipe_levels(emit_observation):
    k = harness._kernel32()
    advapi = harness._advapi32()
    api = NativePipeTokenAPI()
    k.GetNamedPipeClientProcessId.argtypes = [harness.HANDLE, c.POINTER(harness.DWORD)]
    k.GetNamedPipeClientProcessId.restype = harness.BOOL
    assert api.open_thread_token() is None

    with ExitStack() as primary_cleanup:
        primary = harness.HANDLE()
        assert advapi.OpenProcessToken(k.GetCurrentProcess(), harness.TOKEN_QUERY, c.byref(primary)), c.get_last_error()
        primary_cleanup.callback(_checked_cleanup, k.CloseHandle, primary)
        # Both CreateFile calls below originate from this same ordinary process,
        # with no thread impersonation. Establish its primary identity first.
        _raw_ordinary_primary_oracle(advapi, primary)
        expected_user = harness._current_user_sid(advapi, k)
        emit_observation(f'TNC_ORDINARY_PRIMARY_ORACLE client_pid={os.getpid()} is_appcontainer=False appcontainer_sid=None')

        observations = []
        for level, sqos in PIPE_LEVELS:
            assert api.open_thread_token() is None
            with ExitStack() as pipe_cleanup:
                name = rf'\\.\pipe\tnc-level-pair-{uuid.uuid4().hex}'
                server = k.CreateNamedPipeW(
                    name, harness.PIPE_ACCESS_DUPLEX | harness.FILE_FLAG_OVERLAPPED,
                    harness.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, None,
                )
                assert server not in (None, 0, harness.INVALID_HANDLE_VALUE), c.get_last_error()
                pipe_cleanup.callback(_checked_cleanup, k.CloseHandle, server)
                client = k.CreateFileW(
                    name, 0xC0000000, 0, None, 3,
                    harness.FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | sqos, None,
                )
                assert client not in (None, 0, harness.INVALID_HANDLE_VALUE), c.get_last_error()
                pipe_cleanup.callback(_checked_cleanup, k.CloseHandle, client)
                harness._pipe_io(k, server, 'connect')
                client_pid = harness.DWORD()
                assert k.GetNamedPipeClientProcessId(server, c.byref(client_pid)), c.get_last_error()
                assert client_pid.value == os.getpid(), 'pipe client differs from PRIMARY oracle process'
                assert harness._pipe_io(k, client, 'write', c.create_string_buffer(b'X')) == 1
                byte = c.create_string_buffer(1)
                assert harness._pipe_io(k, server, 'read', byte) == 1 and byte.raw == b'X'

                with ExitStack() as token_cleanup:
                    assert api.impersonate(server)
                    token_cleanup.callback(harness._revert_or_fail_fast, api)
                    token = api.open_thread_token()
                    assert token is not None
                    token_cleanup.callback(_checked_cleanup, api.close, token)
                    facts = api.capture(token, harness._no_temporal_guard)
                    assert facts.token_type == 'IMPERSONATION'
                    assert facts.level == level
                    assert facts.user_sid == expected_user
                    evidence = NativeAppContainerProbe().probe(token, token_type=facts.token_type, level=facts.level)
                    result = evaluate_appcontainer_exclusion(evidence)
                    emit_observation(
                        f'TNC_ORDINARY_PIPE_LEVEL_OBSERVATION client_pid={client_pid.value} '
                        f'level={facts.level} oracle_is_appcontainer=False '
                        f'is_appcontainer={evidence.token_is_app_container!r} '
                        f'appcontainer_sid={evidence.app_container_sid!r} '
                        f'{harness._capability_observation_fields(evidence)} '
                        f'status={result.status} reason={result.reason}'
                    )
                    # Security is independent of the expected experimental result.
                    assert result.audit_only
                    assert not result.authorization_granted
                    assert not result.admission_granted
                    # Keep the independent safety invariant as an immediate
                    # failure, before the next connection. Exact experimental
                    # expectations remain below, after both measurements.
                    if level == 'IDENTIFICATION':
                        assert result.status != 'PROVEN_NON_APPCONTAINER'
                    observations.append((level, evidence, result))

                assert api.open_thread_token() is None
                assert harness._pipe_io(k, server, 'write', c.create_string_buffer(b'Y')) == 1
                assert harness._pipe_io(k, client, 'read', byte) == 1 and byte.raw == b'Y'

        # Precommitted branch expectations, checked only after recording both
        # levels. A failure preserves the evidence rather than redefining success.
        for level, evidence, result in observations:
            assert evidence.token_is_app_container is False, (level, evidence)
            assert evidence.app_container_sid is None, (level, evidence)
            expected = ('UNPROVEN', 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN') if level == 'IDENTIFICATION' else (
                'PROVEN_NON_APPCONTAINER', 'TOKEN_IS_APPCONTAINER_FALSE_USABLE'
            )
            assert (result.status, result.reason) == expected, (level, evidence, result)

    assert api.open_thread_token() is None
