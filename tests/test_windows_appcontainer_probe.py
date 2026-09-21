"""Injected and native smoke tests for the audit-only AppContainer token probe."""
import ctypes as c
import os
import struct

import pytest

import _native_harness as h
from tnc.provenance.windows_appcontainer_evidence import evaluate_appcontainer_exclusion
from tnc.provenance import windows_appcontainer_probe as p
from tnc.provenance.windows_pipe_token import SID_AND_ATTRIBUTES, TOKEN_GROUPS_HEADER


class Function:
    def __init__(self, fn):
        self.fn = fn
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.fn(*args)


def sid_bytes(text):
    parts = [int(x) for x in text.split('-')[1:]]
    return bytes((1, len(parts) - 2)) + parts[1].to_bytes(6, 'big') + b''.join(
        struct.pack('<I', value) for value in parts[2:]
    )


class FakeSecurity:
    def __init__(self):
        self.error = p.ERROR_INSUFFICIENT_BUFFER
        self.calls = []
        self.is_appcontainer = False
        self.app_sid = None
        self.capabilities = []
        self.size_override = {}
        self.fail_kind = None
        self.bad_sid_pointer = False
        self.GetTokenInformation = Function(self.query)

    def _capability_size(self):
        if not self.capabilities:
            return 4
        offset = TOKEN_GROUPS_HEADER.Groups.offset
        stride = c.sizeof(SID_AND_ATTRIBUTES)
        return offset + len(self.capabilities) * stride + sum(len(sid_bytes(sid)) for sid in self.capabilities)

    def _app_size(self):
        return c.sizeof(p.TOKEN_APPCONTAINER_INFORMATION) + (len(sid_bytes(self.app_sid)) if self.app_sid else 0)

    def required(self, kind):
        if kind == p.TOKEN_CAPABILITIES:
            return self._capability_size()
        if kind == p.TOKEN_APPCONTAINER_SID:
            return self._app_size()
        raise AssertionError(kind)

    def query(self, token, kind, buffer, capacity, returned):
        assert token == 99
        self.calls.append((kind, buffer is None, int(capacity)))
        out = c.cast(returned, c.POINTER(p.DWORD)).contents
        if self.fail_kind == kind:
            self.error = 5
            out.value = 0
            return False
        if kind == p.TOKEN_IS_APPCONTAINER:
            assert buffer is not None and capacity == 4
            c.cast(buffer, c.POINTER(p.DWORD)).contents.value = int(self.is_appcontainer)
            out.value = 4
            return True

        required = self.size_override.get(kind, self.required(kind))
        if buffer is None:
            out.value = required
            self.error = p.ERROR_INSUFFICIENT_BUFFER
            return False
        if capacity < required:
            out.value = required
            self.error = p.ERROR_INSUFFICIENT_BUFFER
            return False

        base = c.addressof(buffer)
        if kind == p.TOKEN_CAPABILITIES:
            c.memset(base, 0, capacity)
            c.memmove(base, struct.pack('<I', len(self.capabilities)), 4)
            if self.capabilities:
                offset = TOKEN_GROUPS_HEADER.Groups.offset
                stride = c.sizeof(SID_AND_ATTRIBUTES)
                cursor = offset + len(self.capabilities) * stride
                for index, sid in enumerate(self.capabilities):
                    raw = sid_bytes(sid)
                    item = SID_AND_ATTRIBUTES.from_buffer(buffer, offset + index * stride)
                    item.Sid = base + cursor
                    item.Attributes = 4
                    c.memmove(base + cursor, raw, len(raw))
                    cursor += len(raw)
        elif kind == p.TOKEN_APPCONTAINER_SID:
            c.memset(base, 0, capacity)
            info = p.TOKEN_APPCONTAINER_INFORMATION.from_buffer(buffer)
            if self.app_sid:
                raw = sid_bytes(self.app_sid)
                info.TokenAppContainer = base + c.sizeof(p.TOKEN_APPCONTAINER_INFORMATION)
                if self.bad_sid_pointer:
                    info.TokenAppContainer = base + capacity + 8
                else:
                    c.memmove(info.TokenAppContainer, raw, len(raw))
        else:
            raise AssertionError(kind)
        out.value = required
        return True


def probe(fake):
    api = p.NativeAppContainerProbe(
        security_for_testing=fake,
        last_error_for_testing=lambda: fake.error,
    )
    return api


def test_documented_information_class_numbers_are_frozen():
    assert p.TOKEN_IS_APPCONTAINER == 29
    assert p.TOKEN_CAPABILITIES == 30
    assert p.TOKEN_APPCONTAINER_SID == 31


def test_injected_binding_has_exact_gettokeninformation_signature():
    fake = FakeSecurity()
    api = probe(fake)
    assert api.source == 'FAKE_TOKEN_API'
    assert fake.GetTokenInformation.argtypes == [p.HANDLE, c.c_int32, c.c_void_p, p.DWORD, c.POINTER(p.DWORD)]
    assert fake.GetTokenInformation.restype is c.c_int32


def test_identification_zero_with_null_sid_remains_unproven():
    evidence = probe(FakeSecurity()).probe(99, token_type='IMPERSONATION', level='IDENTIFICATION')
    assert evidence.token_is_app_container is False
    assert evidence.app_container_sid is None
    assert evidence.capability_sids == ()
    result = evaluate_appcontainer_exclusion(evidence)
    assert result.status == 'UNPROVEN'
    assert result.reason == 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN'
    assert not result.authorization_granted and not result.admission_granted


def test_nonidentification_zero_can_be_classified_without_granting():
    evidence = probe(FakeSecurity()).probe(99, token_type='IMPERSONATION', level='IMPERSONATION')
    result = evaluate_appcontainer_exclusion(evidence)
    assert result.status == 'PROVEN_NON_APPCONTAINER'
    assert not result.authorization_granted and not result.admission_granted


def test_positive_appcontainer_sid_and_capabilities_are_captured():
    fake = FakeSecurity()
    fake.is_appcontainer = True
    fake.app_sid = 'S-1-15-2-123-456'
    fake.capabilities = ['S-1-15-3-1024']
    evidence = probe(fake).probe(99, token_type='IMPERSONATION', level='IDENTIFICATION')
    assert evidence.app_container_sid == fake.app_sid
    assert evidence.capability_sids == tuple(fake.capabilities)
    result = evaluate_appcontainer_exclusion(evidence)
    assert result.status == 'APPCONTAINER'


def test_false_flag_with_appcontainer_sid_is_indeterminate():
    fake = FakeSecurity()
    fake.app_sid = 'S-1-15-2-123-456'
    evidence = probe(fake).probe(99, token_type='IMPERSONATION', level='IDENTIFICATION')
    result = evaluate_appcontainer_exclusion(evidence)
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'APPCONTAINER_SIGNAL_CONFLICT'


def test_query_order_and_classes_are_exact():
    fake = FakeSecurity()
    probe(fake).probe(99, token_type='PRIMARY', level=None)
    assert [kind for kind, _, _ in fake.calls] == [29, 30, 30, 31, 31]


@pytest.mark.parametrize('value', [True, False, 0, -1, c.c_void_p(-1).value])
def test_invalid_token_handles_do_not_dispatch(value):
    fake = FakeSecurity()
    with pytest.raises(ValueError):
        probe(fake).probe(value, token_type='PRIMARY', level=None)
    assert fake.calls == []


def test_class_30_query_bound_is_audit_only():
    fake = FakeSecurity()
    fake.size_override[p.TOKEN_CAPABILITIES] = p.MAX_QUERY + 1
    evidence = probe(fake).probe(99, token_type='PRIMARY', level=None)
    assert evidence.capability_sids is None
    assert [kind for kind, _, _ in fake.calls] == [29, 30, 31, 31]


def test_class_30_query_failure_is_audit_only():
    fake = FakeSecurity()
    fake.fail_kind = p.TOKEN_CAPABILITIES
    evidence = probe(fake).probe(99, token_type='PRIMARY', level=None)
    assert evidence.capability_sids is None
    assert [kind for kind, _, _ in fake.calls] == [29, 30, 31, 31]


def test_class_30_failure_reaches_classifier_without_changing_disposition():
    fake = FakeSecurity()
    fake.fail_kind = p.TOKEN_CAPABILITIES
    unavailable = probe(fake).probe(99, token_type='IMPERSONATION', level='IMPERSONATION')
    observed_empty = p.AppContainerTokenEvidence(
        source=unavailable.source,
        token_type=unavailable.token_type,
        level=unavailable.level,
        token_is_app_container=unavailable.token_is_app_container,
        app_container_sid=unavailable.app_container_sid,
        capability_sids=(),
    )
    assert unavailable.capability_sids is None
    assert evaluate_appcontainer_exclusion(unavailable).model_dump() == (
        evaluate_appcontainer_exclusion(observed_empty).model_dump()
    )
    unavailable_observation = h._capability_observation_fields(unavailable)
    observed_observation = h._capability_observation_fields(observed_empty)
    assert "capability_count=None" in unavailable_observation
    assert "capability_query='UNAVAILABLE'" in unavailable_observation
    assert observed_observation == "capability_count=0 capability_query='OBSERVED'"


def test_malformed_appcontainer_sid_pointer_is_rejected():
    fake = FakeSecurity()
    fake.app_sid = 'S-1-15-2-123-456'
    fake.bad_sid_pointer = True
    with pytest.raises(p.AppContainerProbeError, match='APPCONTAINER_SID_INVALID'):
        probe(fake).probe(99, token_type='PRIMARY', level=None)


@pytest.mark.parametrize('kind,pattern', [
    (p.TOKEN_IS_APPCONTAINER, 'QUERY_29_FAILED_5'),
    (p.TOKEN_APPCONTAINER_SID, 'QUERY_31_SIZE_PROBE'),
])
def test_required_query_failure_preserves_information_class(kind, pattern):
    fake = FakeSecurity()
    fake.fail_kind = kind
    with pytest.raises(p.AppContainerProbeError, match=pattern):
        probe(fake).probe(99, token_type='PRIMARY', level=None)


@pytest.mark.skipif(os.name != 'nt', reason='Windows native token query only')
def test_native_primary_token_appcontainer_query_smoke():
    kernel = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    advapi = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = p.HANDLE
    kernel.CloseHandle.argtypes = [p.HANDLE]
    kernel.CloseHandle.restype = c.c_int32
    advapi.OpenProcessToken.argtypes = [p.HANDLE, p.DWORD, c.POINTER(p.HANDLE)]
    advapi.OpenProcessToken.restype = c.c_int32

    token = p.HANDLE()
    assert advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, c.byref(token))
    assert token.value
    try:
        evidence = p.NativeAppContainerProbe().probe(token.value, token_type='PRIMARY', level=None)
        assert evidence.source == 'NATIVE_TOKEN_API'
        result = evaluate_appcontainer_exclusion(evidence)
        assert result.status in {'PROVEN_NON_APPCONTAINER', 'APPCONTAINER', 'INDETERMINATE'}
        assert not result.authorization_granted and not result.admission_granted
    finally:
        assert kernel.CloseHandle(token)
