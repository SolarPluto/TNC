"""Audit-only Win32 AppContainer token diagnostic.

This module performs bounded GetTokenInformation queries for the documented
AppContainer token classes and converts them into the pure evidence contract.
It grants no admission or authorization and does not acquire or own token handles.
"""
import ctypes as c
import os
from typing import Literal

from tnc.provenance.windows_appcontainer_evidence import AppContainerTokenEvidence
from tnc.provenance.windows_pipe_token import (
    DWORD, HANDLE, SID_AND_ATTRIBUTES, TOKEN_GROUPS_HEADER, _groups, _sid,
)

ERROR_INSUFFICIENT_BUFFER = 122
TOKEN_IS_APPCONTAINER = 29
TOKEN_CAPABILITIES = 30
TOKEN_APPCONTAINER_SID = 31
MAX_QUERY = 65536


class TOKEN_APPCONTAINER_INFORMATION(c.Structure):
    _fields_ = [('TokenAppContainer', c.c_void_p)]


class AppContainerProbeError(ValueError):
    pass


class NativeAppContainerProbe:
    """Bounded, query-only diagnostic over an already-open TOKEN_QUERY handle."""

    def __init__(self, *, security_for_testing=None, last_error_for_testing=None):
        fake = security_for_testing is not None or last_error_for_testing is not None
        if fake:
            if security_for_testing is None or last_error_for_testing is None:
                raise ValueError('COMPLETE_FAKE_BINDING_REQUIRED')
            self.security = security_for_testing
            self._error = last_error_for_testing
        else:
            if os.name != 'nt':
                raise OSError('WINDOWS_REQUIRED')
            self.security = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
            self._error = c.get_last_error
        fn = self.security.GetTokenInformation
        fn.argtypes = [HANDLE, c.c_int32, c.c_void_p, DWORD, c.POINTER(DWORD)]
        fn.restype = c.c_int32
        self.source = 'FAKE_TOKEN_API' if fake else 'NATIVE_TOKEN_API'

    def _call(self, token, kind, buffer, capacity):
        returned = DWORD()
        ok = self.security.GetTokenInformation(token, kind, buffer, capacity, c.byref(returned))
        error = 0 if ok else self._error()
        return bool(ok), int(error), int(returned.value)

    def _fixed_dword(self, token, kind):
        value = DWORD()
        ok, error, returned = self._call(token, kind, c.byref(value), c.sizeof(value))
        if not ok:
            raise AppContainerProbeError(f'QUERY_{kind}_FAILED_{error}')
        if returned != c.sizeof(value):
            raise AppContainerProbeError(f'QUERY_{kind}_LENGTH')
        if value.value not in (0, 1):
            raise AppContainerProbeError(f'QUERY_{kind}_BOOLEAN')
        return bool(value.value)

    def _variable(self, token, kind):
        ok, error, size = self._call(token, kind, None, 0)
        if ok or error != ERROR_INSUFFICIENT_BUFFER:
            raise AppContainerProbeError(f'QUERY_{kind}_SIZE_PROBE')
        if not 0 < size <= MAX_QUERY:
            raise AppContainerProbeError(f'QUERY_{kind}_BOUND')
        buffer = c.create_string_buffer(size)
        ok, error, returned = self._call(token, kind, buffer, size)
        if not ok:
            raise AppContainerProbeError(f'QUERY_{kind}_FAILED_{error}')
        if not 0 < returned <= size:
            raise AppContainerProbeError(f'QUERY_{kind}_RETURN_LENGTH')
        return buffer, returned

    def _appcontainer_sid(self, token):
        buffer, length = self._variable(token, TOKEN_APPCONTAINER_SID)
        if length < c.sizeof(TOKEN_APPCONTAINER_INFORMATION):
            raise AppContainerProbeError('APPCONTAINER_INFO_HEADER')
        info = TOKEN_APPCONTAINER_INFORMATION.from_buffer_copy(
            bytes(buffer[:c.sizeof(TOKEN_APPCONTAINER_INFORMATION)])
        )
        if not info.TokenAppContainer:
            return None
        try:
            return _sid(buffer, length, int(info.TokenAppContainer), c.sizeof(TOKEN_APPCONTAINER_INFORMATION))
        except Exception as exc:
            raise AppContainerProbeError('APPCONTAINER_SID_INVALID') from exc

    def _capabilities(self, token):
        try:
            return tuple(sid for sid, _ in _groups(*self._variable(token, TOKEN_CAPABILITIES)))
        except AppContainerProbeError:
            raise
        except Exception as exc:
            raise AppContainerProbeError('CAPABILITY_GROUPS_INVALID') from exc

    def probe(
        self,
        token: int,
        *,
        token_type: Literal['IMPERSONATION', 'PRIMARY'],
        level: Literal['IDENTIFICATION', 'IMPERSONATION', 'DELEGATION'] | None,
    ) -> AppContainerTokenEvidence:
        if type(token) is not int or not 0 < token < c.c_void_p(-1).value:
            raise ValueError('INVALID_TOKEN_HANDLE')
        if token_type not in ('IMPERSONATION', 'PRIMARY'):
            raise ValueError('INVALID_TOKEN_TYPE')
        if token_type == 'IMPERSONATION' and level not in ('IDENTIFICATION', 'IMPERSONATION', 'DELEGATION'):
            raise ValueError('INVALID_IMPERSONATION_LEVEL')
        if token_type == 'PRIMARY' and level is not None:
            raise ValueError('PRIMARY_LEVEL_FORBIDDEN')

        is_appcontainer = self._fixed_dword(token, TOKEN_IS_APPCONTAINER)
        capabilities = self._capabilities(token)
        appcontainer_sid = self._appcontainer_sid(token)
        return AppContainerTokenEvidence(
            source=self.source,
            token_type=token_type,
            level=level,
            token_is_app_container=is_appcontainer,
            app_container_sid=appcontainer_sid,
            capability_sids=capabilities,
        )
