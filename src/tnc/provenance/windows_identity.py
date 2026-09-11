"""Read-only Windows process identity for a non-impersonating local operator.

No provisioning permission, privilege adjustment, impersonation or policy loading.
The public entry point accepts no SID, token handle, PID or identity override.
"""
import ctypes
from ctypes import wintypes
import sys

from pydantic import BaseModel, ConfigDict, Field


TOKEN_QUERY = 0x0008
ERROR_NO_TOKEN = 1008
ERROR_INSUFFICIENT_BUFFER = 122
TOKEN_USER = 1
TOKEN_TYPE = 8
TOKEN_ELEVATION = 20
TOKEN_PRIMARY = 1
MAX_TOKEN_BUFFER = 65536


class WindowsIdentityError(Exception):
    """No usable local operator identity was established."""


class WindowsOperatorIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid')
    user_sid: str = Field(pattern=r'^S-1-(?:[0-9]+|0x[0-9A-Fa-f]+)(?:-[0-9]+){0,15}$')
    process_id: int = Field(strict=True, gt=0)
    thread_id: int = Field(strict=True, gt=0)
    elevated: bool = Field(strict=True)


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', wintypes.DWORD)]


class _WindowsTokenAPI:
    def __init__(self):
        # Explicit system DLL search; never resolve libraries from user paths.
        self.kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
        self.security = ctypes.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
        self._bind(self.kernel, 'GetCurrentProcess', [], wintypes.HANDLE)
        self._bind(self.kernel, 'GetCurrentThread', [], wintypes.HANDLE)
        self._bind(self.kernel, 'GetCurrentProcessId', [], wintypes.DWORD)
        self._bind(self.kernel, 'GetCurrentThreadId', [], wintypes.DWORD)
        self._bind(self.kernel, 'CloseHandle', [wintypes.HANDLE], wintypes.BOOL)
        self._bind(self.kernel, 'LocalFree', [ctypes.c_void_p], ctypes.c_void_p)
        self._bind(self.security, 'OpenThreadToken', [wintypes.HANDLE, wintypes.DWORD,
                   wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL)
        self._bind(self.security, 'OpenProcessToken', [wintypes.HANDLE, wintypes.DWORD,
                   ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL)
        self._bind(self.security, 'GetTokenInformation', [wintypes.HANDLE, ctypes.c_int,
                   ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
        self._bind(self.security, 'IsValidSid', [ctypes.c_void_p], wintypes.BOOL)
        self._bind(self.security, 'ConvertSidToStringSidW', [ctypes.c_void_p,
                   ctypes.POINTER(ctypes.c_void_p)], wintypes.BOOL)

    @staticmethod
    def _bind(library, name, args, result):
        function = getattr(library, name)
        function.argtypes, function.restype = args, result

    def open_thread_token(self):
        token = wintypes.HANDLE()
        if self.security.OpenThreadToken(self.kernel.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)):
            if not token.value:
                raise WindowsIdentityError('Invalid thread token handle')
            return token.value
        error = ctypes.get_last_error()
        if error == ERROR_NO_TOKEN:
            return None
        raise WindowsIdentityError('Thread token inspection failed')

    def open_process_token(self):
        token = wintypes.HANDLE()
        if not self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            raise WindowsIdentityError('Process token inspection failed')
        if not token.value:
            raise WindowsIdentityError('Invalid process token handle')
        return token.value

    def close(self, handle):
        if not self.kernel.CloseHandle(handle):
            raise WindowsIdentityError('Token cleanup failed')

    def information(self, handle, kind):
        size = wintypes.DWORD()
        ok = self.security.GetTokenInformation(handle, kind, None, 0, ctypes.byref(size))
        if ok or ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or not 0 < size.value <= MAX_TOKEN_BUFFER:
            raise WindowsIdentityError('Invalid token information size')
        capacity = size.value
        buffer = ctypes.create_string_buffer(capacity)
        if not self.security.GetTokenInformation(handle, kind, buffer, capacity, ctypes.byref(size)):
            raise WindowsIdentityError('Token information unavailable')
        if not 0 < size.value <= capacity:
            raise WindowsIdentityError('Invalid token information length')
        return buffer, size.value

    def dword(self, handle, kind):
        # Fixed-size token classes need no variable-buffer probe. In particular,
        # TokenElevation can reject a zero-length probe with ERROR_BAD_LENGTH.
        value, length = wintypes.DWORD(), wintypes.DWORD()
        if not self.security.GetTokenInformation(handle, kind, ctypes.byref(value),
                                                 ctypes.sizeof(value), ctypes.byref(length)):
            raise WindowsIdentityError('Token scalar unavailable')
        if length.value != ctypes.sizeof(value):
            raise WindowsIdentityError('Invalid token scalar')
        return value.value

    def user_sid(self, handle):
        buffer, length = self.information(handle, TOKEN_USER)
        if length < ctypes.sizeof(_SID_AND_ATTRIBUTES):
            raise WindowsIdentityError('Invalid token user')
        address = _SID_AND_ATTRIBUTES.from_buffer(buffer).Sid
        start = ctypes.addressof(buffer)
        if address is None or not start <= address <= start + length - 8:
            raise WindowsIdentityError('Invalid SID pointer')
        # Bound the complete variable-length SID before handing it to native code.
        count = ctypes.c_ubyte.from_address(address + 1).value
        if count > 15 or address + 8 + 4 * count > start + length:
            raise WindowsIdentityError('Invalid SID length')
        if not self.security.IsValidSid(address):
            raise WindowsIdentityError('Invalid SID')
        text = ctypes.c_void_p()
        if not self.security.ConvertSidToStringSidW(address, ctypes.byref(text)):
            raise WindowsIdentityError('SID conversion failed')
        try:
            if not text.value:
                raise WindowsIdentityError('Missing SID string')
            return ctypes.wstring_at(text.value)
        finally:
            if text.value and self.kernel.LocalFree(text):
                raise WindowsIdentityError('SID cleanup failed')

    def process_id(self):
        return self.kernel.GetCurrentProcessId()

    def thread_id(self):
        return self.kernel.GetCurrentThreadId()


def _require_no_thread_token(api):
    token = api.open_thread_token()
    if token is not None:
        try:
            raise WindowsIdentityError('Impersonated call denied')
        finally:
            api.close(token)


def _read_current_operator(api):
    _require_no_thread_token(api)
    token = api.open_process_token()
    try:
        if api.dword(token, TOKEN_TYPE) != TOKEN_PRIMARY:
            raise WindowsIdentityError('Primary token required')
        sid = api.user_sid(token)
        elevation = api.dword(token, TOKEN_ELEVATION)
        if elevation not in (0, 1):
            raise WindowsIdentityError('Invalid elevation value')
        result = WindowsOperatorIdentity(user_sid=sid, process_id=api.process_id(),
                                         thread_id=api.thread_id(), elevated=bool(elevation))
        # Observe again before returning; do not claim protection from hostile code
        # that can replace tokens in this process between observations.
        _require_no_thread_token(api)
        return result
    finally:
        api.close(token)


def read_windows_operator_identity() -> WindowsOperatorIdentity:
    """Inspect this local process only; never grants provisioning permission."""
    try:
        if sys.platform != 'win32':
            raise WindowsIdentityError('Windows is required')
        return _read_current_operator(_WindowsTokenAPI())
    except Exception:
        raise WindowsIdentityError('Windows operator identity unavailable') from None
