"""Native Windows process API adapter with lazy Win32 binding.

The adapter matches the six-method process API contract used by the process-lease
layer, but does not inherit from the fake test interface. Import performs no DLL
load, handle acquisition, or other native side effect.
"""
import ctypes as c
import sys

DWORD = c.c_uint32
BOOL = c.c_int32
HANDLE = c.c_void_p

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
PROCESS_LEASE_RIGHTS = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE

INVALID_HANDLE_VALUE = c.c_void_p(-1).value
MAX_HANDLE = (1 << (8 * c.sizeof(c.c_void_p))) - 1

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
WAIT_FAILED = 0xFFFFFFFF


class FILETIME(c.Structure):
    _fields_ = [("dwLowDateTime", DWORD), ("dwHighDateTime", DWORD)]


class NativeProcessAPIError(RuntimeError):
    """Stable native-boundary failure carrying operation and Win32 result."""

    def __init__(self, operation, winerror):
        if type(operation) is not str or not operation:
            raise TypeError("operation must be a non-empty string")
        if type(winerror) is not int or not 0 <= winerror <= 0xFFFFFFFF:
            raise TypeError("winerror must be an unsigned DWORD")
        super().__init__(operation)
        self.operation = operation
        self.winerror = winerror


def _last_error():
    getter = getattr(c, "get_last_error", None)
    if getter is None:
        return 0
    value = getter()
    return value if type(value) is int and 0 <= value <= 0xFFFFFFFF else 0


def _validate_handle(value):
    if (
        type(value) is not int
        or not 0 < value <= MAX_HANDLE
        or value == INVALID_HANDLE_VALUE
    ):
        raise ValueError("INVALID_NATIVE_HANDLE")


class NativeProcessAPI:
    """Lazy wrapper matching the frozen process-API semantic contract."""

    def __init__(self, kernel32=None):
        self._kernel32 = kernel32
        self._bound = False

    def _ensure_bound(self):
        if self._bound:
            return
        if self._kernel32 is not None:
            kernel = self._kernel32
        else:
            if sys.platform != "win32":
                raise RuntimeError("NATIVE_PROCESS_API_REQUIRES_WINDOWS")
            kernel = c.WinDLL("kernel32", use_last_error=True)

        self._OpenProcess = kernel.OpenProcess
        self._OpenProcess.argtypes = [DWORD, BOOL, DWORD]
        self._OpenProcess.restype = HANDLE

        self._GetProcessId = kernel.GetProcessId
        self._GetProcessId.argtypes = [HANDLE]
        self._GetProcessId.restype = DWORD

        self._GetProcessTimes = kernel.GetProcessTimes
        self._GetProcessTimes.argtypes = [
            HANDLE,
            c.POINTER(FILETIME),
            c.POINTER(FILETIME),
            c.POINTER(FILETIME),
            c.POINTER(FILETIME),
        ]
        self._GetProcessTimes.restype = BOOL

        self._WaitForSingleObject = kernel.WaitForSingleObject
        self._WaitForSingleObject.argtypes = [HANDLE, DWORD]
        self._WaitForSingleObject.restype = DWORD

        self._CloseHandle = kernel.CloseHandle
        self._CloseHandle.argtypes = [HANDLE]
        self._CloseHandle.restype = BOOL

        self._GetNamedPipeClientProcessId = kernel.GetNamedPipeClientProcessId
        self._GetNamedPipeClientProcessId.argtypes = [HANDLE, c.POINTER(DWORD)]
        self._GetNamedPipeClientProcessId.restype = BOOL
        self._bound = True

    def client_process_id(self, pipe):
        _validate_handle(pipe)
        self._ensure_bound()
        pid = DWORD(0)
        success = self._GetNamedPipeClientProcessId(HANDLE(pipe), c.byref(pid))
        if not success:
            raise NativeProcessAPIError("GetNamedPipeClientProcessId", _last_error())
        if pid.value == 0:
            raise NativeProcessAPIError("GetNamedPipeClientProcessId_InvalidResult", 0)
        return int(pid.value)

    def open_process(self, pid, rights, inherit):
        if type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF:
            raise ValueError("INVALID_PID")
        if type(rights) is not int or rights != PROCESS_LEASE_RIGHTS:
            raise ValueError("PROCESS_RIGHTS_MISMATCH")
        if inherit is not False:
            raise ValueError("INHERITANCE_FORBIDDEN")
        self._ensure_bound()
        handle = self._OpenProcess(DWORD(rights), BOOL(0), DWORD(pid))
        if not handle or handle == INVALID_HANDLE_VALUE:
            raise NativeProcessAPIError("OpenProcess", _last_error())
        value = int(handle)
        _validate_handle(value)
        return value

    def process_id(self, handle):
        _validate_handle(handle)
        self._ensure_bound()
        pid = self._GetProcessId(HANDLE(handle))
        if pid == 0:
            raise NativeProcessAPIError("GetProcessId", _last_error())
        return int(pid)

    def creation_filetime(self, handle):
        _validate_handle(handle)
        self._ensure_bound()
        creation, exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        success = self._GetProcessTimes(
            HANDLE(handle),
            c.byref(creation),
            c.byref(exit_time),
            c.byref(kernel_time),
            c.byref(user_time),
        )
        if not success:
            raise NativeProcessAPIError("GetProcessTimes", _last_error())
        return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)

    def wait_process(self, handle, timeout):
        _validate_handle(handle)
        if type(timeout) is not int or not 0 <= timeout <= 0xFFFFFFFF:
            raise ValueError("INVALID_WAIT_TIMEOUT")
        self._ensure_bound()
        result = self._WaitForSingleObject(HANDLE(handle), DWORD(timeout))
        if result == WAIT_FAILED:
            raise NativeProcessAPIError("WaitForSingleObject", _last_error())
        if result not in (WAIT_OBJECT_0, WAIT_TIMEOUT):
            raise NativeProcessAPIError("WaitForSingleObject_Unexpected", int(result))
        return int(result)

    def close(self, handle):
        _validate_handle(handle)
        self._ensure_bound()
        if not self._CloseHandle(HANDLE(handle)):
            raise NativeProcessAPIError("CloseHandle", _last_error())
        return True
