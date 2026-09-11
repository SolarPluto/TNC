"""Read-only native file primitives. No ACL changes or provisioning authority."""
import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass
import re
import struct


class ProtectedFileError(Exception):
    pass


def _sid(data, offset, end):
    if offset < 20 or offset + 8 > end:
        raise ProtectedFileError('Invalid SID extent')
    revision, count = data[offset:offset+2]
    size = 8 + count * 4
    if revision != 1 or not 1 <= count <= 15 or offset + size > end:
        raise ProtectedFileError('Invalid SID')
    authority = int.from_bytes(data[offset+2:offset+8], 'big')
    values = struct.unpack_from('<' + 'I'*count, data, offset+8)
    return 'S-1-' + str(authority) + ''.join('-'+str(x) for x in values), size


def parse_security(data):
    """Bound every offset before decoding the returned self-relative descriptor."""
    if type(data) is not bytes or not 20 <= len(data) <= 65536:
        raise ProtectedFileError('Invalid descriptor length')
    revision, _, control, owner, _, _, dacl = struct.unpack_from('<BBHIIII', data)
    if revision != 1 or not control & 0x8000 or not control & 4 or not dacl:
        raise ProtectedFileError('Owner and non-null DACL required')
    owner_sid, _ = _sid(data, owner, len(data))
    if dacl < 20 or dacl + 8 > len(data):
        raise ProtectedFileError('Invalid ACL extent')
    revision, _, size, count, _ = struct.unpack_from('<BBHHH', data, dacl)
    if revision not in (2, 4) or size < 8 or size % 4 or dacl+size > len(data) or count > 1024:
        raise ProtectedFileError('Unsupported ACL')
    entries, pos = [], dacl+8
    for _ in range(count):
        if pos+8 > dacl+size:
            raise ProtectedFileError('Truncated ACE')
        kind, flags, length, mask = struct.unpack_from('<BBHI', data, pos)
        if kind not in (0, 1) or flags & ~0x1f or length < 16 or length % 4 or pos+length > dacl+size:
            raise ProtectedFileError('Unsupported ACE')
        sid, sid_size = _sid(data, pos+8, pos+length)
        if 8+sid_size != length:
            raise ProtectedFileError('Unexpected ACE bytes')
        entries.append((kind, flags, mask, sid))
        pos += length
    return owner_sid, tuple(entries)


def validate_security(data, owners, writers):
    owner, entries = parse_security(data)
    if owner not in owners:
        raise ProtectedFileError('Owner denied')
    for kind, flags, mask, sid in entries:
        # Generic write/all and MAXIMUM_ALLOWED are conservatively write-capable.
        # File writes, append, EA/attribute writes, delete-child, DELETE, WRITE_DAC/OWNER.
        unsafe = mask & (0x40000000 | 0x10000000 | 0x02000000 | 0x000d0156)
        if mask & ~0xf31f01ff:
            raise ProtectedFileError('Unknown access rights')
        if kind == 0 and not flags & 8 and unsafe and sid not in writers:
            raise ProtectedFileError('Writer denied')


@dataclass(frozen=True)
class FileFacts:
    directory: bool
    attributes: int
    links: int
    size: int
    volume: int
    file_id: int
    security: bytes


class _FileInfo(c.Structure):
    _fields_ = [('attributes', w.DWORD), ('created', w.FILETIME), ('accessed', w.FILETIME),
                ('written', w.FILETIME), ('volume', w.DWORD), ('size_high', w.DWORD),
                ('size_low', w.DWORD), ('links', w.DWORD), ('id_high', w.DWORD), ('id_low', w.DWORD)]


class _Unicode(c.Structure):
    _fields_ = [('length', w.USHORT), ('maximum', w.USHORT), ('buffer', c.c_void_p)]


class _Attributes(c.Structure):
    _fields_ = [('length', w.ULONG), ('root', w.HANDLE), ('name', c.POINTER(_Unicode)),
                ('attributes', w.ULONG), ('security', c.c_void_p), ('qos', c.c_void_p)]


class _IoStatus(c.Structure):
    _fields_ = [('status', c.c_void_p), ('information', c.c_size_t)]


class _WindowsFileAPI:
    def __init__(self):
        self.kernel = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
        self.security = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
        self.nt = c.WinDLL('ntdll.dll', use_last_error=True, winmode=0x800)
        def bind(lib, name, args, result):
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, result
        bind(self.kernel, 'CreateFileW', [w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE], w.HANDLE)
        bind(self.kernel, 'CloseHandle', [w.HANDLE], w.BOOL)
        bind(self.kernel, 'LocalFree', [c.c_void_p], c.c_void_p)
        bind(self.kernel, 'GetFileType', [w.HANDLE], w.DWORD)
        bind(self.kernel, 'GetFileInformationByHandle', [w.HANDLE,c.POINTER(_FileInfo)], w.BOOL)
        bind(self.kernel, 'GetFinalPathNameByHandleW', [w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD], w.DWORD)
        bind(self.kernel, 'GetVolumeInformationByHandleW', [w.HANDLE,w.LPWSTR,w.DWORD,c.c_void_p,
             c.c_void_p,c.c_void_p,w.LPWSTR,w.DWORD], w.BOOL)
        bind(self.kernel, 'ReadFile', [w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p], w.BOOL)
        bind(self.security, 'GetSecurityInfo', [w.HANDLE,c.c_int,w.DWORD,c.c_void_p,c.c_void_p,
             c.c_void_p,c.c_void_p,c.POINTER(c.c_void_p)], w.DWORD)
        bind(self.security, 'GetSecurityDescriptorLength', [c.c_void_p], w.DWORD)
        bind(self.nt, 'NtCreateFile', [c.POINTER(w.HANDLE),w.DWORD,c.POINTER(_Attributes),
             c.POINTER(_IoStatus),c.c_void_p,w.ULONG,w.ULONG,w.ULONG,w.ULONG,c.c_void_p,w.ULONG], c.c_long)

    def close(self, handle):
        if not self.kernel.CloseHandle(handle):
            raise ProtectedFileError('Handle cleanup failed')

    def open_root(self, drive):
        if not re.fullmatch(r'[A-Z]:\\', drive):
            raise ProtectedFileError('Invalid drive')
        handle = self.kernel.CreateFileW(drive, 0x120080, 1, None, 3, 0x02200000, None)
        if handle in (None, c.c_void_p(-1).value):
            raise ProtectedFileError('Root unavailable')
        try:
            path, fs = c.create_unicode_buffer(128), c.create_unicode_buffer(32)
            length = self.kernel.GetFinalPathNameByHandleW(handle, path, 128, 1)
            if (not 0 < length < 128
                    or not re.fullmatch(r'\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\', path.value)):
                raise ProtectedFileError('Local volume root required')
            if not self.kernel.GetVolumeInformationByHandleW(handle, None, 0, None, None, None, fs, 32) or fs.value != 'NTFS':
                raise ProtectedFileError('NTFS required')
            return handle
        except BaseException:
            self.close(handle)
            raise

    def open_child(self, parent, name, directory):
        if not name or len(name) > 255 or name in ('.', '..') or any(x in name for x in '\\/:\x00'):
            raise ProtectedFileError('Single path component required')
        buffer = c.create_unicode_buffer(name)
        length = len(name.encode('utf-16-le'))
        string = _Unicode(length, length+2, c.cast(buffer, c.c_void_p))
        attrs = _Attributes(c.sizeof(_Attributes), parent, c.pointer(string), 0x40, None, None)
        result, status = w.HANDLE(), _IoStatus()
        access = 0x120080 | (0 if directory else 1)
        options = 0x200000 | 0x20 | (1 if directory else 0x40)
        code = self.nt.NtCreateFile(c.byref(result), access, c.byref(attrs), c.byref(status),
            None, 0, 1, 1, options, None, 0)
        if code < 0 or not result.value:
            raise ProtectedFileError('Child unavailable')
        return result.value

    def facts(self, handle):
        info = _FileInfo()
        if self.kernel.GetFileType(handle) != 1 or not self.kernel.GetFileInformationByHandle(handle, c.byref(info)):
            raise ProtectedFileError('Disk file required')
        descriptor = c.c_void_p()
        error = self.security.GetSecurityInfo(handle, 1, 5, None, None, None, None, c.byref(descriptor))
        try:
            if error or not descriptor.value:
                raise ProtectedFileError('Security unavailable')
            size = self.security.GetSecurityDescriptorLength(descriptor)
            if not 20 <= size <= 65536:
                raise ProtectedFileError('Security too large')
            security = c.string_at(descriptor.value, size)
        finally:
            if descriptor.value and self.kernel.LocalFree(descriptor):
                raise ProtectedFileError('Security cleanup failed')
        return FileFacts(bool(info.attributes & 0x10), info.attributes, info.links,
            (info.size_high << 32) | info.size_low, info.volume,
            (info.id_high << 32) | info.id_low, security)

    def read(self, handle, size):
        if type(size) is not int or not 0 <= size <= 4*1024*1024:
            raise ProtectedFileError('Read size denied')
        chunks, remaining = [], size
        while remaining:
            amount = min(65536, remaining)
            buffer, read = c.create_string_buffer(amount), w.DWORD()
            if not self.kernel.ReadFile(handle, buffer, amount, c.byref(read), None) or not 0 < read.value <= amount:
                raise ProtectedFileError('Incomplete read')
            chunks.append(buffer.raw[:read.value])
            remaining -= read.value
        extra, read = c.create_string_buffer(1), w.DWORD()
        if not self.kernel.ReadFile(handle, extra, 1, c.byref(read), None) or read.value:
            raise ProtectedFileError('Unexpected trailing data')
        return b''.join(chunks)
