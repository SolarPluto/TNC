"""Fake API lifecycle tests and real Windows temporary-file checks."""
from dataclasses import replace
import os
from pathlib import Path
import struct
import sys
import ctypes as c
from ctypes import wintypes as w
import subprocess
from types import SimpleNamespace

import pytest

from test_provisioning_validation import case, SID, SERVICE
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.protected_provisioning import _load, load_protected_provisioning
from tnc.provenance.windows_protected_files import (
    FileFacts, ProtectedFileError, _WindowsFileAPI, parse_security, validate_security,
)


def sid_bytes(sid):
    fields = list(map(int, sid.split('-')[1:]))
    return bytes((1, len(fields)-2)) + fields[1].to_bytes(6, 'big') + b''.join(struct.pack('<I', x) for x in fields[2:])


def sd(owner=SID, entries=((0, 0, 0x1f01ff, SID),)):
    owner_bytes = sid_bytes(owner)
    aces = []
    for kind, flags, mask, sid in entries:
        value = sid_bytes(sid)
        aces.append(struct.pack('<BBHI', kind, flags, 8+len(value), mask) + value)
    acl = struct.pack('<BBHHH', 2, 0, 8+sum(map(len, aces)), len(aces), 0) + b''.join(aces)
    return struct.pack('<BBHIIII', 1, 0, 0x8004, 20, 0, 0, 20+len(owner_bytes)) + owner_bytes + acl


class FakeAPI:
    def __init__(self, case):
        self.data = case['artifacts'] | {'policy.json': canonical_bytes(case['policy']),
            'manifest.json': canonical_bytes(case['manifest'])}
        self.opened, self.closed, self.nodes, self.reads = [], [], {}, []
        self.bad = None
        self.fail_open = None
        self.fail_read = None
        self.fail_close = None
        self.changed = False

    def open_root(self, drive):
        return self.open_child(None, drive, True)

    def open_child(self, parent, name, directory):
        if self.fail_open == name:
            raise OSError('synthetic open error')
        assert parent is None or parent in self.nodes
        handle = len(self.opened)+1
        self.opened.append(handle)
        self.nodes[handle] = (name, directory)
        return handle

    def facts(self, handle):
        name, directory = self.nodes[handle]
        facts = FileFacts(directory, 0x10 if directory else 0, 1,
            0 if directory else len(self.data[name]), 1, handle, sd())
        if self.bad and name == self.bad[0]:
            facts = replace(facts, **self.bad[1])
        if self.changed and self.reads and handle == 1:
            facts = replace(facts, security=sd(entries=()))
        return facts

    def read(self, handle, size):
        name, _ = self.nodes[handle]
        self.reads.append(name)
        if self.fail_read == name:
            raise OSError('synthetic read error')
        return self.data[name]

    def close(self, handle):
        self.closed.append(handle)
        if handle == self.fail_close:
            raise OSError('synthetic close error')


def test_snapshot_holds_handles_and_exact_bytes(case):
    api = FakeAPI(case)
    with _load(case['descriptor'], api) as snapshot:
        assert not api.closed
        assert dict(snapshot.artifacts) == case['artifacts']
        with pytest.raises(TypeError):
            snapshot.artifacts['leaf.der'] = b'other'
    assert api.closed == list(reversed(api.opened))
    snapshot.close()
    with pytest.raises(ProtectedFileError):
        _ = snapshot.artifacts


@pytest.mark.parametrize('name,changes', [
    ('C:\\', {'security': sd(owner=SERVICE)}), ('TNC', {'security': sd(entries=((0,0,2,SERVICE),))}),
    ('config', {'attributes': 0x410}), ('config', {'volume': 2}),
    ('policy.json', {'links': 2}), ('policy.json', {'size': 65537}),
    ('manifest.json', {'directory': True}), ('leaf.der', {'attributes': 0x400}),
    ('leaf.der', {'size': 0}), ('leaf.der', {'volume': 2}),
])
def test_failed_inspection_closes_all(case, name, changes):
    api = FakeAPI(case)
    api.bad = name, changes
    with pytest.raises(ProtectedFileError):
        _load(case['descriptor'], api)
    assert api.closed == list(reversed(api.opened))


@pytest.mark.parametrize('name', ['TNC','config','policy.json','manifest.json','leaf.der','roots.pem','revocations.crl'])
def test_open_failure_cleanup(case, name):
    api = FakeAPI(case)
    api.fail_open = name
    with pytest.raises(OSError):
        _load(case['descriptor'], api)
    assert api.closed == list(reversed(api.opened))


@pytest.mark.parametrize('name', ['policy.json','manifest.json','leaf.der','roots.pem','revocations.crl'])
def test_read_failure_cleanup(case, name):
    api = FakeAPI(case)
    api.fail_read = name
    with pytest.raises(OSError):
        _load(case['descriptor'], api)
    assert api.closed == list(reversed(api.opened))


def test_changed_ancestor_fails(case):
    api = FakeAPI(case)
    api.changed = True
    with pytest.raises(ProtectedFileError, match='Snapshot changed'):
        _load(case['descriptor'], api)
    assert api.closed == list(reversed(api.opened))


def test_cleanup_error_does_not_skip_other_handles(case):
    api = FakeAPI(case)
    snapshot = _load(case['descriptor'], api)
    api.fail_close = api.opened[-1]
    with pytest.raises(ProtectedFileError):
        snapshot.close()
    assert api.closed == list(reversed(api.opened))


def test_time_budget_and_cleanup(case):
    api = FakeAPI(case)
    ticks = iter([0, 11])
    with pytest.raises(ProtectedFileError, match='budget'):
        _load(case['descriptor'], api, clock=lambda: next(ticks))
    assert api.closed == api.opened


@pytest.mark.parametrize('mask', [2, 4, 16, 64, 256, 0x10000, 0x40000, 0x80000,
    0x40000000, 0x10000000, 0x02000000])
def test_untrusted_writer_masks(mask):
    with pytest.raises(ProtectedFileError):
        validate_security(sd(entries=((0,0,mask,SERVICE),)), (SID,), (SID,))


@pytest.mark.parametrize('entry', [(0,0,0x80000000,SERVICE), (0,8,0x1f01ff,SERVICE),
    (1,0,0x1f01ff,SERVICE), (0,0,0x1f01ff,SID)])
def test_supported_ace_semantics(entry):
    validate_security(sd(entries=(entry,)), (SID,), (SID,))


@pytest.mark.parametrize('mutation', [lambda b: b[:10], lambda b: b[:20],
    lambda b: b[:2]+b'\x04\x00'+b[4:], lambda b: b[:16]+b'\0'*4+b[20:],
    lambda b: b[:4]+struct.pack('<I', 99999)+b[8:],
    lambda b: b[:21]+b'\xff'+b[22:]])
def test_malformed_security(mutation):
    with pytest.raises(ProtectedFileError):
        parse_security(mutation(sd()))


@pytest.mark.parametrize('kind,flags', [(5,0), (9,0), (0,0x80)])
def test_unsupported_ace(kind, flags):
    with pytest.raises(ProtectedFileError):
        parse_security(sd(entries=((kind, flags, 1, SID),)))


native = pytest.mark.skipif(sys.platform != 'win32', reason='Windows native test')


def open_native_path(api, path):
    handles = []
    try:
        handles.append(api.open_root(path.anchor))
        for part in path.parts[1:]:
            handles.append(api.open_child(handles[-1], part, True))
        return handles
    except BaseException:
        for handle in reversed(handles):
            api.close(handle)
        raise


@native
def test_native_read_security_and_sharing(tmp_path):
    path = tmp_path / 'data.der'
    path.write_bytes(b'exact frozen bytes')
    api = _WindowsFileAPI()
    handles = open_native_path(api, tmp_path)
    try:
        handles.append(api.open_child(handles[-1], path.name, False))
        facts = api.facts(handles[-1])
        owner, entries = parse_security(facts.security)
        assert owner.startswith('S-1-') and entries
        assert api.read(handles[-1], facts.size) == b'exact frozen bytes'
        with pytest.raises(OSError):
            path.write_bytes(b'replace')
        with pytest.raises(OSError):
            path.rename(tmp_path/'moved.der')
        with pytest.raises(OSError):
            tmp_path.rename(tmp_path.with_name(tmp_path.name+'-moved'))
    finally:
        for handle in reversed(handles):
            api.close(handle)
    path.write_bytes(b'after close')


@native
def test_native_existing_writer_and_hardlink(tmp_path):
    path = tmp_path/'data.der'
    path.write_bytes(b'x')
    api = _WindowsFileAPI()
    handles = open_native_path(api, tmp_path)
    try:
        with path.open('r+b'):
            with pytest.raises(ProtectedFileError):
                api.open_child(handles[-1], path.name, False)
        os.link(path, tmp_path/'second.der')
        handle = api.open_child(handles[-1], path.name, False)
        try:
            assert api.facts(handle).links == 2
        finally:
            api.close(handle)
    finally:
        for handle in reversed(handles):
            api.close(handle)


@native
def test_native_full_loader_and_wrong_owner(tmp_path, case):
    (tmp_path/'policy.json').write_bytes(canonical_bytes(case['policy']))
    (tmp_path/'manifest.json').write_bytes(canonical_bytes(case['manifest']))
    for name, data in case['artifacts'].items():
        (tmp_path/name).write_bytes(data)
    # TEST ONLY: nominate observed SIDs to exercise native orchestration in a temp tree.
    # Production never derives its trust allowlists from the files being checked.
    api = _WindowsFileAPI()
    handles = open_native_path(api, tmp_path)
    owners, writers = set(), set()
    try:
        for name in ['policy.json','manifest.json', *case['artifacts']]:
            handles.append(api.open_child(handles[len(tmp_path.parts)-1], name, False))
        for handle in handles:
            owner, entries = parse_security(api.facts(handle).security)
            owners.add(owner)
            writers.update(entry[3] for entry in entries)
    finally:
        for handle in reversed(handles):
            api.close(handle)
    descriptor = case['descriptor'].model_copy(update={'configuration_root': str(tmp_path),
        'trusted_owner_sids': tuple(sorted(owners)), 'trusted_writer_sids': tuple(sorted(writers))})
    with load_protected_provisioning(descriptor) as snapshot:
        assert dict(snapshot.artifacts) == case['artifacts']
    bad = descriptor.model_copy(update={'trusted_owner_sids': (SERVICE,)})
    with pytest.raises(ProtectedFileError, match='Protected provisioning unavailable'):
        load_protected_provisioning(bad)


@native
def test_native_unsafe_dacl_is_rejected(tmp_path):
    from tnc.provenance.windows_identity import read_windows_operator_identity
    current = read_windows_operator_identity().user_sid
    path = tmp_path/'unsafe.der'
    path.write_bytes(b'x')
    # Only this newly created temporary file is changed. No production ACL edits.
    security = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
    kernel = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p]
    convert.restype = w.BOOL
    set_security = security.SetFileSecurityW
    set_security.argtypes = [w.LPCWSTR,w.DWORD,c.c_void_p]
    set_security.restype = w.BOOL
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [c.c_void_p], c.c_void_p
    descriptor = c.c_void_p()
    assert convert(f'D:P(A;;FA;;;{current})(A;;FW;;;AN)', 1, c.byref(descriptor), None)
    try:
        assert set_security(str(path), 0x80000004, descriptor)
    finally:
        assert not kernel.LocalFree(descriptor)
    api = _WindowsFileAPI()
    handles = open_native_path(api, tmp_path)
    try:
        handles.append(api.open_child(handles[-1], path.name, False))
        facts = api.facts(handles[-1])
        owner, _ = parse_security(facts.security)
        with pytest.raises(ProtectedFileError, match='Writer denied'):
            validate_security(facts.security, (owner,), (current,))
    finally:
        for handle in reversed(handles):
            api.close(handle)


@native
def test_native_junction_is_opened_without_following(tmp_path):
    target = tmp_path/'target'
    target.mkdir()
    junction = tmp_path/'junction'
    # Fixed PowerShell program, literal paths passed as environment values.
    env = os.environ | {'TNC_TEST_LINK': str(junction), 'TNC_TEST_TARGET': str(target)}
    subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
        'New-Item -ItemType Junction -Path $env:TNC_TEST_LINK -Target $env:TNC_TEST_TARGET -ErrorAction Stop | Out-Null'],
        env=env, check=True, capture_output=True, timeout=15)
    try:
        api = _WindowsFileAPI()
        handles = open_native_path(api, tmp_path)
        try:
            handles.append(api.open_child(handles[-1], 'junction', True))
            assert api.facts(handles[-1]).attributes & 0x400
        finally:
            for handle in reversed(handles):
                api.close(handle)
    finally:
        os.rmdir(junction)  # Remove only the junction entry, never recurse into target.
    assert target.is_dir()


@native
@pytest.mark.parametrize('directory', [False, True])
def test_native_open_parameters_are_read_only(directory):
    from tnc.provenance.windows_protected_files import _Attributes
    api = object.__new__(_WindowsFileAPI)
    def create(result, access, attributes, status, allocation, fileattrs, share, disposition, options, ea, length):
        attrs = c.cast(attributes, c.POINTER(_Attributes)).contents
        assert attrs.root == 123
        assert access == 0x120080 | (0 if directory else 1)
        assert share == 1 and disposition == 1
        assert options == 0x200000 | 0x20 | (1 if directory else 0x40)
        assert allocation is None and ea is None and not fileattrs and not length
        c.cast(result, c.POINTER(w.HANDLE)).contents.value = 456
        return 0
    api.nt = SimpleNamespace(NtCreateFile=create)
    assert api.open_child(123, 'file.der', directory) == 456


@native
def test_native_security_buffer_is_freed_on_failure():
    from tnc.provenance.windows_protected_files import _FileInfo
    api = object.__new__(_WindowsFileAPI)
    freed = []
    def info(handle, target):
        c.cast(target, c.POINTER(_FileInfo)).contents.links = 1
        return True
    def get(handle, kind, flags, owner, group, dacl, sacl, target):
        c.cast(target, c.POINTER(c.c_void_p)).contents.value = 123
        return 0
    api.kernel = SimpleNamespace(GetFileType=lambda h: 1, GetFileInformationByHandle=info,
        LocalFree=lambda ptr: freed.append(ptr.value))
    api.security = SimpleNamespace(GetSecurityInfo=get, GetSecurityDescriptorLength=lambda p: 65537)
    with pytest.raises(ProtectedFileError):
        api.facts(456)
    assert freed == [123]


def test_public_error_hides_internal_details(monkeypatch, case):
    import tnc.provenance.protected_provisioning as module
    def fail():
        raise OSError('sensitive internal path')
    monkeypatch.setattr(module, '_WindowsFileAPI', fail)
    with pytest.raises(ProtectedFileError, match='^Protected provisioning unavailable$'):
        load_protected_provisioning(case['descriptor'])
