"""Deterministic enumeration validation, independent of the intermittent pipe flake."""
import ctypes as c
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import test_windows_pipe_process as pipe
import test_windows_pipe_native_token as token


_POINTERS = (0xDEADBEEF, 0xC0FFEE01, 0xCAFEBABE)


def _table(entries):
    raw = bytes(c.c_size_t(len(entries))) + bytes(c.c_size_t())
    for pid, value, pointer in entries:
        entry = pipe._SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
        entry.pid, entry.handle, entry.object = pid, value, pointer
        raw += bytes(entry)
    return raw


def _checks(query=None):
    checks = object.__new__(pipe._NativeChecks)
    checks.ntdll = SimpleNamespace(NtQuerySystemInformation=query)
    return checks


def _needed(returned, size):
    c.cast(returned, c.POINTER(pipe.n.DWORD)).contents.value = size


def _no_pointers(text):
    for pointer in _POINTERS:
        assert str(pointer) not in text
        assert format(pointer, 'x') not in text.lower()


def _both_outputs(note, monkeypatch, tmp_path):
    samples = {'baseline': 40, 'T': 1, '+100ms': 1, '+1000ms': 1}
    original = AssertionError('controlled nonzero T')
    with pytest.raises(AssertionError) as caught:
        with pipe._handle_delta_diagnostic(samples, note):
            raise original
    assert caught.value is original
    rendered_note = '\n'.join(caught.value.__notes__)
    assert note in rendered_note
    _no_pointers(rendered_note)

    # Exercise the real JSON transport boundary and the separate evidence writer.
    done = json.loads(json.dumps({'kind': 'done', 'delta': 1, 'handle_identity': note}))
    path = tmp_path / 'evidence.txt'
    monkeypatch.setenv('TNC_HANDLE_DIAGNOSTIC_SOFT_FAIL', '1')
    monkeypatch.setenv('TNC_HANDLE_DIAGNOSTIC_PATH', str(path))
    assert token._record_handle_diagnostic(done, samples, done.pop('handle_identity'))
    evidence = path.read_text(encoding='utf-8')
    assert note in evidence
    _no_pointers(evidence)


def test_disabled_snapshot_is_a_noop(monkeypatch):
    monkeypatch.delenv('TNC_HANDLE_ENUMERATION', raising=False)
    checks = _checks()
    assert checks.handle_values() == (None, 'enumeration disabled')
    assert not hasattr(checks, '_last_handle_snapshot_metrics')


def test_snapshot_uses_offsets_and_pid_filter_without_raw_copies(monkeypatch, capsys):
    """Use a real ctypes array/memmove and the real from_buffer_copy offset path.

    Only .raw is forbidden: a Python buffer fake would not test this ctypes call.
    """
    pid = os.getpid()
    entries = [(pid + 1, i * 4 + 16, _POINTERS[0]) for i in range(3000)]
    entries += [(pid, 4, _POINTERS[1]), (pid, 8, _POINTERS[2])]
    table = _table(entries)

    def allocate(size):
        class NoRaw(c.Array):
            _type_ = c.c_char
            _length_ = size

        def forbidden_raw(self):
            raise AssertionError('full-buffer copy attempted')

        # ctypes installs its own raw descriptor while constructing the type.
        NoRaw.raw = property(forbidden_raw)
        return NoRaw()

    def query(kind, buffer, size, returned):
        assert kind == pipe._SYSTEM_EXTENDED_HANDLE_INFORMATION
        _needed(returned, len(table))
        if size < len(table):
            return pipe._STATUS_INFO_LENGTH_MISMATCH
        c.memmove(buffer, table, len(table))
        return 0

    monkeypatch.setenv('TNC_HANDLE_ENUMERATION', '1')
    monkeypatch.setattr(pipe.c, 'create_string_buffer', allocate)
    checks = _checks(query)
    values, error = checks.handle_values()
    assert error is None
    assert values == {(4, _POINTERS[1]), (8, _POINTERS[2])}
    metrics = checks._last_handle_snapshot_metrics
    assert metrics['system_entries'] == 3002
    assert metrics['process_handles'] == 2
    assert metrics['query_calls'] == 2 and metrics['resize_retries'] == 1
    assert metrics['outcome'] == 'success'
    _no_pointers(capsys.readouterr().out)
    _no_pointers(json.dumps(metrics))


def test_query_and_parse_timings_are_separate(monkeypatch):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(pipe.time, 'perf_counter', lambda: clock.now)
    table = _table([(os.getpid(), 4, _POINTERS[0])] * 3)
    attempts = []

    def query(kind, buffer, size, returned):
        clock.now += 0.003
        attempts.append(size)
        _needed(returned, len(table))
        if len(attempts) == 1:
            return pipe._STATUS_INFO_LENGTH_MISMATCH
        c.memmove(buffer, table, len(table))
        return 0

    entry_type = pipe._SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    original = entry_type.from_buffer_copy

    def parse(source, offset=0):
        clock.now += 0.002
        return original(source, offset)

    monkeypatch.setattr(entry_type, 'from_buffer_copy', staticmethod(parse))
    monkeypatch.setenv('TNC_HANDLE_ENUMERATION', '1')
    checks = _checks(query)
    assert checks.handle_values()[1] is None
    metrics = checks._last_handle_snapshot_metrics
    assert metrics['query_ms'] == pytest.approx(6)
    assert metrics['parse_ms'] == pytest.approx(6)
    assert metrics['total_ms'] == pytest.approx(12)
    assert [call['duration_ms'] for call in metrics['calls']] == pytest.approx([3, 3])
    assert metrics['query_calls'] == 2 and metrics['resize_retries'] == 1


@pytest.mark.parametrize('fault,reason', [
    ('status', 'status=0xC0000022'),
    ('retry', 'buffer sizing did not converge'),
    ('limit', 'buffer limit exceeded'),
    ('truncated', 'returned truncated table'),
    ('length', 'returned invalid length'),
    ('exception', 'RuntimeError'),
])
def test_snapshot_failures_are_diagnostic_only(fault, reason, monkeypatch, tmp_path, capsys):
    def query(kind, buffer, size, returned):
        if fault == 'exception':
            raise RuntimeError('opaque 0xDEADBEEF 3735928559')
        if fault == 'status':
            return c.c_int32(0xC0000022).value
        if fault in ('retry', 'limit'):
            _needed(returned, 0xFFFFFFFF if fault == 'limit' else 0)
            return pipe._STATUS_INFO_LENGTH_MISMATCH
        header = bytes(c.c_size_t(1)) + bytes(c.c_size_t())
        c.memmove(buffer, header, len(header))
        _needed(returned, len(header) if fault == 'truncated' else 1)
        return 0

    monkeypatch.setenv('TNC_HANDLE_ENUMERATION', '1')
    checks = _checks(query)
    snapshot = checks.handle_values()
    assert snapshot[0] is None and reason in snapshot[1]
    metrics = checks._last_handle_snapshot_metrics
    assert metrics['outcome'] == 'unavailable'
    assert metrics['query_calls'] == (8 if fault == 'retry' else 1)
    note = checks.handle_identity_diagnostic(snapshot, (set(), None), (set(), None))
    assert note.startswith('enumeration unavailable: ')
    _both_outputs(note, monkeypatch, tmp_path)
    _no_pointers(capsys.readouterr().out)


@pytest.mark.parametrize('shape,reason', [
    ('zero_length', 'returned no payload length'),
    ('larger_entries', 'table extent mismatch; unsupported layout'),
    ('extra_payload', 'table extent mismatch; unsupported layout'),
])
def test_snapshot_rejects_unknown_extent_before_parsing_entries(
        shape, reason, monkeypatch, tmp_path, capsys):
    """Feed native-shaped buffers to the real parser, not an arithmetic surrogate."""
    entries = [(os.getpid(), 4, _POINTERS[0]), (os.getpid(), 8, _POINTERS[1])]
    table = _table(entries)
    if shape == 'larger_entries':
        # On a 64-bit host this is a real 48-byte stride against an assumed 40.
        # The old <= check passes; parsing with the old stride would misalign entry 2.
        table = bytes(c.c_size_t(len(entries))) + bytes(c.c_size_t())
        for entry in entries:
            table += _table([entry])[2 * c.sizeof(c.c_size_t):] + b'\xA5' * 8
    elif shape == 'extra_payload':
        table += b'\xA5' * 8
    parse_offsets = []
    entry_type = pipe._SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    original = entry_type.from_buffer_copy

    def parse(source, offset=0):
        parse_offsets.append(offset)
        return original(source, offset)

    def query(kind, buffer, size, returned):
        c.memmove(buffer, table, len(table))
        _needed(returned, 0 if shape == 'zero_length' else len(table))
        return 0

    monkeypatch.setenv('TNC_HANDLE_ENUMERATION', '1')
    monkeypatch.setattr(entry_type, 'from_buffer_copy', staticmethod(parse))
    checks = _checks(query)
    snapshot = checks.handle_values()
    assert snapshot == (None, 'SystemExtendedHandleInformation ' + reason)
    assert parse_offsets == []  # Reject before reading even the first entry.
    metrics = checks._last_handle_snapshot_metrics
    assert metrics['outcome'] == 'unavailable' and metrics['process_handles'] is None
    assert metrics['query_calls'] == 1
    assert metrics['calls'][0]['returned_bytes'] == (0 if shape == 'zero_length' else len(table))
    note = checks.handle_identity_diagnostic(snapshot, (set(), None), (set(), None))
    assert note == 'enumeration unavailable: SystemExtendedHandleInformation ' + reason
    _both_outputs(note, monkeypatch, tmp_path)
    _no_pointers(capsys.readouterr().out)


@pytest.mark.parametrize('count', [0, 2])
def test_snapshot_accepts_exact_payload_in_oversized_allocation(count, monkeypatch):
    """Compare the table extent to ReturnLength, not the 64 KiB allocation."""
    entries = [(os.getpid(), 4 * (i + 1), _POINTERS[i]) for i in range(count)]
    table = _table(entries)

    def query(kind, buffer, size, returned):
        assert size > len(table)
        c.memmove(buffer, table, len(table))
        _needed(returned, len(table))
        return 0

    monkeypatch.setenv('TNC_HANDLE_ENUMERATION', '1')
    checks = _checks(query)
    snapshot = checks.handle_values()
    assert snapshot == ({(value, pointer) for _, value, pointer in entries}, None)
    metrics = checks._last_handle_snapshot_metrics
    assert metrics['outcome'] == 'success'
    assert metrics['system_entries'] == metrics['process_handles'] == count


@pytest.mark.parametrize('shape', ['inspect', 'cleanup', 'reused', 'released', 'empty'])
def test_identity_algebra_and_both_pointer_free_outputs(shape, monkeypatch, tmp_path):
    checks = _checks()
    resolved = []

    def object_type(value):
        resolved.append(value)
        return 'Event', None

    checks._object_type = object_type
    baseline = {(4, _POINTERS[0])}
    pre = baseline | {(8, _POINTERS[1]), (12, _POINTERS[2])}
    post = baseline | {(8, _POINTERS[1])}
    expected = ('added_during_inspect=[0x8, 0xC]', 'released_by_cleanup=[0xC]',
                'persisted_past_cleanup=[0x8]', 'phase invariant:')
    if shape == 'cleanup':
        pre = baseline | {(12, _POINTERS[2])}
        expected = ('cleanup-originated survivors=[0x8]', 'persisted_past_cleanup=[0x8]')
    elif shape == 'reused':
        baseline = {(8, _POINTERS[0])}
        pre = post = {(8, _POINTERS[1])}
        expected = ('persisted_past_cleanup=[0x8]',
                    '0x8: prior instance closed, new instance opened (different object)')
    elif shape == 'released':
        pre = baseline
        post = set()
        expected = ('released_by_cleanup=[0x4]', 'persisted_past_cleanup=[]')
    elif shape == 'empty':
        pre = post = baseline
        expected = ('added_during_inspect=[]', 'persisted_past_cleanup=[]')
    note = checks.handle_identity_diagnostic((baseline, None), (pre, None), (post, None))
    for text in expected:
        assert text in note
    assert 12 not in resolved  # Released-only instances are never resolved.
    if shape == 'released':
        assert resolved == []
    _both_outputs(note, monkeypatch, tmp_path)


@pytest.mark.parametrize('overlap', [False, True])
def test_vanished_after_snapshot_is_preserved_in_both_outputs(overlap, monkeypatch, tmp_path):
    checks = _checks()
    checks.ntdll.NtQueryObject = lambda *args: c.c_int32(pipe._STATUS_INVALID_HANDLE).value
    post = {(8, _POINTERS[0])}
    baseline = post if overlap else set()
    note = checks.handle_identity_diagnostic((baseline, None), (post, None), (post, None))
    assert '0x8: vanished between snapshot and resolution' in note
    if overlap:
        assert 'baseline/post-cleanup' in note
    _both_outputs(note, monkeypatch, tmp_path)


@pytest.mark.parametrize('kind,level,expected', [
    (1, None, 'TOKEN type=PRIMARY'),
    (2, 0, 'TOKEN type=IMPERSONATION level=ANONYMOUS'),
    (2, 1, 'TOKEN type=IMPERSONATION level=IDENTIFICATION'),
    (2, 2, 'TOKEN type=IMPERSONATION level=IMPERSONATION'),
    (2, 3, 'TOKEN type=IMPERSONATION level=DELEGATION'),
])
def test_token_metadata_reaches_both_outputs(kind, level, expected, monkeypatch, tmp_path):
    checks = _checks()
    calls = []

    def information(handle, info_class, buffer, size, returned):
        calls.append(info_class)
        value = kind if info_class == pipe._TOKEN_TYPE else level
        c.cast(buffer, c.POINTER(pipe.n.DWORD)).contents.value = value
        _needed(returned, c.sizeof(pipe.n.DWORD))
        return True

    checks.security = SimpleNamespace(GetTokenInformation=information)
    checks._object_type = lambda value: ('Token', None)
    post = {(8, _POINTERS[0])}
    note = checks.handle_identity_diagnostic((set(), None), (post, None), (post, None))
    assert expected in note
    assert calls == ([8] if kind == 1 else [8, 9])
    _both_outputs(note, monkeypatch, tmp_path)


def test_unexpected_query_exception_does_not_disclose_pointers(monkeypatch, tmp_path):
    checks = _checks()

    def fail(*args):
        raise RuntimeError('0xDEADBEEF 3735928559')

    checks.ntdll.NtQueryObject = fail
    post = {(8, _POINTERS[0])}
    note = checks.handle_identity_diagnostic((set(), None), (post, None), (post, None))
    assert '0x8: RuntimeError' in note
    _both_outputs(note, monkeypatch, tmp_path)
    checks._object_type = fail
    note = checks.handle_identity_diagnostic((set(), None), (post, None), (post, None))
    assert note == 'enumeration unavailable: RuntimeError'
    _both_outputs(note, monkeypatch, tmp_path)


def test_zero_delta_does_not_write_evidence(monkeypatch, tmp_path):
    path = tmp_path / 'evidence.txt'
    monkeypatch.setenv('TNC_HANDLE_DIAGNOSTIC_SOFT_FAIL', '1')
    monkeypatch.setenv('TNC_HANDLE_DIAGNOSTIC_PATH', str(path))
    assert not token._record_handle_diagnostic({'delta': 0}, None, 'not exercised')
    assert not path.exists()


class _SelfTestFailure(Exception):
    pass


def _require(condition, message):
    # No assertion rewriting/operand repr in the native child: snapshots are private.
    if not condition:
        raise _SelfTestFailure(message)


def _native_self_test(evidence_path):
    os.environ['TNC_HANDLE_ENUMERATION'] = '1'
    checks = pipe._NativeChecks(pipe.n.NativePipeApi())
    owned = set()
    metrics = []

    def snapshot():
        result = checks.handle_values()
        metrics.append(dict(checks._last_handle_snapshot_metrics))
        _require(result[0] is not None and result[1] is None, 'enumeration unavailable')
        return result

    def event():
        value = checks.api.create_event()
        owned.add(value)
        return value

    def close(value):
        _require(checks.api.close(value), 'test-owned CloseHandle failed')
        owned.remove(value)

    try:
        # Warm up the event path before taking the baseline.
        close(event())
        baseline_count = checks.handles()
        baseline = snapshot()
        retained, released, vanished = event(), event(), event()
        pre = snapshot()
        close(released)
        started = pipe.time.monotonic()
        delta_at_t = checks.handles() - baseline_count
        post = snapshot()
        before_values = {value for value, _ in baseline[0]}
        pre_values = {value for value, _ in pre[0]}
        post_values = {value for value, _ in post[0]}
        _require(not ({retained, released, vanished} & before_values), 'test handle present at baseline')
        _require({retained, released, vanished} <= pre_values, 'pre snapshot missed test handles')
        _require({retained, vanished} <= post_values and released not in post_values,
                 'post snapshot disagrees with controlled cleanup')
        _require(delta_at_t > 0, 'controlled retained handles did not produce nonzero T')
        close(vanished)  # Deterministic snapshot/resolution race.
        delta, samples = checks.sample_handle_delta(baseline_count, (delta_at_t, started))
        note = checks.handle_identity_diagnostic(baseline, pre, post)
        _require('0x%X: type=Event' % retained in note, 'retained Event not identified')
        _require('0x%X: vanished between snapshot and resolution' % vanished in note,
                 'vanished handle not recorded')
        try:
            with pipe._handle_delta_diagnostic(samples, note):
                assert delta == 0, 'controlled nonzero T'
        except AssertionError as error:
            assertion_text = '\n'.join(error.__notes__)
        else:
            raise _SelfTestFailure('strict assertion did not fire')
        os.environ['TNC_HANDLE_DIAGNOSTIC_SOFT_FAIL'] = '1'
        os.environ['TNC_HANDLE_DIAGNOSTIC_PATH'] = str(evidence_path)
        _require(token._record_handle_diagnostic({'delta': delta}, samples, note),
                 'evidence writer did not run')
        evidence = evidence_path.read_text(encoding='utf-8')
        _require(note in assertion_text and note in evidence, 'output paths disagree')
        # Check real opaque addresses without ever printing them or whole snapshots.
        for _, pointer in baseline[0] | pre[0] | post[0]:
            if pointer:
                for text in (assertion_text, evidence):
                    _require(str(pointer) not in text and format(pointer, 'x') not in text.lower(),
                             'opaque pointer reached an output path')
        print('TNC native enumeration self-test: ' + json.dumps({
            'controlled_nonzero_T': delta_at_t, 'retained_event_identified': True,
            'vanished_handle_recorded': True, 'both_outputs_pointer_free': True,
            'snapshots': metrics,
            'snapshot_budget_met': all(item['total_ms'] < 100 for item in metrics),
        }, sort_keys=True), flush=True)
    finally:
        failures = [value for value in owned if not checks.api.close(value)]
        _require(not failures, 'test-owned handle cleanup failed')


@pytest.mark.skipif(sys.platform != 'win32', reason='Isolated native Windows enumeration self-test')
def test_native_enumeration_self_test(tmp_path, capsys):
    # Only this disposable child opts in; ordinary pipe tests remain unchanged.
    evidence_path = tmp_path / 'native-evidence.txt'
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(evidence_path)],
                            capture_output=True, text=True, timeout=60)
    with capsys.disabled():
        print(result.stdout, end='')  # Preserve timings even on a successful pytest run.
    assert result.returncode == 0, result.stdout + result.stderr
    assert evidence_path.is_file()
    assert 'retained_event_identified": true' in result.stdout
    assert 'vanished_handle_recorded": true' in result.stdout
    assert 'both_outputs_pointer_free": true' in result.stdout


if __name__ == '__main__':
    try:
        _native_self_test(Path(sys.argv[1]))
    except BaseException as error:
        # Never dump child locals or exception repr, which could contain addresses.
        reason = str(error) if type(error) is _SelfTestFailure else type(error).__name__
        print('TNC native enumeration self-test failed: ' + reason, flush=True)
        raise SystemExit(1)
