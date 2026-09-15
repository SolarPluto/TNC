"""Failure injection for diagnostic token cleanup; never impersonates a client."""
from contextlib import ExitStack
import ctypes as c
import os
from pathlib import Path
import subprocess
import sys

import pytest

import _native_harness as harness


class Containment(BaseException):
    pass


class FakeAPI:
    def __init__(self, close_result=True, revert_result=True):
        self.calls = []
        self.close_result = close_result
        self.revert_result = revert_result

    def close(self, token):
        self.calls.append(('close', token))
        if isinstance(self.close_result, Exception):
            raise self.close_result
        return self.close_result

    def revert(self):
        self.calls.append(('revert',))
        if isinstance(self.revert_result, BaseException):
            raise self.revert_result
        return self.revert_result

    def fail_fast(self):
        self.calls.append(('fail_fast',))
        raise Containment()


@pytest.mark.parametrize('result', [False, RuntimeError('native close raised')])
def test_failed_close_is_not_retried_and_still_reverts(monkeypatch, result):
    monkeypatch.setattr(c, 'get_last_error', lambda: 6, raising=False)
    api = FakeAPI(close_result=result)
    cleanup = ExitStack()
    cleanup.callback(harness._revert_or_fail_fast, api)
    cleanup.callback(harness._checked_cleanup, api.close, 123)
    with pytest.raises(pytest.fail.Exception, match='cleanup (failed|raised)'):
        try:
            cleanup.close()
        finally:
            cleanup.close()
    assert api.calls == [('close', 123), ('revert',)]


@pytest.mark.parametrize('result', [False, RuntimeError('native close raised')])
def test_cleanup_failure_preserves_original_assertion(monkeypatch, result):
    monkeypatch.setattr(c, 'get_last_error', lambda: 6, raising=False)
    api = FakeAPI(close_result=result)
    with pytest.raises(AssertionError, match='original finding') as failure:
        with ExitStack() as cleanup:
            cleanup.callback(harness._revert_or_fail_fast, api)
            cleanup.callback(harness._checked_cleanup, api.close, 123)
            raise AssertionError('original finding')
    assert any('cleanup ' in note for note in failure.value.__notes__)
    assert api.calls == [('close', 123), ('revert',)]


@pytest.mark.parametrize('result', [False, RuntimeError('native revert raised')])
def test_revert_failure_requires_containment_without_retry(result):
    api = FakeAPI(revert_result=result)
    with pytest.raises(Containment):
        with ExitStack() as cleanup:
            cleanup.callback(harness._revert_or_fail_fast, api)
    assert api.calls == [('revert',), ('fail_fast',)]


@pytest.mark.skipif(os.name != 'nt', reason='Real Windows native fail_fast path')
@pytest.mark.parametrize('raises', [False, True])
def test_native_fail_fast_terminates_child_without_unwinding(tmp_path, raises):
    # Only revert is injected. Keep the real NativePipeTokenAPI.fail_fast and
    # os._exit; no actual impersonation or natural OS revert failure is induced.
    # Requires tnc importable in bare sys.executable (installed by uv sync or
    # supplied on PYTHONPATH), independently of pytest's test-path insertion.
    tests_directory = str(Path(__file__).resolve().parent)
    script = f'''
import atexit
from pathlib import Path
import sys
sys.path.insert(0, {tests_directory!r})
import _native_harness as harness
from tnc.provenance.windows_pipe_token import NativePipeTokenAPI
api = NativePipeTokenAPI()
assert api._fake is False
def failed_revert():
    if {raises!r}:
        raise RuntimeError('injected revert exception')
    return False
api.revert = failed_revert
atexit.register(lambda: Path('atexit').write_text('unexpected'))
Path('started').write_text('native fail_fast selected')
try:
    harness._revert_or_fail_fast(api)
finally:
    Path('unwound').write_text('unexpected')
Path('continued').write_text('unexpected')
'''
    result = subprocess.run(
        [sys.executable, '-c', script], cwd=tmp_path,
        capture_output=True, text=True, timeout=15,
    )
    assert (tmp_path / 'started').exists(), result.stdout + result.stderr
    assert result.returncode == 78, result.stdout + result.stderr
    assert not any((tmp_path / name).exists() for name in ('unwound', 'continued', 'atexit'))
