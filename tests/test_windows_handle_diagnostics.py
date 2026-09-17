import pytest

import test_windows_pipe_process as pipe


class _Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _checks(*values):
    checks = object.__new__(pipe._NativeChecks)
    samples = iter(values)
    checks.handles = lambda: next(samples)
    return checks


def _patch_clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(pipe.time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(pipe.time, 'sleep', clock.sleep)
    return clock


def test_sample_handle_delta_zero_returns_without_waiting(monkeypatch):
    checks = _checks(42)
    clock = _patch_clock(monkeypatch)

    assert checks.sample_handle_delta(42) == (0, None)
    assert clock.sleeps == []
    assert clock.now == 0.0


def test_sample_handle_delta_exercises_transient_failure_path(monkeypatch):
    checks = _checks(43, 42, 42)
    clock = _patch_clock(monkeypatch)

    delta, samples = checks.sample_handle_delta(42)

    assert delta == 1
    assert samples == {'baseline': 42, 'T': 1, '+100ms': 0, '+1000ms': 0}
    assert clock.sleeps == pytest.approx([0.1, 0.9])
    assert clock.now == pytest.approx(1.0)


def test_sample_handle_delta_exercises_persistent_failure_path(monkeypatch):
    checks = _checks(43, 43, 43)
    clock = _patch_clock(monkeypatch)

    delta, samples = checks.sample_handle_delta(42)

    assert delta == 1
    assert samples == {'baseline': 42, 'T': 1, '+100ms': 1, '+1000ms': 1}
    assert clock.sleeps == pytest.approx([0.1, 0.9])
    assert clock.now == pytest.approx(1.0)


def test_handle_delta_diagnostic_notes_assertion_failure():
    samples = {'baseline': 42, 'T': 1, '+100ms': 0, '+1000ms': 0}

    with pytest.raises(AssertionError) as raised:
        with pipe._handle_delta_diagnostic(samples):
            assert 1 == 0

    assert raised.value.__notes__ == [
        'handle persistence (baseline=42): T=1, +100ms=0, +1000ms=0'
    ]


def test_handle_delta_diagnostic_preserves_exception_identity():
    samples = {'baseline': 42, 'T': 1, '+100ms': 0, '+1000ms': 0}
    error = AssertionError('original failure')

    with pytest.raises(AssertionError) as raised:
        with pipe._handle_delta_diagnostic(samples):
            raise error

    assert raised.value is error
