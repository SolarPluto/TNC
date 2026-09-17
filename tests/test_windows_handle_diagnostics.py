import pytest

import test_windows_pipe_process as pipe


class _Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_sample_handle_delta_exercises_nonzero_failure_path(monkeypatch):
    checks = object.__new__(pipe._NativeChecks)
    values = iter((43, 42, 42))
    checks.handles = lambda: next(values)
    clock = _Clock()
    monkeypatch.setattr(pipe.time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(pipe.time, 'sleep', clock.sleep)

    delta, samples = checks.sample_handle_delta(42)

    assert delta == 1
    assert samples == {'baseline': 42, 'T': 1, '+100ms': 0, '+1000ms': 0}
    assert clock.now == pytest.approx(1.0)


def test_handle_delta_diagnostic_preserves_assertion_and_adds_note():
    samples = {'baseline': 42, 'T': 1, '+100ms': 0, '+1000ms': 0}
    error = AssertionError('original failure')

    with pytest.raises(AssertionError) as raised:
        with pipe._handle_delta_diagnostic(samples):
            raise error

    assert raised.value is error
    assert raised.value.__notes__ == [
        'handle persistence (baseline=42): T=1, +100ms=0, +1000ms=0'
    ]
