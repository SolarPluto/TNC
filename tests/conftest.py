"""Persist diagnostic observations on reports, including successful tests."""
import pytest


@pytest.fixture
def emit_observation(record_property):
    # Store before security assertions: a later failure must retain the evidence.
    # Report properties also survive when the terminal plugin is disabled.
    def emit(line):
        record_property('tnc_observation', line)
    return emit


def pytest_terminal_summary(terminalreporter):
    """Use pytest's injected reporter, without per-test plugin lookups."""
    seen = set()
    for reports in terminalreporter.stats.values():
        for report in reports:
            for name, value in getattr(report, 'user_properties', ()):
                key = (report.nodeid, value)
                if name == 'tnc_observation' and key not in seen:
                    terminalreporter.write_line(value)
                    seen.add(key)
