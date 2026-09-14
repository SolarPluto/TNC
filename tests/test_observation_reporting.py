"""Check observation persistence through real pytest runs, including failures."""
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest


@pytest.mark.parametrize('fails,terminal', [(False, True), (True, True), (False, False)])
def test_observation_survives_test_outcome(tmp_path, fails, terminal):
    (tmp_path / 'conftest.py').write_text(
        Path(__file__).with_name('conftest.py').read_text(encoding='utf-8'), encoding='utf-8'
    )
    (tmp_path / 'test_sample.py').write_text(
        'def test_sample(emit_observation):\n'
        '    emit_observation("TNC_TEST_OBSERVATION status=EXAMPLE")\n'
        f'    assert {not fails!r}\n', encoding='utf-8'
    )
    args = [sys.executable, '-m', 'pytest', '--junitxml=result.xml', '-o', 'junit_family=legacy']
    args += ['-q', '--tb=no'] if terminal else ['-p', 'no:terminal']
    result = subprocess.run(
        args, cwd=tmp_path, capture_output=True, text=True, timeout=30,
        env={**os.environ, 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'},
    )
    assert result.returncode == int(fails), result.stdout + result.stderr
    if terminal:
        assert result.stdout.count('TNC_TEST_OBSERVATION status=EXAMPLE') == 1
    properties = ET.parse(tmp_path / 'result.xml').findall('.//property')
    assert any(p.attrib == {'name': 'tnc_observation', 'value': 'TNC_TEST_OBSERVATION status=EXAMPLE'} for p in properties)
