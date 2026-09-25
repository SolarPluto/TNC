import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_demo_fixture_is_in_built_wheel(tmp_path):
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    wheels = list(tmp_path.glob("tnc_provenance-*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as wheel:
        assert "tnc/fixtures/demo.html" in wheel.namelist()
