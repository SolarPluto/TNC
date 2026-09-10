import sys
from pathlib import Path

import pytest

from tnc import main


FIXTURE = Path(__file__).parent / "fixtures" / "article_v1.html"


def test_parse_cli(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["tnc", "parse", str(FIXTURE)])

    main()

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert captured.err == ""
    assert len(lines) == 8
    assert lines[0] == "0\theading\tBridge closes after structural failure"
    assert lines[6] == (
        "6\tupdate_notice\tUpdate: Officials later said five people were injured."
    )
    assert lines[7] == (
        "7\tcorrection\tCorrection: An earlier version of this article misstated "
        "the time of the incident."
    )


@pytest.mark.parametrize("content", [None, b"\xff", b"<html></html>"])
def test_parse_cli_reports_input_errors(content, tmp_path, monkeypatch, capsys):
    path = tmp_path / "input.html"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(sys, "argv", ["tnc", "parse", str(path)])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "tnc: error:" in captured.err
    assert "Traceback" not in captured.err
