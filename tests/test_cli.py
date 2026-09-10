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
@pytest.mark.parametrize("command", ["parse", "assertions"])
def test_cli_reports_input_errors(command, content, tmp_path, monkeypatch, capsys):
    path = tmp_path / "input.html"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(sys, "argv", ["tnc", command, str(path)])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "tnc: error:" in captured.err
    assert "Traceback" not in captured.err


def test_assertions_cli(monkeypatch, capsys):
    fixture = Path(__file__).parent / "fixtures" / "assertions_v1.html"
    monkeypatch.setattr(sys, "argv", ["tnc", "assertions", str(fixture)])

    main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "Admitted: 2",
        "  Officials reported five people were injured.",
        "    Source spans: 0",
        "  Engineers confirmed inspections were underway.",
        "    Source spans: 1",
        "Rejected: 0",
    ]


def test_assertions_cli_with_no_candidates(tmp_path, monkeypatch, capsys):
    fixture = tmp_path / "no_candidates.html"
    fixture.write_text(
        "<article><p>The bridge remained closed.</p></article>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["tnc", "assertions", str(fixture)])

    main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "Admitted: 0",
        "Rejected: 0",
    ]


def test_assertions_cli_shows_rejection_reason(monkeypatch, capsys):
    from tnc.spans.extractor import extract_assertion_candidates

    fixture = Path(__file__).parent / "fixtures" / "assertions_v1.html"

    def extract_invalid_candidate(spans):
        candidate = extract_assertion_candidates(spans)[0]
        return [
            candidate.model_copy(update={"span_ids": ["missing-span"]})
        ]

    monkeypatch.setattr(
        "tnc.spans.pipeline.extract_assertion_candidates",
        extract_invalid_candidate,
    )
    monkeypatch.setattr(sys, "argv", ["tnc", "assertions", str(fixture)])

    main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "Admitted: 0",
        "Rejected: 1",
        "  Officials reported five people were injured.",
        "    Reason: Unknown span IDs: missing-span",
    ]


def test_parse_cli_selects_one_span(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["tnc", "parse", str(FIXTURE), "--span", "6"],
    )

    main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "6\tupdate_notice\tUpdate: Officials later said five people were injured.",
    ]


@pytest.mark.parametrize("ordinal", [-1, 999])
def test_parse_cli_rejects_missing_span(ordinal, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["tnc", "parse", str(FIXTURE), "--span", str(ordinal)],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"No source span with ordinal {ordinal}" in captured.err
    assert "Traceback" not in captured.err
