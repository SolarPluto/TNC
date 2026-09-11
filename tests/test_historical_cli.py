import json
import sys

import pytest

from tnc import main
import tnc.historical_cli as cli
from test_historical_admission import candidate, AT
from test_historical_replay import engine, store_for


def invoke(monkeypatch, capsys, *extra, document="abc-early", version="abc-early-archive-20130521120016",
           time="2013-05-21T18:00:00Z"):
    monkeypatch.setattr(sys, "argv", ["tnc", "historical-replay", "--document", document,
        "--version", version, "--time", time, *extra])
    with pytest.raises(SystemExit) as result:
        main()
    return result.value.code, capsys.readouterr()


@pytest.mark.parametrize("document,version", [(d, v) for d, v, _ in cli._CAPTURES])
def test_real_captures_print_only_blocked_metadata(monkeypatch, capsys, document, version):
    code, captured = invoke(monkeypatch, capsys, document=document, version=version)
    data = json.loads(captured.out)
    assert code == 2 and captured.err == ""
    assert set(data) == {"status", "reason_codes", "evidence_record_ids"}
    assert data["status"] == "unverified" and data["reason_codes"] == ["MISSING_REVIEW"]
    assert len(data["evidence_record_ids"]) == 1


def test_pre_capture_is_rejected(monkeypatch, capsys):
    code, output = invoke(monkeypatch, capsys, time="2013-05-21T12:00:15Z")
    assert code == 2
    assert json.loads(output.out)["reason_codes"] == ["CAPTURE_TIME_AFTER_QUERY"]


@pytest.mark.parametrize("time", ["2013-05-21", "2013-05-21T12:00:16", "invalid"])
def test_timezone_required_before_loading(monkeypatch, capsys, time):
    def forbidden():
        pytest.fail("Invalid arguments reached host loader")
    monkeypatch.setattr(cli, "load_host", forbidden)
    code, output = invoke(monkeypatch, capsys, time=time)
    assert code == 2 and output.out == ""
    assert "ISO-8601" in output.err


@pytest.mark.parametrize("option", ["--reviews", "--evidence", "--corpus", "--config", "--doc"])
def test_override_and_abbreviated_flags_rejected(monkeypatch, capsys, option):
    code, output = invoke(monkeypatch, capsys, option, "injected")
    assert code == 2 and output.out == "" and "unrecognized arguments" in output.err


def test_startup_failure_is_sanitized(monkeypatch, capsys):
    def broken():
        raise ValueError("PRIVATE PATH AND ARTICLE TEXT")
    monkeypatch.setattr(cli, "load_host", broken)
    code, output = invoke(monkeypatch, capsys)
    assert code == 3 and output.err == ""
    assert json.loads(output.out) == {"status": "rejected", "reason_codes": ["HOST_CONFIGURATION_ERROR"],
                                    "evidence_record_ids": []}


def test_loader_ignores_cwd_and_environment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TNC_CORPUS_ROOT", str(tmp_path))
    (tmp_path/"sources.json").write_text('{"reviews": "approved"}')
    wrapper, store = cli.load_host()
    assert store.history() == store.release_history() == ()
    assert len(wrapper._corpus.versions) == 3


def test_missing_host_corpus_fails_closed(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_CORPUS_ROOT", tmp_path)
    code, output = invoke(monkeypatch, capsys)
    assert code == 3 and json.loads(output.out)["reason_codes"] == ["HOST_CONFIGURATION_ERROR"]


def test_success_prints_snapshot_from_committed_outbox(candidate, monkeypatch, capsys):
    store = store_for(candidate)
    wrapper = engine(candidate, store)
    monkeypatch.setattr(cli, "load_host", lambda: (wrapper, store))
    code, output = invoke(monkeypatch, capsys, document="doc", version="version", time=AT.isoformat())
    data = json.loads(output.out)
    assert code == 0 and output.err == ""
    assert set(data) == {"status", "receipt_id", "snapshot"}
    assert data["receipt_id"] == store.release_history()[0].receipt.release_id
    assert data["snapshot"]["claims"][0]["state"] == "first_reported"


def test_post_commit_read_failure_does_not_print_payload(candidate, monkeypatch, capsys):
    store = store_for(candidate)
    wrapper = engine(candidate, store)
    monkeypatch.setattr(cli, "load_host", lambda: (wrapper, store))
    def corrupt():
        raise ValueError("SECRET article text")
    monkeypatch.setattr(store, "release_history", corrupt)
    code, output = invoke(monkeypatch, capsys, document="doc", version="version", time=AT.isoformat())
    assert code == 3 and "SECRET" not in output.out and output.err == ""
    assert json.loads(output.out)["reason_codes"] == ["EXECUTION_FAILED"]
    assert len(store._release_state[0]) == 1  # Failure does not promise rollback.


def test_loader_does_not_import_sidecar_approval(monkeypatch):
    original = cli._read_json
    def changed(path):
        data = original(path)
        if path.name.endswith("_evidence.json"):
            data["replay_admission_status"] = "approved"
        return data
    monkeypatch.setattr(cli, "_read_json", changed)
    with pytest.raises(ValueError, match="Inconsistent"):
        cli.load_host()
