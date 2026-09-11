"""Repository-hosted historical CLI. No user-selectable evidence or review paths."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from tnc.provenance.admission import ArchiveAvailabilityRecord, FrozenCorpus, FrozenObject, FrozenVersion
from tnc.provenance.historical_replay import HistoricalReplayEngine
from tnc.provenance.review_store import InMemoryReviewStore
from tnc.spans.snapshot import Snapshot


# Deployment configuration is anchored to the source checkout, never cwd or env.
# Wheels without the repository corpus intentionally fail closed at startup.
_CORPUS_ROOT = Path(__file__).resolve().parents[2] / "corpus" / "tib_run_a"
_CAPTURES = (
    ("abc-early", "abc-early-archive-20130521120016", "abc_early_archive_20130521120016_evidence.json"),
    ("abc-correction", "abc-archive-20130521155330", "abc_archive_20130521155330_evidence.json"),
    ("abc-correction", "abc-archive-20130521175757", "abc_archive_20130521175757_evidence.json"),
)
_ORIGINALS = {
    "abc-early": "http://abcnews.go.com/US/oklahoma-tornado-20-children-51-dead-horrific-damage/story?id=19219367",
    "abc-correction": "http://abcnews.go.com/US/oklahoma-tornado-deaths-revised-24-including-children/story?id=19222656",
}


def aware_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError("Missing timezone")
        return result.astimezone(timezone.utc)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Time must be ISO-8601 with Z or a UTC offset") from exc


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _local_file(relative: str) -> Path:
    root = _CORPUS_ROOT.resolve(strict=True)
    target = (root / relative).resolve(strict=True)
    if not target.is_relative_to(root):
        raise ValueError("Corpus path escapes host root")
    return target


def load_host():
    """Build an empty review authority and fixed archive inventory internally.

    Repo files are host configuration, not credentials. No review verdict is
    imported from sidecars. Pending metadata never becomes a ledger approval.
    """
    sources = _read_json(_local_file("sources.json"))
    manifest = [json.loads(line) for line in
                _local_file("archive_manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    versions, availability, indexes = [], [], {}
    for document_id, version_id, filename in _CAPTURES:
        evidence = _read_json(_local_file(filename))
        entries = [v for v in sources["archive_versions"] if v["version_id"] == version_id]
        if len(entries) != 1:
            raise ValueError("Missing or ambiguous host inventory")
        entry = entries[0]
        if (entry["source_id"] != document_id or evidence["source_id"] != document_id
                or evidence["version_id"] != version_id
                or entry["replay_admission_status"] != "pending"
                or evidence["replay_admission_status"] != "pending"
                or any(entry[k] != evidence[k] for k in ("html_body_hash", "index_body_hash", "archive_capture_at"))):
            raise ValueError("Inconsistent host inventory")
        record = ArchiveAvailabilityRecord(
            evidence_record_id=f"corpus/tib_run_a/{filename}", document_id=document_id,
            version_id=version_id, original_url=_ORIGINALS[document_id],
            body_hash=evidence["html_body_hash"], capture_at=aware_time(evidence["archive_capture_at"]),
            index_body_hash=evidence["index_body_hash"], archive_payload_digest=evidence["archive_payload_digest"],
        )
        archive_url = ("https://web.archive.org/web/" + record.capture_at.strftime("%Y%m%d%H%M%S")
                       + "id_/" + record.original_url)
        if (evidence.get("original_url", record.original_url) != record.original_url
                or evidence.get("archive_capture_url", archive_url) != archive_url):
            raise ValueError("Unexpected archive URL")
        retrievals = [r for r in manifest if r["body_hash"] == record.body_hash
                      and r["requested_url"] == archive_url and r["status_code"] == 200]
        if len(retrievals) != 1:
            raise ValueError("Missing or ambiguous retrieval record")
        versions.append(FrozenVersion(document_id=document_id, version_id=version_id,
            original_url=record.original_url, body_hash=record.body_hash,
            observed_at=aware_time(retrievals[0]["retrieved_at"]),
            body=_local_file(f"objects/{record.body_hash}").read_bytes()))
        indexes[record.index_body_hash] = FrozenObject(body_hash=record.index_body_hash,
            body=_local_file(f"objects/{record.index_body_hash}").read_bytes())
        availability.append(record)
    store = InMemoryReviewStore(allowed_reviewers=frozenset())
    engine = HistoricalReplayEngine(corpus=FrozenCorpus(versions=tuple(versions),
        archive_indexes=tuple(indexes.values())), availability=tuple(availability),
        transitions=(), review_store=store)
    return engine, store


def _blocked(reason, status="rejected", evidence=()):
    return {"status": status, "reason_codes": list(reason), "evidence_record_ids": list(evidence)}


def run_historical(*, document_id, version_id, query_time) -> int:
    try:
        engine, store = load_host()
    except Exception:
        # Do not print exception text: it can contain host paths or article bytes.
        print(json.dumps(_blocked(("HOST_CONFIGURATION_ERROR",))))
        return 3
    try:
        outcome = engine.execute(document_id=document_id, version_id=version_id, query_time=query_time)
        if outcome.status != "released":
            evidence = outcome.admission.evidence_record_ids if outcome.admission else ()
            print(json.dumps(_blocked(outcome.reason_codes, outcome.status, evidence)))
            return 2
        receipt = outcome.receipt
        if receipt is None:
            raise ValueError("Missing release receipt")
        releases = [r for r in store.release_history() if r.receipt == receipt]
        if len(releases) != 1:
            raise ValueError("Receipt missing from validated outbox")
        record = releases[0]
        if (record.request.availability.document_id != document_id
                or record.request.availability.version_id != version_id
                or record.request.query_time != query_time):
            raise ValueError("Release request mismatch")
        payload = json.loads(record.request.payload)
        if len(payload["snapshots"]) != 1:
            raise ValueError("Expected one snapshot")
        snapshot = Snapshot.model_validate(payload["snapshots"][0])
        if snapshot.captured_at != query_time:
            raise ValueError("Snapshot time mismatch")
        output = json.dumps({"status": "released", "receipt_id": receipt.release_id,
                             "snapshot": snapshot.model_dump(mode="json")})
    except Exception:
        # A failure after commit may still leave a release in the private outbox.
        # This message asserts no successful output, not rollback of prior commit.
        print(json.dumps(_blocked(("EXECUTION_FAILED",))))
        return 3
    print(output)
    return 0
