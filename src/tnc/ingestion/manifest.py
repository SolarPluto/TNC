import json
import os
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class CorpusManifestEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    requested_url: str
    final_url: str
    retrieved_at: datetime
    status_code: int
    content_type: str
    body_hash: str
    storage_path: str


def serialize_manifest_entry(entry: CorpusManifestEntry) -> str:
    """Return deterministic JSON with sorted keys and no platform newlines."""
    return json.dumps(
        entry.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def read_manifest(path: Path) -> list[CorpusManifestEntry]:
    """Read records in append order; reject malformed or incomplete manifests."""
    if not path.exists():
        return []
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        raise ValueError("Manifest must end with a newline; possible partial write.")
    entries = []
    for number, line in enumerate(data.splitlines(), start=1):
        try:
            entries.append(CorpusManifestEntry.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid manifest record on line {number}.") from exc
    return entries


def append_manifest_entry(path: Path, entry: CorpusManifestEntry) -> bool:
    """Append and sync a record, returning False for an exact record retry.

    Single-writer use only: callers must serialize access to this manifest.
    Identity includes every field, so later retrievals of identical bytes remain
    separate evidence records. Existing bytes are never rewritten or repaired.
    """
    serialized = serialize_manifest_entry(entry)
    existing = read_manifest(path)
    if any(serialize_manifest_entry(record) == serialized for record in existing):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as manifest:
        manifest.write((serialized + "\n").encode("utf-8"))
        manifest.flush()
        os.fsync(manifest.fileno())
    return True
