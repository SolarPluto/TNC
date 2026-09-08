from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.ingestion.manifest import (
    CorpusManifestEntry,
    append_manifest_entry,
    read_manifest,
    serialize_manifest_entry,
)


def test_corpus_manifest_entry_preserves_retrieval_coordinates():
    retrieved_at = datetime(
        2026,
        9,
        8,
        13,
        15,
        tzinfo=timezone.utc,
    )

    entry = CorpusManifestEntry(
        requested_url="https://example.com/story",
        final_url="https://example.com/story?canonical=1",
        retrieved_at=retrieved_at,
        status_code=200,
        content_type="text/html; charset=utf-8",
        body_hash="abc123",
        storage_path="corpus/artifacts/abc123",
    )

    assert entry.requested_url == "https://example.com/story"
    assert entry.final_url == "https://example.com/story?canonical=1"
    assert entry.retrieved_at == retrieved_at
    assert entry.status_code == 200
    assert entry.content_type == "text/html; charset=utf-8"
    assert entry.body_hash == "abc123"
    assert entry.storage_path == "corpus/artifacts/abc123"


def test_corpus_manifest_entry_is_immutable():
    entry = CorpusManifestEntry(
        requested_url="https://example.com/story",
        final_url="https://example.com/story",
        retrieved_at=datetime.now(timezone.utc),
        status_code=200,
        content_type="text/html",
        body_hash="abc123",
        storage_path="corpus/artifacts/abc123",
    )

    with pytest.raises(ValidationError):
        entry.status_code = 404


@pytest.fixture
def entry():
    return CorpusManifestEntry(
        requested_url="https://example.com/café",
        final_url="https://example.com/story",
        retrieved_at=datetime(2026, 9, 8, 13, 15, tzinfo=timezone.utc),
        status_code=200,
        content_type="text/html",
        body_hash="abc123",
        storage_path="corpus/abc123",
    )


def test_manifest_deterministic_utf8_jsonl(tmp_path, entry):
    path = tmp_path / "nested" / "manifest.jsonl"
    expected = (
        '{"body_hash":"abc123","content_type":"text/html",'
        '"final_url":"https://example.com/story",'
        '"requested_url":"https://example.com/café",'
        '"retrieved_at":"2026-09-08T13:15:00Z","status_code":200,'
        '"storage_path":"corpus/abc123"}'
    )
    assert serialize_manifest_entry(entry) == expected
    assert append_manifest_entry(path, entry) is True
    assert path.read_bytes() == (expected + "\n").encode("utf-8")
    assert read_manifest(path) == [entry]
    assert append_manifest_entry(path, read_manifest(path)[0]) is False
    assert path.read_bytes() == (expected + "\n").encode("utf-8")


@pytest.mark.parametrize("changes", [
    {"retrieved_at": datetime(2026, 9, 9, tzinfo=timezone.utc)},
    {"requested_url": "https://example.com/another"},
    {"body_hash": "different", "storage_path": "corpus/different"},
])
def test_manifest_preserves_distinct_records_and_prefix(tmp_path, entry, changes):
    path = tmp_path / "manifest.jsonl"
    append_manifest_entry(path, entry)
    prefix = path.read_bytes()
    second = entry.model_copy(update=changes)
    assert append_manifest_entry(path, second) is True
    assert path.read_bytes().startswith(prefix)
    assert read_manifest(path) == [entry, second]
    assert append_manifest_entry(path, entry) is False
    assert read_manifest(path) == [entry, second]


@pytest.mark.parametrize("bad", [b'{', b'{}\n', b'\n', b'not json\n'])
def test_manifest_rejects_corruption_without_modifying_file(tmp_path, entry, bad):
    path = tmp_path / "manifest.jsonl"
    append_manifest_entry(path, entry)
    original = path.read_bytes() + bad
    path.write_bytes(original)
    with pytest.raises(ValueError):
        append_manifest_entry(path, entry)
    assert path.read_bytes() == original


def test_missing_and_empty_manifest(tmp_path, entry):
    path = tmp_path / "manifest.jsonl"
    assert read_manifest(path) == []
    assert not path.exists()
    path.touch()
    assert read_manifest(path) == []
    assert append_manifest_entry(path, entry)
