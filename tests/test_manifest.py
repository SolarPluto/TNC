from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.ingestion.manifest import CorpusManifestEntry


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