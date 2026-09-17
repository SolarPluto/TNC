from datetime import datetime, timezone

import pytest

from tnc.ingestion.artifacts import FetchArtifact
from tnc.ingestion.storage import artifact_path, store_artifact


def make_artifact(body: bytes) -> FetchArtifact:
    return FetchArtifact.from_bytes(
        artifact_id="artifact-001",
        url="https://example.com/story",
        retrieved_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        content_type="text/html",
        body=body,
    )


def test_store_artifact_writes_exact_bytes(tmp_path):
    artifact = make_artifact(
        b"<html><body>Original report.</body></html>"
    )

    path = store_artifact(tmp_path, artifact)

    assert path == artifact_path(tmp_path, artifact)
    assert path.read_bytes() == artifact.body


def test_store_artifact_rejects_conflicting_existing_bytes(tmp_path):
    artifact = make_artifact(
        b"<html><body>Original report.</body></html>"
    )

    path = artifact_path(tmp_path, artifact)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"different bytes")

    with pytest.raises(ValueError):
        store_artifact(tmp_path, artifact)
