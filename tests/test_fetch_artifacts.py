from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tnc.ingestion.artifacts import FetchArtifact


def test_fetch_artifact_is_immutable():
    artifact = FetchArtifact(
        artifact_id="artifact-001",
        url="https://example.com/story",
        retrieved_at=datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        ),
        content_type="text/html",
        body=b"<html><body>Original report.</body></html>",
        body_hash="hash-001",
    )

    with pytest.raises(ValidationError):
        artifact.body = b"Modified report."