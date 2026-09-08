from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx

from tnc.ingestion.artifacts import FetchArtifact
from tnc.ingestion.manifest import CorpusManifestEntry, append_manifest_entry
from tnc.ingestion.storage import store_artifact


def _fetch_response_and_artifact(
    url: str,
    *,
    client: httpx.Client,
) -> tuple[httpx.Response, FetchArtifact]:
    response = client.get(url)
    response.raise_for_status()

    artifact = FetchArtifact.from_bytes(
        artifact_id=str(uuid4()),
        url=str(response.url),
        retrieved_at=datetime.now(timezone.utc),
        content_type=response.headers.get(
            "content-type",
            "application/octet-stream",
        ),
        body=response.content,
    )

    return response, artifact


def fetch_url(
    url: str,
    *,
    client: httpx.Client | None = None,
) -> FetchArtifact:
    owns_client = client is None

    if client is None:
        client = httpx.Client(follow_redirects=True)

    try:
        _, artifact = _fetch_response_and_artifact(
            url,
            client=client,
        )
        return artifact
    finally:
        if owns_client:
            client.close()


def fetch_and_store(
    url: str,
    *,
    storage_root: Path,
    manifest_path: Path | None = None,
    client: httpx.Client | None = None,
) -> tuple[FetchArtifact, CorpusManifestEntry]:
    owns_client = client is None

    if client is None:
        client = httpx.Client(follow_redirects=True)

    try:
        response, artifact = _fetch_response_and_artifact(
            url,
            client=client,
        )

        stored_path = store_artifact(
            storage_root,
            artifact,
        )

        manifest_entry = CorpusManifestEntry(
            requested_url=url,
            final_url=str(response.url),
            retrieved_at=artifact.retrieved_at,
            status_code=response.status_code,
            content_type=artifact.content_type,
            body_hash=artifact.body_hash,
            storage_path=str(stored_path),
        )

        if manifest_path is not None:
            append_manifest_entry(manifest_path, manifest_entry)

        return artifact, manifest_entry
    finally:
        if owns_client:
            client.close()