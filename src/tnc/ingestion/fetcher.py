from datetime import datetime, timezone
from uuid import uuid4

import httpx

from tnc.ingestion.artifacts import FetchArtifact


def fetch_url(
    url: str,
    *,
    client: httpx.Client | None = None,
) -> FetchArtifact:
    owns_client = client is None

    if client is None:
        client = httpx.Client(follow_redirects=True)

    try:
        response = client.get(url)
        response.raise_for_status()

        return FetchArtifact.from_bytes(
            artifact_id=str(uuid4()),
            url=str(response.url),
            retrieved_at=datetime.now(timezone.utc),
            content_type=response.headers.get(
                "content-type",
                "application/octet-stream",
            ),
            body=response.content,
        )
    finally:
        if owns_client:
            client.close()