import hashlib

import httpx

from tnc.ingestion.fetcher import fetch_and_store, fetch_url


def test_fetch_url_preserves_exact_response_bytes():
    body = b"<html><body>Fetched report.</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=body,
            request=request,
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        artifact = fetch_url(
            "https://example.com/story",
            client=client,
        )

    assert artifact.url == "https://example.com/story"
    assert artifact.content_type == "text/html; charset=utf-8"
    assert artifact.body == body
    assert artifact.body_hash == hashlib.sha256(body).hexdigest()
    assert artifact.retrieved_at.tzinfo is not None


def test_fetch_and_store_persists_exact_response_bytes(tmp_path):
    body = b"<html><body>Stored report.</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=body,
            request=request,
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        artifact = fetch_and_store(
            "https://example.com/story",
            storage_root=tmp_path,
            client=client,
        )

    stored_path = tmp_path / artifact.body_hash

    assert stored_path.exists()
    assert stored_path.read_bytes() == body
    assert artifact.body == body
