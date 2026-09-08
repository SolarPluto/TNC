import hashlib

import httpx

from tnc.ingestion.fetcher import fetch_url


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