import hashlib

import httpx
import pytest

from tnc.ingestion.fetcher import fetch_and_store, fetch_url
from tnc.ingestion.manifest import read_manifest


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


def test_fetch_and_store_persists_artifact_and_manifest(tmp_path):
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
        artifact, manifest_entry = fetch_and_store(
            "https://example.com/story",
            storage_root=tmp_path,
            client=client,
        )

    stored_path = tmp_path / artifact.body_hash

    assert stored_path.exists()
    assert stored_path.read_bytes() == body

    assert manifest_entry.requested_url == "https://example.com/story"
    assert manifest_entry.final_url == "https://example.com/story"
    assert manifest_entry.status_code == 200
    assert manifest_entry.content_type == "text/html; charset=utf-8"
    assert manifest_entry.body_hash == artifact.body_hash
    assert manifest_entry.retrieved_at == artifact.retrieved_at
    assert manifest_entry.storage_path == str(stored_path)

def test_fetch_and_store_appends_after_freezing(tmp_path, monkeypatch):
    from tnc.ingestion import fetcher
    original_append = fetcher.append_manifest_entry
    manifest = tmp_path / "manifest.jsonl"

    def checked_append(path, entry):
        assert (tmp_path / "artifacts" / entry.body_hash).read_bytes() == b"evidence"
        return original_append(path, entry)

    monkeypatch.setattr(fetcher, "append_manifest_entry", checked_append)
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, content=b"evidence")

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        _, entry = fetch_and_store(
            "https://example.com/start", storage_root=tmp_path / "artifacts",
            manifest_path=manifest, client=client,
        )
    assert read_manifest(manifest) == [entry]
    assert entry.final_url == "https://example.com/final"
    assert entry.requested_url == "https://example.com/start"


@pytest.mark.parametrize("failure", ["http", "storage", "manifest"])
def test_fetch_and_store_failure_preserves_manifest(tmp_path, monkeypatch, failure):
    from tnc.ingestion import fetcher
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_bytes(b"" if failure != "manifest" else b"broken")
    original = manifest.read_bytes()
    def fail_storage(*args):
        raise OSError("storage unavailable")
    if failure == "storage":
        monkeypatch.setattr(fetcher, "store_artifact", fail_storage)
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(500 if failure == "http" else 200, content=b"evidence")
    )) as client:
        expected_error = {"http": httpx.HTTPStatusError, "storage": OSError, "manifest": ValueError}[failure]
        with pytest.raises(expected_error):
            fetch_and_store("https://example.com/story", storage_root=tmp_path / "artifacts",
                            manifest_path=manifest, client=client)
    assert manifest.read_bytes() == original
    if failure == "manifest":
        assert (tmp_path / "artifacts" / hashlib.sha256(b"evidence").hexdigest()).read_bytes() == b"evidence"
