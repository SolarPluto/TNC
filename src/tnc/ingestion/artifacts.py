from datetime import datetime
from hashlib import sha256

from pydantic import BaseModel, ConfigDict


class FetchArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    artifact_id: str
    url: str
    retrieved_at: datetime
    content_type: str
    body: bytes
    body_hash: str

    @classmethod
    def from_bytes(
        cls,
        *,
        artifact_id: str,
        url: str,
        retrieved_at: datetime,
        content_type: str,
        body: bytes,
    ) -> "FetchArtifact":
        return cls(
            artifact_id=artifact_id,
            url=url,
            retrieved_at=retrieved_at,
            content_type=content_type,
            body=body,
            body_hash=sha256(body).hexdigest(),
        )
