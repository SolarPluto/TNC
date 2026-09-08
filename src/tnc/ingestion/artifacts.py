from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FetchArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    artifact_id: str
    url: str
    retrieved_at: datetime
    content_type: str
    body: bytes
    body_hash: str