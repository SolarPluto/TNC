from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CorpusManifestEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    requested_url: str
    final_url: str
    retrieved_at: datetime
    status_code: int
    content_type: str
    body_hash: str
    storage_path: str