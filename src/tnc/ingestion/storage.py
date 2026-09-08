from pathlib import Path

from tnc.ingestion.artifacts import FetchArtifact


def artifact_path(
    root: Path,
    artifact: FetchArtifact,
) -> Path:
    return root / artifact.body_hash


def store_artifact(
    root: Path,
    artifact: FetchArtifact,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)

    path = artifact_path(root, artifact)

    if path.exists():
        existing = path.read_bytes()
        if existing != artifact.body:
            raise ValueError(
                "Existing artifact bytes do not match the expected hash."
            )
        return path

    path.write_bytes(artifact.body)
    return path