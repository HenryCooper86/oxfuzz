"""Sandbox-scoped artifact resolution without accepting host paths on JSONL."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from .errors import SidecarError, validation_error
from .hashing import bounded_file_sha256, canonical_json_bytes, sha256_bytes

_ARTIFACT_KEYS = frozenset({"artifact_id", "sha256", "media_type", "size_bytes"})
_ARTIFACT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ArtifactStore(Protocol):
    def resolve(self, artifact: Any, max_bytes: int) -> Path: ...

    def write_bytes(self, prefix: str, media_type: str, value: bytes) -> dict[str, object]: ...

    def write_json(self, prefix: str, media_type: str, value: Any) -> dict[str, object]: ...


def validate_artifact_ref(value: Any) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise validation_error("artifact must be an object with string keys", field="artifact")
    missing = sorted(_ARTIFACT_KEYS - set(value))
    unknown = sorted(set(value) - _ARTIFACT_KEYS)
    if missing or unknown:
        raise validation_error(
            "artifact fields do not match the contract",
            field="artifact",
            details={"missing_fields": missing, "unknown_fields": unknown},
        )
    artifact_id = value["artifact_id"]
    digest = value["sha256"]
    media_type = value["media_type"]
    size_bytes = value["size_bytes"]
    if not isinstance(artifact_id, str) or not _ARTIFACT_ID.fullmatch(artifact_id):
        raise validation_error(
            "artifact_id is not a safe staged identifier", field="artifact.artifact_id"
        )
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise validation_error("artifact sha256 is not a lowercase digest", field="artifact.sha256")
    if (
        not isinstance(media_type, str)
        or "/" not in media_type
        or any(character.isspace() for character in media_type)
    ):
        raise validation_error("artifact media_type is invalid", field="artifact.media_type")
    if (
        isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or not 1 <= size_bytes <= 1_024 * 1_024 * 1_024
    ):
        raise validation_error(
            "artifact size_bytes must be within 1..=1073741824",
            field="artifact.size_bytes",
        )
    return {
        "artifact_id": artifact_id,
        "sha256": digest,
        "media_type": media_type,
        "size_bytes": size_bytes,
    }


class UnavailableArtifactStore:
    def resolve(self, artifact: Any, max_bytes: int) -> Path:
        del artifact, max_bytes
        raise SidecarError(
            "artifact_store_unavailable",
            "no sandbox artifact store was configured",
            retryable=False,
        )

    def write_json(self, prefix: str, media_type: str, value: Any) -> dict[str, object]:
        del prefix, media_type, value
        raise SidecarError(
            "artifact_store_unavailable",
            "no sandbox artifact store was configured",
            retryable=False,
        )

    def write_bytes(self, prefix: str, media_type: str, value: bytes) -> dict[str, object]:
        del prefix, media_type, value
        raise SidecarError(
            "artifact_store_unavailable",
            "no sandbox artifact store was configured",
            retryable=False,
        )


class FilesystemArtifactStore:
    """Resolve IDs beneath fixed sandbox roots supplied out of band."""

    def __init__(self, input_root: Path, output_root: Path) -> None:
        self.input_root = input_root.resolve(strict=True)
        self.output_root = output_root.resolve(strict=True)
        if not self.input_root.is_dir() or not self.output_root.is_dir():
            raise SidecarError(
                "artifact_store_unavailable",
                "artifact roots must be existing directories",
                retryable=False,
            )

    @classmethod
    def from_environment(cls) -> FilesystemArtifactStore | UnavailableArtifactStore:
        input_root = os.environ.get("OXFUZZ_SCAPY_INPUT_ROOT")
        output_root = os.environ.get("OXFUZZ_SCAPY_OUTPUT_ROOT")
        if not input_root or not output_root:
            return UnavailableArtifactStore()
        return cls(Path(input_root), Path(output_root))

    def resolve(self, artifact: Any, max_bytes: int) -> Path:
        reference = validate_artifact_ref(artifact)
        candidate = self.input_root / reference["artifact_id"]
        if candidate.is_symlink() or not candidate.is_file():
            raise SidecarError(
                "artifact_error",
                "staged artifact is absent or is not a regular file",
                field="artifact.artifact_id",
            )
        resolved = candidate.resolve(strict=True)
        if resolved.parent != self.input_root:
            raise SidecarError(
                "artifact_error",
                "staged artifact escaped the sandbox input root",
                field="artifact.artifact_id",
            )
        declared_size = reference["size_bytes"]
        if not isinstance(declared_size, int) or declared_size > max_bytes:
            raise SidecarError(
                "limit_exceeded",
                "staged artifact exceeds the operation input bound",
                field="artifact.size_bytes",
            )
        if resolved.stat().st_size != declared_size:
            raise SidecarError(
                "artifact_error",
                "staged artifact size does not match the request",
                field="artifact.size_bytes",
            )
        observed_digest = bounded_file_sha256(resolved, max_bytes)
        if observed_digest != reference["sha256"]:
            raise SidecarError(
                "artifact_hash_mismatch",
                "staged artifact digest does not match the request",
                field="artifact.sha256",
                details={"observed_sha256": observed_digest},
            )
        return resolved

    def write_bytes(self, prefix: str, media_type: str, value: bytes) -> dict[str, object]:
        if not _ARTIFACT_ID.fullmatch(prefix):
            raise validation_error("artifact prefix is invalid", field="prefix")
        if not isinstance(value, bytes) or not value:
            raise validation_error("artifact bytes must be non-empty", field="value")
        digest = sha256_bytes(value)
        artifact_id = f"{prefix}-{digest}.json"
        destination = self.output_root / artifact_id
        if destination.exists():
            if destination.is_symlink() or bounded_file_sha256(destination, len(value)) != digest:
                raise SidecarError(
                    "artifact_error",
                    "existing output artifact does not match deterministic content",
                    field="artifact.artifact_id",
                )
        else:
            try:
                with destination.open("xb") as output:
                    output.write(value)
            except OSError as error:
                raise SidecarError(
                    "artifact_error",
                    "output artifact could not be written",
                    details={"reason": str(error)},
                ) from error
        return {
            "artifact_id": artifact_id,
            "sha256": digest,
            "media_type": media_type,
            "size_bytes": len(value),
        }

    def write_json(self, prefix: str, media_type: str, value: Any) -> dict[str, object]:
        return self.write_bytes(prefix, media_type, canonical_json_bytes(value))
