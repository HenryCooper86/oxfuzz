"""Canonical JSON and SHA-256 helpers for artifacts and transcripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .errors import SidecarError


def canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise SidecarError(
            "serialization_error",
            "value is not canonical JSON",
            details={"reason": str(error)},
        ) from error
    return encoded.encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def rust_transcript_bytes(events: list[dict[str, Any]]) -> bytes:
    """Encode the immutable transcript artifact exactly as Rust hashes it."""
    canonical = sorted(events, key=lambda event: event["sequence"])
    normalized = [
        {
            "sequence": event["sequence"],
            "protocol": event["protocol"],
            "direction": event["direction"],
            "offset_micros": event["offset_micros"],
            "payload_hex": event["payload_hex"],
            "metadata": dict(sorted(event["metadata"].items())),
        }
        for event in canonical
    ]
    return json.dumps(
        [1, "automotive-transcript", normalized],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def rust_transcript_sha256(events: list[dict[str, Any]]) -> str:
    """Match `hf_automotive::canonical_transcript_hash` byte for byte."""
    return sha256_bytes(rust_transcript_bytes(events))


def rust_state_sha256(protocol: str, observations: dict[str, str]) -> str:
    """Match `hf_automotive::StateSignature::from_observations`."""
    encoded = json.dumps(
        [1, "automotive-state", protocol, dict(sorted(observations.items()))],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(encoded)


def bounded_file_sha256(path: Path, max_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(64 * 1_024):
                total += len(chunk)
                if total > max_bytes:
                    raise SidecarError(
                        "limit_exceeded",
                        "artifact exceeds max_payload_bytes",
                        field="limits.max_payload_bytes",
                        details={"observed_bytes": total, "maximum_bytes": max_bytes},
                    )
                digest.update(chunk)
    except SidecarError:
        raise
    except OSError as error:
        raise SidecarError(
            "artifact_error",
            "artifact could not be read",
            field="path",
            details={"reason": str(error)},
        ) from error
    return digest.hexdigest()
