"""Strict stdin/stdout JSON Lines entrypoint."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from typing import Any, TextIO

from .artifacts import ArtifactStore, FilesystemArtifactStore, UnavailableArtifactStore
from .contract import make_error_response, process_request
from .errors import SidecarError
from .hashing import sha256_bytes
from .pcap import PcapDecoder
from .replay import Transport, UnavailableTransport
from .transport import create_configured_transport
from .validation import validate_operation_config


def run_jsonl(
    source: TextIO,
    destination: TextIO,
    *,
    runtime: Any | None = None,
    artifact_store: ArtifactStore | None = None,
    decoder: PcapDecoder | None = None,
    execution_config: Any = None,
    transport: Transport | None = None,
    transport_factory: Callable[[Any], Transport] | None = None,
) -> int:
    failed = False
    selected_store = artifact_store or FilesystemArtifactStore.from_environment()
    selected_config = execution_config
    selected_transport = transport
    if selected_transport is None and execution_config is not None:
        try:
            selected_config = validate_operation_config(execution_config)
            factory = transport_factory or create_configured_transport
            selected_transport = factory(selected_config)
        except SidecarError:
            selected_transport = UnavailableTransport()
    for line_number, raw_line in enumerate(source, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            request = json.loads(
                line,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON number: {value}")
                ),
            )
            response = process_request(
                request,
                runtime=runtime,
                artifact_store=selected_store,
                decoder=decoder,
                execution_config=selected_config,
                transport=selected_transport,
            )
        except (json.JSONDecodeError, ValueError) as error:
            structured_error = SidecarError(
                "invalid_json",
                "input line is not valid strict JSON",
                retryable=False,
                details={"line_number": line_number, "reason": str(error)},
            )
            response = make_error_response(
                "unknown",
                structured_error,
                request_evidence={"input_sha256": sha256_bytes(line.encode("utf-8"))},
            )
        destination.write(
            json.dumps(
                response, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
            )
            + "\n"
        )
        destination.flush()
        failed = failed or not response["ok"]
    return 1 if failed else 0


def main() -> int:
    execution_config: Any = None
    raw_config = os.environ.get("HOBOT_SCAPY_EXECUTION_CONFIG_JSON")
    if raw_config:
        if len(raw_config.encode("utf-8")) > 64 * 1_024:
            execution_config = {"invalid": "execution config exceeds 64 KiB"}
        else:
            try:
                execution_config = json.loads(raw_config)
            except json.JSONDecodeError:
                execution_config = {"invalid": "execution config is not JSON"}
    try:
        artifact_store: ArtifactStore = FilesystemArtifactStore.from_environment()
    except SidecarError:
        artifact_store = UnavailableArtifactStore()
    return run_jsonl(
        sys.stdin,
        sys.stdout,
        artifact_store=artifact_store,
        execution_config=execution_config,
    )


if __name__ == "__main__":
    raise SystemExit(main())
