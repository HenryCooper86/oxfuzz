"""Bounded offline PCAP decoding with an injectable decoder boundary."""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol

from .constants import SCHEMA_VERSION
from .errors import SidecarError, validation_error
from .hashing import bounded_file_sha256, canonical_sha256


class PcapDecoder(Protocol):
    def decode(self, path: Path, max_events: int) -> list[dict[str, Any]]: ...


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    return str(value)


class ScapyPcapDecoder:
    """A Scapy decoder that only opens a caller-provided PCAP file."""

    def decode(self, path: Path, max_events: int) -> list[dict[str, Any]]:
        try:
            from scapy.utils import PcapReader
        except ImportError as error:
            raise SidecarError(
                "dependency_unavailable",
                "Scapy is required for offline PCAP decoding",
                field="runtime.scapy",
            ) from error

        packets: list[dict[str, Any]] = []
        try:
            with PcapReader(str(path)) as reader:
                for sequence, packet in enumerate(reader):
                    layer_names: list[str] = []
                    layer_fields: dict[str, Any] = {}
                    for layer_class in packet.layers():
                        layer = packet.getlayer(layer_class)
                        layer_name = str(getattr(layer, "name", layer_class.__name__))
                        layer_names.append(layer_name)
                        layer_fields[layer_name] = _json_safe(getattr(layer, "fields", {}))
                    try:
                        timestamp_ns = int(Decimal(str(packet.time)) * Decimal(1_000_000_000))
                    except (InvalidOperation, ValueError):
                        timestamp_ns = 0
                    packets.append(
                        {
                            "sequence": sequence,
                            "timestamp_ns": timestamp_ns,
                            "layers": layer_names,
                            "raw_hex": bytes(packet).hex(),
                            "fields": layer_fields,
                        }
                    )
                    if len(packets) > max_events:
                        break
        except SidecarError:
            raise
        except (OSError, ValueError) as error:
            raise SidecarError(
                "pcap_decode_error",
                "Scapy could not decode the offline capture",
                field="path",
                details={"reason": str(error)},
            ) from error
        return packets


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise validation_error("limit must be a positive integer", field=field)
    return value


def decode_pcap(
    path_value: str | Path, limits_value: Any, *, decoder: PcapDecoder | None = None
) -> dict[str, Any]:
    path = Path(path_value)
    if path.is_symlink() or not path.is_file():
        raise validation_error("path must identify a regular, non-symlink file", field="path")
    if not isinstance(limits_value, Mapping):
        raise validation_error("limits must be an object", field="limits")
    unknown = sorted(set(limits_value) - {"max_events", "max_payload_bytes"})
    if unknown:
        raise validation_error(
            "PCAP limits contain unknown fields",
            field="limits",
            details={"unknown_fields": unknown},
        )
    max_events = _positive_integer(limits_value.get("max_events"), "limits.max_events")
    max_payload_bytes = _positive_integer(
        limits_value.get("max_payload_bytes"), "limits.max_payload_bytes"
    )
    capture_sha256 = bounded_file_sha256(path, max_payload_bytes)
    selected_decoder = decoder or ScapyPcapDecoder()
    packets = selected_decoder.decode(path, max_events)
    if not isinstance(packets, list) or len(packets) > max_events:
        raise SidecarError(
            "limit_exceeded",
            "decoded capture exceeds max_events",
            field="limits.max_events",
            details={"maximum_events": max_events},
        )
    if not all(isinstance(packet, Mapping) for packet in packets):
        raise SidecarError(
            "decoder_contract_error",
            "PCAP decoder returned an invalid packet record",
            retryable=False,
        )
    result = {
        "schema_version": SCHEMA_VERSION,
        "capture_sha256": capture_sha256,
        "packet_count": len(packets),
        "packets": [dict(packet) for packet in packets],
    }
    result["artifact_sha256"] = canonical_sha256(result)
    return result
