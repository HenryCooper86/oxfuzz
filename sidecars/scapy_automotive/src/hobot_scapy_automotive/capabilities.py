"""Deterministic capability discovery for the optional Scapy runtime."""

from __future__ import annotations

from importlib import metadata
from typing import Any

from .constants import ADAPTER_VERSION, PROTOCOLS, SCHEMA_VERSION


def _distribution_version(distribution: str) -> tuple[bool, str | None]:
    try:
        return True, metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return False, None


def discover_runtime() -> dict[str, str | bool | None]:
    scapy_available, scapy_version = _distribution_version("scapy")
    python_can_available, python_can_version = _distribution_version("python-can")
    return {
        "scapy_available": scapy_available,
        "scapy_version": scapy_version,
        "python_can_available": python_can_available,
        "python_can_version": python_can_version,
    }


def capability_report(
    *,
    scapy_available: bool,
    scapy_version: str | None,
    python_can_available: bool,
    python_can_version: str | None,
) -> dict[str, Any]:
    scapy_compatible = scapy_available and scapy_version == "2.7.0"
    python_can_compatible = python_can_available and python_can_version == "4.6.1"
    modes = ["offline_pcap"]
    capabilities = ["generate_mutations", "build_replay_plan", "state_feedback"]
    if scapy_compatible:
        capabilities.insert(0, "decode_capture")
    if python_can_compatible:
        modes.extend(["virtual_can", "physical_bench"])
        capabilities.extend(["execute_virtual", "execute_physical"])
    return {
        "adapter_name": "scapy-sidecar",
        "adapter_version": ADAPTER_VERSION,
        "schema_versions": [SCHEMA_VERSION],
        "protocols": list(PROTOCOLS),
        "modes": modes,
        "capabilities": capabilities,
        "limits": {
            "max_events": 4_096,
            "max_payload_bytes": 1_048_576,
            "max_duration_ms": 300_000,
            "max_rate_per_second": 1_000,
        },
    }
