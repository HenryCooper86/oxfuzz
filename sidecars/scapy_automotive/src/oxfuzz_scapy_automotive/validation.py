"""Fail-closed validation for offline, virtual CAN, and physical bench modes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .constants import MODES, PROTOCOLS
from .errors import SidecarError, validation_error

DANGEROUS_UDS_SERVICES = frozenset(
    {
        0x11,  # ECU reset
        0x27,  # security access
        0x28,  # communication control
        0x2E,  # write data by identifier
        0x31,  # routine control
        0x34,  # request download
        0x35,  # request upload
        0x36,  # transfer data
        0x37,  # request transfer exit
        0x3D,  # write memory by address
        0x85,  # control DTC setting
    }
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "mode",
        "protocol",
        "physical_enabled",
        "interface",
        "interface_allowlist",
        "arbitration_id_allowlist",
        "service_allowlist",
        "allow_dangerous_services",
        "limits",
        "approval",
        "sidecar_image_sha256",
    }
)
_LIMIT_KEYS = frozenset(
    {"max_events", "max_payload_bytes", "max_duration_ms", "max_rate_per_second"}
)
_APPROVAL_KEYS = frozenset(
    {"approval_id", "approved_by", "approved_at", "scope_sha256", "sidecar_image_sha256"}
)
_MODE_CAPS = {
    "offline_pcap": {
        "max_events": 100_000,
        "max_payload_bytes": 64 * 1_024 * 1_024,
        "max_duration_ms": 3_600_000,
        "max_rate_per_second": 100_000,
    },
    "virtual_can": {
        "max_events": 10_000,
        "max_payload_bytes": 16 * 1_024 * 1_024,
        "max_duration_ms": 3_600_000,
        "max_rate_per_second": 1_000,
    },
    "physical_bench": {
        "max_events": 1_000,
        "max_payload_bytes": 1 * 1_024 * 1_024,
        "max_duration_ms": 300_000,
        "max_rate_per_second": 100,
    },
}
_VCAN_INTERFACE = re.compile(r"vcan[0-9]{1,3}\Z")
_PHYSICAL_INTERFACE = re.compile(r"[A-Za-z0-9_.:-]{1,32}\Z")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise validation_error("value must be an object", field=field)
    if not all(isinstance(key, str) for key in value):
        raise validation_error("object keys must be strings", field=field)
    return value


def _strict_keys(value: Mapping[str, Any], allowed: frozenset[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise validation_error(
            "object contains unknown fields",
            field=field,
            details={"unknown_fields": unknown},
        )


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise validation_error("value must be a non-empty string", field=field)
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise validation_error("value must be a boolean", field=field)
    return value


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise validation_error("value must be an integer", field=field)
    if value < minimum or value > maximum:
        raise validation_error(
            "integer is outside the allowed range",
            field=field,
            details={"minimum": minimum, "maximum": maximum, "observed": value},
        )
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise validation_error("value must be a non-empty array", field=field)
    items = [_string(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(set(items)) != len(items):
        raise validation_error("array values must be unique", field=field)
    return sorted(items)


def _integer_list(value: Any, field: str, maximum: int, *, required: bool) -> list[int]:
    if not isinstance(value, list) or (required and not value):
        qualifier = "non-empty " if required else ""
        raise validation_error(f"value must be a {qualifier}array", field=field)
    items = [_integer(item, f"{field}[{index}]", 0, maximum) for index, item in enumerate(value)]
    if len(set(items)) != len(items):
        raise validation_error("array values must be unique", field=field)
    return sorted(items)


def _validate_limits(value: Any, mode: str) -> dict[str, int]:
    limits = _mapping(value, "limits")
    _strict_keys(limits, _LIMIT_KEYS, "limits")
    missing = sorted(_LIMIT_KEYS - set(limits))
    if missing:
        raise validation_error(
            "limits are incomplete", field="limits", details={"missing_fields": missing}
        )
    result: dict[str, int] = {}
    for name, cap in _MODE_CAPS[mode].items():
        result[name] = _integer(limits[name], f"limits.{name}", 1, cap)
    return result


def _validate_approval(config: Mapping[str, Any]) -> dict[str, str]:
    approval = _mapping(config.get("approval"), "approval")
    _strict_keys(approval, _APPROVAL_KEYS, "approval")
    missing = sorted(_APPROVAL_KEYS - set(approval))
    if missing:
        raise validation_error(
            "approval evidence is incomplete",
            field="approval",
            details={"missing_fields": missing},
        )
    approved_at = _string(approval["approved_at"], "approval.approved_at")
    if not _UTC_TIMESTAMP.fullmatch(approved_at):
        raise validation_error(
            "approved_at must be an RFC 3339 UTC timestamp", field="approval.approved_at"
        )
    scope_sha256 = _string(approval["scope_sha256"], "approval.scope_sha256")
    if not _SHA256.fullmatch(scope_sha256):
        raise validation_error(
            "scope_sha256 must be a lowercase SHA-256 digest", field="approval.scope_sha256"
        )
    sidecar_image_sha256 = _string(
        approval["sidecar_image_sha256"], "approval.sidecar_image_sha256"
    )
    if not _SHA256.fullmatch(sidecar_image_sha256):
        raise validation_error(
            "sidecar_image_sha256 must be a lowercase SHA-256 digest",
            field="approval.sidecar_image_sha256",
        )
    return {
        "approval_id": _string(approval["approval_id"], "approval.approval_id"),
        "approved_by": _string(approval["approved_by"], "approval.approved_by"),
        "approved_at": approved_at,
        "scope_sha256": scope_sha256,
        "sidecar_image_sha256": sidecar_image_sha256,
    }


def validate_operation_config(config_value: Any) -> dict[str, Any]:
    config = _mapping(config_value, "config")
    _strict_keys(config, _TOP_LEVEL_KEYS, "config")

    mode = _string(config.get("mode"), "mode")
    if mode not in MODES:
        raise validation_error("unsupported automotive mode", field="mode")
    protocol = _string(config.get("protocol"), "protocol")
    if protocol not in PROTOCOLS:
        raise validation_error("unsupported automotive protocol", field="protocol")
    physical_enabled = _boolean(config.get("physical_enabled", False), "physical_enabled")
    limits = _validate_limits(config.get("limits"), mode)
    sidecar_image_sha256_value = config.get("sidecar_image_sha256")
    sidecar_image_sha256: str | None = None
    if sidecar_image_sha256_value is not None:
        sidecar_image_sha256 = _string(sidecar_image_sha256_value, "sidecar_image_sha256")
        if not _SHA256.fullmatch(sidecar_image_sha256):
            raise validation_error(
                "sidecar_image_sha256 must be a lowercase SHA-256 digest",
                field="sidecar_image_sha256",
            )

    result: dict[str, Any] = {
        "mode": mode,
        "protocol": protocol,
        "physical_enabled": physical_enabled,
        "limits": limits,
    }
    if mode == "offline_pcap":
        forbidden = sorted(
            field
            for field in (
                "interface",
                "interface_allowlist",
                "arbitration_id_allowlist",
                "service_allowlist",
                "allow_dangerous_services",
                "approval",
            )
            if field in config
        )
        if physical_enabled or forbidden:
            raise validation_error(
                (
                    "offline mode cannot configure an interface, allowlist, approval, "
                    "or physical access"
                ),
                field="config",
                details={"forbidden_fields": forbidden},
            )
        return result

    interface = _string(config.get("interface"), "interface")
    interface_allowlist = _string_list(config.get("interface_allowlist"), "interface_allowlist")
    if interface not in interface_allowlist:
        raise SidecarError(
            "interface_not_allowed",
            "requested interface is not present in the interface allowlist",
            field="interface",
        )
    interface_pattern = _VCAN_INTERFACE if mode == "virtual_can" else _PHYSICAL_INTERFACE
    if not interface_pattern.fullmatch(interface):
        raise validation_error(
            "interface name is not valid for the selected mode", field="interface"
        )

    arbitration_ids = _integer_list(
        config.get("arbitration_id_allowlist"),
        "arbitration_id_allowlist",
        0x1FFFFFFF,
        required=True,
    )
    service_required = protocol == "uds" or mode == "physical_bench"
    services = _integer_list(
        config.get("service_allowlist", []),
        "service_allowlist",
        0xFF,
        required=service_required,
    )
    allow_dangerous = _boolean(
        config.get("allow_dangerous_services", False), "allow_dangerous_services"
    )
    dangerous = sorted(DANGEROUS_UDS_SERVICES.intersection(services))
    if dangerous and not allow_dangerous:
        raise SidecarError(
            "dangerous_service_denied",
            "dangerous UDS services are denied by default",
            field="service_allowlist",
            details={"denied_services": dangerous},
        )

    result.update(
        {
            "interface": interface,
            "interface_allowlist": interface_allowlist,
            "arbitration_id_allowlist": arbitration_ids,
            "service_allowlist": services,
            "allow_dangerous_services": allow_dangerous,
        }
    )
    if mode == "virtual_can":
        if physical_enabled:
            raise validation_error(
                "virtual CAN cannot enable physical access", field="physical_enabled"
            )
        if "approval" in config:
            raise validation_error(
                "virtual CAN does not accept physical approval evidence", field="approval"
            )
        return result

    if not physical_enabled:
        raise SidecarError(
            "physical_mode_disabled",
            "physical bench mode is disabled unless physical_enabled is true",
            field="physical_enabled",
        )
    if sidecar_image_sha256 is None:
        raise validation_error(
            "physical bench mode requires an immutable sidecar image identity",
            field="sidecar_image_sha256",
        )
    approval = _validate_approval(config)
    if approval["sidecar_image_sha256"] != sidecar_image_sha256:
        raise SidecarError(
            "approval_scope_mismatch",
            "approval image identity does not match the runtime image identity",
            field="approval.sidecar_image_sha256",
        )
    result["sidecar_image_sha256"] = sidecar_image_sha256
    result["approval"] = approval
    return result
