"""Protocol-scoped state novelty signatures."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .constants import PROTOCOLS
from .errors import validation_error
from .hashing import rust_state_sha256

_VOLATILE_KEYS = frozenset(
    {
        "timestamp",
        "timestamp_ns",
        "offset_micros",
        "latency_micros",
        "duration_micros",
        "duration_ms",
    }
)


def _stable_value(value: Any, field: str) -> Any:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        raise validation_error("floating point observations are not stable", field=field)
    if isinstance(value, list):
        return [_stable_value(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise validation_error("observation keys must be strings", field=field)
        return {
            key: _stable_value(item, f"{field}.{key}")
            for key, item in sorted(value.items())
            if key not in _VOLATILE_KEYS
        }
    raise validation_error("observation is not JSON-compatible", field=field)


def state_signature(observation_value: Any) -> dict[str, Any]:
    if not isinstance(observation_value, Mapping):
        raise validation_error("observation must be an object", field="observation")
    protocol = observation_value.get("protocol")
    if not isinstance(protocol, str) or protocol not in PROTOCOLS:
        raise validation_error("unsupported automotive protocol", field="observation.protocol")
    observations: dict[str, str] = {}
    for key, value in sorted(observation_value.items()):
        if key == "protocol" or key in _VOLATILE_KEYS:
            continue
        stable = _stable_value(value, f"observation.{key}")
        if isinstance(stable, str):
            observations[key] = stable
        elif stable is None:
            observations[key] = "null"
        elif isinstance(stable, bool):
            observations[key] = "true" if stable else "false"
        elif isinstance(stable, int):
            observations[key] = str(stable)
        else:
            observations[key] = json.dumps(
                stable, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
    if not observations:
        raise validation_error(
            "observation must contain at least one stable state field", field="observation"
        )
    digest = rust_state_sha256(protocol, observations)
    return {
        "protocol": protocol,
        "digest": digest,
        "observations": observations,
    }
