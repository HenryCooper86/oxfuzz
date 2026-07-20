"""Deterministic, field-aware automotive payload mutation planning."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from .constants import PROTOCOLS, SCHEMA_VERSION
from .errors import validation_error
from .hashing import canonical_json_bytes, canonical_sha256, sha256_bytes

_REQUEST_KEYS = frozenset(
    {"protocol", "payload_hex", "deterministic_seed", "mutation_count", "fields"}
)
_FIELD_KEYS = frozenset({"name", "offset", "width", "kind"})
_FIELD_KINDS = frozenset({"integer", "service", "subfunction", "raw"})
_MAX_PAYLOAD_BYTES = 4_096
_MAX_MUTATIONS = 4_096


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise validation_error("value must be an object with string keys", field=field)
    return value


def _strict_keys(value: Mapping[str, Any], allowed: frozenset[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise validation_error(
            "object contains unknown fields", field=field, details={"unknown_fields": unknown}
        )


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise validation_error(
            "value must be an integer in the allowed range",
            field=field,
            details={"minimum": minimum, "maximum": maximum},
        )
    return value


def _payload(value: Any, field: str = "payload_hex") -> bytes:
    if not isinstance(value, str) or not value or len(value) % 2:
        raise validation_error("payload must be non-empty even-length hexadecimal", field=field)
    try:
        payload = bytes.fromhex(value)
    except ValueError as error:
        raise validation_error("payload must be hexadecimal", field=field) from error
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise validation_error(
            "payload exceeds the mutation planner limit",
            field=field,
            details={"maximum_bytes": _MAX_PAYLOAD_BYTES},
        )
    return payload


def _derived_fields(protocol: str, payload: bytes) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for offset in range(len(payload)):
        if protocol == "uds" and offset == 0:
            name, kind = "service", "service"
        elif protocol == "uds" and offset == 1:
            name, kind = "subfunction", "subfunction"
        else:
            name, kind = f"payload_byte_{offset}", "raw"
        fields.append({"name": name, "offset": offset, "width": 1, "kind": kind})
    return fields


def _validated_fields(value: Any, payload_size: int) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise validation_error("fields must be a non-empty array", field="fields")
    fields: list[dict[str, Any]] = []
    occupied: set[int] = set()
    names: set[str] = set()
    for index, raw_field in enumerate(value):
        field_name = f"fields[{index}]"
        item = _mapping(raw_field, field_name)
        _strict_keys(item, _FIELD_KEYS, field_name)
        if set(item) != _FIELD_KEYS:
            raise validation_error("field definition is incomplete", field=field_name)
        name = item["name"]
        kind = item["kind"]
        if not isinstance(name, str) or not name or name in names:
            raise validation_error(
                "field name must be non-empty and unique", field=f"{field_name}.name"
            )
        if not isinstance(kind, str) or kind not in _FIELD_KINDS:
            raise validation_error("unsupported field kind", field=f"{field_name}.kind")
        offset = _integer(item["offset"], f"{field_name}.offset", 0, payload_size - 1)
        width = _integer(item["width"], f"{field_name}.width", 1, min(8, payload_size))
        if offset + width > payload_size:
            raise validation_error("field extends beyond the payload", field=field_name)
        positions = set(range(offset, offset + width))
        if occupied.intersection(positions):
            raise validation_error("field definitions overlap", field=field_name)
        occupied.update(positions)
        names.add(name)
        fields.append({"name": name, "offset": offset, "width": width, "kind": kind})
    return sorted(fields, key=lambda item: (item["offset"], item["width"], item["name"]))


def _candidate_values(current: int, width: int) -> tuple[tuple[str, int], ...]:
    maximum = (1 << (width * 8)) - 1
    high_bit = 1 << (width * 8 - 1)
    return (
        ("boundary_zero", 0),
        ("boundary_max", maximum),
        ("flip_msb", current ^ high_bit),
        ("increment", (current + 1) & maximum),
        ("decrement", (current - 1) & maximum),
    )


def generate_mutation_plan(request_value: Any) -> dict[str, Any]:
    request = _mapping(request_value, "request")
    _strict_keys(request, _REQUEST_KEYS, "request")
    required = _REQUEST_KEYS - {"fields"}
    if not required.issubset(request):
        raise validation_error(
            "mutation request is incomplete",
            field="request",
            details={"missing_fields": sorted(required - set(request))},
        )
    protocol = request["protocol"]
    if not isinstance(protocol, str) or protocol not in PROTOCOLS:
        raise validation_error("unsupported automotive protocol", field="protocol")
    payload = _payload(request["payload_hex"])
    seed = _integer(request["deterministic_seed"], "deterministic_seed", 0, 2**64 - 1)
    mutation_count = _integer(request["mutation_count"], "mutation_count", 1, _MAX_MUTATIONS)
    fields = (
        _validated_fields(request["fields"], len(payload))
        if "fields" in request
        else _derived_fields(protocol, payload)
    )

    candidates: list[dict[str, Any]] = []
    for field in fields:
        offset = field["offset"]
        width = field["width"]
        current = int.from_bytes(payload[offset : offset + width], "big")
        for strategy, value in _candidate_values(current, width):
            if value == current:
                continue
            mutated = bytearray(payload)
            mutated[offset : offset + width] = value.to_bytes(width, "big")
            candidate = {
                "field": field["name"],
                "field_kind": field["kind"],
                "strategy": strategy,
                "payload_hex": bytes(mutated).hex(),
            }
            candidate["mutation_id"] = canonical_sha256(candidate)
            candidates.append(candidate)

    unique = {candidate["mutation_id"]: candidate for candidate in candidates}

    def rank(candidate: dict[str, Any]) -> tuple[str, str]:
        seed_material = seed.to_bytes(8, "big") + canonical_json_bytes(candidate)
        return hashlib.sha256(seed_material).hexdigest(), candidate["mutation_id"]

    selected = sorted(unique.values(), key=rank)[:mutation_count]
    plan = {
        "schema_version": SCHEMA_VERSION,
        "protocol": protocol,
        "source_sha256": sha256_bytes(payload),
        "deterministic_seed": seed,
        "requested_mutations": mutation_count,
        "generated_mutations": len(selected),
        "fields": fields,
        "mutations": selected,
    }
    plan["artifact_sha256"] = canonical_sha256(plan)
    return plan
