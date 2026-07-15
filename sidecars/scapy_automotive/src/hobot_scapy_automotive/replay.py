"""Pure replay planning and explicitly injected transport execution."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from .constants import PROTOCOLS, SCHEMA_VERSION
from .errors import SidecarError, validation_error
from .hashing import canonical_sha256, rust_transcript_sha256
from .validation import validate_operation_config

_REQUEST_KEYS = frozenset({"protocol", "mode", "deterministic_seed", "events"})
_EVENT_KEYS = frozenset(
    {"sequence", "protocol", "direction", "offset_micros", "payload_hex", "metadata"}
)
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "mode",
        "deterministic_seed",
        "steps",
        "artifact_sha256",
    }
)
_STEP_KEYS = frozenset({"sequence", "delay_micros", "action", "message"})
_MESSAGE_KEYS = frozenset({"protocol", "payload_hex", "metadata"})
_MAX_REPLAY_DELAY_SECONDS = 5.0


class Transport(Protocol):
    """Transport boundary supplied by the sandbox runtime, never by this package."""

    def send(self, message: dict[str, object]) -> None: ...

    def receive(self, expected: dict[str, object]) -> bytes: ...


class UnavailableTransport:
    """Fail-closed default proving that the sidecar never chooses an interface."""

    def send(self, message: dict[str, object]) -> None:
        del message
        raise SidecarError(
            "transport_unavailable",
            "no transport was injected by the sandbox runtime",
            retryable=False,
        )

    def receive(self, expected: dict[str, object]) -> bytes:
        del expected
        raise SidecarError(
            "transport_unavailable",
            "no transport was injected by the sandbox runtime",
            retryable=False,
        )


def physical_replay_scope_sha256(plan_value: Any, config_value: Any) -> str:
    """Hash the exact service-approved physical replay scope."""
    plan = _mapping(plan_value, "plan")
    config = validate_operation_config(config_value)
    if config["mode"] != "physical_bench":
        raise validation_error(
            "approval scope is defined only for physical bench mode", field="mode"
        )
    return canonical_sha256(
        {
            "interface": config["interface"],
            "plan": plan,
            "limits": config["limits"],
            "arbitration_ids": sorted(config["arbitration_id_allowlist"]),
            "uds_services": sorted(config["service_allowlist"]),
            "allow_dangerous_services": config["allow_dangerous_services"],
        }
    )


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


def _integer(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise validation_error(
            "value must be a non-negative bounded integer",
            field=field,
            details={"maximum": maximum},
        )
    return value


def _payload_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) % 2:
        raise validation_error("payload must be non-empty even-length hexadecimal", field=field)
    try:
        return bytes.fromhex(value).hex()
    except ValueError as error:
        raise validation_error("payload must be hexadecimal", field=field) from error


def _metadata(value: Any, field: str) -> dict[str, object]:
    metadata = _mapping(value, field)
    normalized: dict[str, object] = {}
    for key, item in sorted(metadata.items()):
        if item is None or isinstance(item, str | bool | int):
            normalized[key] = item
        else:
            raise validation_error(
                "metadata values must be scalar JSON values", field=f"{field}.{key}"
            )
    return normalized


def build_replay_plan(request_value: Any) -> dict[str, Any]:
    request = _mapping(request_value, "request")
    _strict_keys(request, _REQUEST_KEYS, "request")
    missing = sorted(_REQUEST_KEYS - set(request))
    if missing:
        raise validation_error(
            "replay request is incomplete", field="request", details={"missing_fields": missing}
        )
    protocol = request["protocol"]
    if not isinstance(protocol, str) or protocol not in PROTOCOLS:
        raise validation_error("unsupported automotive protocol", field="protocol")
    mode = request["mode"]
    if mode not in {"virtual_can", "physical_bench"}:
        raise validation_error("replay mode must be virtual_can or physical_bench", field="mode")
    seed = _integer(request["deterministic_seed"], "deterministic_seed", 2**64 - 1)
    if not isinstance(request["events"], list) or not request["events"]:
        raise validation_error("events must be a non-empty array", field="events")

    events: list[dict[str, Any]] = []
    for index, raw_event in enumerate(request["events"]):
        field = f"events[{index}]"
        event = _mapping(raw_event, field)
        _strict_keys(event, _EVENT_KEYS, field)
        if set(event) != _EVENT_KEYS:
            raise validation_error("transcript event is incomplete", field=field)
        event_protocol = event["protocol"]
        if event_protocol != protocol:
            raise validation_error(
                "event protocol differs from replay protocol", field=f"{field}.protocol"
            )
        direction = event["direction"]
        if direction not in {"transmit", "receive"}:
            raise validation_error("event direction is unsupported", field=f"{field}.direction")
        events.append(
            {
                "sequence": _integer(event["sequence"], f"{field}.sequence", 2**64 - 1),
                "protocol": protocol,
                "direction": direction,
                "offset_micros": _integer(
                    event["offset_micros"], f"{field}.offset_micros", 2**64 - 1
                ),
                "payload_hex": _payload_hex(event["payload_hex"], f"{field}.payload_hex"),
                "metadata": _metadata(event["metadata"], f"{field}.metadata"),
            }
        )
    events.sort(key=lambda event: event["sequence"])
    sequences = [event["sequence"] for event in events]
    if len(set(sequences)) != len(sequences):
        raise validation_error("transcript event sequences must be unique", field="events")
    offsets = [event["offset_micros"] for event in events]
    if offsets != sorted(offsets):
        raise validation_error("event offsets must increase with sequence", field="events")

    steps: list[dict[str, Any]] = []
    previous_offset = 0
    for sequence, event in enumerate(events):
        offset = event["offset_micros"]
        steps.append(
            {
                "sequence": sequence,
                "delay_micros": offset - previous_offset,
                "action": "send" if event["direction"] == "transmit" else "expect_response",
                "message": {
                    "protocol": protocol,
                    "payload_hex": event["payload_hex"],
                    "metadata": event["metadata"],
                },
            }
        )
        previous_offset = offset

    plan = {
        "schema_version": SCHEMA_VERSION,
        "protocol": protocol,
        "mode": mode,
        "deterministic_seed": seed,
        "steps": steps,
    }
    plan["artifact_sha256"] = canonical_sha256(plan)
    return plan


def _validated_plan(plan_value: Any) -> dict[str, Any]:
    plan = _mapping(plan_value, "plan")
    _strict_keys(plan, _PLAN_KEYS, "plan")
    if set(plan) != _PLAN_KEYS:
        raise validation_error("replay plan is incomplete", field="plan")
    if plan["schema_version"] != SCHEMA_VERSION:
        raise validation_error("unsupported replay plan schema", field="plan.schema_version")
    protocol = plan["protocol"]
    mode = plan["mode"]
    if protocol not in PROTOCOLS or mode not in {"virtual_can", "physical_bench"}:
        raise validation_error("replay plan protocol or mode is unsupported", field="plan")
    seed = _integer(plan["deterministic_seed"], "plan.deterministic_seed", 2**64 - 1)
    if not isinstance(plan["steps"], list) or not plan["steps"]:
        raise validation_error("replay steps must be a non-empty array", field="plan.steps")
    steps: list[dict[str, Any]] = []
    for index, raw_step in enumerate(plan["steps"]):
        field = f"plan.steps[{index}]"
        step = _mapping(raw_step, field)
        _strict_keys(step, _STEP_KEYS, field)
        if set(step) != _STEP_KEYS or step["sequence"] != index:
            raise validation_error("replay step sequence is invalid", field=field)
        action = step["action"]
        if action not in {"send", "expect_response"}:
            raise validation_error("replay action is unsupported", field=f"{field}.action")
        message = _mapping(step["message"], f"{field}.message")
        _strict_keys(message, _MESSAGE_KEYS, f"{field}.message")
        if set(message) != _MESSAGE_KEYS or message["protocol"] != protocol:
            raise validation_error(
                "replay message is incomplete or inconsistent", field=f"{field}.message"
            )
        steps.append(
            {
                "sequence": index,
                "delay_micros": _integer(step["delay_micros"], f"{field}.delay_micros", 2**64 - 1),
                "action": action,
                "message": {
                    "protocol": protocol,
                    "payload_hex": _payload_hex(
                        message["payload_hex"], f"{field}.message.payload_hex"
                    ),
                    "metadata": _metadata(message["metadata"], f"{field}.message.metadata"),
                },
            }
        )
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "protocol": protocol,
        "mode": mode,
        "deterministic_seed": seed,
        "steps": steps,
    }
    expected_hash = canonical_sha256(normalized)
    if plan["artifact_sha256"] != expected_hash:
        raise SidecarError(
            "artifact_hash_mismatch",
            "replay plan hash does not match its contents",
            field="plan.artifact_sha256",
        )
    normalized["artifact_sha256"] = expected_hash
    return normalized


def _validate_message_allowlists(
    config: dict[str, Any], message: dict[str, Any], *, validate_request_service: bool
) -> None:
    arbitration_id = message["metadata"].get("arbitration_id")
    if (
        isinstance(arbitration_id, bool)
        or not isinstance(arbitration_id, int)
        or arbitration_id not in config["arbitration_id_allowlist"]
    ):
        raise SidecarError(
            "arbitration_id_not_allowed",
            "replay arbitration ID is absent from the allowlist",
            field="plan.steps.message.metadata.arbitration_id",
        )
    if config["protocol"] == "uds" and validate_request_service:
        service = bytes.fromhex(message["payload_hex"])[0]
        if service not in config["service_allowlist"]:
            raise SidecarError(
                "service_not_allowed",
                "transmit UDS service is absent from the allowlist",
                field="plan.steps.message.payload_hex",
                details={"service": service},
            )


def execute_replay_plan(
    config_value: Any,
    plan_value: Any,
    transport: Transport,
    *,
    sleeper: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    config = validate_operation_config(config_value)
    plan = _validated_plan(plan_value)
    if config["mode"] != plan["mode"] or config["protocol"] != plan["protocol"]:
        raise validation_error("replay config and plan are inconsistent", field="plan")
    limits = config["limits"]
    if len(plan["steps"]) > limits["max_events"]:
        raise SidecarError(
            "limit_exceeded",
            "replay plan exceeds max_events",
            field="limits.max_events",
        )
    payload_bytes = sum(
        len(bytes.fromhex(step["message"]["payload_hex"])) for step in plan["steps"]
    )
    if payload_bytes > limits["max_payload_bytes"]:
        raise SidecarError(
            "limit_exceeded",
            "replay plan exceeds max_payload_bytes",
            field="limits.max_payload_bytes",
        )
    duration_micros = sum(step["delay_micros"] for step in plan["steps"])
    if duration_micros > limits["max_duration_ms"] * 1_000:
        raise SidecarError(
            "limit_exceeded",
            "replay plan exceeds max_duration_ms",
            field="limits.max_duration_ms",
        )
    rate_window_seconds = max(1, math.ceil(duration_micros / 1_000_000))
    if len(plan["steps"]) > limits["max_rate_per_second"] * rate_window_seconds:
        raise SidecarError(
            "limit_exceeded",
            "replay plan exceeds max_rate_per_second",
            field="limits.max_rate_per_second",
        )
    for step in plan["steps"]:
        delay_seconds = step["delay_micros"] / 1_000_000
        if delay_seconds > _MAX_REPLAY_DELAY_SECONDS:
            raise SidecarError(
                "limit_exceeded",
                "replay step delay exceeds the bounded sleep interval",
                field="plan.steps.delay_micros",
                details={"maximum_seconds": _MAX_REPLAY_DELAY_SECONDS},
            )
        _validate_message_allowlists(
            config,
            step["message"],
            validate_request_service=step["action"] == "send",
        )
    transport_preflight = getattr(transport, "preflight", None)
    if transport_preflight is not None:
        if not callable(transport_preflight):
            raise SidecarError(
                "transport_error",
                "transport preflight hook is not callable",
                retryable=False,
            )
        for step in plan["steps"]:
            transport_preflight(step["message"])

    transcript: list[dict[str, Any]] = []
    offset_micros = 0
    selected_sleeper = time.sleep if sleeper is None else sleeper
    for step in plan["steps"]:
        delay_seconds = step["delay_micros"] / 1_000_000
        if delay_seconds:
            selected_sleeper(delay_seconds)
        offset_micros += step["delay_micros"]
        message = step["message"]
        if step["action"] == "send":
            transport.send(message)
            actual_payload = message["payload_hex"]
            direction = "transmit"
        else:
            received = transport.receive(message)
            if not isinstance(received, bytes):
                raise SidecarError(
                    "transport_error", "transport receive result must be bytes", retryable=False
                )
            actual_payload = received.hex()
            direction = "receive"
        transcript.append(
            {
                "sequence": step["sequence"],
                "protocol": plan["protocol"],
                "direction": direction,
                "offset_micros": offset_micros,
                "payload_hex": actual_payload,
                "metadata": {key: str(value) for key, value in sorted(message["metadata"].items())},
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "protocol": plan["protocol"],
        "mode": plan["mode"],
        "planned_events": len(plan["steps"]),
        "executed_events": len(transcript),
        "completed": True,
        "transcript_sha256": rust_transcript_sha256(transcript),
    }
