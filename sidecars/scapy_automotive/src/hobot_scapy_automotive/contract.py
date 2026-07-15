"""Versioned JSONL dispatcher aligned with the Rust automotive contract."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifacts import (
    ArtifactStore,
    UnavailableArtifactStore,
    validate_artifact_ref,
)
from .capabilities import capability_report, discover_runtime
from .constants import MODES, PROTOCOLS, SCHEMA_VERSION
from .errors import SidecarError, validation_error
from .hashing import canonical_sha256, rust_transcript_bytes, rust_transcript_sha256
from .mutation import generate_mutation_plan
from .pcap import PcapDecoder, decode_pcap
from .replay import (
    Transport,
    UnavailableTransport,
    build_replay_plan,
    execute_replay_plan,
    physical_replay_scope_sha256,
)
from .validation import validate_operation_config

_ENVELOPE_KEYS = frozenset({"schema_version", "request_id", "operation", "payload"})
_OPERATIONS = frozenset(
    {
        "capabilities",
        "analyze_capture",
        "generate_mutations",
        "build_replay_plan",
        "execute_replay",
    }
)
_LIMIT_KEYS = frozenset(
    {"max_events", "max_payload_bytes", "max_duration_ms", "max_rate_per_second"}
)
_GLOBAL_LIMITS = {
    "max_events": 1_000_000,
    "max_payload_bytes": 1_048_576,
    "max_duration_ms": 86_400_000,
    "max_rate_per_second": 100_000,
}
_RUNTIME_KEYS = frozenset(
    {
        "scapy_available",
        "scapy_version",
        "python_can_available",
        "python_can_version",
    }
)
_WIRE_ERROR_CODES = {
    "unsupported_schema": "unsupported_schema",
    "unsupported_protocol": "unsupported_protocol",
    "unsupported_mode": "unsupported_mode",
    "dependency_unavailable": "capability_unavailable",
    "limit_exceeded": "limit_exceeded",
    "approval_required": "approval_required",
    "physical_mode_disabled": "approval_required",
    "dangerous_service_denied": "policy_denied",
    "interface_not_allowed": "policy_denied",
    "arbitration_id_not_allowed": "policy_denied",
    "service_not_allowed": "policy_denied",
    "approval_scope_mismatch": "policy_denied",
    "response_mismatch": "malformed_transcript",
    "pcap_decode_error": "malformed_transcript",
    "decoder_contract_error": "malformed_transcript",
    "transport_unavailable": "adapter_failure",
    "transport_error": "adapter_failure",
    "artifact_store_unavailable": "adapter_failure",
    "artifact_error": "adapter_failure",
    "serialization_error": "adapter_failure",
    "internal_error": "adapter_failure",
}


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise validation_error("value must be an object with string keys", field=field)
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], field: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        raise validation_error(
            "object fields do not match the contract",
            field=field,
            details={"missing_fields": missing, "unknown_fields": unknown},
        )


def _request_id(request: Any) -> str:
    if isinstance(request, Mapping):
        request_id = request.get("request_id")
        if isinstance(request_id, str) and request_id:
            return request_id
    return "unknown"


def _detail_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _wire_error(error: SidecarError) -> dict[str, Any]:
    if error.code in _WIRE_ERROR_CODES:
        code = _WIRE_ERROR_CODES[error.code]
    elif error.field and "protocol" in error.field:
        code = "unsupported_protocol"
    elif error.field and "mode" in error.field:
        code = "unsupported_mode"
    else:
        code = "invalid_request"
    return {
        "code": code,
        "message": error.message,
        "field": error.field,
        "retryable": error.retryable,
        "details": {key: _detail_string(value) for key, value in sorted(error.details.items())},
    }


def _success_response(
    request_id: str,
    result_name: str,
    data: dict[str, Any],
    transcript_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "ok": True,
        "result": {"result": result_name, "data": data},
        "error": None,
        "transcript_sha256": transcript_sha256,
    }


def make_error_response(
    request_id: str,
    error: SidecarError,
    *,
    request_evidence: Any | None = None,
) -> dict[str, Any]:
    del request_evidence
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "ok": False,
        "result": None,
        "error": _wire_error(error),
        "transcript_sha256": None,
    }


def _protocol(value: Any, field: str = "protocol") -> str:
    if not isinstance(value, str) or value not in PROTOCOLS:
        raise SidecarError(
            "unsupported_protocol",
            "requested automotive protocol is not supported",
            field=field,
        )
    return value


def _mode(value: Any, field: str = "mode") -> str:
    if not isinstance(value, str) or value not in MODES:
        raise SidecarError(
            "unsupported_mode",
            "requested automotive mode is not supported",
            field=field,
        )
    return value


def _bounded_integer(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        code = (
            "limit_exceeded"
            if isinstance(value, int) and not isinstance(value, bool)
            else "validation_error"
        )
        raise SidecarError(
            code,
            "operation limit must be a positive bounded integer",
            field=field,
            details={"maximum": maximum, "observed": value},
        )
    return value


def _limits(value: Any) -> dict[str, int]:
    limits = _mapping(value, "limits")
    _exact_keys(limits, _LIMIT_KEYS, "limits")
    return {
        key: _bounded_integer(limits[key], f"limits.{key}", maximum)
        for key, maximum in _GLOBAL_LIMITS.items()
    }


def _runtime(value: Any | None) -> dict[str, Any]:
    runtime = _mapping(discover_runtime() if value is None else value, "runtime")
    _exact_keys(runtime, _RUNTIME_KEYS, "runtime")
    normalized: dict[str, Any] = {}
    for dependency in ("scapy", "python_can"):
        available = runtime[f"{dependency}_available"]
        version = runtime[f"{dependency}_version"]
        if not isinstance(available, bool):
            raise validation_error(
                "runtime availability must be a boolean", field=f"runtime.{dependency}_available"
            )
        if version is not None and (not isinstance(version, str) or not version):
            raise validation_error(
                "runtime version must be null or non-empty", field=f"runtime.{dependency}_version"
            )
        if available and version is None:
            raise validation_error(
                "available runtime dependencies must report a version",
                field=f"runtime.{dependency}_version",
            )
        normalized[f"{dependency}_available"] = available
        normalized[f"{dependency}_version"] = version
    return normalized


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise SidecarError(
            "artifact_error",
            "staged artifact could not be read",
            field="artifact.artifact_id",
            details={"reason": str(error)},
        ) from error


def _strict_json_bytes(data: bytes, field: str) -> Any:
    try:
        return json.loads(
            data,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SidecarError(
            "pcap_decode_error",
            "staged transcript artifact is not valid strict JSON",
            field=field,
            details={"reason": str(error)},
        ) from error


def _analyze_capture(
    payload: Mapping[str, Any], artifact_store: ArtifactStore, decoder: PcapDecoder | None
) -> tuple[str, dict[str, Any], str]:
    _exact_keys(payload, frozenset({"protocol", "capture", "limits"}), "payload")
    protocol = _protocol(payload["protocol"])
    limits = _limits(payload["limits"])
    capture = validate_artifact_ref(payload["capture"])
    if capture["media_type"] not in {
        "application/pcap",
        "application/x-pcap",
        "application/vnd.tcpdump.pcap",
    }:
        raise validation_error("capture media type is not PCAP", field="payload.capture.media_type")
    path = artifact_store.resolve(capture, int(capture["size_bytes"]))
    decoded = decode_pcap(
        path,
        {
            "max_events": limits["max_events"],
            "max_payload_bytes": limits["max_payload_bytes"],
        },
        decoder=decoder,
    )
    packets = decoded["packets"]
    if not packets:
        raise SidecarError(
            "pcap_decode_error", "capture contains no decodable events", field="payload.capture"
        )
    first_timestamp = packets[0].get("timestamp_ns", 0)
    if isinstance(first_timestamp, bool) or not isinstance(first_timestamp, int):
        first_timestamp = 0
    events: list[dict[str, Any]] = []
    for sequence, packet_value in enumerate(packets):
        packet = _mapping(packet_value, f"packets[{sequence}]")
        payload_hex = packet.get("payload_hex", packet.get("raw_hex"))
        if not isinstance(payload_hex, str):
            raise SidecarError(
                "decoder_contract_error",
                "decoded packet is missing a hexadecimal payload",
                field=f"packets[{sequence}]",
            )
        try:
            payload_hex = bytes.fromhex(payload_hex).hex()
        except ValueError as error:
            raise SidecarError(
                "decoder_contract_error",
                "decoded packet payload is not hexadecimal",
                field=f"packets[{sequence}]",
            ) from error
        timestamp = packet.get("timestamp_ns", first_timestamp)
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            timestamp = first_timestamp
        layers = packet.get("layers", [])
        layer_text = ",".join(str(layer) for layer in layers) if isinstance(layers, list) else ""
        metadata: dict[str, str] = {}
        if layer_text:
            metadata["layers"] = layer_text
        fields = packet.get("fields")
        if isinstance(fields, Mapping):
            identifier = fields.get("identifier")
            if isinstance(identifier, int) and not isinstance(identifier, bool):
                metadata["arbitration_id"] = str(identifier)
        events.append(
            {
                "sequence": sequence,
                "protocol": protocol,
                "direction": "receive",
                "offset_micros": max(0, timestamp - first_timestamp) // 1_000,
                "payload_hex": payload_hex,
                "metadata": metadata,
            }
        )
    transcript_bytes = rust_transcript_bytes(events)
    transcript_hash = rust_transcript_sha256(events)
    transcript = artifact_store.write_bytes(
        "capture-transcript",
        "application/vnd.hobot-fuzz.automotive-transcript+json",
        transcript_bytes,
    )
    if transcript["sha256"] != transcript_hash:
        raise SidecarError(
            "artifact_hash_mismatch",
            "canonical transcript artifact does not match its semantic digest",
            field="analysis.transcript.sha256",
        )
    return (
        "capture_analysis",
        {
            "protocol": protocol,
            "event_count": len(events),
            "transcript": transcript,
            "transcript_hash": transcript_hash,
            "state_signatures": [],
        },
        transcript_hash,
    )


def _generate_mutations(
    payload: Mapping[str, Any], artifact_store: ArtifactStore
) -> tuple[str, dict[str, Any], None]:
    _exact_keys(
        payload,
        frozenset({"protocol", "source", "deterministic_seed", "mutation_count", "limits"}),
        "payload",
    )
    protocol = _protocol(payload["protocol"])
    limits = _limits(payload["limits"])
    mutation_count = _bounded_integer(
        payload["mutation_count"], "payload.mutation_count", limits["max_events"]
    )
    source = validate_artifact_ref(payload["source"])
    source_path = artifact_store.resolve(source, int(source["size_bytes"]))
    source_bytes = _read_bytes(source_path)
    fields: Any | None = None
    if source["media_type"].endswith("+json") or source["media_type"] == "application/json":
        source_value = _strict_json_bytes(source_bytes, "payload.source")
        source_mapping = _mapping(source_value, "payload.source")
        payload_hex = source_mapping.get("payload_hex")
        fields = source_mapping.get("fields")
    else:
        payload_hex = source_bytes.hex()
    mutation_request: dict[str, Any] = {
        "protocol": protocol,
        "payload_hex": payload_hex,
        "deterministic_seed": payload["deterministic_seed"],
        "mutation_count": mutation_count,
    }
    if fields is not None:
        mutation_request["fields"] = fields
    plan = generate_mutation_plan(mutation_request)
    artifact = artifact_store.write_json(
        "mutation-plan",
        "application/vnd.hobot-fuzz.automotive-mutations+json",
        plan,
    )
    return (
        "mutations",
        {
            "protocol": protocol,
            "generated": plan["generated_mutations"],
            "transcript_hash": None,
            "artifacts": [artifact],
        },
        None,
    )


def _metadata_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    raise validation_error("replay metadata values must be scalar", field="events.metadata")


def _build_replay_plan(
    payload: Mapping[str, Any], artifact_store: ArtifactStore
) -> tuple[str, dict[str, Any], None]:
    _exact_keys(
        payload,
        frozenset({"protocol", "source", "target_mode", "deterministic_seed", "limits"}),
        "payload",
    )
    protocol = _protocol(payload["protocol"])
    target_mode = _mode(payload["target_mode"], "payload.target_mode")
    if target_mode == "offline_pcap":
        raise SidecarError(
            "unsupported_mode",
            "replay plans must target virtual_can or physical_bench",
            field="payload.target_mode",
        )
    limits = _limits(payload["limits"])
    source = validate_artifact_ref(payload["source"])
    source_path = artifact_store.resolve(source, int(source["size_bytes"]))
    source_value = _strict_json_bytes(_read_bytes(source_path), "payload.source")
    canonical_artifact = False
    if isinstance(source_value, list):
        if (
            len(source_value) != 3
            or source_value[0] != SCHEMA_VERSION
            or source_value[1] != "automotive-transcript"
        ):
            raise SidecarError(
                "pcap_decode_error",
                "canonical transcript envelope is invalid",
                field="payload.source",
            )
        events = source_value[2]
        canonical_artifact = True
    else:
        source_mapping = _mapping(source_value, "payload.source")
        events = source_mapping.get("events")
    if not isinstance(events, list) or not events:
        raise SidecarError(
            "pcap_decode_error",
            "replay source must contain a non-empty events array",
            field="payload.source",
        )
    if len(events) > limits["max_events"]:
        raise SidecarError(
            "limit_exceeded", "replay source exceeds max_events", field="limits.max_events"
        )
    if canonical_artifact and rust_transcript_sha256(events) != source["sha256"]:
        raise SidecarError(
            "artifact_hash_mismatch",
            "canonical transcript bytes do not match the semantic transcript digest",
            field="payload.source.sha256",
        )
    internal = build_replay_plan(
        {
            "protocol": protocol,
            "mode": target_mode,
            "deterministic_seed": payload["deterministic_seed"],
            "events": events,
        }
    )
    steps = []
    for step in internal["steps"]:
        metadata = step["message"]["metadata"]
        steps.append(
            {
                "sequence": step["sequence"],
                "delay_micros": step["delay_micros"],
                "action": step["action"],
                "message": {
                    "protocol": protocol,
                    "payload_hex": step["message"]["payload_hex"],
                    "fields": {
                        key: _metadata_string(value) for key, value in sorted(metadata.items())
                    },
                },
            }
        )
    return (
        "replay_plan",
        {
            "protocol": protocol,
            "mode": target_mode,
            "deterministic_seed": internal["deterministic_seed"],
            "steps": steps,
        },
        None,
    )


def _wire_mode(value: Any) -> dict[str, str]:
    mode_config = _mapping(value, "payload.mode")
    mode = _mode(mode_config.get("mode"), "payload.mode.mode")
    expected = {
        "offline_pcap": frozenset({"mode"}),
        "virtual_can": frozenset({"mode", "interface"}),
        "physical_bench": frozenset({"mode", "interface", "approval_id"}),
    }[mode]
    _exact_keys(mode_config, expected, "payload.mode")
    result = {"mode": mode}
    for field in expected - {"mode"}:
        item = mode_config[field]
        if not isinstance(item, str) or not item:
            raise validation_error(
                "mode fields must be non-empty strings", field=f"payload.mode.{field}"
            )
        result[field] = item
    return result


def _wire_plan_to_internal(value: Any) -> dict[str, Any]:
    plan = _mapping(value, "payload.plan")
    _exact_keys(
        plan,
        frozenset({"protocol", "mode", "deterministic_seed", "steps"}),
        "payload.plan",
    )
    protocol = _protocol(plan["protocol"], "payload.plan.protocol")
    mode = _mode(plan["mode"], "payload.plan.mode")
    if mode == "offline_pcap":
        raise SidecarError(
            "unsupported_mode", "offline mode cannot execute replay", field="payload.plan.mode"
        )
    steps_value = plan["steps"]
    if not isinstance(steps_value, list) or not steps_value:
        raise validation_error("replay steps must be non-empty", field="payload.plan.steps")
    ordered: list[tuple[int, Mapping[str, Any]]] = []
    for index, step_value in enumerate(steps_value):
        step = _mapping(step_value, f"payload.plan.steps[{index}]")
        _exact_keys(
            step,
            frozenset({"sequence", "delay_micros", "action", "message"}),
            f"payload.plan.steps[{index}]",
        )
        sequence = step["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise validation_error(
                "step sequence must be non-negative", field="payload.plan.steps.sequence"
            )
        ordered.append((sequence, step))
    ordered.sort(key=lambda pair: pair[0])
    if len({sequence for sequence, _ in ordered}) != len(ordered):
        raise validation_error("step sequences must be unique", field="payload.plan.steps")
    normalized_steps: list[dict[str, Any]] = []
    for normalized_sequence, (_, step) in enumerate(ordered):
        action = step["action"]
        if action not in {"send", "expect_response"}:
            raise validation_error("unsupported replay action", field="payload.plan.steps.action")
        delay = step["delay_micros"]
        if isinstance(delay, bool) or not isinstance(delay, int) or delay < 0:
            raise validation_error(
                "replay delay must be non-negative", field="payload.plan.steps.delay_micros"
            )
        message = _mapping(step["message"], "payload.plan.steps.message")
        _exact_keys(
            message, frozenset({"protocol", "payload_hex", "fields"}), "payload.plan.steps.message"
        )
        if message["protocol"] != protocol:
            raise validation_error(
                "message protocol differs from plan", field="payload.plan.steps.message.protocol"
            )
        fields = _mapping(message["fields"], "payload.plan.steps.message.fields")
        metadata: dict[str, object] = {}
        for key, field_value in sorted(fields.items()):
            if not isinstance(field_value, str) or not field_value:
                raise validation_error(
                    "message fields must contain strings", field="payload.plan.steps.message.fields"
                )
            if key == "arbitration_id":
                try:
                    metadata[key] = int(field_value, 0)
                except ValueError as error:
                    raise validation_error(
                        "arbitration_id field must be an integer",
                        field="payload.plan.steps.message.fields.arbitration_id",
                    ) from error
            else:
                metadata[key] = field_value
        normalized_steps.append(
            {
                "sequence": normalized_sequence,
                "delay_micros": delay,
                "action": action,
                "message": {
                    "protocol": protocol,
                    "payload_hex": message["payload_hex"],
                    "metadata": metadata,
                },
            }
        )
    internal = {
        "schema_version": SCHEMA_VERSION,
        "protocol": protocol,
        "mode": mode,
        "deterministic_seed": plan["deterministic_seed"],
        "steps": normalized_steps,
    }
    internal["artifact_sha256"] = canonical_sha256(internal)
    return internal


def _execute_replay(
    payload: Mapping[str, Any], execution_config: Any, transport: Transport
) -> tuple[str, dict[str, Any], str]:
    _exact_keys(payload, frozenset({"mode", "plan", "limits"}), "payload")
    wire_mode = _wire_mode(payload["mode"])
    if wire_mode["mode"] == "offline_pcap":
        raise SidecarError(
            "unsupported_mode", "offline capture mode cannot execute replay", field="payload.mode"
        )
    plan = _wire_plan_to_internal(payload["plan"])
    limits = _limits(payload["limits"])
    if execution_config is None:
        raise SidecarError(
            "policy_denied",
            "sandbox runtime did not inject an execution policy",
            field="execution_config",
        )
    config = validate_operation_config(execution_config)
    if config["mode"] != wire_mode["mode"] or config["mode"] != plan["mode"]:
        raise SidecarError(
            "policy_denied", "request mode does not match the injected policy", field="payload.mode"
        )
    if config["protocol"] != plan["protocol"]:
        raise SidecarError(
            "policy_denied",
            "request protocol does not match the injected policy",
            field="payload.plan.protocol",
        )
    if config["limits"] != limits:
        raise SidecarError(
            "policy_denied",
            "request limits do not match the approved policy",
            field="payload.limits",
        )
    if config.get("interface") != wire_mode.get("interface"):
        raise SidecarError(
            "policy_denied",
            "request interface does not match the approved policy",
            field="payload.mode.interface",
        )
    if wire_mode["mode"] == "physical_bench":
        approval = config["approval"]
        if approval["approval_id"] != wire_mode["approval_id"]:
            raise SidecarError(
                "approval_required",
                "request approval ID does not match approved evidence",
                field="payload.mode.approval_id",
            )
        expected_scope = physical_replay_scope_sha256(payload["plan"], config)
        if approval["scope_sha256"] != expected_scope:
            raise SidecarError(
                "approval_scope_mismatch",
                "approval evidence does not match the exact physical replay scope",
                field="execution_config.approval.scope_sha256",
                details={"expected_scope_sha256": expected_scope},
            )
    result = execute_replay_plan(config, plan, transport)
    transcript_hash = result["transcript_sha256"]
    return (
        "replay",
        {
            "protocol": result["protocol"],
            "mode": result["mode"],
            "planned_events": result["planned_events"],
            "executed_events": result["executed_events"],
            "transcript_hash": transcript_hash,
            "state_signatures": [],
            "completed": result["completed"],
        },
        transcript_hash,
    )


def _dispatch(
    operation: str,
    payload: Mapping[str, Any],
    *,
    runtime: Any | None,
    artifact_store: ArtifactStore,
    decoder: PcapDecoder | None,
    execution_config: Any,
    transport: Transport,
) -> tuple[str, dict[str, Any], str | None]:
    if operation == "capabilities":
        _exact_keys(payload, frozenset(), "payload")
        runtime_state = _runtime(runtime)
        return "capabilities", capability_report(**runtime_state), None
    if operation == "analyze_capture":
        return _analyze_capture(payload, artifact_store, decoder)
    if operation == "generate_mutations":
        return _generate_mutations(payload, artifact_store)
    if operation == "build_replay_plan":
        return _build_replay_plan(payload, artifact_store)
    if operation == "execute_replay":
        return _execute_replay(payload, execution_config, transport)
    raise SidecarError(
        "unsupported_operation",
        "requested sidecar operation is not supported",
        field="operation",
        details={"supported_operations": sorted(_OPERATIONS)},
    )


def process_request(
    request_value: Any,
    *,
    runtime: Any | None = None,
    artifact_store: ArtifactStore | None = None,
    decoder: PcapDecoder | None = None,
    execution_config: Any = None,
    transport: Transport | None = None,
) -> dict[str, Any]:
    request_id = _request_id(request_value)
    try:
        request = _mapping(request_value, "request")
        _exact_keys(request, _ENVELOPE_KEYS, "request")
        schema_version = request["schema_version"]
        if schema_version != SCHEMA_VERSION:
            raise SidecarError(
                "unsupported_schema",
                "request schema version is not supported",
                field="schema_version",
                details={"supported_schema_versions": [SCHEMA_VERSION]},
            )
        if not isinstance(request["request_id"], str) or not request["request_id"]:
            raise validation_error("request_id must be a non-empty string", field="request_id")
        operation = request["operation"]
        if not isinstance(operation, str) or not operation:
            raise validation_error("operation must be a non-empty string", field="operation")
        payload = _mapping(request["payload"], "payload")
        result_name, data, transcript_hash = _dispatch(
            operation,
            payload,
            runtime=runtime,
            artifact_store=artifact_store or UnavailableArtifactStore(),
            decoder=decoder,
            execution_config=execution_config,
            transport=transport or UnavailableTransport(),
        )
        return _success_response(request_id, result_name, data, transcript_hash)
    except SidecarError as error:
        return make_error_response(request_id, error)
    except Exception as error:
        return make_error_response(
            request_id,
            SidecarError(
                "internal_error",
                "sidecar operation failed unexpectedly",
                retryable=False,
                details={"exception_type": type(error).__name__},
            ),
        )


__all__ = ["MODES", "PROTOCOLS", "SCHEMA_VERSION", "make_error_response", "process_request"]
