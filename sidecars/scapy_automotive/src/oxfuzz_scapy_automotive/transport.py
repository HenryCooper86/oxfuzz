"""Lazy, fail-closed SocketCAN transport selected from validated policy."""

from __future__ import annotations

import importlib
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .errors import SidecarError, validation_error
from .replay import Transport, UnavailableTransport
from .validation import validate_operation_config

IP_BINARY = "/usr/sbin/ip"
COMMAND_TIMEOUT_SECONDS = 2.0
MAX_RECEIVE_TIMEOUT_SECONDS = 1.0
_CLASSIC_CAN_PAYLOAD_BYTES = 8
_CAN_FD_PAYLOAD_BYTES = 64
_STANDARD_CAN_ID_MAX = 0x7FF
_EXTENDED_CAN_ID_MAX = 0x1FFFFFFF
_VCAN_NAME = re.compile(r"vcan[0-9]{1,3}\Z")

CommandRunner = Callable[[tuple[str, ...]], int]
CanLoader = Callable[[], Any]


@dataclass(frozen=True)
class _FrameSpec:
    arbitration_id: int
    payload: bytes
    is_extended_id: bool
    is_fd: bool
    bitrate_switch: bool
    error_state_indicator: bool


def run_fixed_command(argv: tuple[str, ...]) -> int:
    """Run one pre-constructed argv without a shell or inherited output."""
    allowed = False
    if (
        argv[:4]
        in {
            (IP_BINARY, "link", "show", "dev"),
            (IP_BINARY, "link", "add", "dev"),
            (IP_BINARY, "link", "set", "dev"),
        }
        and len(argv) >= 5
    ):
        interface = argv[4]
        allowed = bool(_VCAN_NAME.fullmatch(interface)) and argv in {
            (IP_BINARY, "link", "show", "dev", interface),
            (IP_BINARY, "link", "add", "dev", interface, "type", "vcan"),
            (IP_BINARY, "link", "set", "dev", interface, "up"),
        }
    if not allowed:
        raise SidecarError(
            "transport_error",
            "virtual CAN setup rejected a non-fixed command",
            retryable=False,
        )
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SidecarError(
            "transport_error",
            "virtual CAN interface setup command could not be executed",
            retryable=False,
            details={"exception_type": type(error).__name__},
        ) from error
    return completed.returncode


def _load_python_can() -> Any:
    try:
        return importlib.import_module("can")
    except (ImportError, ModuleNotFoundError) as error:
        raise SidecarError(
            "dependency_unavailable",
            "the pinned python-can dependency is unavailable",
            retryable=False,
        ) from error


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise validation_error("value must be an object with string keys", field=field)
    return value


def _boolean_flag(metadata: Mapping[str, Any], name: str, default: bool) -> bool:
    value = metadata.get(name, default)
    if isinstance(value, bool):
        return value
    if value == "true":
        return True
    if value == "false":
        return False
    raise validation_error(
        "CAN frame flags must be booleans",
        field=f"plan.steps.message.metadata.{name}",
    )


class PythonCanTransport:
    """A lazy python-can bus locked to one already validated interface."""

    def __init__(
        self,
        validated_config: dict[str, Any],
        *,
        can_loader: CanLoader = _load_python_can,
        command_runner: CommandRunner = run_fixed_command,
    ) -> None:
        config = validate_operation_config(validated_config)
        if config["mode"] == "offline_pcap":
            raise validation_error(
                "offline capture mode cannot construct a CAN transport",
                field="mode",
            )
        self._config = config
        self._interface = config["interface"]
        self._can_loader = can_loader
        self._command_runner = command_runner
        self._can_module: Any | None = None
        self._bus: Any | None = None
        self._virtual_configured = False
        duration_seconds = config["limits"]["max_duration_ms"] / 1_000
        self._io_timeout = min(MAX_RECEIVE_TIMEOUT_SECONDS, duration_seconds)

    def _configure_virtual_interface(self) -> None:
        if self._config["mode"] != "virtual_can" or self._virtual_configured:
            return
        interface = self._interface
        show = (IP_BINARY, "link", "show", "dev", interface)
        if self._command_runner(show) != 0:
            add = (IP_BINARY, "link", "add", "dev", interface, "type", "vcan")
            if self._command_runner(add) != 0:
                raise SidecarError(
                    "transport_error",
                    "the validated virtual CAN interface could not be created",
                    field="interface",
                    retryable=False,
                )
        up = (IP_BINARY, "link", "set", "dev", interface, "up")
        if self._command_runner(up) != 0:
            raise SidecarError(
                "transport_error",
                "the validated virtual CAN interface could not be enabled",
                field="interface",
                retryable=False,
            )
        self._virtual_configured = True

    def _load_can_module(self) -> Any:
        if self._can_module is None:
            self._can_module = self._can_loader()
        return self._can_module

    def _open_bus(self) -> Any:
        if self._bus is not None:
            return self._bus
        can_module = self._load_can_module()
        self._configure_virtual_interface()
        try:
            self._bus = can_module.Bus(
                interface="socketcan",
                channel=self._interface,
                receive_own_messages=False,
            )
        except Exception as error:
            raise SidecarError(
                "transport_error",
                "the validated SocketCAN interface could not be opened",
                field="interface",
                retryable=False,
                details={"exception_type": type(error).__name__},
            ) from error
        return self._bus

    def _frame_spec(self, message_value: Any) -> _FrameSpec:
        message = _mapping(message_value, "plan.steps.message")
        protocol = message.get("protocol")
        if protocol != self._config["protocol"]:
            raise SidecarError(
                "transport_error",
                "CAN frame protocol differs from the validated execution policy",
                field="plan.steps.message.protocol",
            )
        metadata = _mapping(message.get("metadata"), "plan.steps.message.metadata")
        requested_interface = metadata.get("interface")
        if requested_interface is not None and requested_interface != self._interface:
            raise SidecarError(
                "interface_not_allowed",
                "CAN frame interface differs from the validated interface",
                field="plan.steps.message.metadata.interface",
            )
        arbitration_id = metadata.get("arbitration_id")
        if (
            isinstance(arbitration_id, bool)
            or not isinstance(arbitration_id, int)
            or arbitration_id not in self._config["arbitration_id_allowlist"]
        ):
            raise SidecarError(
                "arbitration_id_not_allowed",
                "CAN frame arbitration ID is absent from the validated allowlist",
                field="plan.steps.message.metadata.arbitration_id",
            )
        is_extended_id = _boolean_flag(
            metadata, "is_extended_id", arbitration_id > _STANDARD_CAN_ID_MAX
        )
        if arbitration_id > _EXTENDED_CAN_ID_MAX or (
            arbitration_id > _STANDARD_CAN_ID_MAX and not is_extended_id
        ):
            raise validation_error(
                "CAN arbitration ID and extended-frame flag are inconsistent",
                field="plan.steps.message.metadata.arbitration_id",
            )
        is_fd = _boolean_flag(metadata, "is_fd", protocol == "can_fd")
        if protocol == "can_fd" and not is_fd:
            raise validation_error(
                "CAN FD protocol requires the CAN FD frame flag",
                field="plan.steps.message.metadata.is_fd",
            )
        if protocol == "can" and is_fd:
            raise validation_error(
                "classic CAN protocol cannot set the CAN FD frame flag",
                field="plan.steps.message.metadata.is_fd",
            )
        bitrate_switch = _boolean_flag(metadata, "bitrate_switch", False)
        error_state_indicator = _boolean_flag(metadata, "error_state_indicator", False)
        if not is_fd and (bitrate_switch or error_state_indicator):
            raise validation_error(
                "classic CAN frames cannot set CAN FD-only flags",
                field="plan.steps.message.metadata",
            )
        payload_hex = message.get("payload_hex")
        if not isinstance(payload_hex, str) or not payload_hex or len(payload_hex) % 2:
            raise validation_error(
                "CAN frame payload must be non-empty even-length hexadecimal",
                field="plan.steps.message.payload_hex",
            )
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError as error:
            raise validation_error(
                "CAN frame payload must be hexadecimal",
                field="plan.steps.message.payload_hex",
            ) from error
        format_limit = _CAN_FD_PAYLOAD_BYTES if is_fd else _CLASSIC_CAN_PAYLOAD_BYTES
        payload_limit = min(format_limit, self._config["limits"]["max_payload_bytes"])
        if len(payload) > payload_limit:
            raise SidecarError(
                "limit_exceeded",
                "CAN frame payload exceeds its format bound",
                field="plan.steps.message.payload_hex",
                details={"maximum_bytes": payload_limit},
            )
        return _FrameSpec(
            arbitration_id=arbitration_id,
            payload=payload,
            is_extended_id=is_extended_id,
            is_fd=is_fd,
            bitrate_switch=bitrate_switch,
            error_state_indicator=error_state_indicator,
        )

    def send(self, message: dict[str, object]) -> None:
        frame = self._frame_spec(message)
        can_module = self._load_can_module()
        try:
            outbound = can_module.Message(
                arbitration_id=frame.arbitration_id,
                data=frame.payload,
                is_extended_id=frame.is_extended_id,
                is_fd=frame.is_fd,
                bitrate_switch=frame.bitrate_switch,
                error_state_indicator=frame.error_state_indicator,
                is_remote_frame=False,
                is_error_frame=False,
            )
            self._open_bus().send(outbound, timeout=self._io_timeout)
        except SidecarError:
            raise
        except Exception as error:
            raise SidecarError(
                "transport_error",
                "CAN frame transmission failed",
                retryable=False,
                details={"exception_type": type(error).__name__},
            ) from error

    def preflight(self, message: dict[str, object]) -> None:
        """Validate one planned frame without importing, configuring, or opening."""
        self._frame_spec(message)

    def receive(self, expected: dict[str, object]) -> bytes:
        frame = self._frame_spec(expected)
        try:
            received = self._open_bus().recv(timeout=self._io_timeout)
        except SidecarError:
            raise
        except Exception as error:
            raise SidecarError(
                "transport_error",
                "CAN frame receive failed",
                retryable=False,
                details={"exception_type": type(error).__name__},
            ) from error
        if received is None:
            raise SidecarError(
                "transport_error",
                "CAN frame receive deadline expired",
                retryable=True,
            )
        channel = getattr(received, "channel", None)
        if channel is not None and channel != self._interface:
            raise SidecarError(
                "interface_not_allowed",
                "received CAN frame came from a different interface",
                field="interface",
            )
        if getattr(received, "arbitration_id", None) != frame.arbitration_id:
            raise SidecarError(
                "arbitration_id_not_allowed",
                "received CAN frame did not match the expected arbitration ID",
                field="arbitration_id",
            )
        if getattr(received, "is_remote_frame", False) or getattr(
            received, "is_error_frame", False
        ):
            raise SidecarError(
                "transport_error",
                "remote and error CAN frames are not replay payloads",
                retryable=False,
            )
        returned_flags = (
            bool(getattr(received, "is_extended_id", False)),
            bool(getattr(received, "is_fd", False)),
            bool(getattr(received, "bitrate_switch", False)),
            bool(getattr(received, "error_state_indicator", False)),
        )
        expected_flags = (
            frame.is_extended_id,
            frame.is_fd,
            frame.bitrate_switch,
            frame.error_state_indicator,
        )
        if returned_flags != expected_flags:
            raise SidecarError(
                "transport_error",
                "received CAN frame flags did not match the replay plan",
                retryable=False,
            )
        payload_value = getattr(received, "data", None)
        if not isinstance(payload_value, bytes | bytearray):
            raise SidecarError(
                "transport_error",
                "received CAN frame payload was not bytes",
                retryable=False,
            )
        payload = bytes(payload_value)
        format_limit = _CAN_FD_PAYLOAD_BYTES if frame.is_fd else _CLASSIC_CAN_PAYLOAD_BYTES
        payload_limit = min(format_limit, self._config["limits"]["max_payload_bytes"])
        if not payload or len(payload) > payload_limit:
            raise SidecarError(
                "limit_exceeded",
                "received CAN frame payload exceeds its format bound",
                field="payload",
            )
        return payload

    def sniff(self, max_events: int) -> list[dict[str, object]]:
        """Passively receive up to ``max_events`` frames within the bounded
        wall-clock window, returning one normalized record per frame. This is a
        read-only capture: it never transmits."""
        bus = self._open_bus()
        deadline = time.monotonic() + self._config["limits"]["max_duration_ms"] / 1_000
        payload_limit = self._config["limits"]["max_payload_bytes"]
        frames: list[dict[str, object]] = []
        while len(frames) < max_events and time.monotonic() < deadline:
            try:
                received = bus.recv(timeout=self._io_timeout)
            except Exception as error:
                raise SidecarError(
                    "transport_error",
                    "CAN frame receive failed",
                    retryable=False,
                    details={"exception_type": type(error).__name__},
                ) from error
            if received is None:
                break
            channel = getattr(received, "channel", None)
            if channel is not None and channel != self._interface:
                raise SidecarError(
                    "interface_not_allowed",
                    "received CAN frame came from a different interface",
                    field="interface",
                )
            data = getattr(received, "data", b"")
            payload = bytes(data) if isinstance(data, bytes | bytearray) else b""
            arbitration = getattr(received, "arbitration_id", None)
            timestamp = getattr(received, "timestamp", None)
            frames.append(
                {
                    "arbitration_id": int(arbitration)
                    if isinstance(arbitration, int) and not isinstance(arbitration, bool)
                    else 0,
                    "is_extended_id": bool(getattr(received, "is_extended_id", False)),
                    "payload_hex": payload[:payload_limit].hex(),
                    "timestamp": float(timestamp)
                    if isinstance(timestamp, int | float) and not isinstance(timestamp, bool)
                    else 0.0,
                }
            )
        return frames

    def probe(self, request_id: int, response_id: int, payload: bytes) -> bytes | None:
        """Send one short UDS request as an ISO-TP single frame and return the
        first CAN frame received on ``response_id`` within the timeout, or
        ``None`` if the ECU stays silent. Read-only in intent: the caller only
        ever supplies allowlisted read-only diagnostic requests."""
        can_module = self._load_can_module()
        bus = self._open_bus()
        # ISO-TP single frame: PCI byte (length in low nibble) then the payload.
        frame = bytes([len(payload) & 0x0F]) + payload
        try:
            outbound = can_module.Message(
                arbitration_id=request_id,
                data=frame,
                is_extended_id=request_id > _STANDARD_CAN_ID_MAX,
                is_fd=False,
            )
            bus.send(outbound, timeout=self._io_timeout)
        except Exception as error:
            raise SidecarError(
                "transport_error",
                "UDS probe transmission failed",
                retryable=False,
                details={"exception_type": type(error).__name__},
            ) from error
        deadline = time.monotonic() + self._io_timeout
        while time.monotonic() < deadline:
            try:
                received = bus.recv(timeout=self._io_timeout)
            except Exception as error:
                raise SidecarError(
                    "transport_error",
                    "UDS probe receive failed",
                    retryable=False,
                    details={"exception_type": type(error).__name__},
                ) from error
            if received is None:
                break
            if getattr(received, "arbitration_id", None) != response_id:
                continue
            channel = getattr(received, "channel", None)
            if channel is not None and channel != self._interface:
                raise SidecarError(
                    "interface_not_allowed",
                    "received CAN frame came from a different interface",
                    field="interface",
                )
            data = getattr(received, "data", b"")
            return bytes(data) if isinstance(data, bytes | bytearray) else b""
        return None


def create_configured_transport(
    config_value: Any,
    *,
    can_loader: CanLoader = _load_python_can,
    command_runner: CommandRunner = run_fixed_command,
) -> Transport:
    """Select a lazy transport only after fail-closed policy validation."""
    config = validate_operation_config(config_value)
    if config["mode"] == "offline_pcap":
        return UnavailableTransport()
    return PythonCanTransport(
        config,
        can_loader=can_loader,
        command_runner=command_runner,
    )


__all__ = [
    "IP_BINARY",
    "MAX_RECEIVE_TIMEOUT_SECONDS",
    "PythonCanTransport",
    "create_configured_transport",
    "run_fixed_command",
]
