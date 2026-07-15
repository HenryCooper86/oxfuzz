"""Deterministic response parsing for automotive protocol observations."""

from __future__ import annotations

from typing import Any

from .constants import PROTOCOLS
from .errors import SidecarError, validation_error

_UDS_NEGATIVE_RESPONSE_CODES = {
    0x10: "general_reject",
    0x11: "service_not_supported",
    0x12: "subfunction_not_supported",
    0x13: "incorrect_message_length_or_invalid_format",
    0x14: "response_too_long",
    0x21: "busy_repeat_request",
    0x22: "conditions_not_correct",
    0x24: "request_sequence_error",
    0x31: "request_out_of_range",
    0x33: "security_access_denied",
    0x35: "invalid_key",
    0x36: "exceeded_number_of_attempts",
    0x37: "required_time_delay_not_expired",
    0x70: "upload_download_not_accepted",
    0x71: "transfer_data_suspended",
    0x72: "general_programming_failure",
    0x73: "wrong_block_sequence_counter",
    0x78: "request_correctly_received_response_pending",
    0x7E: "subfunction_not_supported_in_active_session",
    0x7F: "service_not_supported_in_active_session",
}


def _decode_hex(value: Any, field: str, *, minimum_bytes: int) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise validation_error("payload must be even-length hexadecimal", field=field)
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise validation_error("payload must be hexadecimal", field=field) from error
    if len(decoded) < minimum_bytes:
        raise validation_error(
            "payload is shorter than required",
            field=field,
            details={"minimum_bytes": minimum_bytes},
        )
    return decoded


def parse_automotive_response(
    protocol: Any, request_payload_hex: Any, response_payload_hex: Any
) -> dict[str, Any]:
    if not isinstance(protocol, str) or protocol not in PROTOCOLS:
        raise validation_error("unsupported automotive protocol", field="protocol")
    request = _decode_hex(request_payload_hex, "request_payload_hex", minimum_bytes=1)
    response = _decode_hex(response_payload_hex, "response_payload_hex", minimum_bytes=1)

    if protocol != "uds":
        return {
            "protocol": protocol,
            "status": "response",
            "request_payload_hex": request.hex(),
            "response_payload_hex": response.hex(),
        }

    request_service = request[0]
    if response[0] == 0x7F:
        if len(response) < 3:
            raise validation_error(
                "negative UDS response must contain a service and response code",
                field="response_payload_hex",
            )
        if response[1] != request_service:
            raise SidecarError(
                "response_mismatch",
                "negative UDS response does not match the request service",
                field="response_payload_hex",
            )
        response_code = response[2]
        return {
            "protocol": protocol,
            "status": "negative",
            "request_service": request_service,
            "negative_response_code": response_code,
            "negative_response_name": _UDS_NEGATIVE_RESPONSE_CODES.get(
                response_code, "manufacturer_specific_or_unknown"
            ),
            "payload_hex": response[3:].hex(),
        }

    expected_service = (request_service + 0x40) & 0xFF
    if response[0] != expected_service:
        raise SidecarError(
            "response_mismatch",
            "positive UDS response service does not match the request",
            field="response_payload_hex",
            details={"expected_response_service": expected_service},
        )
    return {
        "protocol": protocol,
        "status": "positive",
        "request_service": request_service,
        "response_service": response[0],
        "payload_hex": response[1:].hex(),
    }
