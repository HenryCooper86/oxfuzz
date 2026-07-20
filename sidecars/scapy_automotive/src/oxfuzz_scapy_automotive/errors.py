"""Structured errors that can safely cross the JSONL boundary."""

from __future__ import annotations

from typing import Any


class SidecarError(Exception):
    """A stable, non-traceback error returned to the Rust caller."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field
        self.retryable = retryable
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "retryable": self.retryable,
            "details": self.details,
        }


def validation_error(
    message: str, *, field: str | None = None, details: dict[str, Any] | None = None
) -> SidecarError:
    return SidecarError(
        "validation_error",
        message,
        field=field,
        retryable=False,
        details=details,
    )
