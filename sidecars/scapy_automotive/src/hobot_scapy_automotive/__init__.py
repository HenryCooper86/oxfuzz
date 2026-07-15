"""Safety-first Scapy adapter for hobot_fuzz automotive workflows."""

from .contract import SCHEMA_VERSION, process_request

__all__ = ["SCHEMA_VERSION", "process_request"]
__version__ = "0.1.0"
