import tempfile
import unittest
from pathlib import Path
from typing import Any

from test_validation import virtual_config

from oxfuzz_scapy_automotive.artifacts import FilesystemArtifactStore
from oxfuzz_scapy_automotive.contract import process_request


class _SniffTransport:
    """A fake transport that yields canned frames and forbids transmission."""

    def __init__(self, frames: list[dict[str, Any]]) -> None:
        self._frames = frames

    def send(self, message: dict[str, object]) -> None:
        raise AssertionError("live monitor must never transmit")

    def receive(self, expected: dict[str, object]) -> bytes:
        raise AssertionError("live monitor uses sniff, not receive")

    def sniff(self, max_events: int) -> list[dict[str, object]]:
        return list(self._frames[:max_events])


def _store(root: Path) -> FilesystemArtifactStore:
    inputs = root / "inputs"
    outputs = root / "outputs"
    inputs.mkdir()
    outputs.mkdir()
    return FilesystemArtifactStore(inputs, outputs)


class LiveMonitorTests(unittest.TestCase):
    def test_live_monitor_returns_capture_analysis_from_sniffed_frames(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            config = virtual_config()
            transport = _SniffTransport(
                [
                    {
                        "arbitration_id": 0x123,
                        "is_extended_id": False,
                        "payload_hex": "deadbeef",
                        "timestamp": 1.0,
                    },
                    {
                        "arbitration_id": 0x123,
                        "is_extended_id": False,
                        "payload_hex": "deadbe00",
                        "timestamp": 1.01,
                    },
                ]
            )
            request = {
                "schema_version": 1,
                "request_id": "live-1",
                "operation": "live_monitor",
                "payload": {
                    "protocol": config["protocol"],
                    "mode": {"mode": "virtual_can", "interface": config["interface"]},
                    "limits": config["limits"],
                },
            }
            response = process_request(
                request,
                artifact_store=store,
                execution_config=config,
                transport=transport,
            )
            self.assertTrue(response["ok"], response.get("error"))
            self.assertEqual(response["result"]["result"], "capture_analysis")
            data = response["result"]["data"]
            self.assertEqual(data["event_count"], 2)
            self.assertEqual(data["protocol"], config["protocol"])
            self.assertEqual(
                data["transcript"]["media_type"],
                "application/vnd.oxfuzz.automotive-transcript+json",
            )
            self.assertEqual(data["transcript_hash"], response["transcript_sha256"])

    def test_live_monitor_rejects_offline_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            request = {
                "schema_version": 1,
                "request_id": "live-2",
                "operation": "live_monitor",
                "payload": {
                    "protocol": "can",
                    "mode": {"mode": "offline_pcap"},
                    "limits": virtual_config()["limits"],
                },
            }
            response = process_request(
                request,
                artifact_store=store,
                execution_config=None,
                transport=_SniffTransport([]),
            )
            self.assertFalse(response["ok"])

    def test_live_monitor_reports_a_quiet_bus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            config = virtual_config()
            request = {
                "schema_version": 1,
                "request_id": "live-3",
                "operation": "live_monitor",
                "payload": {
                    "protocol": config["protocol"],
                    "mode": {"mode": "virtual_can", "interface": config["interface"]},
                    "limits": config["limits"],
                },
            }
            response = process_request(
                request,
                artifact_store=store,
                execution_config=config,
                transport=_SniffTransport([]),
            )
            self.assertFalse(response["ok"])
            self.assertIn("no frames", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
