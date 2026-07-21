import tempfile
import unittest
from pathlib import Path

from test_validation import virtual_config

from oxfuzz_scapy_automotive.artifacts import FilesystemArtifactStore
from oxfuzz_scapy_automotive.contract import process_request


class _ScanTransport:
    """A fake transport whose probe() returns canned response frames by
    (request_id, service id) and forbids any other transport method."""

    def __init__(self, responses: dict[tuple[int, int], bytes]) -> None:
        self._responses = responses
        self.sent: list[tuple[int, bytes]] = []

    def send(self, message: dict[str, object]) -> None:
        raise AssertionError("a UDS scan uses probe, not send")

    def receive(self, expected: dict[str, object]) -> bytes:
        raise AssertionError("a UDS scan uses probe, not receive")

    def sniff(self, max_events: int) -> list[dict[str, object]]:
        raise AssertionError("a UDS scan uses probe, not sniff")

    def probe(self, request_id: int, response_id: int, payload: bytes) -> bytes | None:
        self.sent.append((request_id, payload))
        return self._responses.get((request_id, payload[0]))


def _store(root: Path) -> FilesystemArtifactStore:
    inputs = root / "inputs"
    outputs = root / "outputs"
    inputs.mkdir()
    outputs.mkdir()
    return FilesystemArtifactStore(inputs, outputs)


class ScanUdsTests(unittest.TestCase):
    def test_scan_classifies_positive_and_negative_responses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            config = virtual_config()  # allowlists 0x7E0 and services 0x10, 0x22
            transport = _ScanTransport(
                {
                    # 0x10 positive: ISO-TP SF, `50 01 00 32 01 F4`.
                    (0x7E0, 0x10): bytes([0x06, 0x50, 0x01, 0x00, 0x32, 0x01, 0xF4]),
                    # 0x22 negative: ISO-TP SF, `7F 22 31` (requestOutOfRange).
                    (0x7E0, 0x22): bytes([0x03, 0x7F, 0x22, 0x31]),
                }
            )
            request = {
                "schema_version": 1,
                "request_id": "scan-1",
                "operation": "scan_uds",
                "payload": {
                    "mode": {"mode": "virtual_can", "interface": config["interface"]},
                    "request_ids": [0x7E0],
                    "services": [0x10, 0x22],
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
            self.assertEqual(response["result"]["result"], "uds_scan")
            ecus = response["result"]["data"]["ecus"]
            self.assertEqual(len(ecus), 1)
            self.assertEqual(ecus[0]["request_id"], 0x7E0)
            self.assertEqual(ecus[0]["response_id"], 0x7E8)
            services = {entry["sid"]: entry for entry in ecus[0]["services"]}
            self.assertTrue(services[0x10]["supported"])
            self.assertIsNone(services[0x10]["nrc"])
            self.assertFalse(services[0x22]["supported"])
            self.assertEqual(services[0x22]["nrc"], 0x31)

    def test_scan_denies_a_service_outside_the_injected_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            config = virtual_config()  # service_allowlist is [0x10, 0x22]
            request = {
                "schema_version": 1,
                "request_id": "scan-2",
                "operation": "scan_uds",
                "payload": {
                    "mode": {"mode": "virtual_can", "interface": config["interface"]},
                    "request_ids": [0x7E0],
                    # 0x11 ECUReset is not in the allowlist and is dangerous.
                    "services": [0x11],
                    "limits": config["limits"],
                },
            }
            response = process_request(
                request,
                artifact_store=store,
                execution_config=config,
                transport=_ScanTransport({}),
            )
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "policy_denied")

    def test_scan_of_a_quiet_bus_returns_no_ecus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            config = virtual_config()
            request = {
                "schema_version": 1,
                "request_id": "scan-3",
                "operation": "scan_uds",
                "payload": {
                    "mode": {"mode": "virtual_can", "interface": config["interface"]},
                    "request_ids": [0x7E0],
                    "services": [0x10],
                    "limits": config["limits"],
                },
            }
            response = process_request(
                request,
                artifact_store=store,
                execution_config=config,
                transport=_ScanTransport({}),  # no responses -> silent bus
            )
            self.assertTrue(response["ok"], response.get("error"))
            self.assertEqual(response["result"]["data"]["ecus"], [])


if __name__ == "__main__":
    unittest.main()
