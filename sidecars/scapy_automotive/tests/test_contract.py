import json
import tempfile
import unittest
from pathlib import Path

from hobot_scapy_automotive.artifacts import FilesystemArtifactStore, validate_artifact_ref
from hobot_scapy_automotive.capabilities import capability_report
from hobot_scapy_automotive.contract import (
    PROTOCOLS,
    SCHEMA_VERSION,
    process_request,
)
from hobot_scapy_automotive.errors import SidecarError
from hobot_scapy_automotive.hashing import sha256_bytes


class ContractTests(unittest.TestCase):
    def test_artifact_references_bind_the_declared_and_observed_file_size(self) -> None:
        data = b"bounded-artifact"
        reference = {
            "artifact_id": "capture.pcap",
            "sha256": sha256_bytes(data),
            "media_type": "application/vnd.tcpdump.pcap",
            "size_bytes": len(data),
        }
        self.assertEqual(validate_artifact_ref(reference), reference)

        for invalid_size in (0, len(data) + 1):
            invalid = dict(reference, size_bytes=invalid_size)
            if invalid_size == 0:
                with self.assertRaises(SidecarError):
                    validate_artifact_ref(invalid)
                continue
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inputs = root / "inputs"
                outputs = root / "outputs"
                inputs.mkdir()
                outputs.mkdir()
                (inputs / "capture.pcap").write_bytes(data)
                with self.assertRaises(SidecarError):
                    FilesystemArtifactStore(inputs, outputs).resolve(invalid, invalid_size)

    def test_protocol_names_and_capability_report_are_stable(self) -> None:
        self.assertEqual(
            PROTOCOLS,
            (
                "can",
                "can_fd",
                "iso_tp",
                "uds",
                "gmlan",
                "some_ip",
                "some_ip_sd",
                "do_ip",
                "obd",
                "ccp",
                "xcp",
                "bmw_hsfz",
                "sec_oc",
            ),
        )

        report = capability_report(
            scapy_available=True,
            scapy_version="2.7.0",
            python_can_available=False,
            python_can_version=None,
        )

        self.assertEqual(report["adapter_name"], "scapy-sidecar")
        self.assertEqual(report["adapter_version"], "0.1.0")
        self.assertEqual(report["schema_versions"], [SCHEMA_VERSION])
        self.assertEqual(report["protocols"], list(PROTOCOLS))
        self.assertEqual(report["modes"], ["offline_pcap"])
        self.assertIn("decode_capture", report["capabilities"])
        self.assertNotIn("execute_virtual", report["capabilities"])

    def test_capability_envelope_and_hash_are_deterministic(self) -> None:
        request = {
            "schema_version": 1,
            "request_id": "capabilities-1",
            "operation": "capabilities",
            "payload": {},
        }
        runtime = {
            "scapy_available": True,
            "scapy_version": "2.7.0",
            "python_can_available": False,
            "python_can_version": None,
        }

        first = process_request(request, runtime=runtime)
        second = process_request(json.loads(json.dumps(request, sort_keys=True)), runtime=runtime)

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], SCHEMA_VERSION)
        self.assertEqual(first["request_id"], request["request_id"])
        self.assertTrue(first["ok"])
        self.assertIsNone(first["error"])
        self.assertEqual(
            set(first),
            {
                "schema_version",
                "request_id",
                "ok",
                "result",
                "error",
                "transcript_sha256",
            },
        )
        self.assertEqual(first["result"]["result"], "capabilities")
        self.assertIsNone(first["transcript_sha256"])

    def test_invalid_requests_fail_closed_with_structured_errors(self) -> None:
        invalid = process_request(
            {
                "schema_version": 2,
                "request_id": "bad-schema",
                "operation": "capabilities",
                "payload": {},
                "unexpected": True,
            }
        )

        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["schema_version"], SCHEMA_VERSION)
        self.assertEqual(invalid["request_id"], "bad-schema")
        self.assertEqual(
            set(invalid),
            {
                "schema_version",
                "request_id",
                "ok",
                "result",
                "error",
                "transcript_sha256",
            },
        )
        self.assertEqual(invalid["error"]["code"], "invalid_request")
        self.assertFalse(invalid["error"]["retryable"])
        self.assertIsNone(invalid["transcript_sha256"])

    def test_capability_exchange_matches_the_cross_language_wire_fixture(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "wire_contract_v1.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

        observed = process_request(fixture["request"], runtime=fixture["runtime"])

        self.assertEqual(observed, fixture["response"])


if __name__ == "__main__":
    unittest.main()
