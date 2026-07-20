import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from test_validation import physical_config, virtual_config

from oxfuzz_scapy_automotive.artifacts import FilesystemArtifactStore
from oxfuzz_scapy_automotive.contract import process_request
from oxfuzz_scapy_automotive.hashing import sha256_bytes
from oxfuzz_scapy_automotive.replay import physical_replay_scope_sha256


def operation_limits() -> dict[str, int]:
    return {
        "max_events": 20,
        "max_payload_bytes": 4_096,
        "max_duration_ms": 10_000,
        "max_rate_per_second": 20,
    }


def stage(root: Path, artifact_id: str, data: bytes, media_type: str) -> dict[str, object]:
    (root / artifact_id).write_bytes(data)
    return {
        "artifact_id": artifact_id,
        "sha256": sha256_bytes(data),
        "media_type": media_type,
        "size_bytes": len(data),
    }


class FakeDecoder:
    def decode(self, path: Path, max_events: int) -> list[dict[str, Any]]:
        del path, max_events
        return [
            {
                "sequence": 0,
                "timestamp_ns": 1_000_000,
                "layers": ["CAN", "UDS"],
                "payload_hex": "221234",
                "fields": {"identifier": 0x7E0},
            }
        ]


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def send(self, message: dict[str, object]) -> None:
        del message
        self.calls.append("send")

    def receive(self, expected: dict[str, object]) -> bytes:
        self.calls.append("receive")
        return bytes.fromhex(str(expected["payload_hex"]))


class WireOperationTests(unittest.TestCase):
    def test_all_rust_operations_return_typed_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()
            outputs.mkdir()
            store = FilesystemArtifactStore(inputs, outputs)

            capture = stage(
                inputs,
                "capture.pcap",
                b"offline-pcap-fixture",
                "application/vnd.tcpdump.pcap",
            )
            analysis = process_request(
                {
                    "schema_version": 1,
                    "request_id": "analysis-1",
                    "operation": "analyze_capture",
                    "payload": {
                        "protocol": "uds",
                        "capture": capture,
                        "limits": operation_limits(),
                    },
                },
                artifact_store=store,
                decoder=FakeDecoder(),
            )
            self.assertTrue(analysis["ok"])
            self.assertEqual(analysis["schema_version"], 1)
            self.assertEqual(analysis["request_id"], "analysis-1")
            self.assertEqual(analysis["result"]["result"], "capture_analysis")
            self.assertEqual(analysis["result"]["data"]["event_count"], 1)
            self.assertEqual(
                analysis["transcript_sha256"], analysis["result"]["data"]["transcript_hash"]
            )
            transcript_ref = analysis["result"]["data"]["transcript"]
            self.assertEqual(
                transcript_ref["media_type"],
                "application/vnd.oxfuzz.automotive-transcript+json",
            )
            self.assertEqual(transcript_ref["sha256"], analysis["transcript_sha256"])
            transcript_path = outputs / transcript_ref["artifact_id"]
            transcript_bytes = transcript_path.read_bytes()
            self.assertEqual(transcript_ref["size_bytes"], len(transcript_bytes))
            self.assertEqual(transcript_ref["sha256"], sha256_bytes(transcript_bytes))
            canonical_transcript = json.loads(transcript_bytes)
            self.assertEqual(canonical_transcript[:2], [1, "automotive-transcript"])
            self.assertEqual(canonical_transcript[2][0]["protocol"], "uds")
            self.assertEqual(canonical_transcript[2][0]["payload_hex"], "221234")

            (inputs / transcript_ref["artifact_id"]).write_bytes(transcript_bytes)
            analysis_replay_plan = process_request(
                {
                    "schema_version": 1,
                    "request_id": "analysis-plan-1",
                    "operation": "build_replay_plan",
                    "payload": {
                        "protocol": "uds",
                        "source": transcript_ref,
                        "target_mode": "virtual_can",
                        "deterministic_seed": 3,
                        "limits": operation_limits(),
                    },
                },
                artifact_store=store,
            )
            self.assertTrue(analysis_replay_plan["ok"])
            self.assertEqual(analysis_replay_plan["result"]["result"], "replay_plan")
            self.assertEqual(len(analysis_replay_plan["result"]["data"]["steps"]), 1)

            seed = stage(inputs, "seed.bin", bytes.fromhex("221234"), "application/octet-stream")
            mutations = process_request(
                {
                    "schema_version": 1,
                    "request_id": "mutations-1",
                    "operation": "generate_mutations",
                    "payload": {
                        "protocol": "uds",
                        "source": seed,
                        "deterministic_seed": 7,
                        "mutation_count": 4,
                        "limits": operation_limits(),
                    },
                },
                artifact_store=store,
            )
            self.assertTrue(mutations["ok"])
            self.assertEqual(mutations["schema_version"], 1)
            self.assertEqual(mutations["request_id"], "mutations-1")
            self.assertEqual(mutations["result"]["result"], "mutations")
            self.assertEqual(mutations["result"]["data"]["generated"], 4)
            generated_ref = mutations["result"]["data"]["artifacts"][0]
            self.assertTrue((outputs / generated_ref["artifact_id"]).is_file())
            self.assertEqual(
                generated_ref["size_bytes"],
                (outputs / generated_ref["artifact_id"]).stat().st_size,
            )

            transcript_data = json.dumps(
                {
                    "events": [
                        {
                            "sequence": 0,
                            "protocol": "uds",
                            "direction": "transmit",
                            "offset_micros": 0,
                            "payload_hex": "221234",
                            "metadata": {"arbitration_id": "2016"},
                        },
                        {
                            "sequence": 1,
                            "protocol": "uds",
                            "direction": "receive",
                            "offset_micros": 200,
                            "payload_hex": "621234",
                            "metadata": {"arbitration_id": "2024"},
                        },
                    ]
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            transcript = stage(
                inputs,
                "transcript.json",
                transcript_data,
                "application/vnd.oxfuzz.automotive-transcript+json",
            )
            replay_plan = process_request(
                {
                    "schema_version": 1,
                    "request_id": "plan-1",
                    "operation": "build_replay_plan",
                    "payload": {
                        "protocol": "uds",
                        "source": transcript,
                        "target_mode": "virtual_can",
                        "deterministic_seed": 5,
                        "limits": operation_limits(),
                    },
                },
                artifact_store=store,
            )
            self.assertTrue(replay_plan["ok"])
            self.assertEqual(replay_plan["schema_version"], 1)
            self.assertEqual(replay_plan["request_id"], "plan-1")
            self.assertEqual(replay_plan["result"]["result"], "replay_plan")

            transport = FakeTransport()
            replay = process_request(
                {
                    "schema_version": 1,
                    "request_id": "replay-1",
                    "operation": "execute_replay",
                    "payload": {
                        "mode": {"mode": "virtual_can", "interface": "vcan0"},
                        "plan": replay_plan["result"]["data"],
                        "limits": operation_limits(),
                    },
                },
                execution_config=virtual_config(),
                transport=transport,
            )
            self.assertTrue(replay["ok"])
            self.assertEqual(replay["schema_version"], 1)
            self.assertEqual(replay["request_id"], "replay-1")
            self.assertEqual(replay["result"]["result"], "replay")
            self.assertEqual(replay["result"]["data"]["state_signatures"], [])
            self.assertEqual(transport.calls, ["send", "receive"])

            physical_plan = dict(replay_plan["result"]["data"], mode="physical_bench")
            physical = physical_config()
            physical["limits"] = operation_limits()
            physical["approval"]["scope_sha256"] = physical_replay_scope_sha256(  # type: ignore[index]
                physical_plan, physical
            )
            physical_transport = FakeTransport()
            physical_replay = process_request(
                {
                    "schema_version": 1,
                    "request_id": "physical-replay-1",
                    "operation": "execute_replay",
                    "payload": {
                        "mode": {
                            "mode": "physical_bench",
                            "interface": "can0",
                            "approval_id": "approval-123",
                        },
                        "plan": physical_plan,
                        "limits": operation_limits(),
                    },
                },
                execution_config=physical,
                transport=physical_transport,
            )
            self.assertTrue(physical_replay["ok"])
            self.assertEqual(physical_transport.calls, ["send", "receive"])

            tampered_plan = dict(physical_plan, deterministic_seed=6)
            denied = process_request(
                {
                    "schema_version": 1,
                    "request_id": "physical-replay-tampered",
                    "operation": "execute_replay",
                    "payload": {
                        "mode": {
                            "mode": "physical_bench",
                            "interface": "can0",
                            "approval_id": "approval-123",
                        },
                        "plan": tampered_plan,
                        "limits": operation_limits(),
                    },
                },
                execution_config=physical,
                transport=FakeTransport(),
            )
            self.assertFalse(denied["ok"])
            self.assertEqual(denied["error"]["code"], "policy_denied")


if __name__ == "__main__":
    unittest.main()
