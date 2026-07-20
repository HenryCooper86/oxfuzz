import io
import json
import subprocess
import sys
import unittest

from test_validation import virtual_config

from oxfuzz_scapy_automotive.cli import run_jsonl
from oxfuzz_scapy_automotive.replay import UnavailableTransport


class CliTests(unittest.TestCase):
    def test_documented_python_module_entrypoint_processes_jsonl(self) -> None:
        request = json.dumps(
            {
                "schema_version": 1,
                "request_id": "module-entrypoint-1",
                "operation": "capabilities",
                "payload": {},
            }
        )

        completed = subprocess.run(
            [sys.executable, "-m", "oxfuzz_scapy_automotive"],
            input=request + "\n",
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        response = json.loads(completed.stdout)
        self.assertEqual(response["request_id"], "module-entrypoint-1")
        self.assertTrue(response["ok"])

    def test_jsonl_processes_each_line_and_keeps_stdout_machine_readable(self) -> None:
        requests = [
            {
                "schema_version": 1,
                "request_id": "capabilities-1",
                "operation": "capabilities",
                "payload": {},
            },
            {
                "schema_version": 1,
                "request_id": "bad-1",
                "operation": "unknown_operation",
                "payload": {},
            },
        ]
        source = io.StringIO("\n".join(json.dumps(item) for item in requests) + "\n")
        destination = io.StringIO()

        exit_code = run_jsonl(
            source,
            destination,
            runtime={
                "scapy_available": True,
                "scapy_version": "2.7.0",
                "python_can_available": False,
                "python_can_version": None,
            },
        )
        lines = destination.getvalue().splitlines()

        self.assertEqual(exit_code, 1)
        self.assertEqual(len(lines), 2)
        responses = [json.loads(line) for line in lines]
        self.assertEqual([response["schema_version"] for response in responses], [1, 1])
        self.assertEqual(
            [response["request_id"] for response in responses],
            ["capabilities-1", "bad-1"],
        )
        self.assertTrue(responses[0]["ok"])
        self.assertEqual(responses[0]["result"]["result"], "capabilities")
        self.assertFalse(responses[1]["ok"])
        self.assertEqual(responses[1]["error"]["code"], "invalid_request")
        self.assertNotIn("Traceback", destination.getvalue())

    def test_malformed_json_is_returned_as_a_structured_error(self) -> None:
        destination = io.StringIO()
        exit_code = run_jsonl(io.StringIO("{not-json}\n"), destination)
        response = json.loads(destination.getvalue())

        self.assertEqual(exit_code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["schema_version"], 1)
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertEqual(response["request_id"], "unknown")
        self.assertIsNone(response["transcript_sha256"])

    def test_transport_factory_receives_only_a_validated_execution_config(self) -> None:
        request = json.dumps(
            {
                "schema_version": 1,
                "request_id": "capabilities-1",
                "operation": "capabilities",
                "payload": {},
            }
        )
        selected_configs: list[object] = []

        def factory(config: object) -> UnavailableTransport:
            selected_configs.append(config)
            return UnavailableTransport()

        run_jsonl(
            io.StringIO(request + "\n"),
            io.StringIO(),
            runtime={
                "scapy_available": True,
                "scapy_version": "2.7.0",
                "python_can_available": True,
                "python_can_version": "4.6.1",
            },
            execution_config=virtual_config(),
            transport_factory=factory,
        )
        self.assertEqual(len(selected_configs), 1)
        self.assertEqual(selected_configs[0], virtual_config())

        invalid = virtual_config()
        invalid["interface"] = "vcan0;invalid"
        selected_configs.clear()
        run_jsonl(
            io.StringIO(request + "\n"),
            io.StringIO(),
            runtime={
                "scapy_available": True,
                "scapy_version": "2.7.0",
                "python_can_available": True,
                "python_can_version": "4.6.1",
            },
            execution_config=invalid,
            transport_factory=factory,
        )
        self.assertEqual(selected_configs, [])

    def test_validated_factory_transport_executes_the_jsonl_replay(self) -> None:
        config = virtual_config()
        calls: list[tuple[str, dict[str, object]]] = []

        class RecordingTransport:
            def send(self, message: dict[str, object]) -> None:
                calls.append(("send", message))

            def receive(self, expected: dict[str, object]) -> bytes:
                calls.append(("receive", expected))
                return b"response"

        request = {
            "schema_version": 1,
            "request_id": "replay-1",
            "operation": "execute_replay",
            "payload": {
                "mode": {"mode": "virtual_can", "interface": "vcan0"},
                "plan": {
                    "protocol": "uds",
                    "mode": "virtual_can",
                    "deterministic_seed": 0,
                    "steps": [
                        {
                            "sequence": 0,
                            "delay_micros": 0,
                            "action": "send",
                            "message": {
                                "protocol": "uds",
                                "payload_hex": "221234",
                                "fields": {"arbitration_id": "2016"},
                            },
                        }
                    ],
                },
                "limits": config["limits"],
            },
        }
        destination = io.StringIO()

        exit_code = run_jsonl(
            io.StringIO(json.dumps(request) + "\n"),
            destination,
            execution_config=config,
            transport_factory=lambda _: RecordingTransport(),
        )
        response = json.loads(destination.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["result"], "replay")
        self.assertEqual([name for name, _ in calls], ["send"])


if __name__ == "__main__":
    unittest.main()
