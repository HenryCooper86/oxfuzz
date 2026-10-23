import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_scan_uds import _ScanTransport, _store
from test_validation import virtual_config

from oxfuzz_scapy_automotive.contract import process_request


class _Clock:
    def __init__(self, oversleep: float = 0.0) -> None:
        self.now = 100.0
        self.oversleep = oversleep

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds + self.oversleep


class _TimedTransport(_ScanTransport):
    def __init__(self, clock: _Clock, reply: bytes | None, duration: float) -> None:
        super().__init__({})
        self.clock = clock
        self.reply = reply
        self.duration = duration
        self.times: list[float] = []

    def probe(self, request_id: int, response_id: int, payload: bytes) -> bytes | None:
        super().probe(request_id, response_id, payload)
        self.times.append(self.clock.now)
        self.clock.now += self.duration
        return self.reply


class ScanLimitsTests(unittest.TestCase):
    def run_scan(
        self,
        *,
        services: list[int] | None = None,
        limits: dict[str, int] | None = None,
        reply: bytes | None = None,
        duration: float = 0.0,
        oversleep: float = 0.0,
    ):
        clock = _Clock(oversleep)
        transport = _TimedTransport(clock, reply, duration)
        config = virtual_config()
        config["limits"].update(limits or {})
        request = {
            "schema_version": 1,
            "request_id": "scan-budget",
            "operation": "scan_uds",
            "payload": {
                "mode": {"mode": "virtual_can", "interface": "vcan0"},
                "request_ids": [0x7E0],
                "services": [0x10, 0x22] if services is None else services,
                "limits": config["limits"],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            store = _store(Path(directory))
            with patch("time.monotonic", clock.monotonic), patch("time.sleep", clock.sleep):
                response = process_request(
                    request, artifact_store=store, execution_config=config, transport=transport
                )
            artifacts = list(store.output_root.iterdir())
            events = json.loads(artifacts[0].read_text())[2] if artifacts else []
        return response, transport, events

    def test_outbound_event_budget_is_checked_before_first_probe(self) -> None:
        response, transport, _ = self.run_scan(limits={"max_events": 1})
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_events")
        self.assertEqual(transport.sent, [])

    def test_outbound_payload_budget_is_checked_before_first_probe(self) -> None:
        response, transport, _ = self.run_scan(limits={"max_payload_bytes": 4})
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_payload_bytes")
        self.assertEqual(transport.sent, [])

    def test_impossible_paced_duration_is_rejected_before_first_probe(self) -> None:
        response, transport, _ = self.run_scan(
            limits={"max_rate_per_second": 1, "max_duration_ms": 1000}
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_duration_ms")
        self.assertEqual(transport.sent, [])

    def test_probes_are_paced_and_transcript_records_observed_time(self) -> None:
        response, transport, events = self.run_scan(limits={"max_rate_per_second": 2})
        self.assertTrue(response["ok"], response.get("error"))
        self.assertEqual(transport.times, [100.0, 100.5])
        self.assertEqual([event["offset_micros"] for event in events], [0, 500000])

    def test_reply_consumes_event_budget_before_next_probe(self) -> None:
        response, transport, events = self.run_scan(limits={"max_events": 2}, reply=b"\x02\x50\x01")
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_events")
        self.assertEqual(len(transport.sent), 1)
        self.assertEqual(events, [])

    def test_reply_consumes_payload_budget_before_next_probe(self) -> None:
        response, transport, _ = self.run_scan(
            limits={"max_payload_bytes": 5}, reply=b"\x02\x50\x01"
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_payload_bytes")
        self.assertEqual(len(transport.sent), 1)

    def test_response_cannot_exceed_remaining_payload_budget(self) -> None:
        response, transport, events = self.run_scan(
            services=[0x10], limits={"max_payload_bytes": 4}, reply=b"\x02\x50\x01"
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_payload_bytes")
        self.assertEqual(len(transport.sent), 1)
        self.assertEqual(events, [])

    def test_response_cannot_exceed_classic_can_frame_size(self) -> None:
        response, transport, _ = self.run_scan(reply=b"\x02\x50\x01" + b"\x00" * 6)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "response")
        self.assertEqual(len(transport.sent), 1)

    def test_deadline_exceeded_by_probe_stops_further_transmission(self) -> None:
        response, transport, _ = self.run_scan(limits={"max_duration_ms": 100}, duration=0.2)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_duration_ms")
        self.assertEqual(len(transport.sent), 1)

    def test_final_probe_cannot_report_success_after_deadline(self) -> None:
        response, transport, _ = self.run_scan(
            services=[0x10], limits={"max_duration_ms": 100}, duration=0.2
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_duration_ms")
        self.assertEqual(len(transport.sent), 1)

    def test_sleep_overshoot_is_checked_before_next_probe(self) -> None:
        response, transport, _ = self.run_scan(limits={"max_duration_ms": 100}, oversleep=0.2)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["field"], "limits.max_duration_ms")
        self.assertEqual(len(transport.sent), 1)

    def test_reply_offsets_use_observed_completion_time(self) -> None:
        response, _, events = self.run_scan(services=[0x10], reply=b"\x02\x50\x01", duration=0.125)
        self.assertTrue(response["ok"], response.get("error"))
        self.assertEqual([event["offset_micros"] for event in events], [0, 125000])
