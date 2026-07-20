import copy
import unittest

from test_validation import limits, virtual_config

from oxfuzz_scapy_automotive.errors import SidecarError
from oxfuzz_scapy_automotive.replay import (
    UnavailableTransport,
    _wire_uds_service,
    build_replay_plan,
    execute_replay_plan,
)
from oxfuzz_scapy_automotive.responses import parse_automotive_response
from oxfuzz_scapy_automotive.state import state_signature


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def send(self, message: dict[str, object]) -> None:
        self.calls.append(("send", copy.deepcopy(message)))

    def receive(self, expected: dict[str, object]) -> bytes:
        self.calls.append(("receive", copy.deepcopy(expected)))
        return bytes.fromhex(str(expected["payload_hex"]))


class ResponseStateReplayTests(unittest.TestCase):
    def test_uds_positive_and_negative_responses_are_parsed(self) -> None:
        positive = parse_automotive_response("uds", "221234", "621234beef")
        self.assertEqual(positive["status"], "positive")
        self.assertEqual(positive["request_service"], 0x22)
        self.assertEqual(positive["response_service"], 0x62)
        self.assertEqual(positive["payload_hex"], "1234beef")

        negative = parse_automotive_response("uds", "221234", "7f2231")
        self.assertEqual(negative["status"], "negative")
        self.assertEqual(negative["negative_response_code"], 0x31)
        self.assertEqual(negative["negative_response_name"], "request_out_of_range")

    def test_malformed_or_mismatched_uds_responses_fail_closed(self) -> None:
        for response in ("", "7f22", "6300", "zz"):
            with self.subTest(response=response), self.assertRaises(SidecarError):
                parse_automotive_response("uds", "221234", response)

    def test_state_signature_ignores_timing_but_is_protocol_scoped(self) -> None:
        observation = {
            "protocol": "uds",
            "status": "negative",
            "request_service": 0x22,
            "negative_response_code": 0x31,
            "session": "extended",
            "timestamp_ns": 100,
            "latency_micros": 12,
        }
        changed_timing = dict(observation, timestamp_ns=999, latency_micros=500)
        changed_protocol = dict(observation, protocol="gmlan")

        first = state_signature(observation)
        self.assertEqual(first, state_signature(changed_timing))
        self.assertNotEqual(first["digest"], state_signature(changed_protocol)["digest"])
        self.assertNotIn("timestamp_ns", first["observations"])

    def test_replay_plan_is_canonical_and_uses_an_injected_transport(self) -> None:
        events = [
            {
                "sequence": 2,
                "protocol": "uds",
                "direction": "receive",
                "offset_micros": 250,
                "payload_hex": "621234",
                "metadata": {"arbitration_id": 0x7E8},
            },
            {
                "sequence": 0,
                "protocol": "uds",
                "direction": "transmit",
                "offset_micros": 0,
                "payload_hex": "221234",
                "metadata": {"arbitration_id": 0x7E0},
            },
            {
                "sequence": 1,
                "protocol": "uds",
                "direction": "transmit",
                "offset_micros": 200,
                "payload_hex": "1001",
                "metadata": {"arbitration_id": 0x7E0},
            },
        ]
        plan = build_replay_plan(
            {"protocol": "uds", "mode": "virtual_can", "deterministic_seed": 5, "events": events}
        )
        reordered = build_replay_plan(
            {
                "protocol": "uds",
                "mode": "virtual_can",
                "deterministic_seed": 5,
                "events": list(reversed(events)),
            }
        )

        self.assertEqual(plan, reordered)
        self.assertEqual(
            [step["action"] for step in plan["steps"]], ["send", "send", "expect_response"]
        )
        self.assertEqual([step["delay_micros"] for step in plan["steps"]], [0, 200, 50])
        self.assertEqual(len(plan["artifact_sha256"]), 64)

        transport = FakeTransport()
        sleep_calls: list[float] = []
        result = execute_replay_plan(virtual_config(), plan, transport, sleeper=sleep_calls.append)
        self.assertEqual([call[0] for call in transport.calls], ["send", "send", "receive"])
        self.assertEqual(sleep_calls, [0.0002, 0.00005])
        self.assertEqual(result["executed_events"], 3)
        self.assertTrue(result["completed"])
        self.assertEqual(len(result["transcript_sha256"]), 64)

    @staticmethod
    def _single_send_plan(payload_hex: str, *, protocol: str = "uds") -> dict:
        return build_replay_plan(
            {
                "protocol": protocol,
                "mode": "virtual_can",
                "deterministic_seed": 1,
                "events": [
                    {
                        "sequence": 0,
                        "protocol": protocol,
                        "direction": "transmit",
                        "offset_micros": 0,
                        "payload_hex": payload_hex,
                        "metadata": {"arbitration_id": 0x7E0},
                    }
                ],
            }
        )

    def test_wire_service_is_iso_tp_framing_aware(self) -> None:
        self.assertEqual(_wire_uds_service("0211"), 0x11)
        self.assertEqual(_wire_uds_service("221234"), 0x22)
        self.assertEqual(_wire_uds_service("11"), 0x11)
        self.assertIsNone(_wire_uds_service("03"))

    def test_single_frame_service_is_read_after_the_pci_byte(self) -> None:
        # PCI 0x02 + service 0x10 (allowlisted): the PCI byte must NOT be treated
        # as the service, so this transmits.
        allowed = self._single_send_plan("0210")
        transport = FakeTransport()
        result = execute_replay_plan(virtual_config(), allowed, transport, sleeper=lambda _s: None)
        self.assertEqual(result["executed_events"], 1)
        # PCI 0x02 + service 0x11 (ECU reset, not allowlisted): rejected on the
        # framed service, not the PCI byte.
        denied = self._single_send_plan("0211")
        with self.assertRaises(SidecarError) as ctx:
            execute_replay_plan(virtual_config(), denied, FakeTransport(), sleeper=lambda _s: None)
        self.assertEqual(ctx.exception.code, "service_not_allowed")

    def test_service_check_applies_regardless_of_protocol_label(self) -> None:
        # A can-labelled transmit is still service-checked (no protocol==uds bypass):
        # payload 0211 frames service 0x11 (not allowlisted) -> rejected.
        config = virtual_config()
        config["protocol"] = "can"
        plan = self._single_send_plan("0211", protocol="can")
        with self.assertRaises(SidecarError) as ctx:
            execute_replay_plan(config, plan, FakeTransport(), sleeper=lambda _s: None)
        self.assertEqual(ctx.exception.code, "service_not_allowed")

    def test_peak_rate_burst_is_rejected(self) -> None:
        # Front-loaded burst passes the average check but must fail the peak check.
        events = [
            {
                "sequence": index,
                "protocol": "uds",
                "direction": "transmit",
                "offset_micros": 2_000_000 if index == 3 else 0,
                "payload_hex": "2210",
                "metadata": {"arbitration_id": 0x7E0},
            }
            for index in range(4)
        ]
        plan = build_replay_plan(
            {"protocol": "uds", "mode": "virtual_can", "deterministic_seed": 1, "events": events}
        )
        config = virtual_config()
        config["limits"] = limits(max_rate_per_second=2)
        with self.assertRaises(SidecarError) as ctx:
            execute_replay_plan(config, plan, FakeTransport(), sleeper=lambda _s: None)
        self.assertEqual(ctx.exception.code, "limit_exceeded")

    def test_replay_never_has_an_implicit_live_transport(self) -> None:
        plan = build_replay_plan(
            {
                "protocol": "uds",
                "mode": "virtual_can",
                "deterministic_seed": 0,
                "events": [
                    {
                        "sequence": 0,
                        "protocol": "uds",
                        "direction": "transmit",
                        "offset_micros": 0,
                        "payload_hex": "221234",
                        "metadata": {"arbitration_id": 0x7E0},
                    }
                ],
            }
        )
        with self.assertRaises(SidecarError):
            execute_replay_plan(virtual_config(), plan, UnavailableTransport())

    def test_entire_replay_is_preflighted_before_the_first_transport_call(self) -> None:
        invalid_allowlist_plan = build_replay_plan(
            {
                "protocol": "uds",
                "mode": "virtual_can",
                "deterministic_seed": 0,
                "events": [
                    {
                        "sequence": 0,
                        "protocol": "uds",
                        "direction": "transmit",
                        "offset_micros": 0,
                        "payload_hex": "221234",
                        "metadata": {"arbitration_id": 0x7E0},
                    },
                    {
                        "sequence": 1,
                        "protocol": "uds",
                        "direction": "transmit",
                        "offset_micros": 100,
                        "payload_hex": "221234",
                        "metadata": {"arbitration_id": 0x123},
                    },
                ],
            }
        )
        transport = FakeTransport()
        with self.assertRaises(SidecarError):
            execute_replay_plan(
                virtual_config(), invalid_allowlist_plan, transport, sleeper=lambda _: None
            )
        self.assertEqual(transport.calls, [])

        excessive_delay_plan = build_replay_plan(
            {
                "protocol": "uds",
                "mode": "virtual_can",
                "deterministic_seed": 0,
                "events": [
                    {
                        "sequence": 0,
                        "protocol": "uds",
                        "direction": "transmit",
                        "offset_micros": 0,
                        "payload_hex": "221234",
                        "metadata": {"arbitration_id": 0x7E0},
                    },
                    {
                        "sequence": 1,
                        "protocol": "uds",
                        "direction": "transmit",
                        "offset_micros": 5_000_001,
                        "payload_hex": "221234",
                        "metadata": {"arbitration_id": 0x7E0},
                    },
                ],
            }
        )
        transport = FakeTransport()
        with self.assertRaises(SidecarError):
            execute_replay_plan(
                virtual_config(), excessive_delay_plan, transport, sleeper=lambda _: None
            )
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
