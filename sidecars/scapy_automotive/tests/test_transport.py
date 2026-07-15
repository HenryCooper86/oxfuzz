import subprocess
import unittest
from unittest.mock import MagicMock, patch

from test_validation import physical_config, virtual_config

from hobot_scapy_automotive.errors import SidecarError
from hobot_scapy_automotive.replay import (
    UnavailableTransport,
    build_replay_plan,
    execute_replay_plan,
)
from hobot_scapy_automotive.transport import (
    IP_BINARY,
    MAX_RECEIVE_TIMEOUT_SECONDS,
    PythonCanTransport,
    create_configured_transport,
    run_fixed_command,
)


class FakeCanMessage:
    def __init__(self, **values: object) -> None:
        for key, value in values.items():
            setattr(self, key, value)


class FakeBus:
    def __init__(self) -> None:
        self.sent: list[tuple[FakeCanMessage, float]] = []
        self.receive_timeouts: list[float] = []
        self.next_message: FakeCanMessage | None = None

    def send(self, message: FakeCanMessage, timeout: float) -> None:
        self.sent.append((message, timeout))

    def recv(self, timeout: float) -> FakeCanMessage | None:
        self.receive_timeouts.append(timeout)
        return self.next_message


class FakeCanModule:
    Message = FakeCanMessage

    def __init__(self, bus: FakeBus) -> None:
        self.bus = bus
        self.bus_calls: list[dict[str, object]] = []

    def Bus(self, **values: object) -> FakeBus:
        self.bus_calls.append(values)
        return self.bus


class RecordingRunner:
    def __init__(self, return_codes: list[int] | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.return_codes = list(return_codes or [])

    def __call__(self, argv: tuple[str, ...]) -> int:
        self.calls.append(argv)
        return self.return_codes.pop(0) if self.return_codes else 0


def can_message(
    *,
    arbitration_id: int,
    payload: bytes,
    channel: str,
    is_extended_id: bool = False,
    is_fd: bool = False,
    bitrate_switch: bool = False,
    error_state_indicator: bool = False,
) -> FakeCanMessage:
    return FakeCanMessage(
        arbitration_id=arbitration_id,
        data=payload,
        channel=channel,
        is_extended_id=is_extended_id,
        is_fd=is_fd,
        bitrate_switch=bitrate_switch,
        error_state_indicator=error_state_indicator,
        is_remote_frame=False,
        is_error_frame=False,
    )


def replay_message(
    *,
    payload_hex: str = "221234",
    arbitration_id: int = 0x7E0,
    interface: str = "vcan0",
    is_extended_id: bool = False,
    is_fd: bool = False,
    bitrate_switch: bool = False,
    error_state_indicator: bool = False,
) -> dict[str, object]:
    return {
        "protocol": "uds",
        "payload_hex": payload_hex,
        "metadata": {
            "interface": interface,
            "arbitration_id": arbitration_id,
            "is_extended_id": is_extended_id,
            "is_fd": is_fd,
            "bitrate_switch": bitrate_switch,
            "error_state_indicator": error_state_indicator,
        },
    }


class TransportTests(unittest.TestCase):
    def test_default_and_offline_config_remain_unavailable(self) -> None:
        offline = {
            "mode": "offline_pcap",
            "protocol": "can",
            "physical_enabled": False,
            "limits": virtual_config()["limits"],
        }
        loader_calls: list[str] = []
        runner = RecordingRunner()

        transport = create_configured_transport(
            offline,
            can_loader=lambda: loader_calls.append("load"),
            command_runner=runner,
        )

        self.assertIsInstance(transport, UnavailableTransport)
        self.assertEqual(loader_calls, [])
        self.assertEqual(runner.calls, [])

    def test_invalid_config_is_rejected_before_dependency_or_process_access(self) -> None:
        invalid = virtual_config()
        invalid["interface"] = "vcan0;touch_tmp"
        loader_calls: list[str] = []
        runner = RecordingRunner()

        with self.assertRaises(SidecarError):
            create_configured_transport(
                invalid,
                can_loader=lambda: loader_calls.append("load"),
                command_runner=runner,
            )

        self.assertEqual(loader_calls, [])
        self.assertEqual(runner.calls, [])

        with self.assertRaises(SidecarError):
            PythonCanTransport(
                invalid,
                can_loader=lambda: loader_calls.append("load"),
                command_runner=runner,
            )
        self.assertEqual(loader_calls, [])
        self.assertEqual(runner.calls, [])

    @patch("hobot_scapy_automotive.transport.subprocess.run")
    def test_default_process_runner_never_uses_a_shell(self, run: MagicMock) -> None:
        run.return_value = subprocess.CompletedProcess([], 0)

        result = run_fixed_command((IP_BINARY, "link", "show", "dev", "vcan0"))

        self.assertEqual(result, 0)
        run.assert_called_once_with(
            (IP_BINARY, "link", "show", "dev", "vcan0"),
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=2.0,
        )

    @patch("hobot_scapy_automotive.transport.subprocess.run")
    def test_default_process_runner_rejects_non_vcan_argv(self, run: MagicMock) -> None:
        for argv in (
            ("/bin/sh", "-c", "ip link set vcan0 up"),
            (IP_BINARY, "link", "set", "dev", "can0", "up"),
            (IP_BINARY, "link", "set", "dev", "vcan0;bad", "up"),
            (IP_BINARY, "address", "show"),
        ):
            with self.subTest(argv=argv), self.assertRaises(SidecarError):
                run_fixed_command(argv)
        run.assert_not_called()

    def test_virtual_transport_is_lazy_and_uses_only_fixed_iproute2_argv(self) -> None:
        bus = FakeBus()
        can_module = FakeCanModule(bus)
        runner = RecordingRunner([1, 0, 0])
        loader_calls: list[str] = []

        def load_can() -> FakeCanModule:
            loader_calls.append("load")
            return can_module

        transport = create_configured_transport(
            virtual_config(), can_loader=load_can, command_runner=runner
        )
        self.assertEqual(runner.calls, [])
        self.assertEqual(can_module.bus_calls, [])
        self.assertEqual(loader_calls, [])

        transport.send(replay_message())

        self.assertEqual(
            runner.calls,
            [
                (IP_BINARY, "link", "show", "dev", "vcan0"),
                (IP_BINARY, "link", "add", "dev", "vcan0", "type", "vcan"),
                (IP_BINARY, "link", "set", "dev", "vcan0", "up"),
            ],
        )
        self.assertEqual(
            can_module.bus_calls,
            [
                {
                    "interface": "socketcan",
                    "channel": "vcan0",
                    "receive_own_messages": False,
                }
            ],
        )
        sent, timeout = bus.sent[0]
        self.assertEqual(sent.arbitration_id, 0x7E0)
        self.assertEqual(sent.data, bytes.fromhex("221234"))
        self.assertFalse(sent.is_fd)
        self.assertLessEqual(timeout, MAX_RECEIVE_TIMEOUT_SECONDS)
        self.assertEqual(loader_calls, ["load"])

    def test_missing_python_can_cannot_trigger_virtual_interface_setup(self) -> None:
        runner = RecordingRunner()

        def missing_dependency() -> object:
            raise SidecarError(
                "dependency_unavailable",
                "python-can unavailable in test",
            )

        transport = create_configured_transport(
            virtual_config(), can_loader=missing_dependency, command_runner=runner
        )

        with self.assertRaises(SidecarError):
            transport.receive(
                replay_message(payload_hex="621234", arbitration_id=0x7E8, interface="vcan0")
            )
        self.assertEqual(runner.calls, [])

    def test_physical_transport_never_configures_the_interface(self) -> None:
        bus = FakeBus()
        bus.next_message = can_message(
            arbitration_id=0x7E8,
            payload=bytes.fromhex("621234"),
            channel="can0",
        )
        can_module = FakeCanModule(bus)

        def forbidden_runner(argv: tuple[str, ...]) -> int:
            self.fail(f"physical mode attempted to execute: {argv!r}")

        transport = create_configured_transport(
            physical_config(), can_loader=lambda: can_module, command_runner=forbidden_runner
        )
        message = replay_message(payload_hex="621234", arbitration_id=0x7E8, interface="can0")

        self.assertEqual(transport.receive(message), bytes.fromhex("621234"))
        self.assertEqual(can_module.bus_calls[0]["channel"], "can0")
        self.assertEqual(bus.receive_timeouts, [MAX_RECEIVE_TIMEOUT_SECONDS])

    def test_send_rejects_interface_id_payload_and_flag_violations(self) -> None:
        bus = FakeBus()
        can_module = FakeCanModule(bus)
        transport = create_configured_transport(
            virtual_config(), can_loader=lambda: can_module, command_runner=RecordingRunner()
        )
        invalid_messages = [
            replay_message(interface="vcan1"),
            replay_message(arbitration_id=0x123),
            replay_message(arbitration_id=0x7E0, is_extended_id=False, payload_hex="00" * 9),
            replay_message(bitrate_switch=True),
        ]

        for message in invalid_messages:
            with self.subTest(message=message), self.assertRaises(SidecarError):
                transport.send(message)

        self.assertEqual(bus.sent, [])

    def test_transport_specific_frames_are_preflighted_before_any_send(self) -> None:
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
                    },
                    {
                        "sequence": 1,
                        "protocol": "uds",
                        "direction": "transmit",
                        "offset_micros": 10,
                        "payload_hex": "22" + "00" * 8,
                        "metadata": {"arbitration_id": 0x7E0},
                    },
                ],
            }
        )
        bus = FakeBus()
        runner = RecordingRunner()
        transport = create_configured_transport(
            virtual_config(),
            can_loader=lambda: FakeCanModule(bus),
            command_runner=runner,
        )

        with self.assertRaises(SidecarError):
            execute_replay_plan(virtual_config(), plan, transport, sleeper=lambda _: None)
        self.assertEqual(runner.calls, [])
        self.assertEqual(bus.sent, [])

    def test_can_fd_flags_and_payload_are_preserved(self) -> None:
        config = virtual_config()
        config["protocol"] = "can_fd"
        config["service_allowlist"] = []
        bus = FakeBus()
        can_module = FakeCanModule(bus)
        transport = create_configured_transport(
            config, can_loader=lambda: can_module, command_runner=RecordingRunner()
        )
        message = replay_message(
            payload_hex="aa" * 64,
            arbitration_id=0x7E0,
            is_fd=True,
            bitrate_switch=True,
            error_state_indicator=True,
        )
        message["protocol"] = "can_fd"

        transport.send(message)

        sent, _ = bus.sent[0]
        self.assertEqual(len(sent.data), 64)
        self.assertTrue(sent.is_fd)
        self.assertTrue(sent.bitrate_switch)
        self.assertTrue(sent.error_state_indicator)

    def test_transport_applies_the_operation_payload_bound_to_each_frame(self) -> None:
        config = virtual_config()
        config["limits"] = dict(config["limits"], max_payload_bytes=2)
        bus = FakeBus()
        transport = create_configured_transport(
            config,
            can_loader=lambda: FakeCanModule(bus),
            command_runner=RecordingRunner(),
        )

        with self.assertRaises(SidecarError):
            transport.send(replay_message(payload_hex="221234"))
        self.assertEqual(bus.sent, [])

    def test_extended_arbitration_id_requires_the_matching_frame_flag(self) -> None:
        config = virtual_config()
        config["arbitration_id_allowlist"] = [0x18DAF110]
        bus = FakeBus()
        transport = create_configured_transport(
            config,
            can_loader=lambda: FakeCanModule(bus),
            command_runner=RecordingRunner(),
        )
        extended = replay_message(arbitration_id=0x18DAF110, is_extended_id=False)

        with self.assertRaises(SidecarError):
            transport.send(extended)
        metadata = extended["metadata"]
        self.assertIsInstance(metadata, dict)
        if not isinstance(metadata, dict):
            self.fail("test message metadata is not a dictionary")
        metadata["is_extended_id"] = True
        transport.send(extended)
        self.assertTrue(bus.sent[0][0].is_extended_id)

    def test_receive_is_deadline_bounded_and_validates_returned_frame(self) -> None:
        config = virtual_config()
        bus = FakeBus()
        can_module = FakeCanModule(bus)
        transport = create_configured_transport(
            config, can_loader=lambda: can_module, command_runner=RecordingRunner()
        )
        expected = replay_message(payload_hex="621234", arbitration_id=0x7E8, interface="vcan0")

        bus.next_message = None
        with self.assertRaises(SidecarError):
            transport.receive(expected)
        self.assertEqual(bus.receive_timeouts, [MAX_RECEIVE_TIMEOUT_SECONDS])

        invalid_frames = [
            can_message(arbitration_id=0x7E0, payload=b"ok", channel="vcan0"),
            can_message(arbitration_id=0x7E8, payload=b"ok", channel="vcan1"),
            can_message(arbitration_id=0x7E8, payload=b"x" * 9, channel="vcan0"),
            can_message(
                arbitration_id=0x7E8,
                payload=b"ok",
                channel="vcan0",
                is_fd=True,
            ),
        ]
        for frame in invalid_frames:
            bus.next_message = frame
            with self.subTest(frame=frame), self.assertRaises(SidecarError):
                transport.receive(expected)

        bus.next_message = can_message(
            arbitration_id=0x7E8,
            payload=bytes.fromhex("621234"),
            channel="vcan0",
        )
        self.assertEqual(transport.receive(expected), bytes.fromhex("621234"))


if __name__ == "__main__":
    unittest.main()
