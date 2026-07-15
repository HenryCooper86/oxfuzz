import tempfile
import unittest
from pathlib import Path
from typing import Any

from hobot_scapy_automotive.errors import SidecarError
from hobot_scapy_automotive.pcap import ScapyPcapDecoder, decode_pcap


class FakeDecoder:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, int]] = []

    def decode(self, path: Path, max_events: int) -> list[dict[str, Any]]:
        self.calls.append((path, max_events))
        return [
            {
                "sequence": 0,
                "timestamp_ns": 1_250_000_000,
                "layers": ["CAN"],
                "payload_hex": "221234",
                "fields": {"identifier": 0x7E0},
            }
        ]


class PcapTests(unittest.TestCase):
    def test_decoder_is_injectable_and_output_hashes_are_deterministic(self) -> None:
        decoder = FakeDecoder()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(b"fixture-pcap")
            limits = {"max_events": 5, "max_payload_bytes": 1_024}

            first = decode_pcap(path, limits, decoder=decoder)
            second = decode_pcap(path, limits, decoder=decoder)

        self.assertEqual(first, second)
        self.assertEqual(decoder.calls[0][1], 5)
        self.assertEqual(len(first["capture_sha256"]), 64)
        self.assertEqual(len(first["artifact_sha256"]), 64)
        self.assertEqual(first["packets"][0]["layers"], ["CAN"])

    def test_file_size_and_packet_count_are_bounded_before_results_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.pcap"
            path.write_bytes(b"12345")
            with self.assertRaises(SidecarError):
                decode_pcap(path, {"max_events": 1, "max_payload_bytes": 4}, decoder=FakeDecoder())

        class TooManyDecoder:
            def decode(self, path: Path, max_events: int) -> list[dict[str, Any]]:
                return [{"sequence": index} for index in range(max_events + 1)]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(b"pcap")
            with self.assertRaises(SidecarError):
                decode_pcap(
                    path,
                    {"max_events": 1, "max_payload_bytes": 64},
                    decoder=TooManyDecoder(),
                )

    def test_real_scapy_decoder_only_reads_an_offline_pcap(self) -> None:
        try:
            from scapy.all import IP, UDP, Ether, Raw, wrpcap
        except ImportError:
            self.skipTest("Scapy is not installed")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "offline.pcap"
            packet = Ether() / IP(dst="192.0.2.1") / UDP(dport=13400) / Raw(b"doip")
            packet.time = 1.25
            wrpcap(str(path), [packet])

            result = decode_pcap(
                path,
                {"max_events": 2, "max_payload_bytes": 64 * 1_024},
                decoder=ScapyPcapDecoder(),
            )

        self.assertEqual(len(result["packets"]), 1)
        self.assertIn("Ethernet", result["packets"][0]["layers"])
        self.assertIn("IP", result["packets"][0]["layers"])
        self.assertTrue(result["packets"][0]["raw_hex"])


if __name__ == "__main__":
    unittest.main()
