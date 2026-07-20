import copy
import unittest

from oxfuzz_scapy_automotive.errors import SidecarError
from oxfuzz_scapy_automotive.validation import (
    DANGEROUS_UDS_SERVICES,
    validate_operation_config,
)


def limits(**overrides: int) -> dict[str, int]:
    result = {
        "max_events": 20,
        "max_payload_bytes": 4_096,
        "max_duration_ms": 10_000,
        "max_rate_per_second": 20,
    }
    result.update(overrides)
    return result


def virtual_config() -> dict[str, object]:
    return {
        "mode": "virtual_can",
        "protocol": "uds",
        "physical_enabled": False,
        "interface": "vcan0",
        "interface_allowlist": ["vcan0"],
        "arbitration_id_allowlist": [0x7E0, 0x7E8],
        "service_allowlist": [0x10, 0x22],
        "allow_dangerous_services": False,
        "limits": limits(),
    }


def physical_config() -> dict[str, object]:
    config: dict[str, object] = {
        "mode": "physical_bench",
        "protocol": "uds",
        "physical_enabled": True,
        "interface": "can0",
        "interface_allowlist": ["can0"],
        "arbitration_id_allowlist": [0x7E0, 0x7E8],
        "service_allowlist": [0x10, 0x22],
        "allow_dangerous_services": False,
        "limits": limits(max_events=100, max_rate_per_second=50),
    }
    config["approval"] = {
        "approval_id": "approval-123",
        "approved_by": "bench-operator",
        "approved_at": "2026-07-15T09:00:00Z",
        "scope_sha256": "ab" * 32,
    }
    return config


class ValidationTests(unittest.TestCase):
    def test_offline_mode_rejects_interfaces_and_physical_enablement(self) -> None:
        config = {
            "mode": "offline_pcap",
            "protocol": "do_ip",
            "physical_enabled": False,
            "limits": limits(),
        }
        validated = validate_operation_config(config)
        self.assertEqual(validated["mode"], "offline_pcap")

        for field, value in (("interface", "vcan0"), ("physical_enabled", True)):
            invalid = dict(config)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(SidecarError):
                validate_operation_config(invalid)

    def test_virtual_can_requires_a_vcan_interface_and_explicit_allowlists(self) -> None:
        self.assertEqual(validate_operation_config(virtual_config())["interface"], "vcan0")

        invalid_interfaces = ("can0", "../vcan0", "vcan0;touch_tmp")
        for interface in invalid_interfaces:
            config = virtual_config()
            config["interface"] = interface
            with self.subTest(interface=interface), self.assertRaises(SidecarError):
                validate_operation_config(config)

        config = virtual_config()
        config["interface_allowlist"] = ["vcan1"]
        with self.assertRaises(SidecarError):
            validate_operation_config(config)

    def test_limits_are_positive_and_mode_capped(self) -> None:
        for field in limits():
            config = virtual_config()
            config["limits"] = limits(**{field: 0})
            with self.subTest(field=field), self.assertRaises(SidecarError):
                validate_operation_config(config)

        config = physical_config()
        config["limits"] = limits(max_events=1_001)
        with self.assertRaises(SidecarError):
            validate_operation_config(config)

    def test_physical_mode_is_disabled_by_default_and_requires_scoped_approval(self) -> None:
        disabled = physical_config()
        disabled["physical_enabled"] = False
        with self.assertRaises(SidecarError):
            validate_operation_config(disabled)

        missing = physical_config()
        del missing["approval"]
        with self.assertRaises(SidecarError):
            validate_operation_config(missing)

        malformed = physical_config()
        malformed["approval"]["scope_sha256"] = "not-a-digest"  # type: ignore[index]
        with self.assertRaises(SidecarError):
            validate_operation_config(malformed)

        self.assertEqual(validate_operation_config(physical_config())["mode"], "physical_bench")

    def test_dangerous_uds_services_are_denied_unless_explicitly_enabled(self) -> None:
        self.assertIn(0x27, DANGEROUS_UDS_SERVICES)
        denied = virtual_config()
        denied["service_allowlist"] = [0x22, 0x27]
        with self.assertRaises(SidecarError):
            validate_operation_config(denied)

        allowed = copy.deepcopy(denied)
        allowed["allow_dangerous_services"] = True
        self.assertEqual(validate_operation_config(allowed)["service_allowlist"], [0x22, 0x27])

    def test_unknown_fields_and_invalid_ids_are_rejected(self) -> None:
        config = virtual_config()
        config["shell_command"] = "ip link set vcan0 up"
        with self.assertRaises(SidecarError):
            validate_operation_config(config)

        config = virtual_config()
        config["arbitration_id_allowlist"] = [0x20000000]
        with self.assertRaises(SidecarError):
            validate_operation_config(config)


if __name__ == "__main__":
    unittest.main()
