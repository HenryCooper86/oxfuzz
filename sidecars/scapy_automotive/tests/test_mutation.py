import unittest

from oxfuzz_scapy_automotive.errors import SidecarError
from oxfuzz_scapy_automotive.mutation import generate_mutation_plan


class MutationPlanTests(unittest.TestCase):
    def test_uds_plan_is_field_aware_bounded_and_deterministic(self) -> None:
        request = {
            "protocol": "uds",
            "payload_hex": "1001a5",
            "deterministic_seed": 7,
            "mutation_count": 8,
        }

        first = generate_mutation_plan(request)
        second = generate_mutation_plan(dict(reversed(list(request.items()))))

        self.assertEqual(first, second)
        self.assertEqual(first["protocol"], "uds")
        self.assertEqual(len(first["mutations"]), 8)
        self.assertEqual(len(first["artifact_sha256"]), 64)
        self.assertIn("service", {mutation["field"] for mutation in first["mutations"]})
        self.assertIn("subfunction", {mutation["field"] for mutation in first["mutations"]})
        for mutation in first["mutations"]:
            self.assertEqual(len(mutation["payload_hex"]), 6)
            self.assertEqual(len(mutation["mutation_id"]), 64)

    def test_custom_field_order_does_not_change_the_plan(self) -> None:
        fields = [
            {"name": "identifier", "offset": 1, "width": 2, "kind": "integer"},
            {"name": "service", "offset": 0, "width": 1, "kind": "service"},
        ]
        request = {
            "protocol": "uds",
            "payload_hex": "221234",
            "deterministic_seed": 19,
            "mutation_count": 6,
            "fields": fields,
        }

        first = generate_mutation_plan(request)
        request["fields"] = list(reversed(fields))
        second = generate_mutation_plan(request)

        self.assertEqual(first, second)

    def test_invalid_hex_overlapping_fields_and_excessive_counts_fail_closed(self) -> None:
        invalid_requests = (
            {
                "protocol": "uds",
                "payload_hex": "xyz",
                "deterministic_seed": 0,
                "mutation_count": 1,
            },
            {
                "protocol": "uds",
                "payload_hex": "221234",
                "deterministic_seed": 0,
                "mutation_count": 2,
                "fields": [
                    {"name": "a", "offset": 0, "width": 2, "kind": "integer"},
                    {"name": "b", "offset": 1, "width": 1, "kind": "integer"},
                ],
            },
            {
                "protocol": "can",
                "payload_hex": "00",
                "deterministic_seed": 0,
                "mutation_count": 4_097,
            },
        )

        for request in invalid_requests:
            with self.subTest(request=request), self.assertRaises(SidecarError):
                generate_mutation_plan(request)


if __name__ == "__main__":
    unittest.main()
