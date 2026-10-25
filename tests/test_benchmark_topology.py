"""Deterministic NX-OS topology search workloads and boundary checks."""

import json
import unittest
from unittest.mock import patch

from tools import benchmark_pipeline as bench
from tools.benchmark_topology import (
    CASES,
    EXPECTED_META_WARNINGS,
    MAX_TOPOLOGY_ROWS,
    NO_LINK_WARNING,
    NO_IFINDEX_WARNING,
    TopologyWorkload,
    device_id,
    expected_interface_ids,
    iter_events,
    load_events,
    manifest,
    search_measurement_complete,
    topology_check,
)


class BenchmarkTopologyTest(unittest.TestCase):
    def test_small_workload_uses_reviewed_nxos_event_shapes_deterministically(self):
        workload = TopologyWorkload("small", devices=2, interfaces=3)
        events = list(iter_events(workload))
        self.assertEqual(events, list(iter_events(workload)))
        self.assertEqual(len(events), 5)
        self.assertEqual(
            {event["sourcetype"] for event in events}, {"cisco:dc:nexus9k"}
        )
        self.assertEqual({event["index"] for event in events}, {"cisco_dc"})
        decoded = [json.loads(event["event"]) for event in events]
        self.assertEqual(
            [event["component"] for event in decoded],
            ["nxhostname", "nxhostname", "nxinterface", "nxinterface", "nxinterface"],
        )
        self.assertEqual(
            [event["Row_info"][0]["hostname"] for event in decoded[:2]],
            [device_id(0), device_id(1)],
        )
        self.assertEqual(
            [event["Row_info"]["interface"] for event in decoded[2:]],
            ["Ethernet1/1", "Ethernet1/1", "Ethernet1/2"],
        )
        self.assertTrue(all(event["device"].endswith(":443") for event in decoded))

    def test_boundary_manifests_hit_below_at_and_above_exact_row_limit(self):
        expected_counts = {"below": 19_999, "at": 20_000, "above": 20_001}
        self.assertEqual(MAX_TOPOLOGY_ROWS, 20_000)
        for name, (devices, interfaces) in CASES.items():
            with self.subTest(name=name):
                value = manifest(
                    TopologyWorkload(f"topology-{name}", devices, interfaces)
                )
                expected = value["expected"]
                self.assertEqual(expected["result_rows"], expected_counts[name])
                self.assertEqual(expected["application_accepts"], name != "above")
                self.assertEqual(expected["device_id_count"], devices)
                self.assertEqual(expected["interface_id_count"], interfaces)
                self.assertEqual(
                    len(
                        expected_interface_ids(
                            TopologyWorkload(f"{name}", devices, interfaces)
                        )
                    ),
                    interfaces,
                )
                self.assertEqual(value["input_events"], devices + interfaces)
                self.assertEqual(
                    value["source_mix"]["components"]["nxhostname"], devices
                )
                self.assertEqual(
                    value["source_mix"]["components"]["nxinterface"], interfaces
                )
                self.assertEqual(len(value["workload_id"]), 64)

    def test_topology_check_requires_exact_row_types_and_identities(self):
        workload = TopologyWorkload("small", devices=2, interfaces=3)
        rows = [
            {"row_type": "device", "device_id": device_id(0)},
            {"row_type": "device", "device_id": device_id(1)},
            {
                "row_type": "interface",
                "device_id": device_id(0),
                "interface": "Ethernet1/1",
            },
            {
                "row_type": "interface",
                "device_id": device_id(1),
                "interface": "Ethernet1/1",
            },
            {
                "row_type": "interface",
                "device_id": device_id(0),
                "interface": "Ethernet1/2",
            },
            {
                "row_type": "meta",
                "devices": "2",
                "links": "0",
                "interfaces": "3",
                "warnings": [NO_LINK_WARNING, NO_IFINDEX_WARNING],
            },
        ]
        self.assertEqual(topology_check(rows, workload), [])
        malformed = rows[:-2] + [rows[-1]]
        warnings = topology_check(malformed, workload)
        self.assertTrue(any("interface rows" in warning for warning in warnings))
        self.assertTrue(any("result rows" in warning for warning in warnings))
        wrong_warning = rows.copy()
        wrong_warning[-1] = {
            **wrong_warning[-1],
            "warnings": list(EXPECTED_META_WARNINGS) + ["unexpected warning"],
        }
        self.assertTrue(
            any(
                "warnings differ" in warning
                for warning in topology_check(wrong_warning, workload)
            )
        )

    def test_expected_one_row_over_limit_is_a_complete_boundary_measurement(self):
        result_limit = MAX_TOPOLOGY_ROWS
        expected_rows = result_limit + 1
        warning = (
            f"Final result count exceeds configured limit {result_limit}; "
            f"retrieval is bounded to {result_limit + 1} rows"
        )
        job = {
            "status": "incomplete",
            "dispatch_state": "DONE",
            "is_done": True,
            "is_failed": False,
            "is_finalized": False,
            "result_limit_exceeded": True,
            "result_count": expected_rows,
            "fetched_rows": expected_rows,
            "result_pages": [{"offset": 0, "returned_count": expected_rows}],
            "warnings": [warning],
        }
        self.assertTrue(
            search_measurement_complete(
                job,
                expected_accepts=False,
                expected_rows=expected_rows,
                result_limit=result_limit,
            )
        )
        job["warnings"].append("Search was finalized early")
        self.assertFalse(
            search_measurement_complete(
                job,
                expected_accepts=False,
                expected_rows=expected_rows,
                result_limit=result_limit,
            )
        )

    def test_failed_hec_batch_retains_generated_and_acknowledged_progress(self):
        events = [
            {"event": "one"},
            {"event": "two"},
            {"event": "three"},
        ]
        progress = {}
        with (
            patch("tools.benchmark_topology.iter_events", return_value=iter(events)),
            patch.object(bench.lab, "MAX_BATCH_BYTES", 1),
            patch.object(
                bench.lab,
                "_hec_post",
                side_effect=[{}, RuntimeError("HEC transport lost")],
            ) as post,
        ):
            with self.assertRaisesRegex(RuntimeError, "HEC transport lost"):
                load_events(TopologyWorkload("small", 1, 1), progress)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(progress["generated_event_count"], 3)
        self.assertEqual(progress["hec_batches_attempted"], 2)
        self.assertEqual(progress["hec_events_attempted"], 2)
        self.assertEqual(progress["hec_batches_acknowledged"], 1)
        self.assertEqual(progress["hec_events_acknowledged"], 1)
        self.assertEqual(progress["last_batch_acknowledgement"], "unknown")
        self.assertEqual(len(progress["generated_prefix_sha256"]), 64)

    def test_workload_rejects_boolean_and_over_budget_counts(self):
        for devices, interfaces in ((True, 1), (2, 1), (10_000, 10_001), (1, True)):
            with self.subTest(devices=devices, interfaces=interfaces):
                with self.assertRaises(ValueError):
                    TopologyWorkload("invalid", devices, interfaces)


if __name__ == "__main__":
    unittest.main()
