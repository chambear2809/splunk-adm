import unittest

from tools.prepare_multicast_cohort import build_event


class PrepareMulticastCohortTest(unittest.TestCase):
    def receipt(self):
        return {
            "request": {
                "version": 1,
                "scope": "test:underlay",
                "sender": "192.0.2.1",
                "group": "239.1.2.3",
                "latest": 200,
            },
            "collectionFrom": 199,
            "collectionUntil": 201,
            "evidence": [
                {
                    "kind": "forwarding",
                    "source": "device_state",
                    "scope": "test:underlay",
                    "group": "239.1.2.3",
                    "sender": "192.0.2.1",
                    "observer": device,
                    "timestamp": 200,
                    "validUntil": 200,
                    "input": port,
                    "outputs": outputs,
                    "ignored_raw_output": "not part of the HEC event",
                }
                for device, port, outputs in (
                    ("leaf-a", "lo1", ["eth1/1"]),
                    ("spine-a", "eth1/2", []),
                )
            ],
            "adjacency": [
                {
                    "scope": "test:underlay",
                    "from": {"observer": "leaf-a", "interface": "eth1/1"},
                    "to": {"observer": "spine-a", "interface": "eth1/2"},
                    "validFrom": 200,
                    "validUntil": 200,
                }
            ],
            "comparisons": [
                {
                    "from": "leaf-a",
                    "output": "eth1/1",
                    "to": "spine-a",
                    "input": "eth1/2",
                    "reciprocal_cdp": True,
                    "reciprocal_pim": True,
                    "rpf_matches_upstream_interface_ip": True,
                }
            ],
        }

    def test_builds_one_minimal_hec_event_at_the_replay_anchor(self):
        event = build_event(self.receipt(), "atlas_multicast", "nxos-snapshot")
        self.assertEqual(event["sourcetype"], "atlas:nxos:multicast:v1")
        self.assertEqual(event["time"], event["event"]["observedAt"])
        self.assertEqual(event["time"], event["event"]["validUntil"])
        self.assertEqual(len(event["event"]["adjacencies"]), 1)
        self.assertNotIn("ignored_raw_output", event["event"]["devices"][0])

    def test_rejects_unverified_adjacency_or_mixed_capture_time(self):
        receipt = self.receipt()
        receipt["comparisons"][0]["reciprocal_pim"] = False
        with self.assertRaises(ValueError):
            build_event(receipt, "atlas_multicast", "nxos-snapshot")
        receipt = self.receipt()
        receipt["evidence"][0]["timestamp"] = 199
        with self.assertRaises(ValueError):
            build_event(receipt, "atlas_multicast", "nxos-snapshot")
