from pathlib import Path
import copy
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin"
sys.path.insert(0, str(ROOT))
from adm_identity_lib.slices import MAX_SLICES, merge, plan  # noqa: E402


def observation(eid, records, last_seen, port=8080, source="pod:a"):
    return {
        "row_type": "edge",
        "id": eid,
        "source": source,
        "target": "pod:b",
        "relationship": "traffic_observation",
        "source_authority": "hubble",
        "observers": ["n1"],
        "sources": ["hubble"],
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "transport": "tcp",
        "evidence": ["ownership: qualified"],
        "count": records,
        "records": records,
        "destination_port": port,
        "traffic_observations": json.dumps(
            [{"last_seen": last_seen + i, "records": 1} for i in range(records)]
        ),
    }


def contextual_slice(start, end):
    context = {
        "schemaVersion": 1,
        "contract": "qualified_v2",
        "authority": "producer-a",
        "scope": "scope-a",
        "configRevision": "a" * 64,
        "observedWindow": {"start": start, "end": end},
    }
    return [
        {
            "row_type": "meta",
            "window_start": start,
            "window_end": end,
            "identity_context": json.dumps(context),
        }
    ]


class SlicePlanTests(unittest.TestCase):
    def test_short_windows_are_contiguous_and_cover_the_window(self):
        slices, total = plan(1000, 1900)
        self.assertEqual(
            (slices, total), ([(1000, 1300), (1300, 1600), (1600, 1900)], 3)
        )
        slices, total = plan(1000, 1950)
        self.assertEqual(slices[0], (1000, 1050))
        self.assertEqual(slices[-1], (1650, 1950))

    def test_long_windows_sample_evenly_and_keep_the_newest_slice(self):
        slices, total = plan(0, 86400)
        self.assertEqual(total, 288)
        self.assertEqual(len(slices), MAX_SLICES)
        self.assertEqual(slices[0], (0, 300))
        self.assertEqual(slices[-1], (86100, 86400))
        self.assertTrue(all(b - a <= 300 for a, b in slices))

    def test_rejects_reversed_or_oversized_windows(self):
        for start, end in ((10, 10), (20, 10), (0, 9 * 86400)):
            with self.assertRaises(ValueError):
                plan(start, end)


class SliceMergeTests(unittest.TestCase):
    def test_context_propagates_only_complete_matching_raw_slices(self):
        outputs = [contextual_slice(0, 300), contextual_slice(300, 600)]
        meta = merge(outputs, 0, 600, 2, [(0, 300), (300, 600)])[-1]
        self.assertEqual(
            json.loads(meta["identity_context"]),
            {
                "schemaVersion": 1,
                "contract": "qualified_v2",
                "authority": "producer-a",
                "scope": "scope-a",
                "configRevision": "a" * 64,
                "observedWindow": {"start": 0, "end": 600},
            },
        )
        for field, value in (
            ("authority", "other"),
            ("scope", "other"),
            ("configRevision", "b" * 64),
            ("contract", "other"),
            ("schemaVersion", 2),
        ):
            changed = copy.deepcopy(outputs)
            context = json.loads(changed[1][0]["identity_context"])
            context[field] = value
            changed[1][0]["identity_context"] = json.dumps(context)
            with self.subTest(field=field):
                self.assertNotIn(
                    "identity_context",
                    merge(changed, 0, 600, 2, [(0, 300), (300, 600)])[-1],
                )

    def test_context_omitted_for_missing_malformed_summary_and_sampling(self):
        good = [contextual_slice(0, 300), contextual_slice(300, 600)]
        invalid = []
        missing = copy.deepcopy(good)
        del missing[1][0]["identity_context"]
        invalid.append(missing)
        for bad in (
            "{",
            '{"schemaVersion":1,"schemaVersion":1}',
            json.dumps({"schemaVersion": True}),
            json.dumps(
                {
                    "schemaVersion": 1,
                    "contract": "qualified_v2",
                    "authority": "producer-a",
                    "scope": "scope-a",
                    "configRevision": "bad",
                    "observedWindow": {"start": 300, "end": 600},
                }
            ),
        ):
            changed = copy.deepcopy(good)
            changed[1][0]["identity_context"] = bad
            invalid.append(changed)
        for marker, value in (
            ("summary_slices", 1),
            ("sampled", True),
            ("read_coverage", 100),
        ):
            changed = copy.deepcopy(good)
            changed[0][0][marker] = value
            invalid.append(changed)
        wrong_window = copy.deepcopy(good)
        wrong_window[1][0]["window_start"] = 301
        invalid.append(wrong_window)
        duplicate_meta = copy.deepcopy(good)
        duplicate_meta[0].append(copy.deepcopy(duplicate_meta[0][0]))
        invalid.append(duplicate_meta)
        for changed in invalid:
            self.assertNotIn(
                "identity_context",
                merge(changed, 0, 600, 2, [(0, 300), (300, 600)])[-1],
            )
        self.assertNotIn(
            "identity_context", merge(good[:1], 0, 600, 2, [(0, 300), (300, 600)])[-1]
        )
        self.assertNotIn(
            "identity_context", merge(good, 0, 900, 3, [(0, 300), (600, 900)])[-1]
        )
        self.assertNotIn(
            "identity_context", merge(good, 0, 600, 2, [(0, 250), (250, 600)])[-1]
        )
        sampled, total = plan(0, 2100)
        outputs = [contextual_slice(start, end) for start, end in sampled]
        self.assertNotIn(
            "identity_context", merge(outputs, 0, 2100, total, sampled)[-1]
        )

    def test_unions_by_qualified_id_and_sums_counts(self):
        call = {
            "row_type": "edge",
            "id": "calls:x",
            "source": "service:a",
            "target": "service:b",
            "relationship": "calls",
            "count": 2,
            "span_ids": ["s1"],
        }
        pod = {
            "row_type": "node",
            "id": "pod:a",
            "label": "a",
            "addresses": ["10.0.0.1"],
        }
        renamed = {**pod, "label": "other-name", "addresses": ["10.0.0.9"]}
        first = [pod, call, observation("t1", 2, 10), {"row_type": "meta", "spans": 3}]
        second = [
            renamed,
            {**call, "count": 1, "span_ids": ["s2"]},
            observation("t2", 3, 400),
            {"row_type": "meta", "spans": 1},
        ]
        out = merge([first, second], 0, 600, 2, [(0, 300), (300, 600)])
        nodes = [r for r in out if r["row_type"] == "node"]
        edges = {r["relationship"]: r for r in out if r["row_type"] == "edge"}
        meta = out[-1]
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["label"], "a")
        self.assertEqual(nodes[0]["addresses"], ["10.0.0.1", "10.0.0.9"])
        self.assertEqual(edges["calls"]["count"], 3)
        self.assertEqual(edges["calls"]["span_ids"], ["s1", "s2"])
        self.assertEqual(edges["traffic_observation"]["records"], 5)
        self.assertEqual(
            len(json.loads(edges["traffic_observation"]["traffic_observations"])), 5
        )
        self.assertEqual((meta["spans"], meta["window_slices_read"]), (4, 2))
        self.assertNotIn("Read", " ".join(meta["warnings"]))

    def test_distinct_endpoints_never_merge_and_ports_that_differ_are_dropped(self):
        out = merge(
            [[observation("t1", 1, 0)], [observation("t2", 1, 400, source="pod:c")]],
            0,
            600,
            2,
            [(0, 300), (300, 600)],
        )
        self.assertEqual(len([r for r in out if r["row_type"] == "edge"]), 2)
        out = merge(
            [[observation("t1", 1, 0)], [observation("t2", 1, 400, port=443)]],
            0,
            600,
            2,
            [(0, 300), (300, 600)],
        )
        edge = [r for r in out if r["row_type"] == "edge"][0]
        self.assertNotIn("destination_port", edge)

    def test_keeps_newest_observations_and_reports_omissions_and_sampling(self):
        out = merge(
            [[observation("t1", 60, 0)], [observation("t2", 10, 1000)]],
            0,
            86400,
            288,
            [(0, 300), (86100, 86400)],
        )
        edge = [r for r in out if r["row_type"] == "edge"][0]
        kept = json.loads(edge["traffic_observations"])
        self.assertEqual((edge["records"], len(kept)), (70, 64))
        self.assertEqual(edge["observation_omitted_count"], 6)
        self.assertEqual(kept[-1]["last_seen"], 1009)
        self.assertIn("Read 2 of 288 five-minute slices", out[-1]["warnings"][0])


if __name__ == "__main__":
    unittest.main()
