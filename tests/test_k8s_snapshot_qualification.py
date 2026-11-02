"""Offline qualification against synthetic native Go golden generations."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

from tools.qualify_k8s_snapshot import (
    SnapshotQualificationError,
    go_json,
    validate_snapshot,
)

GOLDEN = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "integrations/otel_atlas_receiver/testdata/synthetic-golden.json"
    ).read_text()
)


def setup(resource):
    generation = GOLDEN["generations"][0 if resource == "node" else 1]
    rows = [
        {
            "_raw": json.dumps(event, ensure_ascii=False),
            "_time": 1700000001.5,
            "_indextime": 1700000002,
            "index": "atlas_identity",
            "source": generation["source"],
            "sourcetype": generation["sourcetype"],
            "host": "hf",
        }
        for event in generation["events"]
    ]
    args = {
        "resource": resource,
        "index": "atlas_identity",
        "source": generation["source"],
        "sourcetype": generation["sourcetype"],
        "host": "hf",
        "producer_id": "synthetic-producer",
        "cluster": "synthetic-cluster",
        "scope": "synthetic-scope",
        "now": 1700000003,
        "receipt_cutoff": 1700000003,
        "max_age": 60,
        "max_receipt_delay": 60,
        "completion_count": len(rows),
        "truncated": False,
    }
    return rows, args


def changed(row, **fields):
    obj = json.loads(row["_raw"])
    obj.update(fields)
    row["_raw"] = json.dumps(obj)


class K8sSnapshotQualificationTests(unittest.TestCase):
    def test_native_go_golden_and_canonical_escaping(self):
        v = GOLDEN["canonical_vector"]
        self.assertEqual(go_json(v["value"]), v["canonical_go"])
        self.assertEqual(
            hashlib.sha256(go_json(v["value"]).encode()).hexdigest(), v["sha256"]
        )
        for resource in ("node", "pod"):
            rows, args = setup(resource)
            result = validate_snapshot(rows, **args)
            self.assertEqual(result["validity_basis"], "point_snapshot")
            self.assertEqual(len(result["records"]), 1)
            if resource == "pod":
                self.assertNotIn("node_uid", result["records"][0])

    def test_explicit_empty_generation(self):
        rows, args = setup("node")
        rows = rows[1:]
        args["completion_count"] = 1
        changed(
            rows[0], expected_count=0, records_sha256=hashlib.sha256(b"").hexdigest()
        )
        self.assertEqual(validate_snapshot(rows, **args)["records"], [])

    def test_source_and_delivery_fail_closed(self):
        rows, args = setup("node")
        for name in ("index", "source", "sourcetype", "host"):
            bad = copy.deepcopy(rows)
            bad[0][name] = "other"
            with self.subTest(name=name), self.assertRaises(SnapshotQualificationError):
                validate_snapshot(bad, **args)
        for overrides in (
            {"completion_count": 3},
            {"truncated": True},
            {"max_age": 0},
            {"producer_id": "other"},
            {"cluster": "other"},
            {"scope": "other"},
            {"resource": "pod"},
        ):
            with (
                self.subTest(overrides=overrides),
                self.assertRaises(SnapshotQualificationError),
            ):
                validate_snapshot(rows, **{**args, **overrides})
        with self.assertRaises(SnapshotQualificationError):
            validate_snapshot(rows[:-1], **{**args, "completion_count": 1})

    def test_timing_and_capture_conflicts(self):
        rows, args = setup("pod")
        for key, value in (
            ("_time", 1700000002),
            ("_indextime", 1700000010),
            ("_indextime", 1699999990),
        ):
            bad = copy.deepcopy(rows)
            bad[0][key] = value
            with self.subTest(key=key), self.assertRaises(SnapshotQualificationError):
                validate_snapshot(bad, **args)
        for field, value in (
            ("complete", False),
            ("expected_count", 0),
            ("generation_id", "bad"),
            ("records_sha256", "a" * 64),
            ("observation_started_at", float("nan")),
        ):
            bad = copy.deepcopy(rows)
            changed(bad[-1], **{field: value})
            with (
                self.subTest(field=field),
                self.assertRaises(SnapshotQualificationError),
            ):
                validate_snapshot(bad, **args)
        bad = copy.deepcopy(rows)
        changed(bad[0], uid="different")
        with self.assertRaises(SnapshotQualificationError):
            validate_snapshot(bad, **args)
        bad = rows + [rows[0]]
        with self.assertRaises(SnapshotQualificationError):
            validate_snapshot(bad, **{**args, "completion_count": 3})

    def test_duplicate_uid_and_namespace_fail_cleanly(self):
        rows, args = setup("pod")
        duplicate = copy.deepcopy(rows[0])
        rows.insert(1, duplicate)
        changed(rows[-1], expected_count=2)
        with self.assertRaisesRegex(SnapshotQualificationError, "duplicate_uid"):
            validate_snapshot(rows, **{**args, "completion_count": 3})
        rows, args = setup("pod")
        changed(rows[0], namespace=[])
        with self.assertRaisesRegex(SnapshotQualificationError, "namespace_invalid"):
            validate_snapshot(rows, **args)

    def test_invalid_or_duplicate_json_and_semantics(self):
        for resource in ("node", "pod"):
            rows, args = setup(resource)
            bad = copy.deepcopy(rows)
            bad[0]["_raw"] = bad[0]["_raw"].replace("{", '{"kind":"object",', 1)
            with self.assertRaises(SnapshotQualificationError):
                validate_snapshot(bad, **args)
            bad = copy.deepcopy(rows)
            changed(
                bad[0],
                **(
                    {"addresses": [{"type": "InternalIP", "address": "0.0.0.0"}]}
                    if resource == "node"
                    else {"pod_ips": ["ff02::1"]}
                ),
            )
            with self.assertRaises(SnapshotQualificationError):
                validate_snapshot(bad, **args)


if __name__ == "__main__":
    unittest.main()
