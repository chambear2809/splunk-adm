"""Recheck the bounded sanitized observed sample against production parsers."""

import copy
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import (
    normalize_records,
    validate_profiles,
)
from splunk_app.splunk_adm.bin.adm_identity_lib.network_graph import (
    assemble,
    observation_payload,
)
from splunk_app.splunk_adm.bin.adm_identity_lib.protocol import _pod
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import EvidenceError

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures/feature-replay/sanitized-source-sample.json"
)


def epoch(value):
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except ValueError:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must have a timezone")
        return parsed.astimezone(timezone.utc).timestamp()


def row_for_parser(row):
    return {
        **row,
        "event_time": epoch(row["_time"]),
        "receipt_time": epoch(row["_indextime"]),
    }


class ObservedReplayFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text())
        cls.profiles = validate_profiles(
            cls.fixture["network_profiles"], cls.fixture["identity_profile"]
        )

    def normalize(self, rows):
        window = self.fixture["window"]
        return normalize_records(rows, self.profiles, window["start"], window["end"])

    def test_manifest_matches_public_sample_and_selection_limits(self):
        manifest = json.loads((FIXTURE.parent / "manifest.json").read_text())
        self.assertEqual(
            manifest["sample_sha256"], hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        )
        self.assertEqual(manifest["sample_file"], FIXTURE.name)
        self.assertFalse(manifest["capture_selection"]["complete"])
        self.assertEqual(manifest["source_counts"], {"hubble": 4, "pods": 4})
        self.assertEqual(manifest["replay_window"], self.fixture["window"])

    def test_observations_match_raw_projection_and_production_payload(self):
        fixture = self.fixture
        self.assertEqual(fixture["classification"], "sanitized_observed_source_sample")
        self.assertFalse(fixture["report"]["complete"])
        self.assertEqual(fixture["report"]["sample_counts"], {"hubble": 4, "pods": 4})
        rows = [row_for_parser(row) for row in fixture["families"]["hubble"]]
        result = self.normalize(rows)
        self.assertEqual(result["excluded"], {})
        self.assertEqual(len(result["records"]), 4)
        self.assertEqual(
            [observation_payload(record) for record in result["records"]],
            fixture["observations"],
        )
        for row, record in zip(rows, result["records"]):
            raw = json.loads(row["_raw"])
            flow = raw["flow"]
            protocol = next(key for key in ("TCP", "UDP", "SCTP") if key in flow["l4"])
            transport = flow["l4"][protocol]
            self.assertEqual(
                (record["source_ip"], record["destination_ip"]),
                (flow["IP"]["source"], flow["IP"]["destination"]),
            )
            self.assertEqual(
                (
                    record["transport"],
                    record["source_port"],
                    record["destination_port"],
                ),
                (
                    protocol,
                    transport["source_port"],
                    transport["destination_port"],
                ),
            )
            self.assertEqual(
                (record["verdict"], record["direction"], record["is_reply"]),
                (flow["verdict"], flow["traffic_direction"], flow["is_reply"]),
            )
            self.assertEqual(
                (record["observer"], record["observation_point"]),
                (flow["node_name"], flow["trace_observation_point"]),
            )
            self.assertAlmostEqual(record["event_time"], row["event_time"])
            self.assertAlmostEqual(record["first_seen"], epoch(flow["time"]))
            self.assertAlmostEqual(record["last_seen"], epoch(flow["time"]))
            self.assertEqual(record["received_time"], row["receipt_time"])
        self.assertEqual(epoch("1767225600"), epoch("2026-01-01T00:00:00Z"))
        self.assertEqual(epoch(1767225600), epoch("2026-01-01T00:00:00+00:00"))

    def test_pod_shapes_and_condition_pairs_are_not_interval_proof(self):
        uids = []
        conditions = []
        for row in self.fixture["families"]["pods"]:
            raw = json.loads(row["_raw"])["object"]
            parsed = _pod(raw)
            self.assertRegex(parsed["pod_uid"], r"^uid-[a-f0-9]{24}$")
            self.assertEqual(parsed["pod_uid"], raw["metadata"]["uid"])
            self.assertEqual(parsed["ips"], (raw["status"]["podIP"],))
            uids.append(parsed["pod_uid"])
            pair = {c["type"]: c["status"] for c in raw["status"]["conditions"]}
            self.assertEqual(pair["Ready"], pair["ContainersReady"])
            conditions.append(pair)
        self.assertEqual(len(set(uids)), 2)
        for uid in set(uids):
            self.assertEqual(
                conditions[uids.index(uid)],
                conditions[len(uids) - 1 - uids[::-1].index(uid)],
            )
        with self.assertRaises(EvidenceError):
            assemble({"complete": False}, [], {}, {})

    def test_tampered_provenance_observer_and_clocks_are_excluded(self):
        row = row_for_parser(self.fixture["families"]["hubble"][0])
        for key, value in (
            ("source", "other-source"),
            ("host", "other-host"),
            ("k8s.cluster.name", "other-cluster"),
            ("event_time", row["event_time"] - 20),
            ("receipt_time", row["receipt_time"] - 20),
        ):
            with self.subTest(key=key):
                altered = copy.deepcopy(row)
                altered[key] = value
                result = self.normalize([altered])
                self.assertEqual(result["records"], [])
                self.assertEqual(sum(result["excluded"].values()), 1)


if __name__ == "__main__":
    unittest.main()
