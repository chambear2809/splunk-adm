import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import mixed_pipeline as mixed
import lab_lock


class MixedPipelineTest(unittest.TestCase):
    def setUp(self):
        self._lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._lock_directory.cleanup)
        lock_path = Path(self._lock_directory.name) / "lab.lock"
        self._lock_path_patch = patch.object(
            lab_lock, "default_lock_path", return_value=lock_path
        )
        self._lock_path_patch.start()
        self.addCleanup(self._lock_path_patch.stop)

    def test_cases_have_bounded_expected_flow_counts(self):
        for name, expected in (("smoke", 96), ("baseline", 16000), ("scale", 80000)):
            config = mixed.CASES[name]
            self.assertEqual(
                config.pods * config.records_per_pair * config.observers_per_source * 4,
                expected,
            )

    def test_corpus_has_real_source_envelopes_and_metadata(self):
        rows = list(mixed.corpus(mixed.CASES["smoke"]))
        flow_rows = [
            r
            for r in rows
            if r["sourcetype"]
            in {
                "stream:netflow",
                "cisco:dc:nd:flows",
                "cisco:sfw:estreamer",
                "cilium:hubble:flow",
            }
        ]
        self.assertEqual(len(flow_rows), 96)
        # Pod/service/trace support events are required for graph attribution.
        self.assertEqual(len(rows), 109)
        self.assertEqual(
            {(r["index"], r["sourcetype"]) for r in flow_rows},
            {
                ("netflow", "stream:netflow"),
                ("cisco_dc", "cisco:dc:nd:flows"),
                ("cisco_secure_fw", "cisco:sfw:estreamer"),
                ("cilium_hubble", "cilium:hubble:flow"),
            },
        )
        for row in rows:
            self.assertIn("time", row)
            self.assertIn("event", row)

    def test_source_counters_and_hubble_bytes_are_grounded(self):
        rows = list(mixed.corpus(mixed.CASES["smoke"]))
        nd_event = json.loads(
            next(r["event"] for r in rows if r["sourcetype"] == "cisco:dc:nd:flows")
        )
        self.assertEqual(nd_event["stats"][0]["ingressByteCount"], 250)
        self.assertEqual(nd_event["stats"][0]["egressByteCount"], 250)
        ftd_event = json.loads(
            next(r["event"] for r in rows if r["sourcetype"] == "cisco:sfw:estreamer")
        )
        self.assertEqual(
            (ftd_event["InitiatorBytes"], ftd_event["ResponderBytes"]), (120, 80)
        )
        hubble_event = json.loads(
            next(r["event"] for r in rows if r["sourcetype"] == "cilium:hubble:flow")
        )
        self.assertNotIn("bytes", hubble_event["flow"])

    def test_observation_oracle_rejects_dropped_or_wrong_groups(self):
        config = mixed.CASES["smoke"]
        expected = mixed.expected_observations(config)
        rows = [
            {
                "flow_source": s,
                "observer": o,
                **values,
                "scope": mixed.SCOPE,
                "excluded": 0,
            }
            for (s, o), values in expected.items()
        ]
        mixed.check_observations(rows, config)
        with self.assertRaises(ValueError):
            mixed.check_observations(rows[:-1], config)
        with self.assertRaises(ValueError):
            mixed.check_observations(
                [{**rows[0], "bytes_fwd": rows[0]["bytes_fwd"] + 1}] + rows[1:], config
            )
        with self.assertRaises(ValueError):
            mixed.check_observations([{**rows[0], "excluded": 1}] + rows[1:], config)

    def test_graph_checks_sources_observers_and_distinct_ports(self):
        config = mixed.CASES["smoke"]
        observers = {
            f"{s}:{mixed.observer(s, n)}"
            for s in mixed.SOURCES
            for n in range(config.observers_per_source)
        }
        row = {
            "relationship": "communicates_with",
            "sources": list(mixed.SOURCES),
            "observers": list(observers),
            "confidence": "correlated",
            "count": config.connections_per_pair,
        }
        with patch.object(mixed, "graph_check", return_value=[]):
            mixed.check_graph([row], config)
        for wrong in (
            {"sources": ["netflow"]},
            {"observers": list(observers)[:-1]},
            {"confidence": "unresolved"},
            {"count": config.connections_per_pair * config.observers_per_source},
        ):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                with patch.object(mixed, "graph_check", return_value=[]):
                    mixed.check_graph([{**row, **wrong}], config)

    def test_cli_requires_explicit_reset_before_preflight(self):
        with self.assertRaises(SystemExit) as result:
            mixed.main([])
        self.assertEqual(result.exception.code, 2)

    def test_preflight_failure_does_not_reset_lab(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(
                mixed, "preflight", side_effect=RuntimeError("preflight")
            ) as preflight:
                with patch.object(mixed, "reset_lab") as reset:
                    result = mixed.main(
                        ["--reset-lab", "--output", f"{directory}/report.json"]
                    )
        self.assertEqual(result, 1)
        preflight.assert_called_once()
        reset.assert_not_called()


if __name__ == "__main__":
    unittest.main()
