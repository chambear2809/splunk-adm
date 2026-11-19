import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/reconcile_prospective_source.py"


def example():
    contract = {
        "population_sha256": "a" * 64,
        "sampling": "none",
        "signal_semantics_sha256": "b" * 64,
    }
    policy = {
        "version": 1,
        "binding": {
            "cluster": "cluster-a",
            "scope": "scope-a",
            "producer": "producer-a",
            "epoch": "epoch-a",
            "config_sha256": "c" * 64,
        },
        "window": {"start": 100, "end": 200},
        "clock": {
            "basis": "utc_unix_seconds",
            "max_error_seconds": 2,
            "evidence_sha256": "d" * 64,
        },
        "lateness_seconds": 5,
        "families": {
            "identity": copy.deepcopy(contract),
            "spans": copy.deepcopy(contract),
        },
    }
    evidence = {
        "version": 1,
        "binding": copy.deepcopy(policy["binding"]),
        "window": copy.deepcopy(policy["window"]),
        "families": {},
    }
    for index, name in enumerate(("identity", "spans")):
        evidence["families"][name] = {
            "contract": copy.deepcopy(contract),
            "first_sequence": 1,
            "last_sequence": 2,
            "watermark": 207,
            "closure_sha256": "e" * 64,
            "loss_evidence_sha256": "f" * 64,
            "sampling_evidence_sha256": "a" * 64,
            "rejected": 0,
            "dropped": 0,
            "retried": 1,
            "records": [
                {
                    "sequence": n,
                    "event_time": 100 + n,
                    "receipt_sha256": f"{index * 2 + n:064x}",
                    "outcome": "accepted",
                    "attempts": n,
                    "index_ack_sha256": f"{index * 2 + n + 4:064x}",
                }
                for n in (1, 2)
            ],
        }
    return policy, evidence


class ReconciliationTests(unittest.TestCase):
    def run_cli(self, policy, evidence):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / x for x in ("policy.json", "evidence.json")]
            for path, value in zip(paths, (policy, evidence)):
                path.write_text(value if isinstance(value, str) else json.dumps(value))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), *map(str, paths)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode, json.loads(result.stdout)

    def test_eligible_is_never_qualified(self):
        code, result = self.run_cli(*example())
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "eligible_for_independent_review")
        self.assertFalse(result["qualified"])

    def test_fail_closed_on_identity_sequence_and_delivery(self):
        mutations = [
            lambda p, e: e["binding"].update(epoch="other"),
            lambda p, e: e["window"].update(start=True),
            lambda p, e: e["families"]["identity"]["records"][1].update(sequence=1),
            lambda p, e: e["families"]["identity"]["records"][1].update(sequence=3),
            lambda p, e: e["families"]["identity"].update(retried=0),
            lambda p, e: e["families"]["identity"].update(dropped=1),
            lambda p, e: e["families"]["identity"].update(rejected=1),
            lambda p, e: e["families"]["spans"]["records"][0].update(
                index_ack_sha256=e["families"]["identity"]["records"][0][
                    "index_ack_sha256"
                ]
            ),
            lambda p, e: e["families"]["identity"]["records"][0].update(event_time=200),
            lambda p, e: e["families"]["identity"].update(watermark=206),
            lambda p, e: e["families"]["identity"]["records"][0].update(
                outcome="rejected"
            ),
            lambda p, e: e["families"]["identity"]["records"][0].update(
                outcome="dropped"
            ),
            lambda p, e: e["families"]["identity"]["records"][0].update(
                outcome="pending"
            ),
            lambda p, e: e["families"]["identity"]["records"][0].update(
                index_ack_sha256=None
            ),
            lambda p, e: e["families"]["spans"]["records"][0].update(
                receipt_sha256=e["families"]["identity"]["records"][0]["receipt_sha256"]
            ),
            lambda p, e: p["families"]["identity"].update(sampling="unknown"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                policy, evidence = example()
                mutate(policy, evidence)
                code, result = self.run_cli(policy, evidence)
                self.assertEqual(code, 1)
                self.assertFalse(result["qualified"])

    def test_hostile_and_bounded_input(self):
        policy, evidence = example()
        for hostile in (
            '{"version":1,"version":1}',
            "[" * 2000 + "0" + "]" * 2000,
            '{"secret":"' + "x" * 300000 + '"}',
            '{"secret":"private-marker"}',
        ):
            code, result = self.run_cli(policy, hostile)
            self.assertEqual(code, 1)
            self.assertNotIn("private-marker", json.dumps(result))
        evidence["families"]["identity"]["records"][0]["extra"] = "private-marker"
        code, result = self.run_cli(policy, evidence)
        self.assertEqual(code, 1)
        self.assertNotIn("private-marker", json.dumps(result))

    def test_retry_counter_overflow_and_cross_kind_digest_reuse(self):
        policy, evidence = example()
        family = evidence["families"]["identity"]
        for record in family["records"]:
            record["attempts"] = 2**53 - 1
        family["retried"] = 2 * (2**53 - 2)
        code, result = self.run_cli(policy, evidence)
        self.assertEqual(code, 1)
        self.assertEqual(result["gaps"], ["delivery_counters"])

        policy, evidence = example()
        evidence["families"]["spans"]["records"][0]["receipt_sha256"] = evidence[
            "families"
        ]["identity"]["records"][0]["index_ack_sha256"]
        code, result = self.run_cli(policy, evidence)
        self.assertEqual(code, 1)
        self.assertEqual(result["gaps"], ["receipt_missing_or_duplicate"])

    def test_fifo_and_final_symlink_are_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, _ = example()
            (root / "policy.json").write_text(json.dumps(policy))
            os.mkfifo(root / "fifo")
            (root / "link").symlink_to(root / "policy.json")
            for path in (root / "fifo", root / "link"):
                with self.subTest(path=path.name):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(SCRIPT),
                            str(root / "policy.json"),
                            str(path),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=2,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(
                        json.loads(result.stdout)["gaps"], ["unreadable_or_invalid"]
                    )


if __name__ == "__main__":
    unittest.main()
