"""Offline contract checks; no credentials, Cloud access or live searches."""

import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import capture_feature_replay as replay
from tools.discover_feature_sources import Refused


class Fake:
    def __init__(self):
        self.calls = []
        self.request = None
        self.fail_create = False
        self.bad_proof = False
        self.bad_result = False
        self.bad_cleanup = False
        self.extra = {}

    def call(self, method, path, data=None, timeout=10):
        self.calls.append((method, path, data, timeout))
        if "current-context" in path:
            return {"entry": [{"content": {"username": "alice"}}]}
        if "/admin/macros/" in path:
            name = path.split("/")[-1].split("?")[0]
            index = "hubble_idx" if name == "adm_index_hubble" else "pods_idx"
            return {
                "entry": [{"name": name, "content": {"definition": "index=" + index}}]
            }
        if method == "POST":
            self.request = data
            if self.fail_create:
                raise Refused("private-unknown-post")
            return {"sid": "server.123"}
        if method == "DELETE":
            if self.bad_cleanup:
                raise Refused("private-delete")
            return {}
        if "/results?" in path:
            family = "hubble" if "hubble_idx" in self.request["search"] else "pods"
            row = {
                "_raw": '{"private":"event"}',
                "_time": "105",
                "_indextime": "110",
                "source": "private-source",
                "index": "hubble_idx" if family == "hubble" else "pods_idx",
                "sourcetype": replay.SPECS[family][1],
                **self.extra,
            }
            if self.bad_result:
                row["_indextime"] = "121"
            return {"preview": False, "results": [row]}
        content = {
            "sid": "server.123",
            "request": dict(self.request),
            "search": self.request["search"],
            "dispatchState": "DONE",
            "isDone": True,
            "isFinalized": False,
            "eventIsTruncated": False,
            "resultIsTruncated": False,
            "dropCount": 0,
            "resultCount": 1,
        }
        acl = {"owner": "mallory" if self.bad_proof else "alice", "app": "splunk_adm"}
        return {"entry": [{"name": "display-only", "acl": acl, "content": content}]}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.client = Fake()
        self.destination = self.root / "private"

    def run_capture(self):
        return replay.capture(self.client, self.destination, 100, 120, now=150)

    def test_fixed_queries_private_files_and_noncomplete_manifest(self):
        self.client.extra = {
            "host": "private-host",
            "k8s.cluster.name": "private-cluster",
            "_bkt": "private-bucket",
            "_cd": "private-offset",
        }
        result = self.run_capture()
        self.assertEqual(result, {"status": "ok", "samples": {"hubble": 1, "pods": 1}})
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        manifest = json.loads((self.destination / "manifest.json").read_text())
        self.assertFalse(manifest["complete"])
        self.assertEqual(manifest["qualification"], "head_sample_only")
        self.assertEqual(manifest["window"], {"start": 100, "end": 120})
        for family in ("hubble", "pods"):
            file = self.destination / (family + ".jsonl")
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertEqual(file.stat().st_nlink, 1)
            row = json.loads(file.read_text())
            self.assertEqual(set(row), replay.FIELDS | replay.OPTIONAL_FIELDS)
            self.assertEqual(row["source"], "private-source")
        posts = [c for c in self.client.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 2)
        for post in posts:
            self.assertNotIn("id", post[2])
            self.assertIn("| where _indextime < 120 | head 4", post[2]["search"])
            self.assertEqual(
                (post[2]["earliest_time"], post[2]["latest_time"]), ("100", "120")
            )
            self.assertEqual(
                (post[2]["max_time"], post[2]["ttl"], post[2]["auto_cancel"]),
                ("5", "30", "10"),
            )
        self.assertEqual(len([c for c in self.client.calls if c[0] == "DELETE"]), 2)
        self.assertTrue(all(c[3] <= 3 for c in self.client.calls if c[0] == "DELETE"))

    def test_unknown_post_never_guesses_sid_or_starts_next_job(self):
        self.client.fail_create = True
        with self.assertRaisesRegex(Refused, "^creation_unconfirmed$"):
            self.run_capture()
        self.assertEqual(len([c for c in self.client.calls if c[0] == "POST"]), 1)
        self.assertFalse(
            any("/services/search/jobs/" in c[1] for c in self.client.calls)
        )
        self.assertEqual(
            {p.name for p in self.destination.iterdir()}, {"manifest.json"}
        )
        manifest = json.loads((self.destination / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "creation_unconfirmed")
        self.assertEqual(
            manifest["attempts"],
            [{"family": "hubble", "status": "creation_unconfirmed"}],
        )
        self.assertEqual(
            stat.S_IMODE((self.destination / "manifest.json").stat().st_mode), 0o600
        )

    def test_wrong_owner_never_deletes_or_dispatches_again(self):
        self.client.bad_proof = True
        with self.assertRaisesRegex(Refused, "^cleanup_unconfirmed$"):
            self.run_capture()
        self.assertFalse(any(c[0] == "DELETE" for c in self.client.calls))
        self.assertEqual(len([c for c in self.client.calls if c[0] == "POST"]), 1)
        self.assertEqual(
            {p.name for p in self.destination.iterdir()}, {"manifest.json"}
        )

    def test_failed_result_cleans_verified_job_and_stops(self):
        self.client.bad_result = True
        with self.assertRaises(Refused):
            self.run_capture()
        self.assertEqual(len([c for c in self.client.calls if c[0] == "POST"]), 1)
        self.assertEqual(len([c for c in self.client.calls if c[0] == "DELETE"]), 1)
        self.assertEqual(
            {p.name for p in self.destination.iterdir()}, {"manifest.json"}
        )

    def test_cleanup_failure_stops_and_releases_no_samples(self):
        self.client.bad_cleanup = True
        with self.assertRaises(Refused):
            self.run_capture()
        self.assertEqual(len([c for c in self.client.calls if c[0] == "POST"]), 1)
        self.assertEqual(
            {p.name for p in self.destination.iterdir()}, {"manifest.json"}
        )

    def test_mismatched_job_proofs_never_delete(self):
        for field in ("sid", "request", "search", "window", "app"):
            with self.subTest(field=field):
                client = Fake()
                original = client.call

                def corrupt(method, path, data=None, timeout=10):
                    result = original(method, path, data, timeout)
                    if (
                        method == "GET"
                        and path.startswith("/services/search/jobs/")
                        and "/results?" not in path
                    ):
                        entry = result["entry"][0]
                        content = entry["content"]
                        if field == "sid":
                            content["sid"] = "different"
                        elif field == "request":
                            content["request"]["search"] += " | head 1"
                        elif field == "search":
                            content["search"] += " | head 1"
                        elif field == "window":
                            content["request"]["earliest_time"] = "99"
                        else:
                            entry["acl"]["app"] = "other"
                    return result

                client.call = corrupt
                destination = self.root / ("proof-" + field)
                with self.assertRaisesRegex(Refused, "^cleanup_unconfirmed$"):
                    replay.capture(client, destination, 100, 120, now=150)
                self.assertFalse(any(call[0] == "DELETE" for call in client.calls))
                self.assertEqual(
                    len([call for call in client.calls if call[0] == "POST"]), 1
                )
                manifest = json.loads((destination / "manifest.json").read_text())
                self.assertEqual(manifest["status"], "cleanup_unconfirmed")
                self.assertEqual(manifest["attempts"][0]["server_sid"], "server.123")

    def test_metadata_flags_are_strict_and_optional_fields_are_not_fabricated(self):
        self.assertFalse(replay._true(1.0))
        self.assertFalse(replay._false(0.0))
        self.run_capture()
        row = json.loads((self.destination / "hubble.jsonl").read_text())
        self.assertEqual(set(row), replay.FIELDS)
        self.assertEqual(
            json.loads((self.destination / "manifest.json").read_text())["status"],
            "captured",
        )

    def test_legitimately_omitted_result_flag_and_receipt_end_boundary(self):
        original = self.client.call

        def missing_flag(method, path, data=None, timeout=10):
            result = original(method, path, data, timeout)
            for entry in result.get("entry", []):
                entry.get("content", {}).pop("resultIsTruncated", None)
            return result

        self.client.call = missing_flag
        self.assertEqual(self.run_capture()["status"], "ok")
        self.destination = self.root / "exclusive-end"
        self.client.extra = {"_indextime": "120"}
        with self.assertRaises(Refused):
            self.run_capture()
        self.assertEqual(len([c for c in self.client.calls if c[0] == "POST"]), 3)

    def test_window_destination_and_query_restrictions(self):
        for start, end in ((0, 0), (0, 301), (100, 151)):
            with self.subTest(start=start, end=end), self.assertRaises(Refused):
                replay.capture(self.client, self.destination, start, end, now=150)
        self.assertFalse(self.destination.exists())
        with self.assertRaises(Refused):
            replay._query("hubble", 'bad" | delete', 120)
        with self.assertRaises(Refused):
            replay._query("other", "index", 120)
        self.destination.mkdir()
        with self.assertRaises(Refused):
            self.run_capture()
        repo = Path(__file__).resolve().parents[1]
        with self.assertRaises(Refused):
            replay._private_directory(repo / "unused-private-replay-destination")
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Refused):
            replay._private_directory(link / "target")

    def test_cli_requires_run_and_cloud_profile(self):
        script = Path(__file__).resolve().parents[1] / "tools/capture_feature_replay.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--run", result.stdout)
        with (
            mock.patch.object(sys, "stderr"),
            mock.patch.object(
                sys,
                "argv",
                [
                    str(script),
                    "--profile",
                    "cloud",
                    "--credentials",
                    "x",
                    "--destination",
                    "x",
                    "--start",
                    "1",
                    "--end",
                    "2",
                ],
            ),
            self.assertRaises(SystemExit),
        ):
            replay.main()


if __name__ == "__main__":
    unittest.main()
