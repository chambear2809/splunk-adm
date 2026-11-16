"""Local host contract tests; these do not qualify an installed Splunk source."""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_baselines_lib.splunk_host import HostUnavailable, SplunkHost, handle  # noqa: E402
from tests.test_baselines import capture  # noqa: E402


class Source:
    def __init__(self):
        self.captures = {"a": capture()}
        self.denied = set()
        self.calls = []

    def capture(self, principal, selection, window):
        self.calls.append((principal, selection, window))
        return {"reference": "a", "capture": copy.deepcopy(self.captures["a"])}

    def resolve(self, principal, reference):
        return copy.deepcopy(self.captures[reference])

    def entitled(self, principal, reference, evidence):
        return (principal, reference) not in self.denied


class BaselineHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {
            "mode": "single_search_head",
            "platform": "enterprise",
            "source_mode": "unavailable",
        }
        self.context = {"username": "alice", "capabilities": ["adm_investigate"]}
        self.server = {
            "product_type": "enterprise",
            "version": "10.6.0.5",
            "activeLicenseGroup": "Trial",
        }
        self.host = SplunkHost(
            "token",
            database_root=self.temp.name,
            configuration=lambda: self.config,
            request=lambda path: (
                self.context if path.endswith("current-context") else self.server
            ),
            topology=lambda: {"disabled": "true"},
            clock=lambda: 100,
        )

    def call(self, method, path, data=None, *, query=None, headers=None):
        return handle(
            {
                "method": method,
                "path_info": path,
                "payload": json.dumps(data) if data is not None else "",
                "query": query or [],
                "headers": headers or [],
            },
            self.host,
        )

    def headers(self, key):
        return [
            ["Content-Type", "application/json"],
            ["Idempotency-Key", key],
            ["X-Splunk-Form-Key", "test"],
        ]

    def test_fixed_configuration(self):
        with (
            mock.patch.dict(os.environ, {"SPLUNK_HOME": "/opt/splunk"}),
            mock.patch(
                "adm_baselines_lib.splunk_host.subprocess.run",
                return_value=SimpleNamespace(
                    stdout=b"[persistence]\nmode=disabled\nplatform=unqualified\nsource_mode=unavailable\n"
                ),
            ) as command,
        ):
            self.assertEqual(SplunkHost._configuration()["source_mode"], "unavailable")
            self.assertEqual(
                command.call_args.args[0],
                [
                    "/opt/splunk/bin/splunk",
                    "btool",
                    "--app=splunk_adm",
                    "--user=nobody",
                    "adm_baselines",
                    "list",
                    "persistence",
                ],
            )
            self.assertEqual(command.call_args.kwargs["timeout"], 3)
            command.return_value = SimpleNamespace(stdout=b"x" * 16385)
            with self.assertRaises(HostUnavailable):
                SplunkHost._configuration()

    def test_disabled_runtime_and_source_do_not_create_db(self):
        self.config["mode"] = "disabled"
        cap = self.call("GET", "/capabilities")[1]
        self.assertFalse(cap["available"])
        self.assertEqual(self.call("GET", "/baselines")[0], 503)
        self.config["mode"] = "single_search_head"
        cap = self.call("GET", "/capabilities")[1]
        self.assertTrue(cap["available"])
        self.assertFalse(cap["sourceAvailable"])
        self.assertIn("source_unavailable", cap["qualificationReasons"])
        query = [
            [k, v]
            for k, v in {
                "service": "s",
                "environment": "e",
                "cluster": "c",
                "namespace": "n",
                "start": "0",
                "end": "10",
            }.items()
        ]
        self.assertEqual(
            self.call("GET", "/capture", query=query)[:2],
            (422, {"error": "source_unavailable"}),
        )
        self.assertEqual(
            self.call(
                "POST",
                "/baselines",
                {"name": "x", "reference": "a"},
                headers=self.headers("create"),
            )[0],
            422,
        )
        self.assertEqual(os.listdir(self.temp.name), [])
        self.config["source_mode"] = "pretend_qualified"
        self.assertFalse(self.call("GET", "/capabilities")[1]["available"])

    def test_authenticated_private_storage_and_source_reads(self):
        source = Source()
        self.host.source_provider = source
        query = [
            [k, v]
            for k, v in {
                "service": "s",
                "environment": "e",
                "cluster": "c",
                "namespace": "n",
                "start": "0",
                "end": "10",
            }.items()
        ]
        self.assertEqual(self.call("GET", "/capture", query=query)[0], 200)
        self.assertEqual(source.calls[0][0], "alice")
        self.assertEqual(
            self.call("GET", "/capture", query=query + [["start", "1"]])[0], 400
        )
        bad_window = [pair if pair[0] != "end" else ["end", "301"] for pair in query]
        self.assertEqual(self.call("GET", "/capture", query=bad_window)[0], 400)
        status, created, _ = self.call(
            "POST",
            "/baselines",
            {"name": "x", "reference": "a"},
            headers=self.headers("create"),
        )
        self.assertEqual(status, 201)
        path = "/baselines/" + created["id"]
        self.assertEqual(self.call("GET", path)[1]["capture"], capture())
        source.denied.add(("alice", "a"))
        self.assertEqual(self.call("GET", path)[0], 403)
        self.assertEqual(self.call("GET", path + "/versions")[0], 200)
        self.host.source_provider = None
        self.assertEqual(self.call("GET", path + "/versions")[0], 200)
        self.assertEqual(
            self.call(
                "DELETE", path, {"expected_revision": 1}, headers=self.headers("delete")
            )[0],
            200,
        )
        self.assertEqual(
            self.call("POST", "/baselines/purge", {}, headers=self.headers("purge"))[0],
            403,
        )
        self.context["capabilities"] = []
        self.assertEqual(self.call("GET", "/baselines")[0], 403)
        db = Path(self.temp.name) / "splunk_adm_baselines/baselines.sqlite"
        self.assertTrue(db.is_file())
        self.assertEqual(db.stat().st_mode & 0o777, 0o600)

    def test_invalid_qualification_and_unsafe_database(self):
        self.server["isCloud"] = True
        self.assertFalse(self.call("GET", "/capabilities")[1]["available"])
        self.server["isCloud"] = False
        directory = Path(self.temp.name) / "splunk_adm_baselines"
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        with self.assertRaises(HostUnavailable):
            self.host.database()
        self.assertEqual(
            self.call("GET", "/baselines", headers=[["X", "a"], ["x", "b"]])[0], 400
        )

    def test_current_principal_source_changes_and_request_headers(self):
        source = Source()
        source.captures["b"] = capture(10)
        self.host.source_provider = source
        status, created, _ = self.call(
            "POST",
            "/baselines",
            {"name": "x", "reference": "a"},
            headers=self.headers("create"),
        )
        self.assertEqual(status, 201)
        path = "/baselines/" + created["id"]
        result = self.call(
            "POST",
            path + "/versions",
            {"expected_revision": 1, "reference": "b"},
            headers=self.headers("v"),
        )
        self.assertEqual(result[0], 200)
        self.assertEqual(
            self.call(
                "POST",
                path + "/share",
                {"expected_revision": 2, "member": "bob", "grant": True},
                headers=self.headers("share"),
            )[0],
            200,
        )
        self.context["username"] = "bob"
        source.denied.add(("bob", "a"))
        self.assertEqual(self.call("GET", path + "/versions/1")[0], 403)
        self.assertEqual(self.call("GET", path + "/versions/2")[0], 200)
        self.assertEqual(self.call("GET", path + "/versions")[0], 200)
        self.context["username"] = "eve"
        self.assertEqual(self.call("GET", path + "/versions")[0], 403)
        self.context["username"] = "alice"
        self.assertEqual(
            self.call(
                "POST",
                path + "/watches",
                {
                    "expected_revision": 3,
                    "definition": {
                        "id": "w",
                        "threshold": 1,
                        "cooldownSeconds": 0,
                        "expectedWindows": [],
                    },
                },
                headers=[["Content-Type", "application/json"]],
            )[0],
            400,
        )
        self.assertEqual(
            self.call(
                "GET",
                "/baselines",
                headers=[["X-Splunk-Form-Key", "a"], ["x-splunk-form-key", "b"]],
            )[0],
            400,
        )

    def test_database_rejects_symlinks_and_hardlinks(self):
        directory = Path(self.temp.name) / "splunk_adm_baselines"
        directory.mkdir(mode=0o700)
        target = Path(self.temp.name) / "target"
        target.write_text("")
        target.chmod(0o600)
        database = directory / "baselines.sqlite"
        database.symlink_to(target)
        with self.assertRaises(HostUnavailable):
            self.host.database()
        database.unlink()
        os.link(target, database)
        with self.assertRaises(HostUnavailable):
            self.host.database()

    def test_unresolvable_provider_is_known_precommit_failure(self):
        self.host.source_provider = Source()
        response = self.call(
            "POST",
            "/baselines",
            {"name": "x", "reference": "missing"},
            headers=self.headers("create"),
        )
        self.assertEqual(response[:2], (422, {"error": "source_unavailable"}))
        self.assertEqual(self.call("GET", "/baselines")[1]["items"], [])


if __name__ == "__main__":
    unittest.main()
