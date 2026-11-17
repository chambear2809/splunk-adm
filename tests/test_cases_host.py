"""Local host qualification and trust-boundary checks; not an installed test."""

import json
import configparser
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.splunk_host import (
    APP,
    CAPABILITY,
    HostUnavailable,
    SplunkHost,
    handle,
)
from adm_cases_lib.store import Forbidden


class HostTest(unittest.TestCase):
    def test_local_control_reader_is_fixed_app_scoped_and_returns_only_flags(self):
        with (
            mock.patch.dict(os.environ, {"SPLUNK_HOME": "/opt/splunk"}),
            mock.patch(
                "adm_cases_lib.splunk_host.subprocess.run",
                return_value=SimpleNamespace(
                    stdout=b"[persistence]\nmode = single_search_head\nplatform = enterprise\ncapture_mode = disabled\n"
                ),
            ) as command,
        ):
            self.assertEqual(
                SplunkHost._configuration(),
                {
                    "mode": "single_search_head",
                    "platform": "enterprise",
                    "capture_mode": "disabled",
                },
            )
            self.assertEqual(
                command.call_args.args[0],
                [
                    "/opt/splunk/bin/splunk",
                    "btool",
                    "--app=splunk_adm",
                    "--user=nobody",
                    "adm_investigations",
                    "list",
                    "persistence",
                ],
            )
            self.assertEqual(command.call_args.kwargs["timeout"], 3)
            command.return_value = SimpleNamespace(
                stdout=b"[other]\nmode = single_search_head\n"
            )
            with self.assertRaises(HostUnavailable):
                SplunkHost._configuration()
            command.return_value = SimpleNamespace(stdout=b"x" * 16385)
            with self.assertRaises(HostUnavailable):
                SplunkHost._configuration()

    def test_registration_forwards_authentication_and_exposes_exact_client_routes(self):
        default = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/default"
        rest = configparser.ConfigParser(interpolation=None)
        rest.read(default / "restmap.conf")
        registration = rest["script:adm_investigations"]
        self.assertEqual("true", registration["requireAuthentication"])
        self.assertEqual("true", registration["passSession"])
        self.assertEqual("false", registration["passSystemAuth"])
        self.assertEqual("true", registration["passHttpHeaders"])
        self.assertEqual(CAPABILITY, registration["capability"])
        web = configparser.ConfigParser(interpolation=None)
        web.read(default / "web.conf")
        routes = {
            web[section]["pattern"]: set(web[section]["methods"].split(","))
            for section in web.sections()
        }
        for path, methods in {
            "capabilities": {"GET"},
            "cases": {"GET", "POST"},
            "cases/*": {"GET", "DELETE"},
            "cases/*/entries": {"POST"},
            "cases/*/captures": {"POST"},
            "cases/*/share": {"POST"},
            "cases/*/export": {"GET"},
            "cases/*/audit": {"GET"},
        }.items():
            self.assertEqual(methods, routes["adm/investigations/" + path])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.responses = {
            "/services/authentication/current-context": {
                "username": "alice",
                "capabilities": [CAPABILITY],
            },
            APP + "/configs/conf-adm_investigations/persistence": {
                "mode": "single_search_head",
                "platform": "enterprise",
            },
            "/services/server/info": {
                "version": "10.6.0.5",
                "product_type": "enterprise",
                "isCloud": False,
                "activeLicenseGroup": "Trial",
            },
            APP + "/configs/conf-server/shclustering": {"disabled": "1"},
        }
        self.host = SplunkHost(
            "opaque-test-token",
            request=lambda path: self.responses[path],
            database_root=self.directory.name,
            topology=lambda: self.responses[APP + "/configs/conf-server/shclustering"],
            configuration=lambda: self.responses[
                APP + "/configs/conf-adm_investigations/persistence"
            ],
        )

    def call(self, method, path, body=None, headers=None):
        return handle(
            {
                "method": method,
                "path_info": path,
                "payload": json.dumps(body) if body else "",
                "headers": headers or [],
            },
            self.host,
        )

    def test_oversized_payload_rejected_before_storage_or_capture_readiness(self):
        # The limit is bytes, including multibyte UTF-8, and applies even while
        # persistence is unavailable or capture probing would fail.
        for path in ("/cases", "/capabilities"):
            for payload in ("x" * 128_001, "é" * 64_001, "😀" * 32_001):
                with (
                    self.subTest(path=path, characters=len(payload)),
                    mock.patch.object(self.host, "store") as store,
                    mock.patch.object(self.host, "qualify") as qualify,
                    mock.patch.object(self.host, "capture_ready") as capture,
                ):
                    status, body, headers = handle(
                        {
                            "method": "GET" if path == "/capabilities" else "POST",
                            "path_info": path,
                            "payload": payload,
                        },
                        self.host,
                    )
                    self.assertEqual((status, body), (413, {"error": "body_too_large"}))
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                    store.assert_not_called()
                    qualify.assert_not_called()
                    capture.assert_not_called()
        self.assertEqual([], os.listdir(self.directory.name))

    def test_exact_body_byte_limit_reaches_api_and_authentication_still_precedes_rejection(
        self,
    ):
        for payload in (" " * 128_000, "é" * 64_000):
            with mock.patch.object(self.host, "store") as store:
                # Valid size still follows normal API validation (invalid JSON).
                status, _, _ = handle(
                    {
                        "method": "POST",
                        "path_info": "/cases",
                        "payload": payload,
                        "headers": [
                            ["Content-Type", "application/json"],
                            ["Idempotency-Key", "limit"],
                        ],
                    },
                    self.host,
                )
                self.assertEqual(status, 400)
                store.assert_called_once_with("alice")
        with mock.patch.object(self.host, "principal", side_effect=Forbidden()):
            self.assertEqual(
                handle(
                    {"method": "POST", "path_info": "/cases", "payload": "x" * 128_001},
                    self.host,
                )[0],
                403,
            )

    def test_disabled_and_cloud_fail_without_creating_storage(self):
        self.assertFalse(
            handle({"method": "GET", "path_info": "capabilities"}, self.host)[1][
                "qualified"
            ]
        )
        self.responses[APP + "/configs/conf-adm_investigations/persistence"]["mode"] = (
            "disabled"
        )
        self.assertFalse(self.call("GET", "/capabilities")[1]["available"])
        self.assertEqual(503, self.call("GET", "/cases")[0])
        self.assertEqual([], os.listdir(self.directory.name))
        self.responses[APP + "/configs/conf-adm_investigations/persistence"]["mode"] = (
            "single_search_head"
        )
        self.responses["/services/server/info"]["isCloud"] = True
        with self.assertRaises(HostUnavailable):
            self.host.store("alice")

    def test_principal_comes_from_current_context_and_capability_rechecked(self):
        store = self.host.store("alice")
        case = store.create(
            "alice",
            "create",
            {
                "schema_version": 1,
                "title": "Notes",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-01T01:00:00Z",
                },
            },
        )
        self.responses["/services/authentication/current-context"]["username"] = "bob"
        with self.assertRaises(Forbidden):
            store.get("alice", case["id"])
        self.responses["/services/authentication/current-context"]["capabilities"] = []
        self.assertEqual(403, self.call("GET", "/cases")[0])

    def test_installed_enterprise_metadata_and_local_topology_shape(self):
        server = self.responses["/services/server/info"]
        server.pop("isCloud")
        self.responses[APP + "/configs/conf-server/shclustering"]["disabled"] = "true"
        self.host.qualify()
        server["isCloudInstance"] = True
        with self.assertRaises(HostUnavailable):
            self.host.qualify()
        server.pop("isCloudInstance")
        server["activeLicenseGroup"] = "Cloud"
        with self.assertRaises(HostUnavailable):
            self.host.qualify()

    def test_notes_roundtrip_and_evidence_rejected(self):
        headers = [["Content-Type", "application/json"], ["Idempotency-Key", "create"]]
        status, case, _ = self.call(
            "POST",
            "/cases",
            {
                "schema_version": 1,
                "title": "Notes",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-01T01:00:00Z",
                },
            },
            headers,
        )
        self.assertEqual(201, status)
        self.assertEqual(case, self.call("GET", "/cases/" + case["id"])[1])
        status, _, _ = self.call(
            "POST",
            "/cases/" + case["id"] + "/captures",
            {
                "expected_revision": 1,
                "item": {
                    "label": "evidence",
                    "captured_at": "2026-01-01T02:00:00Z",
                    "data": {},
                },
            },
            [["Content-Type", "application/json"], ["Idempotency-Key", "capture"]],
        )
        self.assertEqual(403, status)
        # Simulate a legacy document without passing the new trusted admission.
        import sqlite3
        from contextlib import closing

        legacy = {**case, "attachments": [{"content": "protected"}]}
        with closing(sqlite3.connect(self.host.database())) as db:
            db.execute(
                "UPDATE cases SET document=? WHERE id=?",
                (json.dumps(legacy), case["id"]),
            )
            db.commit()
        status, projected, _ = self.call("GET", "/cases/" + case["id"])
        self.assertEqual(200, status)
        self.assertEqual([], projected["attachments"])
        self.assertEqual(1, projected["redactions"]["attachments"])
        self.assertNotIn("protected", json.dumps(projected))
        self.assertEqual([], self.call("GET", "/cases")[1]["items"][0]["attachments"])

    def test_unsafe_database_and_duplicate_fields_fail_closed(self):
        directory = Path(self.directory.name) / "splunk_adm_investigations"
        directory.mkdir(mode=0o755)
        with self.assertRaises(HostUnavailable):
            self.host.database()
        result = handle(
            {
                "method": "GET",
                "path_info": "/cases",
                "query": [["after", "a"], ["after", "b"]],
            },
            self.host,
        )
        self.assertEqual(400, result[0])

    def test_current_reader_revalidation_and_disabled_notes_recovery(self):
        # This is transport replay, not installed role/search-filter qualification.
        from tests.test_cases_source import graph, reference

        jobs = {}
        job_requests = {}
        job_owners = {}
        issued = []
        restricted = set()

        def native(method, path, data, timeout):
            self.assertGreater(timeout, 0)
            if method == "POST":
                self.assertNotIn("id", data)
                sid = "native_auto_" + str(len(issued) + 1)
                issued.append((self.host.principal(), data.copy()))
                job_requests[sid] = data.copy()
                job_owners[sid] = self.host.principal()
                jobs[sid] = graph(int(data["earliest_time"]), int(data["latest_time"]))
                if self.host.principal() in restricted:
                    jobs[sid] = jobs[sid][1:]  # Same index grant, fewer visible rows.
                return {"sid": sid}
            sid = path.split("/jobs/", 1)[1].split("/", 1)[0].split("?", 1)[0]
            if method == "DELETE":
                del jobs[sid]
                return {}
            if "/results?" in path:
                return {"preview": False, "results": jobs[sid]}
            return {
                "entry": [
                    {
                        "name": "A native display title",
                        "acl": {"owner": job_owners[sid], "app": "splunk_adm"},
                        "content": {
                            "sid": sid,
                            "request": job_requests[sid],
                            "search": job_requests[sid]["search"],
                            "dispatchState": "DONE",
                            "isDone": True,
                            "isFinalized": False,
                            "eventIsTruncated": False,
                            "dropCount": 0,
                            "resultCount": len(jobs[sid]),
                        },
                    }
                ]
            }

        self.host.native_request = native
        self.host.source_fingerprint = lambda: "synthetic-contract-1"
        config = self.responses[APP + "/configs/conf-adm_investigations/persistence"]
        config["capture_mode"] = "reproducible_qualified_v1"
        self.assertTrue(self.call("GET", "/capabilities")[1]["evidenceWrites"])
        case = self.host.store("alice").create(
            "alice",
            "create",
            {
                "schema_version": 1,
                "title": "Source capture",
                "window": {
                    "start": "1970-01-01T00:03:20Z",
                    "end": "1970-01-01T00:05:00Z",
                },
            },
        )
        path = "/cases/" + case["id"]
        body = {"expected_revision": 1, "reference": reference(), "label": "Rechecked"}
        headers = [["Content-Type", "application/json"], ["Idempotency-Key", "capture"]]
        status, saved, _ = self.call("POST", path + "/captures", body, headers)
        self.assertEqual(200, status)
        self.assertEqual(1, len(saved["captures"]))
        self.assertNotIn("source", saved["captures"][0])
        self.assertEqual({}, jobs)
        self.assertTrue(all(who == "alice" for who, _ in issued))
        # A new HTTP request repeats proof instead of reusing the writer's cache.
        count = len(issued)
        self.assertEqual(1, len(self.call("GET", path)[1]["captures"]))
        self.assertEqual(count + 2, len(issued))
        self.host.store("alice").share("alice", "share", case["id"], 2, "bob", True)
        self.responses["/services/authentication/current-context"]["username"] = "bob"
        restricted.add("bob")
        projected = self.call("GET", path)[1]
        self.assertEqual([], projected["captures"])
        self.assertEqual(1, projected["redactions"]["captures"])
        self.assertEqual("bob", issued[-1][0])
        self.assertEqual({}, jobs)
        # Disabling the adapter never makes the case's notes inaccessible.
        config["capture_mode"] = "disabled"
        self.assertFalse(self.call("GET", "/capabilities")[1]["evidenceWrites"])
        self.assertEqual(200, self.call("GET", path)[0])
        self.assertEqual([], self.call("GET", path)[1]["captures"])
        self.assertEqual(
            422,
            self.call(
                "POST",
                path + "/captures",
                {**body, "expected_revision": 3},
                [["Content-Type", "application/json"], ["Idempotency-Key", "disabled"]],
            )[0],
        )

    def test_unconfigured_capture_transport_preserves_notes(self):
        self.responses[APP + "/configs/conf-adm_investigations/persistence"][
            "capture_mode"
        ] = "reproducible_qualified_v1"
        self.host.transport_configuration = lambda: {
            "management_uri": "unconfigured",
            "ca_file": "unconfigured",
        }
        status, caps, _ = self.call("GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertTrue(caps["available"])
        self.assertFalse(caps["evidenceWrites"])
        self.assertEqual(caps["mode"], "notes_only")
        self.assertEqual(self.call("GET", "/cases")[0], 200)

    def test_capture_trust_reader_has_fixed_scope_and_strict_fields(self):
        with (
            mock.patch.dict(os.environ, {"SPLUNK_HOME": "/opt/splunk"}),
            mock.patch(
                "adm_cases_lib.splunk_host.subprocess.run",
                return_value=SimpleNamespace(
                    stdout=b"[capture_transport]\nmanagement_uri = unconfigured\nca_file = unconfigured\n"
                ),
            ) as command,
        ):
            self.assertEqual(
                SplunkHost._transport_configuration(),
                {"management_uri": "unconfigured", "ca_file": "unconfigured"},
            )
            self.assertEqual(
                command.call_args.args[0][-3:],
                ["adm_investigations", "list", "capture_transport"],
            )
            command.return_value = SimpleNamespace(
                stdout=b"[capture_transport]\nmanagement_uri = x\nca_file = y\nextra = z\n"
            )
            with self.assertRaises(HostUnavailable):
                SplunkHost._transport_configuration()

    def test_protected_transport_must_match_host_instance_guid(self):
        self.responses["/services/server/info"]["guid"] = "host-a"
        self.responses[APP + "/configs/conf-adm_investigations/persistence"][
            "capture_mode"
        ] = "reproducible_qualified_v1"
        peer = {"guid": "host-b"}
        calls = []

        class Requester:
            trust_digest = "a" * 64

            ready = True

            def preflight(self):
                return self.ready

            def __call__(self, method, path, data, timeout):
                calls.append((method, path))
                return {"entry": [{"content": peer.copy()}]}

        requester = Requester()
        self.host.capture_request = lambda: requester
        requester.ready = False
        self.assertFalse(self.call("GET", "/capabilities")[1]["evidenceWrites"])
        self.assertEqual(calls, [])
        requester.ready = True
        status, caps, _ = self.call("GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertTrue(caps["available"])
        self.assertFalse(caps["evidenceWrites"])
        self.assertEqual(self.call("GET", "/cases")[0], 200)
        self.assertTrue(
            all(m == "GET" and p == "/services/server/info" for m, p in calls)
        )
        peer["guid"] = "host-a"
        self.assertTrue(self.call("GET", "/capabilities")[1]["evidenceWrites"])
        first = self.host.transport_hash(requester)
        self.host.hosting_guid = "host-b"
        self.assertNotEqual(first, self.host.transport_hash(requester))

    def test_missing_host_guid_does_not_contact_configured_peer(self):
        self.responses[APP + "/configs/conf-adm_investigations/persistence"][
            "capture_mode"
        ] = "reproducible_qualified_v1"
        with mock.patch.object(self.host, "capture_request") as requester:
            self.assertFalse(self.call("GET", "/capabilities")[1]["evidenceWrites"])
            requester.assert_not_called()
        self.assertEqual(self.call("GET", "/cases")[0], 200)

    def test_unsafe_source_ledger_does_not_strand_notes(self):
        self.responses[APP + "/configs/conf-adm_investigations/persistence"][
            "capture_mode"
        ] = "reproducible_qualified_v1"
        self.host.native_request = lambda *args: {}
        file = self.host.database().with_name("capture_jobs.sqlite")
        file.write_text("not sqlite")
        file.chmod(0o600)
        self.assertEqual(self.call("GET", "/cases")[0], 200)

    def test_capture_config_and_fingerprint_fail_closed(self):
        self.assertRegex(self.host.source_fingerprint(), r"^[0-9a-f]{64}$")
        self.responses[APP + "/configs/conf-adm_investigations/persistence"][
            "capture_mode"
        ] = "arbitrary"
        self.assertEqual(503, self.call("GET", "/cases")[0])


if __name__ == "__main__":
    unittest.main()
