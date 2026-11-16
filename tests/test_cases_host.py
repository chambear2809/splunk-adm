"""Local host qualification and trust-boundary checks; not an installed test."""

import json
import configparser
import os
from pathlib import Path
import sys
import tempfile
import unittest

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
        # An externally populated protected record is not readable through the notes host.
        from adm_cases_lib.store import CaseStore

        raw = CaseStore(self.host.database(), lambda *_: True)
        raw.append(
            "alice",
            "external",
            case["id"],
            1,
            "attachment",
            {"label": "secret", "media_type": "text/plain", "content": "protected"},
        )
        self.assertEqual(403, self.call("GET", "/cases/" + case["id"])[0])
        self.assertEqual([], self.call("GET", "/cases")[1]["items"])

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


if __name__ == "__main__":
    unittest.main()
