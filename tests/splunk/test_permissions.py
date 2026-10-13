"""Authorization checks for the least-privileged local Splunk viewer.

The test is intentionally gated behind ``ADM_LAB=1``.  It creates one ephemeral
viewer account through the lab administrator API, uses that account for every
read/write assertion, and removes it during teardown.  The generated password
never leaves this process.
"""

from __future__ import annotations

import base64
import configparser
import json
import os
import secrets
import ssl
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / "expected" / "graph.json").read_text(encoding="utf-8"))
MGMT = "https://127.0.0.1:8089"
APP = "splunk_adm"
ALLOWED_INDEXES = [
    "netflow",
    "cisco_dc",
    "cisco_secure_fw",
    "cisco_isovalent",
    "k8s",
    "otel_traces",
    "cilium_hubble",
    "adm_summary",
    "adm",
]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class SearchRejected(RuntimeError):
    pass


def _auth(username: str, password: str) -> str:
    value = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {value}"


def _response(
    method: str,
    path: str,
    username: str,
    password: str,
    data: bytes | None = None,
    content_type: str = "application/x-www-form-urlencoded",
) -> tuple[int, bytes]:
    headers = {"Authorization": _auth(username, password)}
    if data is not None:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(
        MGMT + path, data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=120) as result:
            return result.status, result.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(2000)


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class RestrictedViewerTest(unittest.TestCase):
    """A viewer can read the graph but cannot access writer operations."""

    username: str
    password: str
    role: str
    probe_key: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        import sys

        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        # Keep this test self-contained: the data-layer setup loads and builds
        # the known fixture before the restricted account is created.
        from test_data_layer import DataLayerTest

        DataLayerTest.setUpClass()
        cls.admin_rows = DataLayerTest.rows
        saved = configparser.RawConfigParser()
        saved.read(HERE.parent / "../splunk_app/splunk_adm/default/savedsearches.conf")
        cls.saved_searches = [
            name for name in saved.sections() if name.startswith("ADM - ")
        ]
        for name in cls.saved_searches:
            path = f"/servicesNS/nobody/{APP}/saved/searches/" + urllib.parse.quote(
                name, safe=""
            )
            original = lab._json("GET", path)["entry"][0]["content"]
            cls.addClassCleanup(
                lab._json,
                "POST",
                path,
                {
                    "disabled": str(int(original["disabled"] in (True, 1, "1"))),
                    "is_scheduled": str(
                        int(original["is_scheduled"] in (True, 1, "1"))
                    ),
                },
            )
            # A disabled search is not proof of an authorization boundary.
            lab._json("POST", path, {"disabled": "0", "is_scheduled": "0"})
        cls.username = "adm_viewer_" + secrets.token_hex(8)
        cls.password = secrets.token_urlsafe(24)
        cls.role = "adm_restricted_" + secrets.token_hex(8)
        admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]
        role_payload = urllib.parse.urlencode(
            {
                "name": cls.role,
                "capabilities": "search",
                "srchIndexesAllowed": ALLOWED_INDEXES,
                "srchIndexesDisallowed": ["_internal", "_audit"],
            },
            doseq=True,
        ).encode()
        status, _ = _response(
            "POST",
            "/services/authorization/roles",
            "admin",
            admin_password,
            role_payload,
        )
        if status not in (200, 201):
            raise AssertionError(f"could not create ephemeral role (HTTP {status})")
        # Register cleanup as each resource is created.  LIFO ordering removes
        # the user before its role.
        cls.addClassCleanup(cls._delete_role, cls.role, admin_password)
        # A newly created role inherits enabled capabilities from [default].
        # Updating its explicit list removes those defaults (including collect).
        lab._json(
            "POST",
            f"/services/authorization/roles/{cls.role}",
            {"capabilities": "search"},
        )
        payload = urllib.parse.urlencode(
            {
                "name": cls.username,
                "password": cls.password,
                "roles": cls.role,
            }
        ).encode()
        status, _ = _response(
            "POST",
            "/services/authentication/users",
            "admin",
            admin_password,
            payload,
        )
        if status not in (200, 201):
            raise AssertionError(f"could not create ephemeral viewer (HTTP {status})")
        cls.addClassCleanup(cls._delete_user, cls.username, admin_password)

    @classmethod
    def _delete_user(cls, username: str, password: str) -> None:
        path = "/services/authentication/users/" + urllib.parse.quote(username, safe="")
        status, _ = _response("DELETE", path, "admin", password)
        if status not in (200, 204):
            raise AssertionError(f"viewer cleanup returned HTTP {status}")

    @classmethod
    def _delete_role(cls, role: str, password: str) -> None:
        path = "/services/authorization/roles/" + urllib.parse.quote(role, safe="")
        status, _ = _response("DELETE", path, "admin", password)
        if status not in (200, 204):
            raise AssertionError(f"role cleanup returned HTTP {status}")

    @classmethod
    def _delete_probe(cls, collection: str, key: str, password: str) -> None:
        path = f"{collection}/{urllib.parse.quote(key, safe='')}"
        status, _ = _response("DELETE", path, "admin", password)
        if status not in (200, 204, 404):
            raise AssertionError(f"KV probe cleanup returned HTTP {status}")

    @classmethod
    def _restore_config(cls, path: str, definition: str, password: str) -> None:
        payload = urllib.parse.urlencode({"definition": definition}).encode()
        status, _ = _response("POST", path, "admin", password, payload)
        if status not in (200, 201):
            raise AssertionError(f"config cleanup returned HTTP {status}")

    def _viewer_json(
        self, method: str, path: str, data: dict | None = None
    ) -> tuple[int, dict]:
        encoded = (
            urllib.parse.urlencode(data, doseq=True).encode()
            if data is not None
            else None
        )
        status, body = _response(method, path, self.username, self.password, encoded)
        try:
            return status, json.loads(body or b"{}")
        except json.JSONDecodeError:
            return status, {}

    def _viewer_search(self, search: str, earliest: int, latest: int) -> list[dict]:
        status, body = _response(
            "POST",
            f"/servicesNS/{urllib.parse.quote(self.username, safe='')}/"
            f"{APP}/search/v2/jobs?output_mode=json",
            self.username,
            self.password,
            urllib.parse.urlencode(
                {
                    "search": search if search.startswith("|") else f"search {search}",
                    "exec_mode": "blocking",
                    "earliest_time": str(earliest),
                    "latest_time": str(latest),
                }
            ).encode(),
        )
        if status not in (200, 201):
            raise SearchRejected(
                f"HTTP {status}: {body.decode('utf-8', 'replace')[:2000]}"
            )
        sid = json.loads(body)["sid"]
        self.addCleanup(self._delete_job, sid)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status, job = self._viewer_json(
                "GET",
                f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}"
                "?output_mode=json",
            )
            self.assertEqual(status, 200, f"viewer job status returned HTTP {status}")
            content = job["entry"][0]["content"]
            messages = content.get("messages", [])
            problems = [
                message.get("text", "")
                for message in messages
                if message.get("type", "").upper() in {"ERROR", "FATAL"}
            ]
            if problems:
                raise SearchRejected(" | ".join(problems))
            # A warning can accompany a successful write; it is not a denial.
            self.assertFalse(
                [
                    m
                    for m in messages
                    if m.get("type", "").upper() in {"WARN", "WARNING"}
                ],
                "viewer search returned a warning rather than a rejection",
            )
            if content.get("dispatchState") == "FAILED":
                self.fail("viewer graph search failed")
            if content.get("isFinalized") in (1, "1", True):
                self.fail("viewer graph search finalized before completion")
            if content.get("isDone"):
                break
            time.sleep(1)
        else:
            self.fail("viewer graph search did not finish")
        status, result = self._viewer_json(
            "GET",
            f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}/results?count=0&output_mode=json",
        )
        self.assertEqual(status, 200, f"viewer results returned HTTP {status}")
        self.lab._raise_messages(result.get("messages"), "viewer results")
        rows = result.get("results", [])
        self.assertEqual(len(rows), int(content["resultCount"]))
        return rows

    def _delete_job(self, sid):
        # Also cancels a failed or timed-out probe so it cannot write later.
        status, _ = self._viewer_json(
            "DELETE", f"/services/search/v2/jobs/{sid}?output_mode=json"
        )
        self.assertIn(status, (200, 204, 404))

    @staticmethod
    def _nodes(rows: list[dict]) -> set[str]:
        return {row["id"] for row in rows if row.get("row_type") == "node"}

    @staticmethod
    def _edges(rows: list[dict]) -> set[tuple[str, str, str]]:
        return {
            (row["relationship"], row["source"], row["target"])
            for row in rows
            if row.get("row_type") == "edge"
        }

    def assertDenied(
        self,
        method: str,
        path: str,
        data: bytes | None = None,
        content_type: str = "application/x-www-form-urlencoded",
        hidden: bool = False,
    ) -> None:
        status, body = _response(
            method, path, self.username, self.password, data, content_type
        )
        if status in (200, 201) and "/dispatch" in path:
            sid = json.loads(body)["sid"]
            self.lab._json("DELETE", f"/services/search/v2/jobs/{sid}")
        self.assertIn(
            status,
            (403, 404) if hidden else (403,),
            f"{method} {path} unexpectedly returned HTTP {status}",
        )

    def test_viewer_can_read_known_graph(self):
        args = EXPECTED["args"]
        call = ", ".join(
            f'"{args[key]}"'
            for key in ("service", "environment", "cluster", "namespace")
        )
        window = EXPECTED["window"]
        rows = self._viewer_search(
            f"`adm_graph({call})`", window["earliest"], window["latest"]
        )
        meta = [row for row in rows if row.get("row_type") == "meta"]
        self.assertEqual(len(meta), 1)
        self.assertNotIn("warnings", meta[0])
        for key, value in EXPECTED["meta"].items():
            self.assertEqual(meta[0].get(key), value, key)
        expected_edges = {
            (edge["relationship"], edge["source"], edge["target"])
            for edge in EXPECTED["edges"]
        }
        self.assertEqual(self._nodes(rows), self._nodes(self.admin_rows))
        self.assertEqual(self._edges(rows), self._edges(self.admin_rows))
        self.assertEqual(self._nodes(rows), set(EXPECTED["nodes"]))
        self.assertTrue(expected_edges <= self._edges(rows))

    def test_role_context_has_only_search_and_allowed_indexes(self):
        status, context = self._viewer_json(
            "GET", "/services/authentication/current-context?output_mode=json"
        )
        self.assertEqual(status, 200)
        content = context["entry"][0]["content"]
        self.assertEqual(set(content.get("roles", [])), {self.role})
        capabilities = set(content.get("capabilities", []))
        self.assertEqual(capabilities, {"search"})
        if "srchIndexesAllowed" in content:
            self.assertEqual(set(content["srchIndexesAllowed"]), set(ALLOWED_INDEXES))
        if "srchIndexesDisallowed" in content:
            self.assertEqual(
                set(content["srchIndexesDisallowed"]), {"_internal", "_audit"}
            )
        admin_password = self.lab.read_secrets()["SPLUNK_PASSWORD"]
        status, role = _response(
            "GET",
            "/services/authorization/roles/"
            + urllib.parse.quote(self.role, safe="")
            + "?output_mode=json",
            "admin",
            admin_password,
        )
        self.assertEqual(status, 200)
        role_content = json.loads(role)["entry"][0]["content"]
        imported = role_content.get(
            "importedRoles", role_content.get("imported_roles", [])
        )
        self.assertIn(imported, ([], ""))
        capabilities = role_content.get("capabilities", [])
        if isinstance(capabilities, str):
            capabilities = [item for item in capabilities.split(",") if item]
        self.assertEqual(set(capabilities), {"search"})
        self.assertEqual(
            set(role_content.get("srchIndexesAllowed", [])), set(ALLOWED_INDEXES)
        )
        self.assertEqual(
            set(role_content.get("srchIndexesDisallowed", [])), {"_internal", "_audit"}
        )

    def test_viewer_cannot_mutate_kvstore_or_app_config(self):
        collection = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity"
        )
        self.probe_key = "permission-probe-" + secrets.token_hex(8)
        admin_password = self.lab.read_secrets()["SPLUNK_PASSWORD"]
        self.addCleanup(self._delete_probe, collection, self.probe_key, admin_password)
        self.assertDenied(
            "POST",
            collection,
            json.dumps({"_key": self.probe_key}).encode(),
            "application/json",
        )
        config = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_prune_maintenance"
        )
        status, original = _response(
            "GET", config + "?output_mode=json", "admin", admin_password
        )
        self.assertEqual(status, 200)
        original_definition = json.loads(original)["entry"][0]["content"].get(
            "definition", ""
        )
        self.addCleanup(
            self._restore_config, config, original_definition, admin_password
        )
        self.assertDenied(
            "POST",
            config,
            urllib.parse.urlencode({"definition": original_definition}).encode(),
        )

    def test_shared_lookups_reject_search_writes_even_with_output_file(self):
        # Many ordinary Splunk roles have output_file for personal lookups.
        # Test object ACLs independently of that command capability.
        role_path = f"/services/authorization/roles/{self.role}"
        self.lab._json(
            "POST",
            role_path,
            {"capabilities": ["search", "output_file", "edit_own_objects"]},
        )
        self.addCleanup(self.lab._json, "POST", role_path, {"capabilities": "search"})
        status, context = self._viewer_json(
            "GET", "/services/authentication/current-context?output_mode=json"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            set(context["entry"][0]["content"]["capabilities"]),
            {"search", "output_file", "edit_own_objects"},
        )
        for lookup in (
            "adm_observer_scope",
            "adm_observer_scope.csv",
            "adm_ip_identity",
        ):
            with self.subTest(lookup=lookup):
                before = self.lab.search(f"| inputlookup {lookup}")
                self.assertTrue(before)
                try:
                    with self.assertRaisesRegex(
                        SearchRejected,
                        r"(?i)permission|not authorized|not allowed|denied|privilege|cannot write",
                    ):
                        self._viewer_search(
                            f"| inputlookup {lookup} | outputlookup {lookup}",
                            0,
                            int(time.time()),
                        )
                finally:
                    after = self.lab.search(f"| inputlookup {lookup}")
                    self.assertEqual(
                        sorted(json.dumps(r, sort_keys=True) for r in before),
                        sorted(json.dumps(r, sort_keys=True) for r in after),
                    )

    def test_viewer_cannot_dispatch_owner_builders_or_maintenance(self):
        admin_password = self.lab.read_secrets()["SPLUNK_PASSWORD"]
        for name in self.saved_searches:
            saved_path = (
                "/servicesNS/nobody/splunk_adm/saved/searches/"
                + urllib.parse.quote(name, safe="")
                + "?output_mode=json"
            )
            status, body = _response("GET", saved_path, "admin", admin_password)
            self.assertEqual(status, 200, name)
            self.assertEqual(
                json.loads(body)["entry"][0]["content"].get("dispatchAs"), "owner"
            )
            path = (
                "/servicesNS/nobody/splunk_adm/saved/searches/"
                + urllib.parse.quote(name, safe="")
                + "/dispatch?output_mode=json"
            )
            self.assertDenied(
                "POST",
                path,
                urllib.parse.urlencode({"trigger_actions": "0"}).encode(),
                hidden=True,
            )


if __name__ == "__main__":
    unittest.main()
