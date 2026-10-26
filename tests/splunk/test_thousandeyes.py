"""Installed exact-query qualification for synthetic ThousandEyes fixtures.

This suite runs only when explicitly requested against the owned disposable
lab with the statically copied 0.9.0 search-time TA. It does not execute vendor
inputs or claim a live ThousandEyes producer.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest
import urllib.parse
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = ROOT / "fixtures" / "thousandeyes"
SEARCH_HELPER = ROOT / "tools" / "thousandeyes_search.mjs"
INDEX = "atlas_te"
SOURCETYPES = {
    "metric": "cisco:thousandeyes:metric",
    "trace": "cisco:thousandeyes:trace",
    "activity": "cisco:thousandeyes:activity",
    "event": "cisco:thousandeyes:event",
    "alert": "cisco:thousandeyes:alerts",
    "path": "atlas:thousandeyes:path",
}
SOURCES = {
    "metric": "cisco:thousandeyes:stream",
    "trace": "cisco:thousandeyes:stream",
    "activity": "cisco:thousandeyes:stream",
    "event": "event-input-default",
    "alert": "cisco:thousandeyes:webhook",
    "path": "atlas:thousandeyes:path",
}
FIXTURE_FILES = {
    "metric": "metric-v2.json",
    "trace": "trace-v2.json",
    "activity": "activity-v2.json",
    "event": "event.json",
    "alert": "alert.json",
    "path": "path-export-wrapper.json",
}


def helper(payload: dict) -> dict:
    completed = subprocess.run(
        ["node", str(SEARCH_HELPER)],
        cwd=ROOT,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=90,
    )
    if completed.returncode:
        raise AssertionError("ThousandEyes exact helper rejected its contract input")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError("ThousandEyes helper did not return JSON") from error
    if not isinstance(result, dict):
        raise AssertionError("ThousandEyes helper result must be an object")
    return result


def _error_messages(values: list[dict] | None) -> list[str]:
    return [
        str(item.get("text", ""))
        for item in values or []
        if str(item.get("type", "")).upper() in {"ERROR", "FATAL"}
    ]


def _warning_messages(values: list[dict] | None) -> list[str]:
    return [
        str(item.get("text", ""))
        for item in values or []
        if str(item.get("type", "")).upper() in {"WARN", "WARNING"}
    ]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1" and os.environ.get("ADM_THOUSANDEYES_LAB") == "1",
    "requires ADM_LAB=1 and explicit ADM_THOUSANDEYES_LAB=1 with the owned disposable lab",
)
class ThousandEyesInstalledLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "tools"))
        sys.path.insert(0, str(HERE))
        from lab_lock import LabLock
        import lab
        import test_permissions

        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")
        cls.lab = lab
        cls.permissions = test_permissions
        cls._require_vendor_search_time_ta()

        cls.token = "te-lab-" + uuid.uuid4().hex[:16]
        cls.scope = "te-qualification-" + uuid.uuid4().hex[:8]
        cls.now = int(time.time())
        cls.window = {"start": 1_699_999_950, "end": 1_700_000_100}
        cls.authority = "te-qualification-" + secrets.token_hex(6)
        cls.account_group_id = str(1000000 + secrets.randbelow(8999999))
        cls.stream_account_id = str(10000000 + secrets.randbelow(89999999))
        cls.alert_account_id = str(20000000 + secrets.randbelow(79999999))
        cls.organization_id = "org-" + secrets.token_hex(6)
        cls.test_id = "17-" + secrets.token_hex(4)
        cls.agent_id = "9-" + secrets.token_hex(4)
        cls.mapping = {
            "observer_kind": "thousandeyes_account_group",
            "observer": cls.authority,
            "scope": cls.scope,
            "cluster": "",
            "mapping_status": "verified",
            "te_account_group_id": cls.account_group_id,
            "te_stream_account_id": cls.stream_account_id,
            "te_alert_account_id": cls.alert_account_id,
            "te_organization_id": cls.organization_id,
            "te_families": json.dumps(
                ["metric", "path", "trace", "event", "alert", "activity"]
            ),
            "te_bindings": json.dumps(
                [
                    {
                        "id": "te-lab-binding-v1",
                        "authority": cls.authority,
                        "accountGroupId": cls.account_group_id,
                        "scope": cls.scope,
                        "testId": cls.test_id,
                        "agentId": cls.agent_id,
                        "testDomain": "cea",
                        "target": {
                            "ip": "198.51.100.20",
                            "protocol": "tcp",
                            "port": 443,
                        },
                        "endpointAddresses": ["198.51.100.20"],
                        "validFrom": cls.window["start"] - 60,
                        "validTo": cls.window["end"] + 60,
                        "configurationId": "te-lab-test-config-v1",
                    }
                ]
            ),
            "te_path_sources": json.dumps(
                [{"index": INDEX, "source": SOURCES["path"]}]
            ),
            "thousandeyes_origin": "https://app.thousandeyes.example.test",
        }
        cls.config = {
            "source": "thousandeyes",
            "state": "active",
            "indexes": [INDEX],
            "authorities": [cls.authority],
            "schemaQualified": True,
            "staleAfterSeconds": 1200,
            "mappings": [cls.mapping],
        }
        cls.selection = {
            "schemaVersion": 1,
            "workflow": "endpoint",
            "selectionId": cls.token,
            "trafficContract": 1,
            "window": cls.window,
            "scope": cls.scope,
            "addresses": ["198.51.100.20"],
            "contexts": [],
            "identityBasis": "disposable ThousandEyes indexed evidence qualification",
            "configurationFingerprint": "a" * 64,
        }

        admin_password = cls.lab.read_secrets()["SPLUNK_PASSWORD"]
        cls.username = "adm_te_viewer_" + secrets.token_hex(8)
        cls.password = secrets.token_urlsafe(24)
        cls.role = "adm_te_viewer_role_" + secrets.token_hex(8)
        role_payload = urllib.parse.urlencode(
            {
                "name": cls.role,
                "capabilities": ["search", "list_conf_objects"],
                "srchIndexesAllowed": [INDEX],
                "srchIndexesDisallowed": ["atlas_asset", "_internal", "_audit"],
            },
            doseq=True,
        ).encode()
        status, _ = cls.permissions._response(
            "POST",
            "/services/authorization/roles",
            "admin",
            admin_password,
            role_payload,
        )
        if status not in (200, 201):
            raise AssertionError(
                "could not create the temporary ThousandEyes viewer role"
            )
        cls.addClassCleanup(cls._delete_role, cls.role, admin_password)
        cls.lab._json(
            "POST",
            "/services/authorization/roles/" + urllib.parse.quote(cls.role, safe=""),
            {"capabilities": ["search", "list_conf_objects"]},
        )
        user_payload = urllib.parse.urlencode(
            {"name": cls.username, "password": cls.password, "roles": cls.role}
        ).encode()
        status, _ = cls.permissions._response(
            "POST",
            "/services/authentication/users",
            "admin",
            admin_password,
            user_payload,
        )
        if status not in (200, 201):
            raise AssertionError("could not create the temporary ThousandEyes viewer")
        cls.addClassCleanup(cls._delete_user, cls.username, admin_password)

        cls.events = cls._fixtures_as_hec_events()
        cls.events.append(cls._bgp_monitor_event())
        cls.events.append(cls._wrong_account_metric())
        cls.events.append(cls._asset_index_metric())
        cls.lab._hec_post(
            b"\n".join(
                json.dumps(event, separators=(",", ":")).encode()
                for event in cls.events
            )
        )
        cls._wait_for_indexed(len(cls.events) - 1, INDEX)
        cls._wait_for_indexed(1, "atlas_asset")

    @classmethod
    def _require_vendor_search_time_ta(cls) -> None:
        try:
            app = cls.lab._json("GET", "/services/apps/local/ta_cisco_thousandeyes")[
                "entry"
            ][0]
        except Exception as error:
            raise RuntimeError(
                "ADM_THOUSANDEYES_LAB=1 requires the optional 0.9.0 search-time TA co-install"
            ) from error
        if app.get("name") != "ta_cisco_thousandeyes":
            raise RuntimeError(
                "the ThousandEyes search-time TA app identity is invalid"
            )
        if app.get("content", {}).get("version") != "0.9.0":
            raise RuntimeError(
                "the installed ThousandEyes search-time TA must be version 0.9.0"
            )
        if app.get("content", {}).get("disabled") in (True, 1, "1"):
            raise RuntimeError("the ThousandEyes search-time TA must be enabled")
        props = cls.lab._json(
            "GET",
            "/servicesNS/nobody/ta_cisco_thousandeyes/configs/conf-props?count=0",
        )["entry"]
        stanzas = {entry["name"]: entry["content"] for entry in props}
        metric = stanzas.get(SOURCETYPES["metric"])
        if not metric or metric.get("KV_MODE") != "json":
            raise RuntimeError(
                "the installed 0.9.0 metric search-time props are absent"
            )
        if metric.get("DATETIME_CONFIG") != "CURRENT":
            raise RuntimeError(
                "the installed 0.9.0 metric time contract differs from research"
            )

    @classmethod
    def _fixtures_as_hec_events(cls) -> list[dict]:
        events = []
        for family, filename in FIXTURE_FILES.items():
            event = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
            if family in {"metric", "trace", "activity"}:
                cls._set_otlp_attribute(
                    event, "thousandeyes.account.id", cls.stream_account_id
                )
            if family in {"metric", "trace"}:
                cls._set_otlp_attribute(event, "thousandeyes.test.id", cls.test_id)
                cls._set_otlp_attribute(
                    event, "thousandeyes.source.agent.id", cls.agent_id
                )
                cls._set_otlp_attribute(event, "thousandeyes.test.domain", "cea")
            if family == "event":
                event["aid"] = cls.account_group_id
                event["id"] = cls.token + "-event"
            if family == "alert":
                event["accountId"] = cls.alert_account_id
                event["orgId"] = cls.organization_id
                event["eventId"] = cls.token + "-webhook"
                event["alert"]["id"] = cls.token + "-alert"
                event["alert"]["rule"]["account"]["id"] = cls.alert_account_id
                event["alert"]["rule"]["account"]["organization"]["id"] = (
                    cls.organization_id
                )
                event["alert"]["test"]["id"] = cls.test_id
            if family == "path":
                event["authority"] = cls.authority
                event["account_group_id"] = cls.account_group_id
                event["test_id"] = cls.test_id
                event["test_domain"] = "cea"
                event["capture_id"] = cls.token + "-path-capture"
                event["result"]["agent"]["agentId"] = cls.agent_id
            # Deliberately unrelated: no normalizer may use Splunk host as the
            # ThousandEyes authority or agent identity.
            events.append(
                {
                    "time": cls.now,
                    "host": cls.token + "-untrusted-host",
                    "source": SOURCES[family],
                    "sourcetype": SOURCETYPES[family],
                    "index": INDEX,
                    "event": event,
                }
            )
        return events

    @staticmethod
    def _set_otlp_attribute(value: object, name: str, replacement: str) -> None:
        if isinstance(value, dict):
            if value.get("key") == name and isinstance(value.get("value"), dict):
                fields = value["value"]
                for field in ("string_value", "stringValue"):
                    if field in fields:
                        fields[field] = replacement
                        break
            for child in value.values():
                ThousandEyesInstalledLabTest._set_otlp_attribute(
                    child, name, replacement
                )
        elif isinstance(value, list):
            for child in value:
                ThousandEyesInstalledLabTest._set_otlp_attribute(
                    child, name, replacement
                )

    @classmethod
    def _wrong_account_metric(cls) -> dict:
        event = json.loads((FIXTURES / FIXTURE_FILES["metric"]).read_text())
        cls._set_otlp_attribute(event, "thousandeyes.account.id", "9999")
        cls._set_otlp_attribute(event, "thousandeyes.test.id", cls.test_id)
        cls._set_otlp_attribute(event, "thousandeyes.source.agent.id", cls.agent_id)
        return {
            "time": cls.now,
            "host": cls.token + "-wrong-account",
            "source": SOURCES["metric"],
            "sourcetype": SOURCETYPES["metric"],
            "index": INDEX,
            "event": event,
        }

    @classmethod
    def _bgp_monitor_event(cls) -> dict:
        event = json.loads((FIXTURES / "bgp-monitor-v2.json").read_text())
        cls._set_otlp_attribute(event, "thousandeyes.account.id", cls.stream_account_id)
        return {
            "time": cls.now,
            "host": cls.token + "-bgp-monitor",
            "source": SOURCES["metric"],
            "sourcetype": SOURCETYPES["metric"],
            "index": INDEX,
            "event": event,
        }

    @classmethod
    def _asset_index_metric(cls) -> dict:
        event = json.loads((FIXTURES / FIXTURE_FILES["metric"]).read_text())
        cls._set_otlp_attribute(event, "thousandeyes.account.id", cls.stream_account_id)
        cls._set_otlp_attribute(event, "thousandeyes.test.id", cls.test_id)
        cls._set_otlp_attribute(event, "thousandeyes.source.agent.id", cls.agent_id)
        return {
            "time": cls.now,
            "host": cls.token + "-restricted-index",
            "source": SOURCES["metric"],
            "sourcetype": SOURCETYPES["metric"],
            "index": "atlas_asset",
            "event": event,
        }

    @classmethod
    def _wait_for_indexed(cls, expected: int, index: str) -> None:
        deadline = time.monotonic() + 45
        query = f'index={index} host="{cls.token}*" | stats count AS count'
        while time.monotonic() < deadline:
            rows = cls.lab.search(query, "0", "+1h")
            if rows and int(rows[0].get("count", -1)) == expected:
                return
            time.sleep(0.5)
        raise AssertionError("synthetic ThousandEyes fixture events were not indexed")

    @classmethod
    def _delete_user(cls, username: str, password: str) -> None:
        path = "/services/authentication/users/" + urllib.parse.quote(username, safe="")
        status, _ = cls.permissions._response("DELETE", path, "admin", password)
        if status not in (200, 204):
            raise AssertionError("temporary ThousandEyes viewer cleanup failed")

    @classmethod
    def _delete_role(cls, role: str, password: str) -> None:
        path = "/services/authorization/roles/" + urllib.parse.quote(role, safe="")
        status, _ = cls.permissions._response("DELETE", path, "admin", password)
        if status not in (200, 204):
            raise AssertionError("temporary ThousandEyes viewer role cleanup failed")

    @classmethod
    def _wait_for_kvstore(cls, timeout: float = 300) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status = cls.lab._json("GET", "/services/kvstore/status")["entry"][0][
                    "content"
                ]
            except Exception:
                time.sleep(3)
                continue
            if status.get("current", {}).get("status") == "ready":
                return
            time.sleep(3)
        raise AssertionError(
            "KV store did not become ready for ThousandEyes fixture setup"
        )

    @classmethod
    def _restore_role_indexes(
        cls, role: str, indexes: list[str], password: str
    ) -> None:
        path = "/services/authorization/roles/" + urllib.parse.quote(role, safe="")
        body = urllib.parse.urlencode(
            {"srchIndexesAllowed": indexes}, doseq=True
        ).encode()
        status, _ = cls.permissions._response("POST", path, "admin", password, body)
        if status not in (200, 201):
            raise AssertionError("temporary ThousandEyes viewer index cleanup failed")

    @classmethod
    def _remove_scope_mapping(cls, key: str, password: str) -> None:
        path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            "adm_observer_scope/" + urllib.parse.quote(key, safe="")
        )
        status, _ = cls.permissions._response("DELETE", path, "admin", password)
        if status not in (200, 204):
            raise AssertionError("temporary ThousandEyes scope cleanup failed")

    @classmethod
    def _macro_path(cls, name: str) -> str:
        return "/servicesNS/nobody/splunk_adm/admin/macros/" + urllib.parse.quote(
            name, safe=""
        )

    @classmethod
    def _macro_content(cls, name: str) -> dict:
        return cls.lab._json("GET", cls._macro_path(name))["entry"][0]["content"]

    @classmethod
    def _write_and_verify_macro_states(cls, states: dict[str, str]) -> None:
        for name, definition in states.items():
            cls.lab._json("POST", cls._macro_path(name), {"definition": definition})
        cls.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")
        for name, definition in states.items():
            if cls._macro_content(name).get("definition") != definition:
                raise AssertionError("temporary ThousandEyes macro did not verify")

    def _write_deployment_state(
        self, fixture, state: str, expected_revision: str | None
    ) -> str:
        status, snapshot = fixture.request("GET")
        self.assertEqual(status, 200, "deployment settings read failed")
        self.assertTrue(
            snapshot.get("canWrite"), "deployment settings are not writable"
        )
        definitions = json.loads(
            (ROOT / "config" / "deployment-health.json").read_text("utf-8")
        )["sources"]
        sources = {
            source["id"]: {
                "state": "not_selected",
                "cadenceSeconds": source["cadenceSeconds"],
                "staleAfterSeconds": source["staleAfterSeconds"],
            }
            for source in definitions
            if source.get("selectable")
        }
        sources["thousandeyes"]["state"] = state
        payload = {
            "namespace": snapshot["namespace"],
            "requestId": uuid.uuid4().hex,
            "expectedRevision": expected_revision,
            "settings": {"schemaVersion": 1, "revision": "draft", "sources": sources},
        }
        status, response = fixture.request("POST", payload=payload)
        self.assertEqual(status, 200, "temporary deployment state write failed")
        revision = response.get("committedRevision")
        self.assertRegex(revision or "", r"^[a-f0-9]{64}$")
        return revision

    def _run_native_browser(self, mode: str) -> dict:
        screenshot = (
            ROOT / "dist" / "thousandeyes-qualification" / "native-inspection.png"
        )
        result = subprocess.run(
            [
                "node",
                str(HERE / "thousandeyes-browser.mjs"),
                mode,
                self.scope,
                str(self.window["start"]),
                str(self.window["end"]),
                str(screenshot),
            ],
            cwd=ROOT,
            env=dict(
                os.environ,
                ADM_VIEWER_USER=self.username,
                ADM_VIEWER_PASS=self.password,
            ),
            capture_output=True,
            text=True,
            timeout=360,
        )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            self.fail("native ThousandEyes browser returned no sanitized evidence")
        try:
            evidence = json.loads(lines[-1])
        except json.JSONDecodeError:
            self.fail("native ThousandEyes browser returned invalid evidence JSON")
        self.assertEqual(result.returncode, 0, evidence)
        self.assertTrue(evidence.get("ok"), evidence)
        self.assertEqual(evidence.get("mode"), mode, evidence)
        self.assertTrue(evidence.get("noEagerSidecar"), evidence)
        self.assertEqual(evidence.get("pageErrors"), 0, evidence)
        self.assertEqual(evidence.get("unexpectedConsoleErrors"), 0, evidence)
        self.assertEqual(evidence.get("unexpectedHttpErrors"), 0, evidence)
        self.assertEqual(evidence.get("failedRequestCount"), 0, evidence)
        denials = evidence.get("metadataReadDenials")
        self.assertIsInstance(denials, list, evidence)
        self.assertEqual(
            {item.get("name") for item in denials},
            {
                "app_icon",
                "global_web_settings",
                "structured_data_service_limits",
                "legacy_macro_adm_data_contract_version",
                "legacy_macro_adm_health_sources",
                "legacy_macro_adm_find_1",
                "legacy_macro_adm_graph_4",
                "legacy_macro_adm_catalog_build",
                "legacy_macro_adm_health_quality",
            },
            evidence,
        )
        self.assertTrue(
            all(
                item.get("method") == "GET"
                and item.get("status") == 403
                and isinstance(item.get("path"), str)
                and isinstance(item.get("count"), int)
                and isinstance(item.get("consoleErrors"), int)
                for item in denials
            ),
            evidence,
        )
        return evidence

    @staticmethod
    def _build(configuration: dict, selection: dict) -> str:
        output = helper(
            {
                "mode": "build",
                "configuration": configuration,
                "selection": selection,
            }
        )
        search = output.get("search")
        if not isinstance(search, str) or not search:
            raise AssertionError("ThousandEyes helper did not return a search string")
        return search

    @staticmethod
    def _auth(username: str, password: str) -> str:
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {encoded}"

    def _run_as(
        self,
        username: str,
        password: str,
        search: str,
    ) -> dict:
        endpoint = (
            "/servicesNS/"
            + urllib.parse.quote(username, safe="")
            + "/splunk_adm/search/v2/jobs?output_mode=json"
        )
        body = urllib.parse.urlencode(
            {
                "search": search,
                "exec_mode": "normal",
                "earliest_time": "0",
                "latest_time": "+1h",
                "max_time": "30",
                "auto_cancel": "30",
                "auto_pause": "0",
                "status_buckets": "0",
            }
        ).encode()
        status, raw = self.permissions._response(
            "POST", endpoint, username, password, body
        )
        if status not in (200, 201):
            return {"status": status, "rows": [], "errors": [], "warnings": []}
        try:
            sid = json.loads(raw)["sid"]
        except (ValueError, KeyError, TypeError) as error:
            raise AssertionError(
                "Splunk did not acknowledge the caller search"
            ) from error
        deadline = time.monotonic() + 60
        content: dict = {}
        job_acl: dict = {}
        while time.monotonic() < deadline:
            status, status_body = self.permissions._response(
                "GET",
                f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}?output_mode=json",
                username,
                password,
            )
            if status != 200:
                break
            try:
                entry = json.loads(status_body)["entry"][0]
            except (ValueError, KeyError, TypeError):
                break
            content = entry.get("content", {})
            job_acl = entry.get("acl", {})
            if content.get("isDone") in (True, 1, "1"):
                break
            time.sleep(0.5)
        else:
            self.permissions._response(
                "DELETE",
                f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}?output_mode=json",
                username,
                password,
            )
            self.fail("caller-owned ThousandEyes search did not finish")
        result_status, result_body = self.permissions._response(
            "GET",
            f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}/results?count=0&output_mode=json",
            username,
            password,
        )
        result: dict = {}
        if result_status == 200:
            try:
                result = json.loads(result_body)
            except json.JSONDecodeError:
                result = {}
        self.permissions._response(
            "DELETE",
            f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}?output_mode=json",
            username,
            password,
        )
        return {
            "status": status,
            "result_status": result_status,
            "owner": job_acl.get("owner"),
            "content": content,
            "rows": result.get("results", []),
            "errors": _error_messages(content.get("messages"))
            + _error_messages(result.get("messages")),
            "warnings": _warning_messages(content.get("messages"))
            + _warning_messages(result.get("messages")),
        }

    @staticmethod
    def _records(rows: list[dict]) -> list[dict]:
        return [row for row in rows if row.get("kind") == "supplemental_record"]

    @staticmethod
    def _completions(rows: list[dict]) -> list[dict]:
        return [row for row in rows if row.get("kind") == "supplemental_completion"]

    def test_exact_installed_query_normalizes_six_families_and_bgp_context_for_admin(
        self,
    ):
        search = self._build(self.config, self.selection)
        self.assertIn("index=atlas_te", search)
        for sourcetype in SOURCETYPES.values():
            self.assertIn(f'sourcetype="{sourcetype}"', search)
        self.assertNotRegex(search, r"(?i)`|\|\s*(lookup|join|map)\b")
        self.assertNotIn('thousandeyes.account.id="9999"', search)

        admin = self._run_as(
            "admin",
            self.lab.read_secrets()["SPLUNK_PASSWORD"],
            search,
        )
        self.assertEqual(admin["status"], 200)
        self.assertEqual(admin["owner"], "admin")
        self.assertFalse(admin["errors"])
        self.assertFalse(admin["warnings"])
        records = self._records(admin["rows"])
        completions = self._completions(admin["rows"])
        self.assertEqual(len(records), 7)
        self.assertEqual(len(completions), 1)
        completion = completions[0]
        self.assertEqual(int(completion["schema_version"]), 1)
        self.assertEqual(int(completion["input_count"]), 7)
        self.assertEqual(int(completion["returned_count"]), 7)
        self.assertEqual(int(completion["input_capped"]), 0)
        self.assertEqual(int(completion["source_scan_count"]), 7)
        self.assertEqual(int(completion["source_scan_capped"]), 0)
        self.assertTrue(
            all(record.get("index") == INDEX for record in records),
            "the exact query must not return the restricted-index clone",
        )
        normalized = helper(
            {
                "mode": "normalize",
                "configuration": self.config,
                "selection": self.selection,
                "rows": records,
            }
        )
        self.assertEqual(normalized["rejected"], 0)
        self.assertEqual(
            {record["family"] for record in normalized["records"]},
            {"metric", "path", "trace", "event", "alert", "activity"},
        )
        self.assertTrue(
            all(record["index"] == INDEX for record in normalized["records"])
        )
        self.assertTrue(
            all(
                record["authority"] == self.authority
                for record in normalized["records"]
            )
        )
        self.assertTrue(
            all(
                record.get("agentId") in (self.agent_id, None)
                for record in normalized["records"]
            )
        )
        self.assertTrue(
            all(record.get("rowTime") is not None for record in normalized["records"]),
            "Splunk _time must be retained as row time",
        )
        self.assertTrue(
            all(
                record.get("indexedTime") is not None
                for record in normalized["records"]
            ),
            "Splunk _indextime must be retained as indexed receipt time",
        )
        self.assertTrue(
            all(record.get("receiptTime") is None for record in normalized["records"]),
            "unattested Splunk times must not be promoted to producer receipt time",
        )
        bgp = next(
            record
            for record in normalized["records"]
            if record.get("monitorId") == "monitor-4"
        )
        self.assertEqual(bgp["family"], "metric")
        self.assertNotIn("testId", bgp)
        self.assertNotIn("agentId", bgp)
        self.assertEqual(bgp["attribution"]["state"], "context_only")
        self.assertEqual(bgp["attribution"]["bindingIds"], [])

    def test_restricted_viewer_owns_search_and_partial_indexes_do_not_look_complete(
        self,
    ):
        exact = self._build(self.config, self.selection)
        viewer = self._run_as(self.username, self.password, exact)
        self.assertEqual(viewer["status"], 200)
        self.assertEqual(viewer["owner"], self.username)
        self.assertFalse(viewer["errors"])
        self.assertFalse(viewer["warnings"])
        self.assertEqual(len(self._records(viewer["rows"])), 7)
        self.assertEqual(len(self._completions(viewer["rows"])), 1)

        expanded = {**self.config, "indexes": [INDEX, "atlas_asset"]}
        expanded_search = self._build(expanded, self.selection)
        admin = self._run_as(
            "admin",
            self.lab.read_secrets()["SPLUNK_PASSWORD"],
            expanded_search,
        )
        self.assertEqual(admin["status"], 200)
        self.assertFalse(admin["errors"])
        self.assertFalse(admin["warnings"])
        self.assertEqual(len(self._records(admin["rows"])), 8)
        self.assertEqual(int(self._completions(admin["rows"])[0]["input_count"]), 8)

        partial = self._run_as(self.username, self.password, expanded_search)
        no_complete_read = (
            partial["status"] >= 400
            or partial["result_status"] >= 400
            or partial["errors"]
            or partial["warnings"]
            or len(self._completions(partial["rows"])) != 1
            or len(self._records(partial["rows"])) != 8
            or int(self._completions(partial["rows"])[0]["input_count"]) != 8
        )
        self.assertTrue(
            no_complete_read,
            "a viewer missing one configured index must not receive a complete result envelope",
        )

    def test_native_packaged_sidecar_is_lazy_and_reads_as_endpoint_viewer(self):
        from settings_fixture import SettingsFixture

        self._wait_for_kvstore()
        admin_password = self.lab.read_secrets()["SPLUNK_PASSWORD"]
        deployment = SettingsFixture(self)
        deployment.clear()
        revision = self._write_deployment_state(
            deployment, "not_selected", expected_revision=None
        )

        collection = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_observer_scope"
        )
        mapping_key = self.token + "-native-browser"
        mapping = {"_key": mapping_key, **self.mapping}
        status, _ = self.permissions._response(
            "POST",
            collection,
            "admin",
            admin_password,
            json.dumps(mapping).encode(),
            "application/json",
        )
        self.assertIn(status, (200, 201))
        self.addCleanup(self._remove_scope_mapping, mapping_key, admin_password)

        self.addCleanup(self._restore_role_indexes, self.role, [INDEX], admin_password)
        role_path = "/services/authorization/roles/" + urllib.parse.quote(
            self.role, safe=""
        )
        role_body = urllib.parse.urlencode(
            {
                "srchIndexesAllowed": [INDEX, "adm_summary", "adm_summary_v2"],
            },
            doseq=True,
        ).encode()
        status, _ = self.permissions._response(
            "POST", role_path, "admin", admin_password, role_body
        )
        self.assertIn(status, (200, 201))

        self._run_native_browser("not-selected")

        macro_names = (
            "adm_index_thousandeyes",
            "adm_thousandeyes_schema_qualified",
        )
        originals = {
            name: self._macro_content(name)["definition"] for name in macro_names
        }
        self.addCleanup(self._write_and_verify_macro_states, originals)
        self._write_and_verify_macro_states(
            {
                "adm_index_thousandeyes": f"index={INDEX}",
                "adm_thousandeyes_schema_qualified": "1",
            }
        )
        self._write_deployment_state(deployment, "active", revision)

        evidence = self._run_native_browser("active")
        self.assertEqual(evidence.get("activeRows"), 7, evidence)
        self.assertTrue(evidence.get("bgpContextOnly"), evidence)
        self.assertEqual(evidence.get("sourceSearchCount"), 1, evidence)
        self.assertTrue(
            all(asset.get("status") == 200 for asset in evidence["sidecarAssets"]),
            evidence,
        )


if __name__ == "__main__":
    unittest.main()
