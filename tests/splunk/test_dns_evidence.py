"""Execute the frontend's exact bounded DNS and endpoint SPL in the lab."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import unittest
import urllib.parse
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools" / "dns_qualification_queries.mjs"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class DnsEvidenceRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.token = "dnsqual-" + uuid.uuid4().hex[:12]
        self.now = int(time.time())
        self.start = self.now - 300
        self.end = self.now + 10
        self.ipv4 = "198.51.100.41"
        self.ipv6 = "2001:db8::41"
        self.fingerprint = "a" * 64

    def build_queries(self, source_counts: list[int]):
        selection = {
            "schemaVersion": 1,
            "workflow": "endpoint",
            "selectionId": self.token,
            "trafficContract": 2,
            "window": {"start": self.start, "end": self.end},
            "scope": self.token,
            "addresses": [self.ipv4],
            "contexts": [],
            "identityBasis": "disposable runtime qualification",
            "configurationFingerprint": self.fingerprint,
        }
        dns = [
            {
                "source": "dns_stream",
                "state": "active",
                "indexes": ["netflow"],
                "authorities": [self.token],
                "schemaQualified": True,
            },
            {
                "source": "dns_hubble",
                "state": "active",
                "indexes": ["cilium_hubble"],
                "authorities": [self.token],
                "schemaQualified": True,
            },
        ]
        endpoint = []
        for contract in (1, 2):
            endpoint_selection = {
                "schemaVersion": 1,
                "id": self.token,
                "address": self.ipv4,
                "scope": self.token,
                "start": self.start,
                "end": self.end,
                "configurationFingerprint": self.fingerprint,
                "trafficContract": contract,
            }
            endpoint.append(
                {"selection": endpoint_selection, "indexes": ["adm_summary"]}
            )
        payload = {
            "selection": selection,
            "dns": dns,
            "endpoint": endpoint,
            "sourceCounts": source_counts,
        }
        completed = subprocess.run(
            ["node", str(HELPER)],
            cwd=ROOT,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        searches = json.loads(completed.stdout)
        for item in searches["dns"]:
            self.assertNotRegex(item["search"], r"(?i)`|\|\s*(lookup|join|map)\b")
        return selection, searches

    def load_rows(self, rows: list[dict]) -> None:
        if not rows:
            return
        # HEC batches stay comfortably below the configured lab request limit.
        batch: list[bytes] = []
        size = 0
        for row in rows:
            encoded = json.dumps(row, separators=(",", ":")).encode()
            if batch and size + len(encoded) > 3_500_000:
                lab._hec_post(b"\n".join(batch))
                batch, size = [], 0
            batch.append(encoded)
            size += len(encoded) + 1
        if batch:
            lab._hec_post(b"\n".join(batch))

    def _wait_for_count(self, search: str, expected: int) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            rows, _ = self._run(
                search if search.startswith("search ") else f"search {search}"
            )
            if rows and int(rows[0].get("count", -1)) == expected:
                return
            time.sleep(0.5)
        self.fail("synthetic lab events did not reach the expected indexed count")

    def _run(self, search: str, *, timeout: int = 60) -> tuple[list[dict], dict]:
        with lab._mgmt(
            "POST",
            f"/servicesNS/admin/{lab.APP}/search/v2/jobs?output_mode=json",
            {
                "search": search,
                "exec_mode": "normal",
                "earliest_time": str(self.start),
                "latest_time": str(self.end),
                "max_time": "30",
                "auto_cancel": "30",
                "auto_pause": "0",
                "status_buckets": "0",
            },
            35,
        ) as response:
            sid = json.loads(response.read())["sid"]
        deadline = time.monotonic() + timeout
        content = {}
        while time.monotonic() < deadline:
            entry = lab._json("GET", f"/services/search/v2/jobs/{sid}")["entry"][0]
            content = entry["content"]
            if content.get("dispatchState") == "FAILED":
                self.fail("native Splunk search job failed before completion")
            if content.get("isDone"):
                break
            time.sleep(0.5)
        else:
            with lab._mgmt(
                "POST", f"/services/search/v2/jobs/{sid}/control", {"action": "cancel"}
            ):
                pass
            self.fail(
                "native Splunk search exceeded qualification timeout and was cancelled"
            )
        messages = content.get("messages", [])
        errors = [
            m for m in messages if m.get("type", "").upper() in {"ERROR", "FATAL"}
        ]
        self.assertFalse(errors, "native Splunk job returned an error message")
        self.assertFalse(
            content.get("isFinalized"), "native Splunk job finalized before completion"
        )
        self.assertFalse(
            content.get("resultIsTruncated"), "native Splunk results were truncated"
        )
        result = lab._json("GET", f"/services/search/v2/jobs/{sid}/results?count=0")
        result_errors = [
            m
            for m in result.get("messages", [])
            if m.get("type", "").upper() in {"ERROR", "FATAL"}
        ]
        self.assertFalse(
            result_errors, "native Splunk results endpoint returned an error"
        )
        return result.get("results", []), content

    def _assert_dns_envelope(self, query: str, expected_input: int):
        rows, content = self._run(query)
        meta = [row for row in rows if row.get("kind") == "dns_completion"]
        records = [row for row in rows if row.get("kind") == "dns_record"]
        self.assertEqual(
            len(meta),
            1,
            "DNS query must return exactly one completion row, including for zero matches",
        )
        self.assertEqual(len(rows), len(records) + 1)
        self.assertEqual(int(meta[0]["input_count"]), expected_input)
        self.assertEqual(int(meta[0]["returned_count"]), min(expected_input, 64))
        self.assertEqual(int(meta[0]["input_capped"]), int(expected_input > 10000))
        self.assertEqual(len(records), min(expected_input, 64))
        self.assertTrue(content.get("isDone"))

    def _make_viewer(
        self, allowed_indexes: list[str], extra_capabilities: tuple[str, ...] = ()
    ) -> tuple[str, str, str]:
        import test_permissions as permission_helpers

        admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]
        role = "dns_qual_role_" + secrets.token_hex(6)
        username = "dns_qual_user_" + secrets.token_hex(6)
        password = secrets.token_urlsafe(24)
        role_data = urllib.parse.urlencode(
            {
                "name": role,
                "capabilities": "search",
                "srchIndexesAllowed": allowed_indexes,
                "srchIndexesDisallowed": ["_internal", "_audit"],
            },
            doseq=True,
        ).encode()
        capabilities = ["search", *extra_capabilities]
        status, _ = permission_helpers._response(
            "POST", "/services/authorization/roles", "admin", admin_password, role_data
        )
        self.assertIn(
            status, (200, 201), f"ephemeral role creation failed: HTTP {status}"
        )
        self.addCleanup(self._delete_ephemeral, "role", role, admin_password)
        status, _ = permission_helpers._response(
            "POST",
            f"/services/authorization/roles/{urllib.parse.quote(role, safe='')}",
            "admin",
            admin_password,
            urllib.parse.urlencode({"capabilities": capabilities}, doseq=True).encode(),
        )
        self.assertIn(
            status, (200, 201), f"ephemeral role scoping failed: HTTP {status}"
        )
        role_info = lab._json(
            "GET",
            f"/services/authorization/roles/{urllib.parse.quote(role, safe='')}",
        )["entry"][0]["content"]
        observed_capabilities = role_info.get("capabilities", [])
        if isinstance(observed_capabilities, str):
            observed_capabilities = observed_capabilities.split(",")
        self.assertEqual(set(observed_capabilities), set(capabilities))
        user_data = urllib.parse.urlencode(
            {"name": username, "password": password, "roles": role}
        ).encode()
        status, _ = permission_helpers._response(
            "POST", "/services/authentication/users", "admin", admin_password, user_data
        )
        self.assertIn(
            status, (200, 201), f"ephemeral viewer creation failed: HTTP {status}"
        )
        self.addCleanup(self._delete_ephemeral, "user", username, admin_password)
        return username, password, role

    @staticmethod
    def _delete_ephemeral(kind: str, name: str, admin_password: str) -> None:
        import test_permissions as permission_helpers

        if kind == "user":
            path = "/services/authentication/users/" + urllib.parse.quote(name, safe="")
        else:
            path = "/services/authorization/roles/" + urllib.parse.quote(name, safe="")
        status, _ = permission_helpers._response(
            "DELETE", path, "admin", admin_password
        )
        if status not in (200, 204, 404):
            raise AssertionError(f"ephemeral {kind} cleanup failed: HTTP {status}")

    def _viewer_search(
        self, username: str, password: str, search: str
    ) -> tuple[int, list[dict], list[dict]]:
        import test_permissions as permission_helpers

        path = (
            f"/servicesNS/{urllib.parse.quote(username, safe='')}/{lab.APP}"
            "/search/v2/jobs?output_mode=json"
        )
        params = urllib.parse.urlencode(
            {
                "search": search,
                "exec_mode": "normal",
                "earliest_time": str(self.start),
                "latest_time": str(self.end),
                "max_time": "30",
                "auto_cancel": "30",
                "auto_pause": "0",
                "status_buckets": "0",
            }
        ).encode()
        status, body = permission_helpers._response(
            "POST", path, username, password, params
        )
        if status not in (200, 201):
            return (
                status,
                [],
                [{"type": "HTTP", "text": body.decode("utf-8", "replace")[:500]}],
            )
        sid = json.loads(body)["sid"]
        self.addCleanup(self._delete_viewer_job, username, password, sid)
        deadline = time.monotonic() + 60
        content = {}
        while time.monotonic() < deadline:
            status, job = permission_helpers._response(
                "GET",
                f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}?output_mode=json",
                username,
                password,
            )
            if status != 200:
                self.fail(f"viewer job status failed: HTTP {status}")
            content = json.loads(job)["entry"][0]["content"]
            if content.get("isDone"):
                break
            time.sleep(0.25)
        else:
            permission_helpers._response(
                "POST",
                f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}/control",
                username,
                password,
                urllib.parse.urlencode({"action": "cancel"}).encode(),
            )
            self.fail("viewer search failed to reach terminal status within 60 seconds")
        result_status, result = permission_helpers._response(
            "GET",
            f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}/results?count=0&output_mode=json",
            username,
            password,
        )
        if result_status != 200:
            return result_status, [], content.get("messages", [])
        result_data = json.loads(result)
        results = result_data.get("results", [])
        messages = content.get("messages", []) + result_data.get("messages", [])
        permission_helpers._response(
            "DELETE",
            f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}?output_mode=json",
            username,
            password,
        )
        return 200, results, messages

    @staticmethod
    def _delete_viewer_job(username: str, password: str, sid: str) -> None:
        import test_permissions as permission_helpers

        status, _ = permission_helpers._response(
            "DELETE",
            f"/services/search/v2/jobs/{urllib.parse.quote(sid, safe='')}?output_mode=json",
            username,
            password,
        )
        if status not in (200, 204, 404):
            raise AssertionError(f"viewer search job cleanup failed: HTTP {status}")

    def _private_config(
        self, username: str, config: str, name: str, data: dict
    ) -> tuple[int, dict]:
        import test_permissions as permission_helpers

        path = (
            f"/servicesNS/{urllib.parse.quote(username, safe='')}/{lab.APP}"
            f"/admin/{config}/{urllib.parse.quote(name, safe='')}"
        )
        admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]
        status, body = permission_helpers._response(
            "POST", path, "admin", admin_password, urllib.parse.urlencode(data).encode()
        )
        return status, json.loads(body) if body.startswith(b"{") else {}

    def test_viewer_literal_dns_search_ignores_private_macro_shadow(self):
        import test_permissions as permission_helpers

        username, password, _ = self._make_viewer(
            ["netflow", "adm_summary"],
            extra_capabilities=("list_conf_objects",),
        )
        shared_path = (
            "/servicesNS/nobody/splunk_adm/configs/v1/conftypes/macros/"
            "stanzas:get?output_mode=json&view=app-merged"
        )
        status, shared_body = permission_helpers._response(
            "POST",
            shared_path,
            username,
            password,
            json.dumps({"stanza": "adm_index_dns_stream"}).encode(),
            "application/json",
        )
        self.assertEqual(status, 200)
        shared = json.loads(shared_body)
        shared_settings = {
            item["setting"]: item["value"] for item in shared["settings"]
        }
        shared_definition = shared_settings["definition"]
        self.assertEqual(shared_definition, "index=unconfigured_dns")

        status, _ = self._private_config(
            username,
            "macros",
            "adm_index_dns_stream",
            {"definition": "index=private_dns_shadow", "iseval": "0"},
        )
        self.assertIn(
            status, (200, 201), f"private macro fixture setup failed: HTTP {status}"
        )
        status, private_body = permission_helpers._response(
            "GET",
            f"/servicesNS/{urllib.parse.quote(username, safe='')}/splunk_adm/configs/conf-macros/adm_index_dns_stream?output_mode=json",
            "admin",
            lab.read_secrets()["SPLUNK_PASSWORD"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(private_body)["entry"][0]["content"]["definition"],
            "index=private_dns_shadow",
        )
        private_macro = json.loads(private_body)["entry"][0]
        self.assertEqual(private_macro["acl"]["sharing"], "user")
        status, shared_after = permission_helpers._response(
            "POST",
            shared_path,
            username,
            password,
            json.dumps({"stanza": "adm_index_dns_stream"}).encode(),
            "application/json",
        )
        self.assertEqual(status, 200)
        after = json.loads(shared_after)
        self.assertEqual(
            {item["setting"]: item["value"] for item in after["settings"]}[
                "definition"
            ],
            shared_definition,
        )

        _, searches = self.build_queries([])
        literal_stream = next(
            item["search"] for item in searches["dns"] if item["source"] == "dns_stream"
        )
        self.assertNotRegex(literal_stream, r"(?i)`|\|\s*(lookup|join|map)\b")
        self.assertNotIn("adm_index_dns_stream", literal_stream)
        status, rows, messages = self._viewer_search(username, password, literal_stream)
        self.assertEqual(status, 200)
        self.assertFalse(
            [m for m in messages if m.get("type", "").upper() in {"ERROR", "FATAL"}]
        )
        completions = [row for row in rows if row.get("kind") == "dns_completion"]
        self.assertEqual(len(completions), 1)
        self.assertEqual(int(completions[0]["input_count"]), 0)

    def test_summary_only_viewer_endpoint_access_does_not_grant_dns_access(self):
        username, password, role = self._make_viewer(["adm_summary"])
        import test_permissions as permission_helpers

        role_info = lab._json(
            "GET",
            f"/services/authorization/roles/{urllib.parse.quote(role, safe='')}",
        )["entry"][0]["content"]
        self.assertEqual(set(role_info.get("srchIndexesAllowed", [])), {"adm_summary"})
        self.assertNotIn("netflow", role_info.get("srchIndexesAllowed", []))
        config_status, config_body = permission_helpers._response(
            "POST",
            "/servicesNS/nobody/splunk_adm/configs/v1/conftypes/macros/stanzas:get?output_mode=json&view=app-merged",
            username,
            password,
            json.dumps({"stanza": "adm_index_dns_stream"}).encode(),
            "application/json",
        )
        self.assertEqual(
            config_status,
            403,
            "search-only viewer must not read shared config without REST read capability: "
            + config_body.decode("utf-8", "replace")[:250],
        )
        _, searches = self.build_queries([])
        endpoint_query = next(
            item["conversation"]
            for item in searches["endpoint"]
            if item["contract"] == 1
        )
        status, rows, messages = self._viewer_search(username, password, endpoint_query)
        self.assertEqual(status, 200)
        self.assertFalse(
            [m for m in messages if m.get("type", "").upper() in {"ERROR", "FATAL"}]
        )
        self.assertEqual([row.get("row_type") for row in rows], ["completion"])

        dns_query = next(
            item["search"] for item in searches["dns"] if item["source"] == "dns_stream"
        )
        status, rows, messages = self._viewer_search(username, password, dns_query)
        if status != 200:
            self.assertIn(status, (400, 401, 403))
            return
        self.assertFalse(
            [row for row in rows if row.get("kind") == "dns_record"],
            "restricted viewer received DNS rows",
        )
        completion = [row for row in rows if row.get("kind") == "dns_completion"]
        if completion:
            self.assertEqual(int(completion[0]["input_count"]), 0)
        # Splunk may silently return zero for a forbidden index. This test
        # therefore treats result absence as no data, never as entitlement.

    def test_dns_stream_count_envelopes_and_hubble_ipv6(self):
        # Exercise all public envelope boundaries against real indexed events.
        counts = [0, 64, 65, 10001]
        stream_rows = []
        for count in counts:
            authority = f"{self.token}-{count}"
            for n in range(count):
                stream_rows.append(
                    {
                        "time": self.now,
                        "index": "netflow",
                        "sourcetype": "stream:dns",
                        "host": authority,
                        "source": self.token,
                        "event": {
                            "src_ip": self.ipv4,
                            "dest_ip": "192.0.2.53",
                            "query": f"host-{n}.example.test",
                            "message_type": "RESPONSE",
                            "query_type": "A",
                            "reply_code": 0,
                            "host_addr": ["203.0.113.8"],
                            "ttl": [60],
                            "txt_payload": "synthetic-private-text-must-not-be-collected",
                        },
                    }
                )
        hubble_node = f"{self.token}/node-a"
        stream_rows.append(
            {
                "time": self.now,
                "index": "cilium_hubble",
                "sourcetype": "cilium:hubble:flow",
                "host": self.token,
                "source": self.token,
                "event": {
                    "node_name": hubble_node,
                    "flow": {
                        "time": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now)
                        ),
                        "uuid": self.token,
                        "node_name": hubble_node,
                        "IP": {
                            "source": "2001:0db8:0:0:0:0:0:41",
                            "destination": "2001:db8::53",
                        },
                        "l7": {
                            "type": "RESPONSE",
                            "dns": {
                                "query": "v6.example.test",
                                "qtypes": ["AAAA"],
                                "rcode": 0,
                                "ips": ["2001:db8::99"],
                                "ttl": 60,
                            },
                        },
                    },
                },
            }
        )
        self.load_rows(stream_rows)
        selection, searches = self.build_queries(counts)
        stream_template = next(
            item["search"] for item in searches["dns"] if item["source"] == "dns_stream"
        )
        for count in counts:
            query = stream_template.replace(
                f'host IN ("{self.token}")', f'host IN ("{self.token}-{count}")'
            )
            self._assert_dns_envelope(query, count)
            if count == 64:
                rows, _ = self._run(query)
                records = [row for row in rows if row.get("kind") == "dns_record"]
                for record in records:
                    projected = record["_raw"]
                    if isinstance(projected, str):
                        projected = json.loads(projected)
                    self.assertIn("query", projected)
                    self.assertEqual(projected["host_addr"], ["203.0.113.8"])
                    self.assertNotIn("txt_payload", projected)
        hubble_template = next(
            item["search"] for item in searches["dns"] if item["source"] == "dns_hubble"
        )
        hubble_query = hubble_template.replace(f'"{self.token}/*"', f'"{self.token}/*"')
        hubble_query = hubble_query.replace(f'"{self.ipv4}/32"', '"2001:db8::41/128"')
        rows, _ = self._run(hubble_query)
        records = [row for row in rows if row.get("kind") == "dns_record"]
        self.assertEqual(
            len(records),
            1,
            "equivalent expanded IPv6 source must match the selected canonical address",
        )
        projected = records[0]["_raw"]
        if isinstance(projected, str):
            projected = json.loads(projected)
        self.assertEqual(projected["flow"]["IP"]["source"], "2001:0db8:0:0:0:0:0:41")
        self.assertIn("dns", projected["flow"]["l7"])

    def test_endpoint_v1_v2_completion_and_v2_observation(self):
        events = [
            {
                "time": self.now,
                "index": "adm_summary",
                "sourcetype": "adm:summary",
                "source": "adm:conversation",
                "host": self.token,
                "event": {
                    "adm_record": "conversation",
                    "scope": self.token,
                    "client_ip": self.ipv4,
                    "server_ip": "203.0.113.20",
                    "server_port": 443,
                    "transport": "tcp",
                    "rollup_id": self.token,
                    "first_seen": self.now - 1,
                    "last_seen": self.now,
                    "records": 2,
                    "conns": 1,
                    "sampled": 0,
                    "conns_capped": 0,
                    "direction_basis": "observed",
                    "flow_source": "netflow",
                    "observer": "sensor-a",
                    "bytes_c2s": 100,
                    "bytes_s2c": 200,
                    "packets": 2,
                },
            },
            {
                "time": self.now,
                "index": "adm_summary",
                "sourcetype": "adm:summary",
                "source": "adm:conversation",
                "host": self.token,
                "event": {
                    "adm_record": "conversation",
                    "contract_version": 2,
                    "scope": self.token,
                    "scope_mapping_verified": 1,
                    "client_ip": self.ipv4,
                    "server_ip": "203.0.113.21",
                    "server_port": 443,
                    "transport": "tcp",
                    "rollup_id": self.token + "-v2",
                    "first_seen": self.now - 1,
                    "last_seen": self.now,
                    "records": 1,
                    "conns": f"50000@{self.now - 1}@{self.now}",
                    "sampled": 0,
                    "conns_capped": 0,
                    "direction_basis": "observed",
                    "flow_source": "netflow",
                    "observer": "sensor-a",
                    "bytes_c2s": 100,
                    "bytes_s2c": 200,
                    "packets": 2,
                },
            },
            {
                "time": self.now,
                "index": "adm_summary",
                "sourcetype": "adm:summary",
                "source": "adm:traffic_observation",
                "host": self.token,
                "event": {
                    "adm_record": "traffic_observation",
                    "contract_version": 2,
                    "rollup_id": self.token + "-obs",
                    "scope": self.token,
                    "adm_profile_status": "mapped",
                    "adm_quality_status": "accepted",
                    "source_ip": self.ipv4,
                    "destination_ip": "203.0.113.22",
                    "source_port": 51000,
                    "destination_port": 53,
                    "transport": "udp",
                    "first_seen": self.now - 1,
                    "last_seen": self.now,
                    "records": 1,
                    "counter_semantics": "per_record",
                    "metrics_authoritative": 0,
                    "adm_scope_source": "hubble",
                    "adm_scope_authority": "sensor-a",
                },
            },
        ]
        # The source builder retains excluded rows for diagnostics. Endpoint
        # evidence must apply the public reader's quality gate before counts.
        observation = events[-1]
        for status in ("excluded", "unknown", None):
            event = {
                **observation["event"],
                "rollup_id": self.token + "-obs-" + str(status),
            }
            if status is None:
                event.pop("adm_quality_status")
            else:
                event["adm_quality_status"] = status
            events.append({**observation, "event": event})
        self.load_rows(events)
        self._wait_for_count(
            f'index=adm_summary host="{self.token}" source="adm:conversation" | stats count',
            2,
        )
        self._wait_for_count(
            f'index=adm_summary host="{self.token}" source="adm:traffic_observation" | stats count',
            4,
        )
        _, searches = self.build_queries([])
        for built in searches["endpoint"]:
            rows, content = self._run(built["conversation"])
            completion = [row for row in rows if row.get("row_type") == "completion"]
            conversations = [
                row for row in rows if row.get("row_type") == "conversation"
            ]
            self.assertEqual(len(completion), 1)
            self.assertEqual(int(completion[0]["input_count"]), 1)
            self.assertEqual(len(conversations), 1)
            self.assertTrue(content.get("isDone"))
            if built["contract"] == 2:
                rows, _ = self._run(built["observation"])
                completion = [
                    row for row in rows if row.get("row_type") == "completion"
                ]
                observations = [
                    row for row in rows if row.get("row_type") == "traffic_observation"
                ]
                self.assertEqual(len(completion), 1)
                self.assertEqual(int(completion[0]["input_count"]), 1)
                self.assertEqual(len(observations), 1)

    def test_native_job_cancellation_reaches_terminal_status(self):
        with lab._mgmt(
            "POST",
            f"/servicesNS/admin/{lab.APP}/search/v2/jobs?output_mode=json",
            {
                "search": "| makeresults count=10000000 | eval qualification_hash=sha256(tostring(random())) | stats count",
                "exec_mode": "normal",
                "max_time": "30",
                "auto_cancel": "30",
                "auto_pause": "0",
                "status_buckets": "0",
            },
            60,
        ) as response:
            sid = json.loads(response.read())["sid"]
        with lab._mgmt(
            "POST", f"/services/search/v2/jobs/{sid}/control", {"action": "cancel"}
        ):
            pass
        deadline = time.monotonic() + 30
        content = {}
        removed = False
        while time.monotonic() < deadline:
            try:
                content = lab._json("GET", f"/services/search/v2/jobs/{sid}")["entry"][
                    0
                ]["content"]
            except lab.LabError as error:
                message = str(error)
                if (
                    "HTTP 404" in message or "HTTP 410" in message
                ) and "unknown sid" in message.lower():
                    removed = True
                    break
                raise
            if content.get("isDone"):
                break
            time.sleep(0.25)
        self.assertTrue(
            removed or content.get("isDone"),
            "cancelled native job did not reach terminal status or cleanup",
        )
        if not removed:
            self.assertTrue(
                content.get("isFinalized")
                or content.get("dispatchState") in {"FAILED", "DONE", "CANCELED"},
                "terminal cancelled job status was not reported by Splunk",
            )
