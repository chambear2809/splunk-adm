"""Cursor, retention and durable-before-delete maintenance contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from tools import retention_maintenance as rm


class FakeApi:
    def __init__(self, rows=(), native_cap=1000):
        self.rows = {row["_key"]: dict(row) for row in rows}
        self.native_cap = native_cap
        self.calls = []
        self.on_delete = None
        self.on_get = None
        self.active = False
        self.gate = "1"

    def request(self, method, path, data=None, **kwargs):
        self.calls.append((method, path))
        parsed = urlsplit(path)

        def entry(content, **extra):
            return {"entry": [{"content": content, **extra}]}

        if parsed.path == "/services/server/info":
            return entry(
                {
                    "guid": "target-guid",
                    "version": "10.6.0.5",
                    "build": "build",
                    "product_type": "enterprise",
                    "mode": "normal",
                    "isForwarding": False,
                    "server_roles": [
                        "indexer",
                        "license_master",
                        "license_manager",
                        "kv_store",
                    ],
                }
            )
        if parsed.path.endswith("/conf-server/shclustering"):
            return entry({"disabled": True})
        if parsed.path.endswith("/conf-server/clustering"):
            return entry({"mode": "disabled"})
        if parsed.path.endswith("/search/distributed/peers"):
            return {"entry": [], "paging": {"total": 0, "offset": 0}}
        if parsed.path.endswith("/authentication/current-context"):
            return entry({"roles": ["admin"], "capabilities": ["admin_all_objects"]})
        if parsed.path.endswith("/conf-macros/adm_identity_retention"):
            return entry({"definition": "5"})
        if parsed.path.endswith("/conf-macros/adm_prune_maintenance"):
            return entry({"definition": self.gate})
        if "/storage/collections/config/" in parsed.path:
            return entry({}, acl={"can_write": True, "perms": {"write": ["admin"]}})
        if parsed.path.endswith("/saved/searches"):
            rows = [
                {"name": name, "content": {"disabled": True, "is_scheduled": False}}
                for name in (
                    "ADM - Identity builder",
                    "ADM - Service binding",
                    "ADM - Conversation rollup",
                )
            ]
            return {"entry": rows, "paging": {"total": len(rows), "offset": 0}}
        if parsed.path.endswith("/search/v2/jobs"):
            rows = (
                [{"content": {"isDone": False, "dispatchState": "RUNNING"}}]
                if self.active
                else []
            )
            return {"entry": rows, "paging": {"total": len(rows), "offset": 0}}
        if "/storage/collections/data/" in parsed.path:
            if parsed.query:
                query = parse_qs(parsed.query)
                self.assert_query(query)
                last = json.loads(query["query"][0]).get("_key", {}).get("$gt")
                rows = [
                    row
                    for key, row in sorted(self.rows.items())
                    if last is None or key > last
                ]
                return rows[: min(self.native_cap, int(query["limit"][0]))]
            key = unquote(parsed.path.rsplit("/", 1)[1])
            if method == "GET":
                return self.on_get(key) if self.on_get else dict(self.rows[key])
            if method == "DELETE":
                if self.on_delete:
                    self.on_delete(key)
                self.rows.pop(key)
                return {}
        raise AssertionError((method, path))

    @staticmethod
    def assert_query(query):
        assert query["sort"] == ["_key:1"]
        assert "count" not in query


class RetentionMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve() / "backup"

    def tool(self, api, **kwargs):
        return rm.RetentionMaintenance(api, now=lambda: 10, **kwargs)

    def test_listing_reduces_count_at_same_offset_after_oversized_response(self):
        class ListingApi:
            def __init__(self):
                self.calls = []

            def request(self, method, path, **kwargs):
                query = parse_qs(urlsplit(path).query)
                count, offset = int(query["count"][0]), int(query["offset"][0])
                self.calls.append((count, offset, kwargs["max_response_bytes"]))
                if count == 1000:
                    raise rm.ResponseTooLarge("oversized")
                page = [
                    {"name": str(index)}
                    for index in range(offset, min(offset + count, 3))
                ]
                return {"entry": page, "paging": {"total": 3, "offset": offset}}

        api = ListingApi()
        self.assertEqual(
            self.tool(api).listing("/services/saved/searches"),
            [
                {"name": "0"},
                {"name": "1"},
                {"name": "2"},
            ],
        )
        self.assertEqual(
            [(count, offset) for count, offset, _ in api.calls],
            [(1000, 0), (500, 0)],
        )
        self.assertTrue(all(cap == 16 * 1024 * 1024 for _, _, cap in api.calls))

    def test_listing_reduces_count_on_a_later_page_and_retains_it(self):
        class ListingApi:
            def __init__(self):
                self.calls = []

            def request(self, method, path, **kwargs):
                query = parse_qs(urlsplit(path).query)
                count, offset = int(query["count"][0]), int(query["offset"][0])
                self.calls.append((count, offset))
                if offset == 1 and count == 1000:
                    raise rm.ResponseTooLarge("oversized")
                page = [
                    {"name": str(index)} for index in range(offset, min(offset + 1, 3))
                ]
                return {"entry": page, "paging": {"total": 3, "offset": offset}}

        api = ListingApi()
        self.assertEqual(len(self.tool(api).listing("/services/saved/searches")), 3)
        self.assertEqual(api.calls, [(1000, 0), (1000, 1), (500, 1), (500, 2)])

    def test_listing_propagates_irreducible_response_too_large(self):
        class ListingApi:
            def __init__(self):
                self.counts = []

            def request(self, method, path, **kwargs):
                count = int(parse_qs(urlsplit(path).query)["count"][0])
                self.counts.append(count)
                raise rm.ResponseTooLarge("oversized")

        api = ListingApi()
        with self.assertRaises(rm.ResponseTooLarge):
            self.tool(api).listing("/services/saved/searches")
        self.assertEqual(api.counts, [1000, 500, 250, 125, 62, 31, 15, 7, 3, 1])

    def test_listing_propagates_unrelated_value_error(self):
        class ListingApi:
            def request(self, method, path, **kwargs):
                raise ValueError("unrelated")

        with self.assertRaisesRegex(ValueError, "unrelated"):
            self.tool(ListingApi()).listing("/services/saved/searches")

    def test_listing_enforces_aggregate_inventory_byte_budget(self):
        class ListingApi:
            calls = 0

            def request(self, method, path, **kwargs):
                self.calls += 1
                offset = int(parse_qs(urlsplit(path).query)["offset"][0])
                return {
                    "entry": [{"name": "entry"}],
                    "paging": {"total": 3, "offset": offset},
                }

        api = ListingApi()
        budget = 2 * (len(rm.canonical({"name": "entry"})) + 1)
        with self.assertRaisesRegex(rm.MaintenanceError, "inventory_incomplete"):
            self.tool(api, max_bytes=budget).listing("/services/saved/searches")
        self.assertEqual(api.calls, 3)

    def test_lower_native_query_cap_does_not_turn_short_page_into_completion(self):
        api = FakeApi(
            [{"_key": str(i), "valid_end": 1} for i in range(7)], native_cap=2
        )
        report = self.tool(api).status("adm_ip_identity")
        self.assertTrue(report["complete"])
        self.assertEqual(report["rows_read"], 7)
        self.assertEqual(report["rows_expired"], 7)
        self.assertEqual(len([path for _, path in api.calls if "?limit=" in path]), 5)

    def test_cursor_scans_beyond_original_reader_cliff_without_quadratic_fixture(self):
        class Generated(FakeApi):
            def request(self, method, path, **kwargs):
                if "/storage/collections/data/" not in path:
                    return super().request(method, path, **kwargs)
                query = parse_qs(urlsplit(path).query)
                last = json.loads(query["query"][0]).get("_key", {}).get("$gt")
                start = int(last) + 1 if last is not None else 0
                end = min(start + int(query["limit"][0]), rm.CLIFF + 1)
                return [{"_key": f"{i:08d}", "valid_end": 1} for i in range(start, end)]

        report = self.tool(Generated()).status("adm_ip_identity")
        self.assertTrue(report["complete"])
        self.assertEqual(report["rows_read"], rm.CLIFF + 1)
        self.assertIn("spl_reader_capacity", report["warnings"])

    def test_exact_row_bound_needs_empty_sentinel_and_overflow_is_incomplete(self):
        rows = [{"_key": str(i), "valid_end": 1} for i in range(3)]
        self.assertTrue(
            self.tool(FakeApi(rows), max_rows=3).status("adm_ip_identity")["complete"]
        )
        report = self.tool(FakeApi(rows), max_rows=2).status("adm_ip_identity")
        self.assertFalse(report["complete"])
        self.assertEqual(report["rows_read"], 2)

    def test_all_expiry_fields_match_shipped_prune_rules(self):
        expected = {
            "adm_ip_identity": "valid_end",
            "adm_service_workload": "last_seen",
            "adm_service_backends": "valid_to",
            "adm_service_routes": "valid_to",
            "adm_aci_policy": "last_seen",
        }
        for collection, field in expected.items():
            with self.subTest(collection=collection):
                self.assertEqual(
                    rm.RetentionMaintenance.expiry(collection, {field: 1}), 1
                )
                self.assertIsNone(
                    rm.RetentionMaintenance.expiry(collection, {field: None})
                )
                for invalid in ("NaN", "Infinity", -1, True, ""):
                    self.assertIsNone(
                        rm.RetentionMaintenance.expiry(collection, {field: invalid})
                    )
        self.assertIsNone(
            rm.RetentionMaintenance.expiry(
                "adm_network_client_history", {"received_time": 1}
            )
        )
        self.assertEqual(
            rm.RetentionMaintenance.expiry(
                "adm_network_client_history",
                {"received_time": 1, "latest_received_time": 3},
            ),
            3,
        )

    def test_complete_private_backup_and_pending_journal_precede_delete(self):
        api = FakeApi(
            [{"_key": "expired", "valid_end": 1}, {"_key": "open", "valid_end": None}]
        )

        def before_delete(key):
            journal = json.loads((self.directory / "manifest.json").read_text())
            backup = self.directory / journal["backup"]
            self.assertEqual(journal["pending_key"], key)
            self.assertEqual(journal["snapshot"]["rows_read"], 2)
            self.assertEqual(
                hashlib.sha256(backup.read_bytes()).hexdigest(),
                journal["backup_sha256"],
            )
            self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (self.directory / "manifest.json").stat().st_mode & 0o777, 0o600
            )

        api.on_delete = before_delete
        result = self.tool(api).prune(
            "adm_ip_identity", backup_dir=self.directory, confirm=True
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["rows_deleted"], 1)
        self.assertEqual(set(api.rows), {"open"})

    def test_lost_delete_response_stops_uncertain_with_durable_exact_key(self):
        api = FakeApi([{"_key": "a", "valid_end": 1}, {"_key": "b", "valid_end": 1}])

        def lose_response(key):
            api.rows.pop(key)
            raise OSError("sensitive native response")

        api.on_delete = lose_response
        result = self.tool(api).prune(
            "adm_ip_identity", backup_dir=self.directory, confirm=True
        )
        self.assertEqual(result["status"], "uncertain")
        journal = json.loads((self.directory / "manifest.json").read_text())
        self.assertEqual(journal["pending_key"], "a")
        self.assertEqual(set(api.rows), {"b"})
        self.assertNotIn("sensitive", json.dumps(result))
        self.assertNotIn("pending_key", result)

    def test_incomplete_snapshot_active_jobs_and_row_drift_never_delete(self):
        for scenario in ("overflow", "active", "drift"):
            with self.subTest(scenario=scenario):
                api = FakeApi(
                    [{"_key": "a", "valid_end": 1}, {"_key": "b", "valid_end": 1}]
                )
                api.active = scenario == "active"
                if scenario == "drift":
                    api.on_get = lambda key: {"_key": key, "valid_end": None}
                tool = self.tool(
                    api, max_rows=1 if scenario == "overflow" else rm.MAX_ROWS
                )
                directory = self.directory.with_name(scenario)
                if scenario == "active":
                    with self.assertRaises(rm.MaintenanceError):
                        tool.prune(
                            "adm_ip_identity", backup_dir=directory, confirm=True
                        )
                else:
                    self.assertFalse(
                        tool.prune(
                            "adm_ip_identity", backup_dir=directory, confirm=True
                        )["complete"]
                    )
                self.assertFalse(any(method == "DELETE" for method, _ in api.calls))

    def test_confirmation_and_retention_mismatch_refuse_before_delete(self):
        api = FakeApi([])
        with self.assertRaises(rm.MaintenanceError):
            self.tool(api).prune("adm_ip_identity", backup_dir=self.directory)
        self.assertEqual(api.calls, [])
        with self.assertRaises(rm.MaintenanceError):
            self.tool(api).status("adm_ip_identity", retention_seconds=-1)

    def test_bounded_deletion_returns_known_partial_outcome(self):
        api = FakeApi([{"_key": "a", "valid_end": 1}, {"_key": "b", "valid_end": 1}])
        result = self.tool(api, max_deletes=1).prune(
            "adm_ip_identity", backup_dir=self.directory, confirm=True
        )
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["complete"])
        self.assertEqual(result["rows_deleted"], 1)
        self.assertIsNone(
            json.loads((self.directory / "manifest.json").read_text())["pending_key"]
        )


if __name__ == "__main__":
    unittest.main()
