"""Lab-gated contract tests for the application catalog and exact Find.

The expected scope and pod facts in this file come from the raw scenario and
the hand-reviewed graph expectation.  No expected value is obtained by
running the catalog macro itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import unittest
import urllib.parse

from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / "expected" / "graph.json").read_text())
CATALOG_WINDOW = (EXPECTED["window"]["latest"] - 3600, EXPECTED["window"]["latest"])
APP = "splunk_adm"


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class CatalogTest(unittest.TestCase):
    """Read-only catalog checks plus one bounded writer-safety regression."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(HERE))
        import lab
        from test_permissions import RestrictedViewerTest

        cls.lab = lab
        cls.RestrictedViewerTest = RestrictedViewerTest
        # This established fixture owns lab reset, indexing, and the ephemeral
        # restricted account.  The suite runner supplies the cooperative lock.
        RestrictedViewerTest.setUpClass()
        cls.addClassCleanup(RestrictedViewerTest.doClassCleanups)
        cls.catalog = lab.search("| `adm_catalog_build`", *CATALOG_WINDOW)
        cls.catalog_again = lab.search("| `adm_catalog_build`", *CATALOG_WINDOW)

    @staticmethod
    def _key(service: str, environment: str, cluster: str, namespace: str) -> str:
        raw = json.dumps(
            [service, environment, cluster, namespace], separators=(",", ":")
        ).encode()
        return hashlib.sha256(raw).hexdigest()

    def test_catalog_schema_keys_and_temporal_pods(self):
        fields = {
            "_key",
            "service",
            "environment",
            "cluster",
            "namespace",
            "pods",
            "first_seen",
            "last_seen",
            "peers",
            "conversations_1h",
            "blocked_1h",
            "unknown_peers_1h",
            "updated",
            "window_start",
            "window_end",
        }
        self.assertTrue(self.catalog)
        keys = set()
        for row in self.catalog:
            self.assertTrue(fields >= set(row))
            scope = tuple(
                row.get(name, "")
                for name in ("service", "environment", "cluster", "namespace")
            )
            self.assertEqual(row["_key"], self._key(*scope))
            self.assertNotIn(row["_key"], keys)
            keys.add(row["_key"])
            self.assertEqual(int(row["window_start"]), CATALOG_WINDOW[0])
            self.assertEqual(int(row["window_end"]), CATALOG_WINDOW[1])
            self.assertGreaterEqual(int(row["pods"]), 1)
            self.assertLessEqual(int(row["conversations_1h"]), len(EXPECTED["edges"]))
        # These are the five application services grounded by scenario.json;
        # infrastructure/external identities must not manufacture catalog rows.
        services = {row["service"] for row in self.catalog}
        self.assertTrue(
            {"frontend", "checkout", "catalog", "payment", "cart"} <= services
        )
        base = ("catalog", "prod", "demo-cluster", "shop")
        for index in range(4):
            variant = list(base)
            variant[index] += "-variant"
            self.assertNotEqual(self._key(*base), self._key(*variant))

    def test_exact_metrics_match_grounded_direct_pod_conversations(self):
        # scenario.json: frontend has ingress + checkout; catalog has checkout
        # seen by four exporters; payment has checkout + its public peer; cart
        # has checkout + the private unknown source. Counts are distinct tuples.
        expected = {
            "frontend": (2, 2, 0, 0),
            "catalog": (1, 1, 0, 0),
            "payment": (2, 2, 0, 0),
            "cart": (2, 2, 0, 1),
        }
        rows = {
            row["service"]: row for row in self.catalog if row["namespace"] == "shop"
        }
        for service, counts in expected.items():
            with self.subTest(service=service):
                actual = tuple(
                    int(rows[service][field])
                    for field in (
                        "conversations_1h",
                        "peers",
                        "blocked_1h",
                        "unknown_peers_1h",
                    )
                )
                self.assertEqual(actual, counts)

    def test_replayed_summary_does_not_inflate_metrics(self):
        from test_data_layer import DataLayerTest

        chosen = self.lab.search(
            'search `adm_index_summary` source="adm:conversation" adm_record="conversation" | `adm_summary_dedup` | head 1 | fields rollup_id',
            *CATALOG_WINDOW,
        )[0]["rollup_id"]
        query = (
            'search `adm_index_summary` source="adm:conversation" rollup_id='
            + json.dumps(chosen)
        )
        before = DataLayerTest.count(query)
        self.lab.search(
            query
            + ' | `adm_summary_dedup` | head 1 | collect index=`adm_summary_index_name` source="adm:conversation"',
            *CATALOG_WINDOW,
        )
        DataLayerTest.wait_for_count(query, before + 1)
        after = self.lab.search("| `adm_catalog_build`", *CATALOG_WINDOW)
        fields = ("pods", "peers", "conversations_1h", "blocked_1h", "unknown_peers_1h")
        baseline = {
            row["_key"]: tuple(row[field] for field in fields) for row in self.catalog
        }
        self.assertEqual(
            {row["_key"]: tuple(row[field] for field in fields) for row in after},
            baseline,
        )

    def test_catalog_is_stable_and_replay_deduplicated(self):
        left = {row["_key"]: row for row in self.catalog}
        right = {row["_key"]: row for row in self.catalog_again}
        self.assertEqual(left.keys(), right.keys())
        for key in left:
            for field in (
                "service",
                "environment",
                "cluster",
                "namespace",
                "pods",
                "peers",
                "conversations_1h",
                "blocked_1h",
                "unknown_peers_1h",
                "window_start",
                "window_end",
            ):
                self.assertEqual(
                    str(left[key].get(field)), str(right[key].get(field)), (key, field)
                )
        self.lab.search(
            "| `adm_catalog_build` | outputlookup append=true key_field=_key adm_app_catalog",
            *CATALOG_WINDOW,
        )
        self.lab.search(
            "| `adm_catalog_build` | outputlookup append=true key_field=_key adm_app_catalog",
            *CATALOG_WINDOW,
        )
        stored = self.lab.search("| inputlookup adm_app_catalog", *CATALOG_WINDOW)
        self.assertEqual({row["_key"] for row in stored}, set(left))
        self.assertEqual(
            sum(int(row["conversations_1h"]) for row in self.catalog),
            sum(int(row["conversations_1h"]) for row in self.catalog_again),
        )

    def test_same_pod_binding_timestamps_stay_with_each_service(self):
        key = "catalog-binding-" + secrets.token_hex(8)
        first, last = CATALOG_WINDOW[0] + 120, CATALOG_WINDOW[0] + 180
        self.addCleanup(self._delete_collection_key, "adm_service_workload", key)
        self.lab.search(
            "| inputlookup adm_service_workload | search service=frontend namespace=shop | head 1 "
            + f'| eval _key={json.dumps(key)}, service="catalog-probe", first_seen={first}, last_seen={last} '
            + "| outputlookup append=true key_field=_key adm_service_workload",
            *CATALOG_WINDOW,
        )
        rows = self.lab.search("| `adm_catalog_build`", *CATALOG_WINDOW)
        probe = next(row for row in rows if row["service"] == "catalog-probe")
        self.assertEqual(
            (int(probe["first_seen"]), int(probe["last_seen"])), (first, last)
        )
        baseline = next(row for row in self.catalog if row["service"] == "frontend")
        frontend = next(row for row in rows if row["service"] == "frontend")
        self.assertEqual(frontend["first_seen"], baseline["first_seen"])
        self.assertEqual(frontend["last_seen"], baseline["last_seen"])
        found = self.lab.search('| `adm_find("10.42.0.10")`', *CATALOG_WINDOW)
        self.assertEqual(
            int(
                next(row for row in found if row["service"] == "catalog-probe")[
                    "last_seen"
                ]
            ),
            last,
        )

    def _delete_collection_key(self, collection: str, key: str) -> None:
        with self.lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{APP}/storage/collections/data/{collection}/{urllib.parse.quote(key, safe='')}",
        ) as response:
            response.read()

    def test_find_exact_ip_and_empty_query(self):
        found = self.lab.search('| `adm_find("10.42.0.30")`', *CATALOG_WINDOW)
        self.assertTrue(found)
        self.assertTrue(any(row.get("service") == "catalog" for row in found))
        self.assertEqual(
            self.lab.search('| `adm_find("10.42.99.99")`', *CATALOG_WINDOW), []
        )
        for value in (
            '10.42.0.30" | stats count',
            "`stats count`",
            "$(whoami)",
            "10.42.0.30\n| stats count",
        ):
            with self.assertRaises(RuntimeError):
                self.lab.search(f"| `adm_find({json.dumps(value)})`", *CATALOG_WINDOW)

    def test_temporal_cart_identity_and_scope_key_separation(self):
        rows = self.lab.search(
            "| inputlookup adm_service_workload | search service=cart cluster=demo-cluster namespace=shop | fields environment cluster namespace pod_uid first_seen last_seen",
            *CATALOG_WINDOW,
        )
        uids = {row.get("pod_uid") for row in rows}
        self.assertIn("ce6f7a8b-9c0d-4e1f-8a3b-4c5d6e7f8a06", uids)
        self.assertNotIn("bd5e6f7a-8b9c-4d0e-9f2a-3b4c5d6e7f05", uids)
        self.assertEqual(len({row["_key"] for row in self.catalog}), len(self.catalog))

    def test_identity_cap_emits_no_rows_and_saved_writer_preserves_prior_snapshot(self):
        from test_data_layer import DataLayerTest

        macro_path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_identity_max_matches"
        )
        original = self.lab._json("GET", macro_path)["entry"][0]["content"].get(
            "definition", ""
        )
        self.addCleanup(self.lab._json, "POST", macro_path, {"definition": original})
        self.lab._json("POST", macro_path, {"definition": "0"})
        sentinel = "adm-cap-" + secrets.token_hex(8)
        self.addCleanup(
            self._delete_catalog_key,
            sentinel,
        )
        self.lab.search(
            "| makeresults | eval _key=%s, service=sentinel, environment=sentinel, cluster=sentinel, namespace=sentinel | outputlookup append=true key_field=_key adm_app_catalog"
            % json.dumps(sentinel)
        )
        self.assertEqual(self.lab.search("| `adm_catalog_build`", *CATALOG_WINDOW), [])
        DataLayerTest.dispatch(
            "ADM - Application catalog",
            earliest=str(CATALOG_WINDOW[0]),
            latest=str(CATALOG_WINDOW[1]),
        )
        retained = self.lab.search(
            "| inputlookup adm_app_catalog | search _key=%s" % json.dumps(sentinel),
            *CATALOG_WINDOW,
        )
        self.assertEqual(len(retained), 1)

    def test_identity_cap_with_no_resolved_pod_still_invalidates_snapshot(self):
        path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_identity_max_matches"
        )
        original = self.lab._json("GET", path)["entry"][0]["content"]["definition"]
        self.addCleanup(self.lab._json, "POST", path, {"definition": original})
        for ip in ("10.42.0.10", "10.42.0.20"):
            key = "identity-cap-" + secrets.token_hex(8)
            self.addCleanup(self._delete_collection_key, "adm_ip_identity", key)
            self.lab.search(
                "| inputlookup adm_ip_identity | search entity_kind=pod ip="
                + json.dumps(ip)
                + " | head 1 | eval _key="
                + json.dumps(key)
                + ", entity_id="
                + json.dumps(key)
                + ", ek="
                + json.dumps(key)
                + " | `adm_identity_desc` | outputlookup append=true key_field=_key adm_ip_identity",
                *CATALOG_WINDOW,
            )
        self.lab._json("POST", path, {"definition": "2"})
        capped = self.lab.search(
            '| `adm_catalog_edges` | search client_ip="10.42.0.10" server_ip="10.42.0.20" | fields adm_catalog_invalid adm_c_pkey adm_s_pkey',
            *CATALOG_WINDOW,
        )
        self.assertTrue(capped)
        for row in capped:
            self.assertEqual(row["adm_catalog_invalid"], "1")
            self.assertFalse(row.get("adm_c_pkey"))
            self.assertFalse(row.get("adm_s_pkey"))
        self.assertEqual(self.lab.search("| `adm_catalog_build`", *CATALOG_WINDOW), [])
        warning = self.lab.search('| `adm_find("10.42.0.10")`', *CATALOG_WINDOW)
        self.assertEqual(len(warning), 1)
        self.assertIn("complete", warning[0]["warnings"])

    def test_expansion_memory_limit_does_not_publish_partial_scopes(self):
        prefix = "catalog-expand-" + secrets.token_hex(8)
        self.addCleanup(
            self.lab.search,
            "| inputlookup adm_service_workload | where NOT like(_key, "
            + json.dumps(prefix + "%")
            + ") | outputlookup adm_service_workload",
            *CATALOG_WINDOW,
        )
        self.lab.search(
            "| inputlookup adm_service_workload | search service=frontend namespace=shop | head 1 "
            + "| eval probe=mvrange(0, 5000) | mvexpand probe | eval _key="
            + json.dumps(prefix)
            + '.probe, service="expand-probe-".probe '
            + "| fields - probe | outputlookup append=true key_field=_key adm_service_workload",
            *CATALOG_WINDOW,
        )
        count = self.lab.search(
            "| inputlookup adm_service_workload | where like(_key, "
            + json.dumps(prefix + "%")
            + ") | stats count",
            *CATALOG_WINDOW,
        )
        self.assertEqual(int(count[0]["count"]), 5000)
        path = "/servicesNS/nobody/splunk_adm/configs/conf-limits/mvexpand"
        original = self.lab._json("GET", path)["entry"][0]["content"][
            "max_mem_usage_mb"
        ]
        self.addCleanup(
            self.lab._json, "POST", path, {"max_mem_usage_mb": str(original)}
        )
        self.lab._json("POST", path, {"max_mem_usage_mb": "1"})
        self.assertEqual(self.lab.search("| `adm_catalog_build`", *CATALOG_WINDOW), [])
        found = self.lab.search('| `adm_find("10.42.0.10")`', *CATALOG_WINDOW)
        self.assertEqual(len(found), 1)
        self.assertIn("complete", found[0]["warnings"])

    def _delete_catalog_key(self, key: str) -> None:
        with self.lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{APP}/storage/collections/data/adm_app_catalog/{urllib.parse.quote(key, safe='')}",
        ) as response:
            response.read()

    def test_viewer_reads_catalog_and_find_but_cannot_write_or_dispatch_owner(self):
        case = self.RestrictedViewerTest("runTest")
        try:
            self.assertTrue(
                case._viewer_search(
                    "| `adm_catalog_build`", *CATALOG_WINDOW, allow_warnings=True
                )
            )
            self.assertTrue(
                case._viewer_search(
                    '| `adm_find("10.42.0.30")`', *CATALOG_WINDOW, allow_warnings=True
                )
            )
            from test_permissions import SearchRejected

            self.lab.search(
                "| `adm_catalog_build` | outputlookup append=true key_field=_key adm_app_catalog",
                *CATALOG_WINDOW,
            )
            self.assertTrue(
                case._viewer_search("| inputlookup adm_app_catalog", *CATALOG_WINDOW)
            )
            before = self.lab.search("| inputlookup adm_app_catalog", *CATALOG_WINDOW)
            with self.assertRaisesRegex(
                SearchRejected,
                r"(?i)permission|not authorized|not allowed|denied|privilege|cannot write",
            ):
                case._viewer_search(
                    "| inputlookup adm_app_catalog | outputlookup adm_app_catalog",
                    *CATALOG_WINDOW,
                )
            after = self.lab.search("| inputlookup adm_app_catalog", *CATALOG_WINDOW)
            self.assertEqual(
                sorted(json.dumps(row, sort_keys=True) for row in before),
                sorted(json.dumps(row, sort_keys=True) for row in after),
            )
            case.assertDenied(
                "POST",
                "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Application%20catalog/dispatch",
                urllib.parse.urlencode({"trigger_actions": "0"}).encode(),
                hidden=True,
            )
            case.assertDenied(
                "POST",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_app_catalog",
                json.dumps({"_key": "viewer-probe"}).encode(),
                "application/json",
            )
        finally:
            case.doCleanups()

    def test_catalog_saved_search_is_admin_owned_and_readable(self):
        path = "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Application%20catalog"
        entry = self.lab._json("GET", path)["entry"][0]
        content = entry["content"]
        self.assertEqual(content.get("dispatchAs"), "owner")
        self.assertIn(entry.get("acl", {}).get("owner"), {"nobody", "admin"})
        permissions = entry.get("acl", {}).get("perms", {})
        self.assertEqual(set(permissions.get("write", [])), {"admin", "sc_admin"})
        self.assertEqual(set(permissions.get("read", [])), {"admin", "sc_admin"})
