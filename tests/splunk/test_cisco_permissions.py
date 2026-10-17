"""Restricted-viewer authorization checks for the combined Cisco V2 dataset.

The enclosing test runner initializes and owns the disposable lab. This module
only creates an ephemeral search-only viewer and verifies public read paths and
denied mutation/dispatch paths; it never resets or seeds the lab.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import sys
import unittest
import urllib.parse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import test_permissions as permission_helpers  # noqa: E402

sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import LabLock  # noqa: E402


V2_ALLOWED_INDEXES = sorted(
    set(permission_helpers.ALLOWED_INDEXES)
    | {"adm_summary_v2", "cisco_catalyst", "cisco_meraki"}
)
V2_COLLECTIONS = (
    "adm_network_source_scope",
    "adm_network_client_history",
    "adm_cilium_cluster_settings",
    "adm_app_catalog_v2",
)
V2_WRITERS = (
    "ADM - Network client history builder",
    "ADM - Conversation rollup v2",
    "ADM - Traffic observation rollup v2",
    "ADM - Application catalog v2",
)
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoV2RestrictedViewerTest(unittest.TestCase):
    """A search-only user can read V2 views while all writers stay protected."""

    # Reuse the existing ephemeral viewer request/search/cleanup helpers without
    # inheriting its V1 TestCase or running its reset-and-seed setUpClass.
    _viewer_json = permission_helpers.RestrictedViewerTest._viewer_json
    _viewer_search = permission_helpers.RestrictedViewerTest._viewer_search
    _delete_job = permission_helpers.RestrictedViewerTest._delete_job
    assertDenied = permission_helpers.RestrictedViewerTest.assertDenied

    @classmethod
    def setUpClass(cls) -> None:
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")

        import lab

        cls.lab = lab
        initialized_path = ROOT / "dist/networking-path-tests/initialization.json"
        if not initialized_path.is_file():
            raise RuntimeError(
                "the combined Cisco dataset must be initialized before this suite"
            )
        cls.initialized = json.loads(initialized_path.read_text(encoding="utf-8"))
        # The initialization manifest counts input events; derived summaries are
        # built afterwards and must be checked from the indexed output itself.
        for index in ("cisco_catalyst", "cisco_meraki"):
            if int(cls.initialized.get("indexed_counts", {}).get(index, 0)) <= 0:
                raise RuntimeError(f"combined dataset lacks required index {index}")
        cls.window = (
            int(cls.initialized["window"]["earliest"]),
            int(cls.initialized["window"]["latest"]),
        )
        cls.build_window = (
            int(cls.initialized["build_window"]["earliest"]),
            int(cls.initialized["build_window"]["latest"]),
        )
        summary_counts = {
            row["source"]: int(row["count"])
            for row in lab.search(
                "search index=adm_summary_v2 | stats count by source",
                *cls.build_window,
            )
        }
        for source in ("adm:conversation", "adm:traffic_observation"):
            if summary_counts.get(source, 0) <= 0:
                raise RuntimeError(f"combined dataset lacks summary {source}")

        cls.username = "adm_cisco_viewer_" + secrets.token_hex(8)
        cls.password = secrets.token_urlsafe(24)
        cls.role = "adm_cisco_viewer_" + secrets.token_hex(8)
        admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]

        role_payload = urllib.parse.urlencode(
            {
                "name": cls.role,
                "capabilities": "search",
                "srchIndexesAllowed": V2_ALLOWED_INDEXES,
                "srchIndexesDisallowed": ["_internal", "_audit"],
            },
            doseq=True,
        ).encode()
        status, _ = permission_helpers._response(
            "POST",
            "/services/authorization/roles",
            "admin",
            admin_password,
            role_payload,
        )
        if status not in (200, 201):
            raise AssertionError(
                f"could not create ephemeral V2 viewer role (HTTP {status})"
            )
        cls.addClassCleanup(
            permission_helpers.RestrictedViewerTest._delete_role,
            cls.role,
            admin_password,
        )
        lab._json(
            "POST",
            f"/services/authorization/roles/{urllib.parse.quote(cls.role, safe='')}",
            {"capabilities": "search"},
        )

        user_payload = urllib.parse.urlencode(
            {"name": cls.username, "password": cls.password, "roles": cls.role}
        ).encode()
        status, _ = permission_helpers._response(
            "POST",
            "/services/authentication/users",
            "admin",
            admin_password,
            user_payload,
        )
        if status not in (200, 201):
            raise AssertionError(
                f"could not create ephemeral V2 viewer (HTTP {status})"
            )
        cls.addClassCleanup(
            permission_helpers.RestrictedViewerTest._delete_user,
            cls.username,
            admin_password,
        )

    def test_search_only_role_is_explicitly_scoped_to_v2_inputs(self):
        status, context = self._viewer_json(
            "GET", "/services/authentication/current-context?output_mode=json"
        )
        self.assertEqual(status, 200)
        content = context["entry"][0]["content"]
        self.assertEqual(set(content.get("roles", [])), {self.role})
        self.assertEqual(set(content.get("capabilities", [])), {"search"})
        if "srchIndexesAllowed" in content:
            self.assertEqual(
                set(content["srchIndexesAllowed"]), set(V2_ALLOWED_INDEXES)
            )
        if "srchIndexesDisallowed" in content:
            self.assertEqual(
                set(content["srchIndexesDisallowed"]), {"_internal", "_audit"}
            )

    def test_viewer_reads_both_v2_graphs_and_topology_completely(self):
        for cluster in ("cilium-aci-east", "cilium-nxos-west"):
            with self.subTest(cluster=cluster):
                macro = f'`adm_graph_v2("checkout","demo","{cluster}","shop")`'
                rows = self._viewer_search(
                    f"| search {macro}",
                    *self.window,
                )
                implicit_search_rows = self._viewer_search(macro, *self.window)
                self.assertTrue(rows, "V2 graph returned no rows")

                # Each search emits its own generation time. Compare every
                # evidence field while validating that timestamp separately.
                def comparable_graph_rows(result):
                    normalized = []
                    for row in result:
                        value = dict(row)
                        if value.get("row_type") == "meta":
                            self.assertGreater(int(value.pop("generated_at")), 0)
                        normalized.append(json.dumps(value, sort_keys=True))
                    return normalized

                self.assertCountEqual(
                    comparable_graph_rows(rows),
                    comparable_graph_rows(implicit_search_rows),
                    "implicit-search V2 graph differs from explicit | search",
                )
                metas = [row for row in rows if row.get("row_type") == "meta"]
                self.assertEqual(len(metas), 1)
                self.assertEqual(str(metas[0].get("root_present")), "1")
                self.assertFalse(metas[0].get("warnings"))
                self.assertTrue(any(row.get("row_type") == "node" for row in rows))
                self.assertTrue(any(row.get("row_type") == "edge" for row in rows))

        topology_macro = "`adm_topology_v2`"
        topology = self._viewer_search(f"| search {topology_macro}", *self.window)
        implicit_topology = self._viewer_search(topology_macro, *self.window)
        self.assertTrue(topology, "V2 topology returned no rows")
        self.assertCountEqual(
            [json.dumps(row, sort_keys=True) for row in topology],
            [json.dumps(row, sort_keys=True) for row in implicit_topology],
            "implicit-search V2 topology differs from explicit | search",
        )
        self.assertTrue(any(row.get("row_type") == "device" for row in topology))
        self.assertTrue(any(row.get("row_type") == "link" for row in topology))
        metas = [row for row in topology if row.get("row_type") == "meta"]
        self.assertEqual(len(metas), 1)
        warnings = metas[0].get("warnings")
        warnings = warnings if isinstance(warnings, list) else [warnings]
        # The baseline includes two ESXi vmnic2 LLDP peers without host
        # inventory. They must remain gaps, including for the restricted viewer.
        self.assertCountEqual(
            warnings,
            [
                "Some inventory records, links, or interfaces have missing, conflicting, or differently scoped device identities and remain unresolved.",
                "Some LLDP peers could not be matched to a unique Kubernetes host in the same scope and cluster; those attachments remain unresolved.",
                "Nexus Dashboard fabric labels are not yet correlated into V2 inventory; flow observations remain available separately.",
            ],
        )
        admin_topology = self.lab.search("| search `adm_topology_v2`", *self.window)
        self.assertCountEqual(
            [json.dumps(row, sort_keys=True) for row in topology],
            [json.dumps(row, sort_keys=True) for row in admin_topology],
            "restricted viewer topology differs from the administrator result",
        )
        self.assertFalse(
            any(
                row.get("row_type") == "link" and row.get("b_interface") == "vmnic2"
                for row in topology
            ),
            "unresolved ESXi LLDP peers must not become asserted adjacency",
        )

    def test_viewer_reads_v2_profiles_history_cluster_settings_catalog_find_and_health(
        self,
    ):
        for collection in V2_COLLECTIONS[:3]:
            with self.subTest(collection=collection):
                rows = self._viewer_search(
                    f"| inputlookup strict=true {collection} | stats count",
                    *self.build_window,
                )
                self.assertEqual(len(rows), 1, f"{collection} read was incomplete")
                self.assertGreater(int(rows[0]["count"]), 0, f"{collection} was empty")

        catalog = self._viewer_search(
            "| `adm_catalog_build_status_v2`", *self.build_window
        )
        status_rows = [row for row in catalog if row.get("adm_kind") == "status"]
        result_rows = [row for row in catalog if row.get("adm_kind") == "result"]
        self.assertEqual(len(status_rows), 1)
        self.assertEqual(str(status_rows[0].get("adm_catalog_invalid")), "0")
        self.assertTrue(result_rows, "V2 catalog build returned no applications")

        graph = self._viewer_search(
            '| search `adm_graph_v2("checkout","demo","cilium-aci-east","shop")`',
            *self.window,
        )
        pod_addresses = [
            address
            for row in graph
            if row.get("kind") == "workload" and row.get("addresses")
            for address in str(row["addresses"]).split("|")
            if IPV4.fullmatch(address)
        ]
        self.assertTrue(pod_addresses, "V2 graph exposed no workload IP for Find")
        found = self._viewer_search(
            f'| `adm_find_v2("{pod_addresses[0]}")`', *self.build_window
        )
        self.assertTrue(
            found, "V2 Find returned no application for a graph workload IP"
        )
        self.assertFalse(any(row.get("warnings") for row in found))

        health = self._viewer_search("| `adm_health_sources_v2`", *self.build_window)
        self.assertGreater(len(health), 0, "V2 health returned no source rows")
        profiles = [
            row
            for row in health
            if row.get("name") == "Version 2 source scope profiles"
        ]
        self.assertEqual(len(profiles), 1)
        self.assertEqual(str(profiles[0].get("source_seen")), "1")
        self.assertTrue(
            any(
                row.get("name")
                in {"Conversation summary v2", "Traffic observation summary v2"}
                and row.get("status") == "visible"
                for row in health
            ),
            "V2 health could not see either versioned summary stream",
        )

    def test_viewer_cannot_write_v2_collections_or_dispatch_v2_writers(self):
        admin_password = self.lab.read_secrets()["SPLUNK_PASSWORD"]
        for collection in V2_COLLECTIONS:
            with self.subTest(collection=collection):
                path = (
                    f"/servicesNS/nobody/{permission_helpers.APP}/storage/collections/data/"
                    f"{collection}"
                )
                key = "viewer-write-probe-" + secrets.token_hex(8)
                self.addCleanup(
                    permission_helpers.RestrictedViewerTest._delete_probe,
                    path,
                    key,
                    admin_password,
                )
                self.assertDenied(
                    "POST",
                    path,
                    json.dumps({"_key": key, "mapping_status": "forged"}).encode(),
                    "application/json",
                )
                with self.assertRaises(permission_helpers.SearchRejected):
                    self._viewer_search(
                        f'| makeresults | eval _key="{key}" | outputlookup {collection}',
                        *self.build_window,
                    )
                self.assertFalse(
                    self.lab.search(
                        f'| inputlookup {collection} where _key="{key}"',
                        *self.build_window,
                    ),
                    f"viewer wrote a probe row to {collection}",
                )

        for name in V2_WRITERS:
            with self.subTest(saved_search=name):
                path = (
                    "/servicesNS/nobody/"
                    f"{permission_helpers.APP}/saved/searches/"
                    f"{urllib.parse.quote(name, safe='')}/dispatch?output_mode=json"
                )
                payload = urllib.parse.urlencode(
                    {
                        "trigger_actions": "0",
                        "dispatch.earliest_time": "0",
                        "dispatch.latest_time": "now",
                    }
                ).encode()
                self.assertDenied("POST", path, payload, hidden=True)


if __name__ == "__main__":
    unittest.main()
