"""End-to-end data layer test against the local Splunk lab.

Skipped unless ADM_LAB=1. Prerequisites: `tests/splunk/lab.sh up` and `tests/splunk/lab.sh install`
with the current splunk_app/splunk_adm. Expectations in expected/graph.json are derived from
fixtures/raw/scenario.json, not from search output.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RAW = ROOT / "fixtures" / "raw"
EXPECTED = json.loads((HERE / "expected" / "graph.json").read_text(encoding="utf-8"))
CONTAINER = "adm-splunk-lab"
APP_DIR = "/opt/splunk/etc/apps/splunk_adm"

SAVED = [
    "ADM - Interface inventory",
    "ADM - Identity builder",
    "ADM - Service binding",
    "ADM - Conversation rollup",
    "ADM - Identity prune",
    "ADM - Service binding prune",
]
COLLECTIONS = [
    "adm_ip_identity",
    "adm_service_workload",
    "adm_interfaces",
    "adm_service_backends",
    "adm_service_routes",
    "adm_aci_policy",
]
SCOPE_ROWS = [
    ("exporter", "192.0.2.11", "prod", ""),
    ("exporter", "192.0.2.12", "prod", ""),
    ("fabric", "dc1-vxlan", "prod", ""),
    ("firewall", "192.0.2.1", "prod", ""),
    ("hec_source", "http:isovalent", "prod", "demo-cluster"),
    ("cluster", "demo-cluster", "prod", "demo-cluster"),
    ("apic", "192.0.2.50", "prod", ""),
    ("nd_host", "192.0.2.60", "prod", ""),
]
ARGS = EXPECTED["args"]
CALL = ", ".join(
    f'"{ARGS[k]}"' for k in ("service", "environment", "cluster", "namespace")
)
WINDOW = (str(EXPECTED["window"]["earliest"]), str(EXPECTED["window"]["latest"]))


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class DataLayerTest(unittest.TestCase):
    rows: list[dict]

    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        subprocess.run([str(HERE / "lab.sh"), "reset"], check=True, capture_output=True)
        cls.wait_for_kvstore()
        cls.restore_macros()
        for name in COLLECTIONS:
            lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/splunk_adm/storage/collections/data/{name}",
            )
        csv = "observer_kind,observer,scope,cluster\n" + "\n".join(
            ",".join(r) for r in SCOPE_ROWS
        )
        lab.search(
            f'| makeresults format=csv data="{csv}" | fields - _time | outputlookup adm_observer_scope.csv'
        )
        for name in SAVED:
            lab._mgmt(
                "POST",
                "/servicesNS/nobody/splunk_adm/saved/searches/"
                + urllib.parse.quote(name, safe=""),
                {"disabled": "0", "is_scheduled": "0"},
            )

        # Batch 1: everything except the late NetFlow segments, rolled up in its own index-time slice.
        start = int(time.time()) - 5
        sent = lab.load(sorted(RAW.glob("*.ndjson")))
        cls.wait_for_count("index=* NOT index=_* NOT index=adm_summary", sent)
        cls.slice1 = (start, int(time.time()) + 1)
        time.sleep(2)
        cls.builder = {}
        for name in SAVED[:3]:
            cls.builder[name] = cls.dispatch(name, index_window=(start, start + 3600))
        cls.rollup1 = cls.dispatch(SAVED[3], index_window=cls.slice1)
        # Batch 2: the late NetFlow export, picked up by the next index-time slice only.
        late = lab.load(sorted((RAW / "late").glob("*.ndjson")))
        netflow = sum(
            p.read_text().count("\n")
            for p in (RAW / "stream_netflow.ndjson", *(RAW / "late").glob("*.ndjson"))
        )
        cls.wait_for_count("index=netflow", netflow)
        assert late > 0
        cls.slice2 = (cls.slice1[1], int(time.time()) + 60)
        cls.rollup2 = cls.dispatch(SAVED[3], index_window=cls.slice2)
        cls.wait_for_count(
            'index=adm_summary source="adm:conversation"',
            len(cls.rollup1) + len(cls.rollup2),
        )
        cls.rows = lab.search(f"`adm_graph({CALL})`", *WINDOW)

    @classmethod
    def dispatch(
        cls, name: str, index_window=None, earliest="0", latest="now"
    ) -> list[dict]:
        data = {
            "trigger_actions": "1",
            "dispatch.earliest_time": earliest,
            "dispatch.latest_time": latest,
        }
        if index_window:
            data["dispatch.index_earliest"] = str(index_window[0])
            data["dispatch.index_latest"] = str(index_window[1])
        path = (
            "/servicesNS/nobody/splunk_adm/saved/searches/"
            + urllib.parse.quote(name, safe="")
            + "/dispatch?output_mode=json"
        )
        with cls.lab._mgmt("POST", path, data) as r:
            sid = json.loads(r.read())["sid"]
        cls.lab._wait_job(sid)
        return cls.lab._results(sid)

    @classmethod
    def count(cls, spl: str) -> int:
        return int(cls.lab.search(f"{spl} | stats count", "0", "now")[0]["count"])

    @classmethod
    def wait_for_kvstore(cls, timeout: float = 300) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = cls.lab._json("GET", "/services/kvstore/status")["entry"][0][
                "content"
            ]
            if status.get("current", {}).get("status") == "ready":
                return
            time.sleep(3)
        raise AssertionError("KV store did not become ready")

    @classmethod
    def wait_for_count(cls, spl: str, expected: int, timeout: float = 120) -> None:
        deadline = time.time() + timeout
        got = 0
        while time.time() < deadline:
            got = cls.count(spl)
            if got >= expected:
                return
            time.sleep(2)
        raise AssertionError(f"only {got} of {expected} events for {spl}")

    @classmethod
    def set_macros(cls, overrides: dict[str, str]) -> None:
        """Lab-only override of shipped macros through the app's local/macros.conf."""
        text = "".join(
            f"[{name}]\ndefinition = {value}\n\n" for name, value in overrides.items()
        )
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "-u",
                "splunk",
                CONTAINER,
                "sh",
                "-c",
                f"mkdir -p {APP_DIR}/local && cat > {APP_DIR}/local/macros.conf",
            ],
            input=text.encode(),
            check=True,
        )
        cls.lab._mgmt("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

    @classmethod
    def restore_macros(cls) -> None:
        subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "splunk",
                CONTAINER,
                "rm",
                "-f",
                f"{APP_DIR}/local/macros.conf",
            ],
            check=True,
        )
        cls.lab._mgmt("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

    def nodes(self) -> dict[str, dict]:
        return {r["id"]: r for r in self.rows if r.get("row_type") == "node"}

    def edges(self) -> list[dict]:
        return [r for r in self.rows if r.get("row_type") == "edge"]

    def edge(self, relationship: str, source: str, target: str) -> dict:
        found = [
            e
            for e in self.edges()
            if e["relationship"] == relationship
            and e["source"] == source
            and e["target"] == target
        ]
        self.assertEqual(len(found), 1, f"{relationship} {source} -> {target}: {found}")
        return found[0]

    def meta(self) -> dict:
        meta = [r for r in self.rows if r.get("row_type") == "meta"]
        self.assertEqual(len(meta), 1)
        return meta[0]

    # ---- graph contract against the scenario ----

    def test_expected_nodes(self):
        nodes = self.nodes()
        for node_id, attrs in EXPECTED["nodes"].items():
            self.assertIn(node_id, nodes)
            for key, value in attrs.items():
                got = nodes[node_id].get(key)
                if isinstance(value, list):
                    self.assertEqual(
                        sorted(as_list(got)), sorted(value), f"{node_id}.{key}"
                    )
                else:
                    self.assertEqual(got, value, f"{node_id}.{key}")
        self.assertEqual(set(nodes), set(EXPECTED["nodes"]), "unexpected extra nodes")
        for node_id in EXPECTED["absent_nodes"]:
            self.assertNotIn(node_id, nodes)

    def test_expected_edges(self):
        for want in EXPECTED["edges"]:
            got = self.edge(want["relationship"], want["source"], want["target"])
            for key, value in want.items():
                if key in ("relationship", "source", "target"):
                    continue
                if key == "evidence_includes":
                    for item in value:
                        self.assertIn(item, as_list(got.get("evidence")))
                elif key == "observer_prefixes":
                    for prefix in value:
                        self.assertTrue(
                            any(
                                o.startswith(prefix)
                                for o in as_list(got.get("observers"))
                            ),
                            f"{prefix} not in {got.get('observers')}",
                        )
                elif value is None:
                    self.assertNotIn(key, got, f"{got['id']}.{key} should be absent")
                elif isinstance(value, list):
                    self.assertEqual(
                        sorted(as_list(got.get(key))),
                        sorted(value),
                        f"{got['id']}.{key}",
                    )
                else:
                    self.assertEqual(got.get(key), value, f"{got['id']}.{key}")

    def test_edge_counts_and_no_reversed_duplicates(self):
        counts: dict[str, int] = {}
        for e in self.edges():
            counts[e["relationship"]] = counts.get(e["relationship"], 0) + 1
        self.assertEqual(counts, EXPECTED["edge_counts"])
        keys = {(e["source"], e["target"], e.get("transport")) for e in self.edges()}
        for source, target, transport in keys:
            if transport:
                self.assertNotIn(
                    (target, source, transport), keys, "reversed duplicate edge"
                )

    def test_every_edge_endpoint_is_a_node(self):
        nodes = self.nodes()
        for e in self.edges():
            self.assertIn(e["source"], nodes)
            self.assertIn(e["target"], nodes)

    def test_meta(self):
        meta = self.meta()
        for key, value in EXPECTED["meta"].items():
            self.assertEqual(meta.get(key), value, key)
        self.assertNotIn("warnings", meta)

    def test_payment_has_no_calls_to_gateway(self):
        payment = "service:demo-cluster/shop/payment/demo"
        self.assertFalse(
            [
                e
                for e in self.edges()
                if e["relationship"] == "calls" and e["source"] == payment
            ]
        )

    # ---- C2 / M1: index-time slices, each record counted once, summed across runs ----

    def test_late_record_is_summed_across_rollup_runs(self):
        self.assertEqual(len(self.rollup2), 1, self.rollup2)
        e = self.edge(
            "communicates_with",
            "ip:prod/10.99.0.7",
            "pod:demo-cluster/ce6f7a8b-9c0d-4e1f-8a3b-4c5d6e7f8a06",
        )
        # One connection (client port 52011) continued by the late record.
        self.assertEqual((e["bytes"], e["count"]), ("150", "1"))

    def test_every_flow_record_is_counted_exactly_once(self):
        records = self.count("| `adm_flows`")
        summarized = self.lab.search(
            'index=adm_summary source="adm:conversation" | stats sum(records) AS n',
            "0",
            "now",
        )
        self.assertEqual(int(summarized[0]["n"]), records)
        self.assertEqual(
            self.dispatch(SAVED[3], index_window=(self.slice2[1], self.slice2[1] + 60)),
            [],
        )

    # ---- M2: argument validation ----

    def test_injection_and_backslash_arguments_are_rejected(self):
        # SPL text of the arguments: the reviewer payload, an escaped trailing backslash, a raw one.
        payloads = {'zzz\\" OR adm_ns!=\\"': True, "shop\\\\": True, "shop\\": False}
        macros = [
            "adm_graph",
            "adm_graph_inputs",
            "adm_graph_resolve",
            "adm_graph_edges",
            "adm_graph_output",
        ]
        for macro in macros:
            for payload, reaches_validation in payloads.items():
                for position in range(4):
                    args = [
                        f'"{ARGS[k]}"'
                        for k in ("service", "environment", "cluster", "namespace")
                    ]
                    args[position] = f'"{payload}"'
                    pattern = "Invalid graph arguments" if reaches_validation else "."
                    with self.assertRaisesRegex(
                        self.lab.LabError, pattern, msg=f"{macro} {position} {payload}"
                    ):
                        self.lab.search(
                            f"| makeresults | `{macro}({', '.join(args)})`", *WINDOW
                        )

    # ---- M3: per-bucket resolution ----

    def test_ip_reused_inside_window_resolves_each_bucket(self):
        checkout = "pod:demo-cluster/8a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c02"
        self.edge(
            "communicates_with",
            "pod:demo-cluster/e1a2b3c4-d5e6-4f70-8a9b-0c1d2e3f4a08",
            checkout,
        )
        self.edge(
            "communicates_with",
            "pod:demo-cluster/f2b3c4d5-e6f7-4a81-9b0c-1d2e3f4a5b09",
            checkout,
        )
        self.assertNotIn("ip:prod/10.42.0.60", self.nodes())

    def test_reused_ip_before_window_resolves_to_old_pod(self):
        args = CALL
        rows = self.lab.search(
            f"`adm_graph_inputs({args})` | `adm_graph_resolve({args})` "
            '| search adm_row="conv" server_ip="10.42.0.50" | table client_ip adm_s_id adm_s_state',
            "1791372900",
            "1791373200",
        )
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["adm_s_state"], "resolved")
            self.assertEqual(
                row["adm_s_id"], "pod:demo-cluster/bd5e6f7a-8b9c-4d0e-9f2a-3b4c5d6e7f05"
            )

    # ---- M4: hostNetwork pods ----

    def test_host_network_pod_is_not_an_ip_owner(self):
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where ip="10.10.20.11" | table entity_kind entity_name'
        )
        kinds = {r["entity_kind"] for r in rows}
        self.assertNotIn("pod", kinds)
        self.assertIn("k8s_node", kinds)
        self.assertNotIn(
            "pod:demo-cluster/b4d5e6f7-a8b9-4ca3-9d2e-3f4a5b6c7d11", self.nodes()
        )

    def test_tunnel_is_not_attached_to_pods(self):
        tunnels = [e for e in self.edges() if e.get("encapsulation")]
        self.assertEqual(len(tunnels), 1)
        for e in tunnels:
            self.assertTrue(
                e["source"].startswith("node:") and e["target"].startswith("node:")
            )

    # ---- M5: ACI and Nexus Dashboard describing one endpoint ----

    def test_aci_and_nd_rows_for_one_endpoint_are_one_entity(self):
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where ip="10.20.30.40" | table source'
        )
        self.assertEqual(sorted(r["source"] for r in rows), ["aci", "nd_endpoints"])
        node = self.nodes()["vm:prod/10.20.30.40"]
        self.assertEqual(
            node["attr_attach_device"], "pod-1/node-201", "ACI attributes win over ND"
        )
        self.assertEqual(self.meta()["ambiguous_conversations"], "0")

    # ---- M6: node replacement reusing an IP ----

    def test_replaced_node_row_is_closed_at_replacement(self):
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where ip="10.10.20.13" entity_kind="k8s_node" | table entity_name valid_from valid_to'
        )
        by_name = {r["entity_name"]: r for r in rows}
        self.assertEqual(by_name["node-c"]["valid_to"], by_name["node-d"]["valid_from"])
        self.assertNotIn("valid_to", by_name["node-d"])
        self.assertIn("node:demo-cluster/node-d", self.nodes())

    # ---- M7: orientation reconciliation ----

    def test_high_port_server_is_one_edge(self):
        inventory = "pod:demo-cluster/a3c4d5e6-f7a8-4b92-8c1d-2e3f4a5b6c10"
        edges = [e for e in self.edges() if inventory in (e["source"], e["target"])]
        self.assertEqual(len(edges), 1, edges)
        self.assertEqual(edges[0]["server_port"], "50051")

    # ---- M8: prefilters ----

    def test_inputs_only_read_boundary_conversations_and_traces(self):
        rows = self.lab.search(
            f'`adm_graph_inputs({CALL})` | stats count(eval(adm_row=="span")) AS spans '
            'values(eval(if(adm_row=="conv", client_ip, null()))) AS clients',
            *WINDOW,
        )
        self.assertEqual(rows[0]["spans"], "11")
        self.assertNotIn("198.51.100.8", as_list(rows[0].get("clients")))

    # ---- minors ----

    def test_icmp_record_without_ports_is_kept(self):
        e = self.edge(
            "communicates_with",
            "vm:prod/10.20.30.40",
            "pod:demo-cluster/8a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c02",
        )
        self.assertEqual(e["transport"], "icmp")
        self.assertNotIn("server_port", e)

    def test_ipv4_mapped_nd_records_join_the_ipv4_conversation(self):
        e = self.edge(
            "communicates_with",
            "pod:demo-cluster/8a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c02",
            "vm:prod/10.20.30.40",
        )
        self.assertIn("nd", as_list(e["sources"]))

    def test_missing_cluster_is_reported_by_identity_builder(self):
        summary = self.builder["ADM - Identity builder"][0]
        self.assertEqual(summary["rows_missing_cluster"], "1")
        self.assertIn("k8s.cluster.name", summary["warnings"])
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where entity_kind="k8s_node" cluster="unknown"'
        )
        self.assertEqual(rows, [])

    def test_missing_entry_service_returns_only_meta_with_warning(self):
        rows = self.lab.search(
            '`adm_graph("no-such-service", "demo", "demo-cluster", "shop")`', *WINDOW
        )
        self.assertEqual([r["row_type"] for r in rows], ["meta"])
        self.assertIn("no spans", rows[0]["warnings"])

    def test_identity_builder_is_idempotent(self):
        before = self.lab.search("| inputlookup adm_ip_identity | stats count")[0][
            "count"
        ]
        start = self.slice1[0]
        self.dispatch("ADM - Identity builder", index_window=(start, start + 3600))
        after = self.lab.search(
            "| inputlookup adm_ip_identity | stats count dc(_key) AS keys"
        )[0]
        self.assertEqual(after["count"], before)
        self.assertEqual(after["keys"], before)

    # ---- C1: pruning only after a complete paged read (runs last) ----

    def prune(self) -> dict:
        # The emulated lab KV store intermittently fails single reads; a failed prune never writes.
        for attempt in range(3):
            try:
                return self.dispatch("ADM - Identity prune")[0]
            except self.lab.LabError as e:
                if "returned error code" not in str(e) or attempt == 2:
                    raise
                time.sleep(3)
        raise AssertionError("unreachable")

    def paged_reader(self, page: int, cap: int | None = None, pages: int = 20) -> str:
        """adm_kv_read_all with a different page size; cap emulates a store returning at most cap rows."""
        size = cap or page
        parts = [f"inputlookup $collection$ start=0 max={size} | eval adm_page=1"]
        parts.append(
            f"inputlookup append=true $collection$ start=1 max={size} | eval adm_page=coalesce(adm_page, 0)"
        )
        for k in range(2, pages + 1):
            parts.append(
                f"inputlookup append=true $collection$ start={(k - 1) * page} max={size} | eval adm_page=coalesce(adm_page, {k})"
            )
        return " | ".join(parts) + " | `adm_kv_complete`"

    def test_zz_prune_refuses_read_capped_by_the_store(self):
        try:
            self.set_macros(
                {
                    "adm_kv_page_size": "100",
                    "adm_kv_read_all(1)": self.paged_reader(100, cap=5),
                }
            )
            before = self.count("| inputlookup adm_ip_identity")
            self.assertGreater(before, 5)
            result = self.prune()
            self.assertEqual(result["complete"], "0", result)
            self.assertIn("nothing was pruned", result["warnings"])
            self.assertEqual(self.count("| inputlookup adm_ip_identity"), before)
        finally:
            self.restore_macros()

    def test_zz_prune_removes_only_expired_rows_after_complete_paged_read(self):
        cutoff = 1791373800  # 11:50Z: rows that ended before this expire
        try:
            self.set_macros(
                {
                    "adm_kv_page_size": "4",
                    "adm_kv_read_all(1)": self.paged_reader(4),
                    "adm_identity_retention": str(int(time.time()) - cutoff),
                }
            )
            rows = self.lab.search(
                "| inputlookup adm_ip_identity | eval k=_key | table k valid_end"
            )
            keep = {
                r["k"]
                for r in rows
                if "valid_end" not in r or float(r["valid_end"]) >= cutoff
            }
            self.assertLess(len(keep), len(rows))
            result = self.prune()
            self.assertEqual(result["complete"], "1", result)
            self.assertEqual(int(result["rows_pruned"]), len(rows) - len(keep))
            after = {
                r["k"]
                for r in self.lab.search(
                    "| inputlookup adm_ip_identity | eval k=_key | table k"
                )
            }
            self.assertEqual(after, keep)
        finally:
            self.restore_macros()


if __name__ == "__main__":
    unittest.main()
