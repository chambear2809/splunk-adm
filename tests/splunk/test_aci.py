"""ACI pilot data-layer test against the local Splunk lab (fixtures/raw-aci).

Skipped unless ADM_LAB=1. Prerequisites: `tests/splunk/lab.sh up` and `tests/splunk/lab.sh install`
with the current splunk_app/splunk_adm. Expectations in expected/aci_graph.json and
expected/aci_topology.json are derived from fixtures/raw-aci/scenario.json, not from search output;
several tests also read the scenario's per-conversation expectations directly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RAW = ROOT / "fixtures" / "raw-aci"
EDGE = RAW / "edge"
SCENARIO = json.loads((RAW / "scenario.json").read_text("utf-8"))
EDGE_CASES = json.loads((RAW / "edge-cases.json").read_text("utf-8"))
EDGE_WINDOW = ("1791375300", "1791376200")  # 12:15-12:30Z, the edge-case window
EXPECTED = json.loads((HERE / "expected" / "aci_graph.json").read_text("utf-8"))
TOPOLOGY = json.loads((HERE / "expected" / "aci_topology.json").read_text("utf-8"))
CONTAINER = "adm-splunk-lab"
APP_DIR = "/opt/splunk/etc/apps/splunk_adm"
ARGS = EXPECTED["args"]
CALL = ", ".join(
    f'"{ARGS[k]}"' for k in ("service", "environment", "cluster", "namespace")
)
WINDOW = (str(EXPECTED["window"]["earliest"]), str(EXPECTED["window"]["latest"]))
BUILDERS = [
    "ADM - Identity builder",
    "ADM - Service binding",
    "ADM - Interface inventory",
    "ADM - Service backends",
    "ADM - ACI policy",
]
BATCHES = [
    ("base", lambda: sorted(RAW.glob("*.ndjson"))),
    ("edge", lambda: sorted(EDGE.glob("*.ndjson"))),
    ("late", lambda: sorted((EDGE / "late").glob("*.ndjson"))),
]
ROLLUP = "ADM - Conversation rollup"
SAVED = BUILDERS + [
    ROLLUP,
    "ADM - Identity prune",
    "ADM - Service binding prune",
    "ADM - Service backends prune",
    "ADM - Service routes prune",
    "ADM - ACI policy prune",
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
    ("exporter", "192.0.2.101", "prod", ""),
    ("exporter", "192.0.2.102", "prod", ""),
    ("exporter", "192.0.2.103", "prod", ""),
    ("fabric", "aci-1", "prod", ""),
    ("hec_source", "http:isovalent", "prod", "demo-cluster"),
    ("cluster", "demo-cluster", "prod", "demo-cluster"),
    ("cluster", "pull-cluster", "pull", "pull-cluster"),
    ("apic", "192.0.2.50", "prod", ""),
    ("nd_host", "192.0.2.60", "prod", ""),
]


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def envelopes(path: Path) -> list[dict]:
    out = []
    for line in path.read_text("utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def pull_mode(events: list[dict]) -> list[dict]:
    """Watch events re-shaped as k8sobjects pull snapshots of a second cluster.

    In pull mode the receiver emits each listed object as the log body (k8sobjectsreceiver
    pullObjectsToLogData), so the body is the object itself, without the {type, object} wrapper.
    """
    out = []
    for e in events:
        if not e["sourcetype"].startswith("kube:object:"):
            continue
        body = e["event"]
        if body.get("type") == "DELETED":
            continue
        fields = dict(e.get("fields", {}), **{"k8s.cluster.name": "pull-cluster"})
        out.append(dict(e, event=body["object"], fields=fields))
    return out


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class AciDataLayerTest(unittest.TestCase):
    rows: list[dict]

    @classmethod
    def setUpClass(cls):
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
        # Multi-run ingestion: each batch is indexed in its own index-time slice, then the
        # builders and the rollup run over that slice only, as the scheduled searches would.
        cls.slices, cls.rollups, cls.builder, total, prev_end = [], [], {}, 0, 0
        for label, paths in BATCHES:
            events = [e for p in paths() for e in envelopes(p)]
            if label == "base":
                cls.kube = [
                    e for e in events if e["sourcetype"].startswith("kube:object:")
                ]
            while time.time() <= prev_end:
                time.sleep(1)
            start = max(int(time.time()) - 1, prev_end)
            cls.load(events)
            total += len(events)
            cls.wait_for_count("index=* NOT index=_* NOT index=adm_*", total)
            prev_end = int(time.time()) + 1
            time.sleep(2)
            sl = (start, prev_end)
            cls.builder[label] = {
                name: cls.dispatch(name, index_window=sl) for name in BUILDERS
            }
            cls.rollups.append(cls.dispatch(ROLLUP, index_window=sl))
            cls.wait_for_count(
                'index=adm_summary source="adm:conversation"',
                sum(len(r) for r in cls.rollups),
            )
            cls.slices.append(sl)
            if label == "base":
                cls.rows_first = lab.search(f"`adm_graph({CALL})`", *WINDOW)
                cls.shape_first = cls.shape("demo-cluster")
        cls.slice = cls.slices[0]
        cls.all_slices = (cls.slices[0][0], cls.slices[-1][1])
        cls.rows = lab.search(f"`adm_graph({CALL})`", *WINDOW)
        cls.edge_rows = lab.search(f"`adm_graph({CALL})`", *EDGE_WINDOW)
        cls.topology = lab.search(
            "`adm_topology`", *map(str, TOPOLOGY["window"].values())
        )

    @classmethod
    def shape(cls, cluster: str):
        ident = cls.lab.search(
            f'| inputlookup adm_ip_identity where cluster="{cluster}" | eval ip=replace(ip, "{cluster}", "C") | stats count by entity_kind ip port'
        )
        back = cls.lab.search(
            f'| inputlookup adm_service_backends where cluster="{cluster}" | stats count by service pod_name target_port'
        )
        routes = cls.lab.search(
            f'| inputlookup adm_service_routes where cluster="{cluster}" | stats count by parent_kind parent_name backend_service'
        )
        return (
            {(r["entity_kind"], r["ip"], r.get("port")) for r in ident},
            {(r["service"], r["pod_name"], r["target_port"]) for r in back},
            {
                (r["parent_kind"], r["parent_name"], r["backend_service"])
                for r in routes
            },
        )

    @classmethod
    def load(cls, events: list[dict]) -> None:
        path = Path("/tmp/adm-aci-load.ndjson")
        path.write_text("\n".join(json.dumps(e) for e in events) + "\n", "utf-8")
        try:
            cls.lab.load([path])
        finally:
            path.unlink()

    @classmethod
    def dispatch(cls, name, index_window=None, earliest="0", latest="now"):
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
    def wait_for_count(cls, spl: str, expected: int, timeout: float = 180) -> None:
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

    def nodes(self, rows=None) -> dict[str, dict]:
        return {r["id"]: r for r in (rows or self.rows) if r.get("row_type") == "node"}

    def edges(self, rows=None) -> list[dict]:
        return [r for r in (rows or self.rows) if r.get("row_type") == "edge"]

    def find(self, relationship, source, target, **match) -> list[dict]:
        return [
            e
            for e in self.edges()
            if e["relationship"] == relationship
            and e["source"] == source
            and e["target"] == target
            and all(e.get(k) == v for k, v in match.items())
        ]

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
                if value is None:
                    self.assertNotIn(key, nodes[node_id], f"{node_id}.{key}")
                elif isinstance(value, list):
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
            keys = {
                k: want[k]
                for k in ("handoff_basis",)
                if want["relationship"] == "forwards_to"
            }
            found = self.find(
                want["relationship"], want["source"], want["target"], **keys
            )
            self.assertEqual(len(found), 1, f"{want}: {found}")
            got = found[0]
            for key, value in want.items():
                if key in ("relationship", "source", "target"):
                    continue
                if value is None:
                    self.assertNotIn(key, got, f"{got['id']}.{key} should be absent")
                elif isinstance(value, list):
                    self.assertEqual(
                        sorted(as_list(got.get(key))),
                        sorted(value),
                        f"{got['id']}.{key}",
                    )
                else:
                    self.assertEqual(got.get(key), value, f"{got['id']}.{key}")

    def test_edge_counts_and_endpoints(self):
        counts: dict[str, int] = {}
        for e in self.edges():
            counts[e["relationship"]] = counts.get(e["relationship"], 0) + 1
        self.assertEqual(counts, EXPECTED["edge_counts"])
        nodes = self.nodes()
        for e in self.edges():
            self.assertIn(e["source"], nodes)
            self.assertIn(e["target"], nodes)

    def test_meta(self):
        meta = self.meta()
        for key, value in EXPECTED["meta"].items():
            self.assertEqual(meta.get(key), value, key)
        self.assertNotIn("warnings", meta)

    def test_rows_satisfy_the_ui_contract(self):
        """Mirrors frontend/src/graph.ts and rows.ts validation of the v2 fields."""
        for rows in (self.rows, self.edge_rows):
            self.check_ui_contract(rows)

    def check_ui_contract(self, rows):
        nodes = self.nodes(rows)
        for e in self.edges(rows):
            rel = e["relationship"]
            if rel == "forwards_to":
                self.assertIn(
                    e["handoff_basis"],
                    [
                        "hubble_client_tuple",
                        "hubble_xlate",
                        "time_inferred",
                        "l7_forwarded_for",
                    ],
                )
                self.assertIn(e["confidence"], ["observed", "inferred"])
                self.assertEqual(nodes[e["source"]].get("endpoint_kind"), "k8s_service")
                self.assertEqual(nodes[e["target"]]["kind"], "workload")
            else:
                self.assertNotIn("handoff_basis", e)
                self.assertNotEqual(e["confidence"], "inferred")
            if rel != "communicates_with":
                for key in ("contract", "contract_basis", "acl_action", "acl_leaf"):
                    self.assertNotIn(key, e)
            self.assertIn(
                e.get("contract_basis", "intent"),
                ["intent", "not_evaluated", "none", "intra_epg"],
            )
            self.assertEqual(
                "contract" in e, e.get("contract_basis") == "intent", e["id"]
            )
            self.assertIn(e.get("encapsulation", "vxlan"), ["vxlan", "geneve"])
            self.assertIn(e.get("acl_action", "permit"), ["permit", "drop"])
        for n in nodes.values():
            if n.get("attr_handoff"):
                self.assertEqual(n["attr_handoff"], "service_only")

    # ---- per-conversation expectations read directly from the scenario ----

    def frontend_id(self, conv: dict) -> str:
        access = conv["access"]
        ns, name = access["service"].split("/")
        return f"k8s_service:{ARGS['cluster']}/{ns}/{name}/{access['frontend']}"

    def pod_id(self, name: str) -> str:
        uid = next(
            p["uid"] for p in SCENARIO["kubernetes"]["pods"] if p["name"] == name
        )
        return f"pod:{ARGS['cluster']}/{uid}"

    def test_every_attribution_rule_in_the_scenario(self):
        for conv in SCENARIO["conversations"]:
            basis = (conv.get("expected") or {}).get("handoff_basis")
            if not basis:
                continue
            for pod in conv["expected"]["backend_pods"]:
                with self.subTest(conv=conv["id"], pod=pod):
                    found = self.find(
                        "forwards_to",
                        self.frontend_id(conv),
                        self.pod_id(pod),
                        handoff_basis=basis,
                    )
                    self.assertEqual(len(found), 1, conv["id"])
                    landing = conv["access"].get("landing_node")
                    self.assertEqual(found[0].get("via_node"), landing, conv["id"])

    def test_contracts_match_the_scenario_classification(self):
        for conv in SCENARIO["conversations"]:
            cls = conv.get("aci_class")
            if not cls or "service" not in (conv.get("access") or {}):
                continue
            with self.subTest(conv=conv["id"]):
                found = [
                    e
                    for e in self.edges()
                    if e["relationship"] == "communicates_with"
                    and e["target"] == self.frontend_id(conv)
                ]
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].get("contract"), cls["contract"])
                self.assertEqual(found[0].get("contract_basis"), "intent")

    def test_same_node_traffic_has_no_contract(self):
        fe_b, checkout = (
            self.pod_id("frontend-7d9c6b5f4-q4m9z"),
            self.pod_id("checkout-5f8b9c7d6-m4n7q"),
        )
        (edge,) = self.find("communicates_with", fe_b, checkout)
        for key in ("contract", "contract_basis", "acl_action"):
            self.assertNotIn(key, edge)

    def test_backend_side_connections_are_consumed(self):
        backends = {
            self.pod_id(p)
            for c in SCENARIO["conversations"]
            if (c.get("expected") or {}).get("handoff_basis")
            for p in c["expected"]["backend_pods"]
        }
        vm = "vm:prod/10.30.40.25"
        for e in self.edges():
            if e["relationship"] != "communicates_with":
                continue
            self.assertFalse(
                e["source"].startswith("node:") and e["target"].startswith("pod:"),
                f"SNAT leg shown: {e['id']}",
            )
            if e["source"] == vm and e["target"] in backends:
                # Only the direct pod-IP conversation (c7) may connect the VM to a pod.
                self.assertEqual(e["target"], self.pod_id("frontend-7d9c6b5f4-q4m9z"))
                self.assertEqual(e["contract"], "win-to-pods")

    def test_dsr_dispatch_is_node_to_node_only(self):
        (edge,) = [e for e in self.edges() if e.get("transport") == "ipip"]
        self.assertTrue(edge["source"].startswith("node:"))
        self.assertTrue(edge["target"].startswith("node:"))
        summary = self.lab.search(
            'index=adm_summary source="adm:conversation" transport=ipip | stats values(encapsulation) AS enc',
            "0",
            "now",
        )
        self.assertEqual(summary[0]["enc"], "ipip")

    def test_masqueraded_internet_leg_is_not_attributed(self):
        node_a = "10.10.20.11"
        ext = "ip:prod/203.0.113.40"
        self.assertFalse(
            [e for e in self.edges() if e["target"] == ext and node_a in e["source"]]
        )
        self.assertTrue(
            self.find("communicates_with", self.pod_id("payment-2b4d6f8a1-k3j6h"), ext)
        )

    def test_blocked_attempt_is_shown_from_the_acl_log(self):
        (edge,) = self.find(
            "communicates_with", "vm:prod/10.30.40.25", "vm:prod/10.20.30.40"
        )
        self.assertEqual(edge["acl_action"], "drop")
        self.assertEqual(edge["contract_basis"], "none")
        self.assertEqual(as_list(edge["sources"]), ["aci_acllog"])

    # ---- identity, backends, routes, policy ----

    def test_service_frontend_identity_rows(self):
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where entity_kind="k8s_service" cluster="demo-cluster" | table ip port service'
        )
        got = {(r["ip"], r["port"], r["service"]) for r in rows}
        want = set()
        for s in SCENARIO["kubernetes"]["services"] + EDGE_CASES["add"]["services"]:
            if s["type"] not in ("LoadBalancer", "NodePort"):
                continue
            for p in s["ports"]:
                if s.get("load_balancer_ip"):
                    want.add((s["load_balancer_ip"], str(p["port"]), s["name"]))
                if p.get("node_port"):
                    want.add(
                        (
                            f"nodeport:demo-cluster:{p['node_port']}/tcp",
                            str(p["node_port"]),
                            s["name"],
                        )
                    )
        self.assertEqual(got, want)
        proxies = self.lab.search(
            '| inputlookup adm_ip_identity where entity_kind="k8s_node_proxy" cluster="demo-cluster" | table ip node'
        )
        nodes = SCENARIO["kubernetes"]["nodes"] + EDGE_CASES["add"]["nodes"]
        self.assertEqual(
            {(r["ip"], r["node"]) for r in proxies},
            {(n["ingress_ip"], n["name"]) for n in nodes},
        )
        # m3: the frontend keeps the Service port name, which selects the EndpointSlice port.
        (mp,) = self.lab.search(
            '| inputlookup adm_ip_identity where entity_kind="k8s_service" ip="10.50.0.21" port=8080 | table port_name target_port'
        )
        self.assertEqual((mp["port_name"], mp["target_port"]), ("http", "http"))

    def test_backends_and_routes(self):
        rows = self.lab.search(
            '| inputlookup adm_service_backends where cluster="demo-cluster" | table service pod_name ip node target_port'
        )
        got = {(r["service"], r["pod_name"]) for r in rows}
        for svc in (
            "catalog-api",
            "catalog-np",
            "cart-api",
            "checkout-api",
            "payment-np",
        ):
            self.assertTrue(any(s == svc for s, _ in got), svc)
        self.assertFalse([r for r in rows if r.get("ip") == "192.192.192.192"])
        routes = self.lab.search(
            '| inputlookup adm_service_routes where cluster="demo-cluster" | table parent_kind parent_namespace parent_name backend_namespace backend_service host'
        )
        self.assertEqual(
            {
                (
                    r["parent_kind"],
                    r["parent_namespace"],
                    r["parent_name"],
                    r["backend_namespace"],
                    r["backend_service"],
                    r["host"],
                )
                for r in routes
            },
            {
                (
                    "Gateway",
                    "shop",
                    "shop",
                    "shop",
                    "frontend",
                    "shop.example.internal",
                ),
                (
                    "Ingress",
                    "shop",
                    "shop-www",
                    "shop",
                    "frontend",
                    "www.shop.example.internal",
                ),
                (
                    "Gateway",
                    "gateway-system",
                    "shared",
                    "shop",
                    "frontend",
                    "shared.example.internal",
                ),
            },
        )

    def test_aci_policy_objects(self):
        rows = self.lab.search(
            "| inputlookup adm_aci_policy | stats count by object_kind"
        )
        counts = {r["object_kind"]: int(r["count"]) for r in rows}
        contracts = SCENARIO["fabric"]["contracts"] + EDGE_CASES["add"]["contracts"]
        self.assertEqual(counts["contract"], len(contracts))
        self.assertEqual(
            counts["entry"],
            len(
                {
                    (f["name"], e["name"])
                    for c in contracts
                    for s in c["subjects"]
                    for f in s["filters"]
                    for e in f["entries"]
                }
            ),
        )
        self.assertEqual(
            counts["subnet"],
            sum(
                len(x["subnets"])
                for o in SCENARIO["fabric"]["l3outs"]
                for x in o["ext_epgs"]
            ),
        )

    def test_pull_mode_objects_build_the_same_rows(self):
        events = pull_mode(self.kube)
        start = int(time.time()) - 1
        self.load(events)
        self.wait_for_count("index=k8s k8s.cluster.name::pull-cluster", len(events))
        for name in ("ADM - Identity builder", "ADM - Service backends"):
            self.dispatch(name, index_window=(start, int(time.time()) + 60))
        self.assertEqual(self.shape("pull-cluster"), self.shape_first)

    # ---- fabric source independence (ACI NetFlow or Nexus Dashboard) ----

    def handoffs_with(self, disabled: str, index: str) -> set:
        try:
            self.set_macros(
                {
                    disabled: "`adm_index_netflow` adm_disabled_source=1",
                    "adm_index_summary": f"index={index}",
                    "adm_summary_index_name": index,
                }
            )
            out = self.dispatch(ROLLUP, index_window=self.slice)
            self.wait_for_count(f'index={index} source="adm:conversation"', len(out))
            rows = self.lab.search(f"`adm_graph({CALL})`", *WINDOW)
        finally:
            self.restore_macros()
        return {
            (e["source"], e["target"], e["handoff_basis"], e.get("via_node"))
            for e in self.edges(rows)
            if e["relationship"] == "forwards_to"
        }

    def test_handoffs_do_not_depend_on_which_fabric_source_is_enabled(self):
        full = {
            (e["source"], e["target"], e["handoff_basis"], e.get("via_node"))
            for e in self.edges()
            if e["relationship"] == "forwards_to"
        }
        self.assertEqual(
            self.handoffs_with("adm_flows_nd", "adm_alt_nf"), full, "NetFlow only"
        )
        nd_only = self.handoffs_with("adm_flows_netflow", "adm_alt_nd")
        # Without NetFlow the DSR IPIP leg (seen only by ACI NetFlow) is missing, so the
        # receiving node of the DSR Service is unknown; every backend is still attributed.
        self.assertEqual(
            {h[:3] for h in nd_only}, {h[:3] for h in full}, "Nexus Dashboard only"
        )
        cart = [h for h in nd_only if "/cart-api/" in h[0]]
        self.assertEqual([h[3] for h in cart], [None])
        self.assertEqual(
            {h for h in nd_only if "/cart-api/" not in h[0]},
            {h for h in full if "/cart-api/" not in h[0]},
        )

    # ---- argument validation on the new stage macros ----

    def test_injection_is_rejected_by_new_stage_macros(self):
        payload = 'zzz\\" OR adm_ns!=\\"'
        for macro in ("adm_graph_handoffs", "adm_graph_contracts"):
            for position in range(4):
                args = [
                    f'"{ARGS[k]}"'
                    for k in ("service", "environment", "cluster", "namespace")
                ]
                args[position] = f'"{payload}"'
                with self.assertRaisesRegex(
                    self.lab.LabError, "Invalid graph arguments"
                ):
                    self.lab.search(
                        f"| makeresults | `{macro}({', '.join(args)})`", *WINDOW
                    )
        with self.assertRaisesRegex(
            self.lab.LabError, "adm_graph_scope_filter expects"
        ):
            self.lab.search(
                f'`adm_graph_scope_filter("demo-cluster", "{payload}")`', *WINDOW
            )

    # ---- multi-run: later batches with object updates (C1) ----

    def edge_ids(self, rows):
        return sorted(
            (
                e["relationship"],
                e["source"],
                e["target"],
                e.get("handoff_basis"),
                e.get("count"),
                e.get("contract_basis"),
            )
            for e in self.edges(rows)
        )

    def test_c1_base_graph_is_unchanged_by_later_batches(self):
        self.assertEqual(self.edge_ids(self.rows), self.edge_ids(self.rows_first))
        self.assertEqual(set(self.nodes(self.rows)), set(self.nodes(self.rows_first)))

    def backend_rows(self, service: str) -> list[dict]:
        return self.lab.search(
            f'| inputlookup adm_service_backends where cluster="demo-cluster" service="{service}" | table pod_name valid_from valid_to'
        )

    def test_c1_unchanged_endpointslice_keeps_its_interval(self):
        rows = self.backend_rows("frontend")
        self.assertEqual(len(rows), 2, rows)
        for r in rows:
            self.assertEqual(r["valid_from"], "1791363605", r)
            self.assertNotIn("valid_to", r)

    def test_c1_not_ready_endpoint_closes_and_reopens(self):
        rows = sorted(self.backend_rows("payment-np"), key=lambda r: r["valid_from"])
        self.assertEqual(
            [(r["valid_from"], r.get("valid_to")) for r in rows],
            [("1791363605", "1791375000"), ("1791376800", None)],
        )

    def test_c1_service_builder_rerun_is_idempotent(self):
        before = self.count("| inputlookup adm_service_backends")
        self.dispatch("ADM - Service backends", index_window=self.all_slices)
        self.assertEqual(self.count("| inputlookup adm_service_backends"), before)
        self.test_c1_not_ready_endpoint_closes_and_reopens()

    # ---- edge-case hand-offs (connection-level decisions) ----

    def decisions(self) -> dict:
        if not hasattr(type(self), "_decisions"):
            stages = " | ".join(
                f"`{m}({CALL})`"
                for m in ("adm_graph_inputs", "adm_graph_resolve", "adm_graph_handoffs")
            )
            rows = self.lab.search(
                f"{stages} | search adm_row=hconn | table client_ip adm_cport adm_fe_id handoff_basis adm_targets via_node",
                *EDGE_WINDOW,
            )
            type(self)._decisions = {(r["client_ip"], r["adm_cport"]): r for r in rows}
        return type(self)._decisions

    def test_edge_case_handoffs_per_connection(self):
        for conv in EDGE_CASES["conversations"]:
            exp = conv["expected"]
            if "handoff_basis" not in exp:
                continue
            ip, port = conv["wire"][0]["src"].split(":")
            with self.subTest(conv=conv["id"]):
                got = self.decisions().get((ip, port))
                self.assertIsNotNone(got, conv["id"])
                self.assertEqual(got.get("handoff_basis"), exp["handoff_basis"])
                if exp["handoff_basis"]:
                    self.assertEqual(
                        sorted(as_list(got.get("adm_targets"))),
                        sorted(self.pod_id(p) for p in exp["backend_pods"]),
                    )
                    landing = conv["access"].get("landing_node")
                    if landing:
                        self.assertEqual(as_list(got.get("via_node")), [landing])

    def test_m1_parallel_snat_connections_are_counted_once_each(self):
        cat = self.frontend_id(
            {"access": {"service": "shop/catalog-api", "frontend": "10.50.0.30:8080"}}
        )
        edges = self.find_in(
            self.edge_rows, "forwards_to", cat, self.pod_id("catalog-6a1c2d3e4-p9r5t")
        )
        self.assertEqual(
            [(e["handoff_basis"], e["count"]) for e in edges], [("hubble_xlate", "3")]
        )
        # The SNAT legs of ec-m1-parallel (43301-43303), the traced leg of ec-m1-ambiguous (43401)
        # and the time-assigned leg of ec-m2-time-ok (51601) are consumed per connection; the legs of
        # connections no rule can attribute (43402, 43901, 43902) stay visible.
        stages = " | ".join(
            f"`{m}({CALL})`"
            for m in ("adm_graph_inputs", "adm_graph_resolve", "adm_graph_handoffs")
        )
        rows = self.lab.search(
            f'{stages} | search adm_row=conv client_ip="10.10.20.11" server_ip="10.42.2.30" | table adm_conns',
            *EDGE_WINDOW,
        )
        left = {c.split("@")[0] for r in rows for c in as_list(r.get("adm_conns"))}
        self.assertEqual(left, {"43402", "43901", "43902"})

    def find_in(self, rows, relationship, source, target):
        return [
            e
            for e in self.edges(rows)
            if e["relationship"] == relationship
            and e["source"] == source
            and e["target"] == target
        ]

    def test_m3_long_flow_is_one_connection(self):
        co = self.frontend_id(
            {"access": {"service": "shop/checkout-api", "frontend": "10.50.0.20:8080"}}
        )
        (edge,) = self.find_in(
            self.edge_rows, "communicates_with", "vm:prod/10.30.40.25", co
        )
        self.assertEqual(edge["count"], "1")
        (fwd,) = self.find_in(
            self.edge_rows, "forwards_to", co, self.pod_id("checkout-5f8b9c7d6-m4n7q")
        )
        self.assertEqual(fwd["count"], "2")  # VM1's long flow and VM2's connection

    def test_m5_nodeport_on_a_node_without_app_pods(self):
        fe = "k8s_service:demo-cluster/shop/catalog-np/10.10.20.14:30081"
        (fwd,) = self.find_in(
            self.edge_rows, "forwards_to", fe, self.pod_id("catalog-6a1c2d3e4-p9r5t")
        )
        self.assertEqual(
            (fwd["handoff_basis"], fwd["via_node"]), ("hubble_xlate", "node-d")
        )

    def test_m6_shared_gateway_in_another_namespace(self):
        fe = "k8s_service:demo-cluster/gateway-system/cilium-gateway-shared/10.50.0.12:443"
        node = self.nodes(self.edge_rows)[fe]
        self.assertEqual(node["attr_route"], "shared.example.internal/ → frontend:8080")
        (fwd,) = self.find_in(
            self.edge_rows, "forwards_to", fe, self.pod_id("frontend-7d9c6b5f4-x2k8p")
        )
        self.assertEqual(
            (fwd["handoff_basis"], fwd["count"]), ("l7_forwarded_for", "2")
        )
        self.assertEqual(sorted(as_list(fwd["via_node"])), ["node-a", "node-c"])  # m4
        (conv,) = self.find_in(
            self.edge_rows, "communicates_with", "vm:prod/10.30.40.25", fe
        )
        self.assertEqual(sorted(as_list(conv["via_node"])), ["node-a", "node-c"])

    def test_m7_header_values_are_validated_before_collect(self):
        rows = self.lab.search(
            'index=adm_summary source="adm:conversation" adm_record=hubble_l7 | stats values(xff) AS xff values(trace_ids) AS t',
            "0",
            "now",
        )
        for x in as_list(rows[0].get("xff")):
            self.assertRegex(x, r"^\d+\.\d+\.\d+\.\d+$")
        for t in "|".join(as_list(rows[0].get("t"))).split("|"):
            self.assertRegex(t, r"^[0-9a-f]{32}$")

    def test_m8_contract_bases(self):
        for conv in EDGE_CASES["conversations"]:
            want = conv["expected"].get("contract_basis")
            if not want:
                continue
            c_ip, s_ip = conv["wire"][0]["src"].split(":")[0], conv["wire"][0]["dst"]
            with self.subTest(conv=conv["id"]):
                found = [
                    e
                    for e in self.edges(self.edge_rows)
                    if e["relationship"] == "communicates_with"
                    and c_ip
                    in as_list(self.nodes(self.edge_rows)[e["source"]].get("addresses"))
                    and s_ip.split(":")[0]
                    in as_list(self.nodes(self.edge_rows)[e["target"]].get("addresses"))
                    and e.get("server_port") == s_ip.split(":")[1]
                ]
                self.assertEqual(len(found), 1, conv["id"])
                self.assertEqual(found[0].get("contract_basis"), want)
                self.assertNotIn("contract", found[0])

    def test_m8_policy_completeness_switch(self):
        try:
            self.set_macros({"adm_aci_policy_complete": "1"})
            rows = self.lab.search(f"`adm_graph({CALL})`", *EDGE_WINDOW)
        finally:
            self.restore_macros()
        bases = {
            e.get("server_port"): e.get("contract_basis")
            for e in self.edges(rows)
            if e["relationship"] == "communicates_with"
            and e["target"].endswith("3f71df45-2ba1-555e-8c88-c22276d1ebe6")
            and e["source"] == "vm:prod/10.30.40.26"
        }
        self.assertEqual(
            bases, {"9443": "not_evaluated", "9444": "none", "9445": "not_evaluated"}
        )

    def test_m9_acl_record_reported_by_several_polls_counts_once(self):
        raw = self.count(
            "index=cisco_dc component=acllogPermitL3Pkt srcIp=10.30.40.26 srcPort=52301"
        )
        self.assertEqual(raw, 3)
        co = self.frontend_id(
            {"access": {"service": "shop/checkout-api", "frontend": "10.50.0.20:8080"}}
        )
        (edge,) = self.find_in(
            self.edge_rows, "communicates_with", "vm:prod/10.30.40.26", co
        )
        self.assertEqual((edge["acl_action"], edge["acl_permits"]), ("permit", "1"))

    def test_hostnet_pod_marks_but_never_owns_the_node_address(self):
        kinds = {
            r["entity_kind"]
            for r in self.lab.search(
                '| inputlookup adm_ip_identity where ip="10.10.20.12" | table entity_kind'
            )
        }
        self.assertEqual(kinds, {"k8s_node", "k8s_hostnet_pod", "endpoint"})
        (edge,) = self.find_in(
            self.edge_rows,
            "communicates_with",
            self.pod_id("payment-2b4d6f8a1-k3j6h"),
            "node:demo-cluster/node-b",
        )
        self.assertEqual(edge["contract_basis"], "intra_epg")

    def test_zz_m4_connection_cap_is_reported_and_creates_no_phantom_edges(self):
        try:
            self.set_macros(
                {
                    "adm_conn_cap": "2",
                    "adm_index_summary": "index=adm_alt_x",
                    "adm_summary_index_name": "adm_alt_x",
                }
            )
            out = self.dispatch(ROLLUP, index_window=self.all_slices)
            self.wait_for_count('index=adm_alt_x source="adm:conversation"', len(out))
            rows = self.lab.search(f"`adm_graph({CALL})`", *EDGE_WINDOW)
        finally:
            self.restore_macros()
        (meta,) = [r for r in rows if r["row_type"] == "meta"]
        self.assertTrue(
            any(
                "listed only the first 2 connections" in w
                for w in as_list(meta.get("warnings"))
            ),
            meta,
        )
        catalog = self.pod_id("catalog-6a1c2d3e4-p9r5t")
        for e in self.edges(rows):
            self.assertFalse(
                e["source"].startswith("vm:") and e["target"] == catalog, e["id"]
            )
        cat = "k8s_service:demo-cluster/shop/catalog-api/10.50.0.30:8080"
        bases = {
            e["handoff_basis"] for e in self.find_in(rows, "forwards_to", cat, catalog)
        }
        self.assertEqual(bases, {"hubble_xlate"})

    def test_zz_sampling_and_dsr_opt_injections(self):
        """Test-only events (not fixtures): a sampled copy of ec-m2-time-ok's NetFlow record, and
        the VM->pod leg that DSR with loadBalancer.dsrDispatch=opt would put on the fabric for c4."""
        base = [
            json.loads(line)
            for line in (EDGE / "stream_netflow.ndjson").read_text().splitlines()
        ]
        rec = next(
            e
            for e in base
            if e["event"]["src_ip"] == "10.30.40.26"
            and e["event"].get("src_port") == 51601
        )
        sampled = json.loads(json.dumps(rec))
        sampled["event"].update(exporter_sampling_interval=100, seqnumber=9_000_001)
        main = [
            json.loads(line)
            for line in (RAW / "stream_netflow.ndjson").read_text().splitlines()
        ]
        c4 = next(
            e
            for e in main
            if e["event"]["src_ip"] == "10.30.40.25"
            and e["event"].get("src_port") == 51005
        )
        opt = json.loads(json.dumps(c4))
        opt["event"].update(
            dest_ip="10.42.2.50", exporter_ip="192.0.2.102", seqnumber=9_000_002
        )
        self.load([sampled, opt])
        self.wait_for_count("index=netflow seqnumber>=9000001", 2)
        end = int(time.time()) + 1
        time.sleep(2)
        try:
            self.set_macros(
                {
                    "adm_index_summary": "index=adm_alt_y",
                    "adm_summary_index_name": "adm_alt_y",
                }
            )
            out = self.dispatch(ROLLUP, index_window=(self.all_slices[0], end))
            self.wait_for_count('index=adm_alt_y source="adm:conversation"', len(out))
            edge_rows = self.lab.search(f"`adm_graph({CALL})`", *EDGE_WINDOW)
            base_rows = self.lab.search(f"`adm_graph({CALL})`", *WINDOW)
        finally:
            self.restore_macros()
        fe = "k8s_service:demo-cluster/shop/catalog-np/10.10.20.11:30081"
        self.assertFalse(
            [
                e
                for e in self.edges(edge_rows)
                if e["source"] == fe and e["relationship"] == "forwards_to"
            ]
        )
        self.assertFalse(
            self.find_in(
                base_rows,
                "communicates_with",
                "vm:prod/10.30.40.25",
                self.pod_id("cart-4c2e5a7b9-w8v2c"),
            )
        )
        (meta,) = [r for r in base_rows if r["row_type"] == "meta"]
        self.assertTrue(
            any("dsrDispatch opt" in w for w in as_list(meta.get("warnings"))), meta
        )

    # ---- topology ----

    def test_topology(self):
        devices = {
            r["device_id"]: r for r in self.topology if r["row_type"] == "device"
        }
        self.assertEqual(set(devices), set(TOPOLOGY["devices"]))
        for name, attrs in TOPOLOGY["devices"].items():
            for key, value in attrs.items():
                self.assertEqual(devices[name].get(key), value, f"{name}.{key}")
        links = {
            (
                r["link_source"],
                r["a_device"],
                r.get("a_interface"),
                r["b_device"],
                r.get("b_interface") if r["link_source"] != "lldp" else None,
            )
            for r in self.topology
            if r["row_type"] == "link"
        }
        self.assertEqual(links, {tuple(x) for x in TOPOLOGY["links"]})
        (meta,) = [r for r in self.topology if r["row_type"] == "meta"]
        for key, value in TOPOLOGY["meta"].items():
            self.assertEqual(meta.get(key), value, key)
        self.assertNotIn("warnings", meta)


if __name__ == "__main__":
    unittest.main()
