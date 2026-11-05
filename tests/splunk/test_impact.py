"""adm_impact_* macros against the local Splunk lab.

Skipped unless ADM_LAB=1. Prerequisites: `tests/splunk/lab.sh up` and `tests/splunk/lab.sh install`.
Resets the lab indexes, loads fixtures/raw-aci/*.ndjson plus the raw-vmware VDS IPFIX,
hvsAdj/compHpNic and IS-IS/COOP records, builds adm_ip_identity, and checks the bounded
blast-radius search. Expectations come from fixtures/raw-aci/scenario.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ACI = json.loads((ROOT / "fixtures" / "raw-aci" / "scenario.json").read_text("utf-8"))
WINDOW = ("1791370800", "1791376200")
SWITCH = {s["name"]: s for s in ACI["fabric"]["switches"]}
VM = {v["name"]: v for v in ACI["vms"]}


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class ImpactMacrosTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        subprocess.run([str(HERE / "lab.sh"), "reset"], check=True, capture_output=True)
        lab.wait_ready()
        files = sorted((ROOT / "fixtures" / "raw-aci").glob("*.ndjson")) + [
            ROOT / "fixtures" / "raw-vmware" / "vds_ipfix.ndjson",
            ROOT / "fixtures" / "raw-vmware" / "aci_vmm_adjacency.ndjson",
            ROOT / "fixtures" / "raw-vmware" / "aci_fabric_evidence.ndjson",
            ROOT / "fixtures" / "raw-vmware" / "aci_port_channels.ndjson",
        ]
        sent = lab.load(files)
        deadline = time.time() + 180
        while time.time() < deadline:
            got = int(
                lab.search("search index=* NOT index=_* | stats count", "0", "now")[0][
                    "count"
                ]
            )
            if got >= sent:
                break
            time.sleep(2)
        # lab.sh reset clears event data only; identities left by earlier lab
        # tests (for example the edge-case node-d) must not leak into this one.
        # The KV Store can still be initializing right after the reset.
        deadline = time.time() + 300
        while True:
            try:
                lab._mgmt(
                    "DELETE",
                    "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity",
                )
                break
            except lab.LabError as error:
                initializing = "KV Store is initializing" in str(error)
                if not initializing or time.time() > deadline:
                    raise
                time.sleep(5)
        lab.search("| `adm_identity_build`", *WINDOW)

    def search(self, spl: str) -> list[dict]:
        return self.lab.search(spl, *WINDOW)

    def conversations(self, spl: str) -> list[dict]:
        return [r for r in self.search(spl) if r.get("row_type") == "conversation"]

    def test_observer_anchor_returns_conversations_exported_there(self):
        leaf = SWITCH["leaf-103"]["oob"]
        rows = self.conversations(f"| `adm_impact_element({leaf};pod-1/node-103,-)`")
        self.assertTrue(rows)
        for r in rows:
            self.assertTrue(
                any(
                    o.startswith(f"netflow:{leaf}:") or o == "aci_acllog:pod-1/node-103"
                    for o in as_list(r["observers"])
                ),
                r,
            )
            self.assertEqual(r["source"], "raw")
        by_pair = {(r["src"], r["dst"], r.get("dest_port")): r for r in rows}
        db, client = VM["orders-db-01"]["ip"], VM["win-client-01"]["ip"]
        # c8 is dropped at leaf-103: seen only in its ACL log.
        self.assertEqual(by_pair[(client, db, "5432")]["drops"], "1")

    def test_endpoint_anchor_sees_every_exporter_of_that_address(self):
        db = VM["orders-db-01"]["ip"]
        rows = self.conversations(f"| `adm_impact_element(-,{db})`")
        self.assertTrue(rows)
        self.assertTrue(all(db in (r["src"], r["dst"]) for r in rows))
        observers = {o for r in rows for o in as_list(r["observers"])}
        # The esx-03 VDS IPFIX record and the leaf-103 NetFlow record of c8.
        self.assertTrue(any(o.startswith("netflow:192.0.2.73:") for o in observers))
        self.assertIn("aci_acllog:pod-1/node-103", observers)

    def test_identity_enrichment_names_both_ends(self):
        db, client = VM["orders-db-01"]["ip"], VM["win-client-01"]["ip"]
        rows = self.conversations(f"| `adm_impact_element(-,{db})`")
        row = next(r for r in rows if r["src"] == client and r["dst"] == db)
        self.assertEqual(row["dst_name"], "orders-db-01")
        self.assertIn("vm", as_list(row["dst_kinds"]))
        self.assertEqual(row["src_name"], "win-client-01")
        nodes = [
            r
            for r in self.search(f"| `adm_impact_element(-,{db})`")
            if r.get("row_type") == "k8s_node"
        ]
        self.assertEqual(
            sorted(r["entity_name"] for r in nodes),
            sorted(n["name"] for n in ACI["kubernetes"]["nodes"]),
        )

    def test_kubernetes_ends_carry_their_node(self):
        node_a = next(n for n in ACI["kubernetes"]["nodes"] if n["name"] == "node-a")
        rows = self.conversations(
            f"| `adm_impact_element({SWITCH['leaf-102']['oob']},-)`"
        )
        placed = {
            r[side]: r[f"{side}_node"]
            for r in rows
            for side in ("src", "dst")
            if r.get(f"{side}_node")
            and {"k8s_node", "k8s_node_proxy"} & set(as_list(r.get(f"{side}_kinds")))
        }
        self.assertEqual(placed.get(node_a["ip"]), "node-a")
        self.assertEqual(placed.get(node_a["ingress_ip"]), "node-a")

    def test_totals_are_bounded_and_consistent(self):
        spl = (
            "| `adm_impact_element("
            + ";".join(SWITCH[n]["oob"] for n in ("leaf-101", "leaf-102", "leaf-103"))
            + ",-)`"
        )
        rows = self.conversations(spl)
        self.assertLessEqual(len(rows), 500)
        totals = {r["total_conversations"] for r in rows}
        self.assertEqual(totals, {str(len(rows))})
        self.assertEqual({r["truncated"] for r in rows}, {"0"})
        self.assertEqual(
            int(rows[0]["total_bytes"]), sum(int(r.get("bytes") or 0) for r in rows)
        )
        self.assertEqual(
            [r for r in rows if r["bytes"]],
            sorted([r for r in rows if r["bytes"]], key=lambda r: -int(r["bytes"])),
        )

    def test_raw_and_summary_readers_share_one_contract(self):
        leaf = SWITCH["leaf-103"]["oob"]
        key = lambda rs: sorted(  # noqa: E731
            (r["src"], r["dst"], r.get("dest_port"), r["bytes"])
            for rs_ in [rs]
            for r in rs_
        )
        seam = self.conversations(f"| `adm_impact_element({leaf},-)`")
        raw = self.conversations(f"| `adm_impact_element({leaf},-,raw)`")
        summary = self.conversations(f"| `adm_impact_element({leaf},-,summary)`")
        self.assertEqual(key(seam), key(raw))
        self.assertEqual(key(raw), key(summary))

    def test_invalid_tokens_are_rejected_before_search(self):
        for spl in (
            '| `adm_impact_element(192.0.2.103" OR index=*,-)`',
            "| `adm_impact_element(-,leaf-101)`",
            "| `adm_impact_element(-,-,both)`",
            "| `adm_impact_element(-,1-2)`",
            "| `adm_impact_element(-,10.0.0.1;-)`",
        ):
            with self.assertRaises(Exception, msg=spl):
                self.search(spl)

    def test_inventory_carries_redundancy_evidence(self):
        rows = self.search("| `adm_impact_inventory`")
        uplinks = [r for r in rows if r.get("link_kind") == "uplink"]
        self.assertEqual(len(uplinks), len(ACI["hypervisors"]))
        ports = [r for r in rows if r.get("link_kind") == "virtual_port"]
        self.assertEqual(sorted(r["b_device_name"] for r in ports), sorted(VM))
        for r in ports:
            leaf = SWITCH[VM[r["b_device_name"]]["leaf"]]
            self.assertEqual(
                as_list(r["attach_nodes"]), [f"pod-1/node-{leaf['node_id']}"]
            )
        nodes = {r.get("aci_node") for r in rows if r.get("row_type") == "device"}
        self.assertTrue({"pod-1/node-201", "pod-1/node-202"} <= nodes)

    def test_members_resolve_an_epg_to_addresses(self):
        rows = self.search("| `adm_impact_members(db)`")
        self.assertEqual([r["ip"] for r in rows], [VM["orders-db-01"]["ip"]])

    def test_port_channels_map_policy_groups_to_member_ports(self):
        rows = [
            r
            for r in self.search("| `adm_impact_inventory`")
            if r.get("row_type") == "port_channel"
        ]
        got = sorted(
            (r["node"], r["port_channel"], r["policy"], tuple(as_list(r["members"])))
            for r in rows
        )
        self.assertEqual(
            got,
            [
                ("pod-1/node-102", "po3", "esx-01-pc", ("eth1/6",)),
                ("pod-1/node-103", "po4", "esx-03-pc", ("eth1/5",)),
            ],
        )

    def test_port_channels_before_collection_use_the_next_snapshot(self):
        # A window that ends before pcAggrIf/pcRsMbrIfs were first collected
        # (and more than the inventory lookback before them) still resolves
        # vPC membership, from the first snapshot after it, marked as such.
        inside = [
            r
            for r in self.search("| `adm_impact_port_channels`")
            if r.get("row_type") == "port_channel"
        ]
        self.assertTrue(inside)
        self.assertEqual({r["after_window"] for r in inside}, {"0"})
        rows = [
            r
            for r in self.lab.search(
                "| `adm_impact_port_channels`", "1791350000", "1791360000"
            )
            if r.get("row_type") == "port_channel"
        ]
        got = sorted(
            (r["node"], r["port_channel"], r["policy"], tuple(as_list(r["members"])))
            for r in rows
        )
        self.assertEqual(
            got,
            [
                ("pod-1/node-102", "po3", "esx-01-pc", ("eth1/6",)),
                ("pod-1/node-103", "po4", "esx-03-pc", ("eth1/5",)),
            ],
        )
        for r in rows:
            self.assertEqual(r["after_window"], "1", r)
            self.assertGreater(float(r["snapshot_time"]), 1791360000)

    def test_port_channels_drop_members_removed_since_an_earlier_poll(self):
        # Two polls of the same APIC, 300 s apart, after every other test
        # window: the earlier one still lists eth1/7 in po3 and a po9 on
        # node-104; the newest one does not. Only the newest poll counts.
        import tempfile

        template = [
            json.loads(line)
            for line in (ROOT / "fixtures/raw-vmware/aci_port_channels.ndjson")
            .read_text()
            .splitlines()
        ][:2]
        aggr, member = template

        def at(record, t, old, new):
            out = dict(record, time=float(t))
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))
            out["event"] = stamp + record["event"][19:].replace(old, new)
            return out

        stale, current = 1791390000, 1791390300
        events = [
            at(aggr, stale, "", ""),
            at(member, stale, "", ""),
            at(member, stale, "eth1/6", "eth1/7"),
            at(aggr, stale, "node-102/sys/aggr-[po3]", "node-104/sys/aggr-[po9]"),
            at(aggr, current, "", ""),
            at(member, current, "", ""),
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False) as f:
            f.write("\n".join(json.dumps(e) for e in events) + "\n")
        try:
            self.lab.load([Path(f.name)])
        finally:
            Path(f.name).unlink()
        window = (str(stale - 600), str(current + 60))
        deadline = time.time() + 120
        while True:
            count = self.lab.search(
                'search index=cisco_dc sourcetype="cisco:dc:aci:class" '
                "(component=pcAggrIf OR component=pcRsMbrIfs) | stats count",
                *window,
            )
            if int(count[0]["count"]) >= len(events) or time.time() > deadline:
                break
            time.sleep(2)
        rows = [
            r
            for r in self.lab.search("| `adm_impact_port_channels`", *window)
            if r.get("row_type") == "port_channel"
        ]
        got = sorted(
            (r["node"], r["port_channel"], tuple(as_list(r["members"]))) for r in rows
        )
        self.assertEqual(got, [("pod-1/node-102", "po3", ("eth1/6",))])

    def test_directions_merge_into_one_client_to_listener_row(self):
        leaves = ";".join(
            SWITCH[n]["oob"] for n in ("leaf-101", "leaf-102", "leaf-103")
        )
        rows = self.conversations(f"| `adm_impact_element({leaves},-)`")
        pairs = [(r["src"], r["dst"], r["dest_port"], r["protocol"]) for r in rows]
        self.assertEqual(len(pairs), len(set(pairs)))
        unordered = [(frozenset((s, d)), p, t) for s, d, p, t in pairs]
        self.assertEqual(len(unordered), len(set(unordered)), "a reverse twin remains")
        client = VM["win-client-01"]["ip"]
        cart = next(r for r in rows if r["src"] == client and r["dst"] == "10.50.0.40")
        self.assertEqual(cart["dest_port"], "8080")
        self.assertEqual(cart["directions"], "both")
        self.assertEqual(
            int(cart["bytes"]), int(cart["bytes_fwd"]) + int(cart["bytes_rev"])
        )
        self.assertFalse([r for r in rows if r["dest_port"] == "51005"])

    def test_hubble_workload_pairs_and_hosted_apps(self):
        rows = self.search(f"| `adm_impact_element({SWITCH['leaf-102']['oob']},-)`")
        hubble = [r for r in rows if r.get("row_type") == "hubble_apps"]
        self.assertIn(
            ("node-b", "frontend"), {(r["dst_node"], r["dst_app"]) for r in hubble}
        )
        self.assertTrue(all(r.get("first_seen") and r.get("last_seen") for r in hubble))
        hosted = [r for r in rows if r.get("row_type") == "hosted"]
        for r in hosted:
            self.assertTrue(r.get("node") and as_list(r.get("hosted_apps")))


if __name__ == "__main__":
    unittest.main()
