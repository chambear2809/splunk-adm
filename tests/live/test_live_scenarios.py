"""Read-only live checks for the Atlas lab scenarios in docs/operators/LIVE_SCENARIOS.md.

Skipped unless ADM_LIVE=1. ADM_LIVE_SEARCH names an executable that takes
``SPL EARLIEST`` as arguments and prints oneshot CSV results from the Atlas app
context (for example a wrapper around the splunk-cisco-skills REST helper). It
must read credentials itself; nothing secret is passed on the command line.

Lab addresses default to the 2026-11 lab and can be overridden by environment.
Checks for the Atlas gaps found during the live runs (gaps 1, 5, 6, 7 and 8) are
normal assertions; they need an Atlas build that includes the fixes (and, for
gap 7, one identity-builder backfill over the affected index window).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIVE = os.environ.get("ADM_LIVE") == "1"
HELPER = os.environ.get("ADM_LIVE_SEARCH", "")


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


SRC = env("ADM_LIVE_SRC", "10.110.96.3")
DST = env("ADM_LIVE_DST", "10.110.97.2")
SAME_HOST = env("ADM_LIVE_SAME_HOST", "10.110.96.4,10.110.96.6").split(",")
BLOCKED = env("ADM_LIVE_BLOCKED", "10.110.96.50,10.101.255.41,7680").split(",")
L3OUT_IP = env("ADM_LIVE_L3OUT_IP", "10.110.254.6")
LEAVES = dict(
    item.split("=")
    for item in env("ADM_LIVE_LEAF_EXPORTERS", "101=10.110.5.2,102=10.110.5.3").split(
        ","
    )
)
K8S_NAMESPACE_PREFIX = env("ADM_LIVE_POD_PREFIX", "teastore-")
POLL_SECONDS = 300


def search(spl: str, earliest: str = "-15m") -> list[dict[str, str]]:
    out = subprocess.run(
        [HELPER, spl, earliest], capture_output=True, text=True, timeout=600, check=True
    ).stdout
    text = out.strip()
    if text.startswith("<?xml") or "<response>" in text[:200]:
        raise AssertionError(f"search failed: {text[:400]}")
    if not text:
        return []
    return list(csv.DictReader(io.StringIO(text)))


def multi(value: str | None) -> list[str]:
    return [v for v in (value or "").split("\n") if v]


def trace(src: str, dst: str, earliest: str = "-15m") -> list[dict[str, str]]:
    return search(f'`adm_path_trace("{src}","{dst}")`', earliest)


def rows_of(rows, row_type):
    return [r for r in rows if r.get("row_type") == row_type]


def netflow_exporters(rows) -> set[str]:
    return {
        r["observer_device"]
        for r in rows_of(rows, "observation")
        if r.get("flow_source") == "netflow"
    }


@unittest.skipUnless(LIVE and HELPER, "set ADM_LIVE=1 and ADM_LIVE_SEARCH")
class LiveScenarioChecks(unittest.TestCase):
    """Evidence shapes Atlas must keep producing for the lab scenarios."""

    def test_a_vm_attachment_matches_observing_vds_exporter(self):
        rows = trace(SRC, DST)
        ports = [
            r
            for r in rows_of(rows, "link")
            if r.get("link_kind") == "virtual_port" and r.get("ip") == DST
        ]
        self.assertTrue(ports, "no vSphere virtual port for the destination VM")
        hosts = {r["hypervisor"] for r in ports}
        mgmt = {
            r["mgmt_ip"]
            for r in rows_of(rows, "device")
            if r.get("device_id") in hosts and r.get("mgmt_ip")
        }
        self.assertTrue(mgmt, "destination hypervisor has no management address")
        self.assertTrue(
            mgmt & netflow_exporters(rows),
            f"hypervisor {mgmt} did not export IPFIX for the pair; after a vMotion "
            "the VDS exporter and ACI rsHyper must move together",
        )
        self.assertTrue(all(r.get("attach_interface") for r in ports))

    def test_b_leaf_observers_are_known_vpc_leaves(self):
        rows = trace(SRC, DST)
        leaves = netflow_exporters(rows) & set(LEAVES.values())
        self.assertTrue(leaves, "no leaf exporter observed the pair")
        for r in rows_of(rows, "observation"):
            if r.get("observer_device") in LEAVES.values():
                self.assertRegex(r["observer"], r"ifIndex 3690987\d\d")

    def test_c_acl_drop_rows_name_the_enforcing_leaf(self):
        src, dst, port = BLOCKED
        drops = [
            r
            for r in rows_of(trace(src, dst, "-24h"), "observation")
            if r.get("flow_source") == "aci_acllog"
        ]
        if not drops:
            self.skipTest("no ACI ACL-log records for the blocked pair in 24 h")
        for r in drops:
            self.assertRegex(r["observer_device"], r"^pod-\d+/node-\d+$")
            self.assertEqual(r["drops"], r["records"])
            self.assertIn(port, multi(r["dest_ports"]))

    def test_c_acl_drops_in_window_are_fresh(self):
        """adm_path_trace counts each buffered acllog record once, from its first
        poll, by its own timeStamp: re-polled old drops are not in the window."""
        src, dst, _ = BLOCKED
        floor = time.time() - 900 - 60
        polled = search(
            'search `adm_index_dcn` sourcetype="cisco:dc:aci:class" '
            f'component="acllogDropL3Pkt" srcIp="{src}" dstIp="{dst}" | stats count',
            "-15m",
        )
        if not int(polled[0]["count"]):
            self.skipTest("no ACL-log polls for the blocked pair in 15 min")
        rows = [
            r
            for r in rows_of(trace(src, dst), "observation")
            if r.get("flow_source") == "aci_acllog"
        ]
        for r in rows:
            self.assertGreaterEqual(float(r["first_seen"]), floor, r["observer"])
            self.assertLessEqual(int(r["drops"]), int(polled[0]["count"]))

    def test_e_l3out_traffic_seen_only_at_border_leaf(self):
        att = search(
            'search `adm_index_dcn` sourcetype="cisco:dc:aci:class" '
            f'component=l3extRsPathL3OutAtt addr="{L3OUT_IP}/*" '
            "| dedup dn | table dn addr",
            "-1h",
        )
        self.assertTrue(att, "l3extRsPathL3OutAtt not collected for the L3Out IP")
        border = {
            part.split("-")[1]
            for r in att
            for part in r["dn"].split("/")
            if part.startswith("paths-")
        }
        rows = trace(SRC, L3OUT_IP)
        leaves = netflow_exporters(rows) & set(LEAVES.values())
        self.assertTrue(leaves, "no leaf observed the L3Out flow")
        self.assertEqual(leaves, {LEAVES[n] for n in border if n in LEAVES})
        isis = [
            r
            for r in rows_of(rows, "fabric_evidence")
            if r.get("evidence_kind") == "isis_adjacency"
        ]
        self.assertTrue(
            any(r["node"].endswith(f"node-{n}") for r in isis for n in border)
        )

    def test_e_l3out_address_has_attachment(self):
        """The L3Out SVI address is on a border-leaf path (l3extRsPathL3OutAtt):
        adm_path_trace returns that path, so the trace ends at the border leaf."""
        rows = trace(SRC, L3OUT_IP)
        ip = ipaddress.ip_address(L3OUT_IP)
        paths = [
            r
            for r in rows_of(rows, "l3out_path")
            if r.get("address")
            and ip in ipaddress.ip_network(r["address"], strict=False)
        ]
        self.assertTrue(paths, "no L3Out path row whose interface subnet has the IP")
        self.assertTrue(all(multi(r["nodes"]) for r in paths))

    def test_f_same_host_same_segment_is_vds_only(self):
        a, b = SAME_HOST
        rows = trace(a, b)
        exporters = netflow_exporters(rows)
        self.assertTrue(exporters, "no IPFIX for the same-host pair")
        self.assertFalse(exporters & set(LEAVES.values()), "leaf saw a host-local flow")
        hosts = {
            r["ip"]: r["hypervisor"]
            for r in rows_of(rows, "link")
            if r.get("link_kind") == "virtual_port" and r.get("ip") in (a, b)
        }
        self.assertEqual(len(set(hosts.values())), 1, hosts)

    def test_f_device_flows_truncation_shape(self):
        leaf = next(iter(LEAVES.values()))
        rows = search(f'`adm_device_flows("{leaf}")`', "-1h")
        self.assertTrue(rows)
        self.assertLessEqual(len(rows), 200)
        total = int(rows[0]["total_conversations"])
        self.assertGreaterEqual(total, len(rows))
        self.assertEqual({r["truncated"] for r in rows}, {"1" if total > 200 else "0"})

    def test_f_selected_source_probes_are_fresh(self):
        config = json.loads((ROOT / "config/deployment-health.json").read_text())
        stale = {
            s["probeMacro"]: s["staleAfterSeconds"]
            for s in (o for o in _objects(config) if "probeMacro" in o)
            if s["id"] in ("aci", "netflow", "k8s")
        }
        for macro, limit in stale.items():
            with self.subTest(macro=macro):
                row = search(f"| `{macro}`", "-1m")[0]
                self.assertEqual(row["status"], "ok")
                age = time.time() - float(row["latest_event"])
                self.assertLessEqual(age, limit, f"{macro} stale for {age:.0f}s")

    def test_d_rescheduled_pod_intervals_do_not_overlap_per_ip(self):
        rows = search(
            "| inputlookup adm_ip_identity where entity_kind=pod "
            f'| search entity_name="{K8S_NAMESPACE_PREFIX}*" scope!="unmapped:*" '
            "| table ip entity_name valid_from valid_to",
            "-1m",
        )
        self.assertTrue(rows)
        open_by_ip: dict[str, set[str]] = {}
        for r in rows:
            if not r.get("valid_to"):
                open_by_ip.setdefault(r["ip"], set()).add(r["entity_name"])
        for ip, names in open_by_ip.items():
            self.assertEqual(len(names), 1, f"{ip} has several open pod identities")

    def test_d_deleted_pods_have_closed_intervals(self):
        """Pods with a kube:object:pods DELETED event have closed intervals (the
        builder reads the watch type from _raw; automatic JSON extraction stops
        at 10240 characters)."""
        deleted = {
            r["name"]
            for r in search(
                "search `adm_index_k8s` sourcetype=kube:object:pods DELETED "
                '| spath path=type output=type | where type=="DELETED" '
                "| spath path=object.metadata.name output=name | dedup name "
                "| table name",
                "-7d",
            )
        }
        open_rows = search(
            "| inputlookup adm_ip_identity where entity_kind=pod "
            '| where isnull(valid_to) OR valid_to="" | table entity_name',
            "-1m",
        )
        self.assertFalse(deleted & {r["entity_name"] for r in open_rows})

    def test_d_running_pods_have_identity(self):
        """Every pod whose newest watch event carries a pod IP has an identity
        row for that IP, including pods whose objects exceed 10240 characters."""
        latest = search(
            "search `adm_index_k8s` sourcetype=kube:object:pods "
            f'"{K8S_NAMESPACE_PREFIX}" '
            '| eval type=spath(_raw, "type"), '
            'name=spath(_raw, "object.metadata.name"), '
            'ip=spath(_raw, "object.status.podIP"), '
            'ns=spath(_raw, "object.metadata.namespace") '
            "| where isnotnull(name) | dedup name "
            '| where type!="DELETED" AND isnotnull(ip) | table name ip',
            "-24h",
        )
        if not latest:
            self.skipTest("no pod watch events with an IP in 24 h")
        known = {
            (r["entity_name"], r["ip"])
            for r in search(
                "| inputlookup adm_ip_identity where entity_kind=pod "
                "| table entity_name ip",
                "-1m",
            )
        }
        missing = [
            (r["name"], r["ip"]) for r in latest if (r["name"], r["ip"]) not in known
        ]
        self.assertFalse(missing)

    def test_g_hubble_flows_reach_pod_pair_traces(self):
        """adm_path_trace reads Hubble flows (every verdict) for pod addresses."""
        pair = search(
            "search `adm_index_hubble` `adm_hubble_sourcetypes` "
            f'"{K8S_NAMESPACE_PREFIX}" '
            '| eval s=spath(_raw, "flow.IP.source"), d=spath(_raw, "flow.IP.destination") '
            "| stats count by s d | sort - count | head 1",
            "-15m",
        )
        if not pair:
            self.skipTest("no Hubble flows in 15 min")
        rows = rows_of(trace(pair[0]["s"], pair[0]["d"]), "observation")
        hubble = [r for r in rows if r.get("flow_source") == "hubble"]
        self.assertTrue(hubble)
        self.assertTrue(all(r["observer"].startswith("hubble:") for r in hubble))

    def test_h_trace_ports_are_service_ports(self):
        """Trace services are listener ports; client source ports stay apart."""
        rows = [
            r
            for r in rows_of(trace(SRC, DST), "observation")
            if r.get("flow_source") == "netflow"
        ]
        self.assertTrue(rows)
        services = {s for r in rows for s in multi(r["services"])}
        self.assertTrue(services, "no services on the pair's observations")
        clients = {p for r in rows for p in multi(r.get("client_ports"))}
        self.assertFalse({s.split("/")[-1] for s in services} & clients)


def _objects(value):
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _objects(v)
    elif isinstance(value, list):
        for v in value:
            yield from _objects(v)


if __name__ == "__main__":
    unittest.main()
