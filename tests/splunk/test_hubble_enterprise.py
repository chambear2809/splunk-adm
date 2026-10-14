"""Isovalent Enterprise Hubble export against the local Splunk lab.

Skipped unless ADM_LAB=1. Prerequisites: `tests/splunk/lab.sh up` and `tests/splunk/lab.sh install`
with the current splunk_app/splunk_adm. The input is a real export from an ephemeral Isovalent
Enterprise lab (fixtures/samples/hubble-enterprise/README.md), sent unchanged as the HEC event body.
Expectations come from classifying the exported JSON here with the rules documented for
adm_flows_hubble, not from search output.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import time
import unittest
from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SAMPLE = (
    ROOT / "fixtures" / "samples" / "hubble-enterprise" / "enterprise-hubble.ndjson"
)
CONTAINER = "adm-splunk-lab"
APP_DIR = "/opt/splunk/etc/apps/splunk_adm"
INDEX_SPL = 'index=cilium_hubble sourcetype="cilium:hubble:flow"'
FIELDS = (
    "adm_kind adm_source adm_src_ip adm_dest_ip adm_src_port adm_dest_port adm_transport "
    "adm_observer adm_scope_observer adm_start adm_xff adm_trace_id"
)


def iso_epoch(value: str) -> float:
    """RFC 3339 with up to nanosecond digits; datetime alone stops at microseconds."""
    head, _, frac = value.rstrip("Z").partition(".")
    base = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return base.timestamp() + (float(f"0.{frac}") if frac else 0.0)


def ports(flow: dict) -> tuple[int | None, int | None, str | None]:
    l4 = flow.get("l4") or {}
    for proto in ("TCP", "UDP", "SCTP"):
        if proto in l4:
            return (
                l4[proto].get("source_port"),
                l4[proto].get("destination_port"),
                proto.lower(),
            )
    if "ICMPv4" in l4:
        return None, None, "icmp"
    if "ICMPv6" in l4:
        return None, None, "ipv6-icmp"
    return None, None, None


def rightmost_xff(flow: dict) -> str | None:
    headers = ((flow.get("l7") or {}).get("http") or {}).get("headers") or []
    values = [
        h.get("value", "")
        for h in headers
        if h.get("key", "").lower() == "x-forwarded-for"
    ]
    last = ",".join(values).split(",")[-1].strip() if values else ""
    try:
        return str(ip_address(last))
    except ValueError:
        return None


def classify(flow: dict) -> str | None:
    """Kind adm_flows_hubble should assign, per its description in macros.conf."""
    kind, point = flow.get("Type"), flow.get("trace_observation_point")
    if (
        kind == "L3_L4"
        and point == "TO_ENDPOINT"
        and flow.get("verdict") == "FORWARDED"
        and flow.get("is_reply") is not True
    ):
        return "conv"
    if (
        kind == "L3_L4"
        and point == "TO_NETWORK"
        and (flow.get("IP") or {}).get("source_xlated")
    ):
        return "xlate"
    if (
        kind == "L7"
        and str((flow.get("l7") or {}).get("type", "")).lower() == "request"
    ):
        return "l7" if rightmost_xff(flow) else None
    return None


def tuple_of(flow: dict) -> tuple:
    sport, dport, transport = ports(flow)
    return (
        flow["IP"]["source"],
        flow["IP"]["destination"],
        None if sport is None else str(sport),
        None if dport is None else str(dport),
        transport,
    )


def load_sample() -> tuple[list[str], list[dict]]:
    lines = [line for line in SAMPLE.read_text("utf-8").splitlines() if line.strip()]
    return lines, [json.loads(line) for line in lines]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class HubbleEnterpriseExportTest(unittest.TestCase):
    rows: list[dict]

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        subprocess.run([str(HERE / "lab.sh"), "reset"], check=True, capture_output=True)
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
        lab._mgmt("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")
        cls.lines, cls.events = load_sample()
        envelopes = [
            {
                "time": f"{iso_epoch(e['flow']['time']):.6f}",
                "host": e["node_name"].split("/")[-1],
                "source": "/var/run/cilium/hubble/events.log",
                "sourcetype": "cilium:hubble:flow",
                "index": "cilium_hubble",
                "event": raw,
            }
            for raw, e in zip(cls.lines, cls.events)
        ]
        path = Path("/tmp/adm-hubble-enterprise-load.ndjson")
        path.write_text("\n".join(json.dumps(e) for e in envelopes) + "\n", "utf-8")
        try:
            lab.load([path])
        finally:
            path.unlink()
        starts = [iso_epoch(e["flow"]["time"]) for e in cls.events]
        cls.window = (
            str(math.floor(min(starts)) - 60),
            str(math.ceil(max(starts)) + 60),
        )
        deadline, got = time.time() + 180, 0
        while time.time() < deadline:
            got = int(lab.search(f"{INDEX_SPL} | stats count", *cls.window)[0]["count"])
            if got >= len(cls.events):
                break
            time.sleep(2)
        if got != len(cls.events):
            raise AssertionError(f"indexed {got} of {len(cls.events)} sample events")
        cls.rows = lab.search(f"`adm_flows_hubble` | table {FIELDS}", *cls.window)
        cls.flows = [e["flow"] for e in cls.events]

    def test_json_fields_extracted(self):
        rows = self.lab.search(
            f'{INDEX_SPL} | stats count by "flow.Type" "flow.trace_observation_point" "flow.verdict"',
            *self.window,
        )
        got = Counter(
            {
                (
                    r["flow.Type"],
                    r.get("flow.trace_observation_point"),
                    r["flow.verdict"],
                ): int(r["count"])
                for r in rows
            }
        )
        # stats drops groups whose by-field is null; flows without an observation point are compared separately.
        want = Counter(
            (f["Type"], f["trace_observation_point"], f["verdict"])
            for f in self.flows
            if f.get("trace_observation_point")
        )
        self.assertEqual(got, want)
        rows = self.lab.search(
            f"{INDEX_SPL} | where isnull('flow.trace_observation_point') "
            '| stats count by "flow.Type" "flow.verdict"',
            *self.window,
        )
        self.assertEqual(
            Counter(
                {(r["flow.Type"], r["flow.verdict"]): int(r["count"]) for r in rows}
            ),
            Counter(
                (f["Type"], f["verdict"])
                for f in self.flows
                if not f.get("trace_observation_point")
            ),
        )

    def test_enterprise_alias_matches_hubble(self):
        rows = self.lab.search(
            f"`adm_flows_hubble_enterprise` | table {FIELDS}", *self.window
        )
        self.assertEqual(
            Counter(json.dumps(r, sort_keys=True) for r in rows),
            Counter(json.dumps(r, sort_keys=True) for r in self.rows),
        )

    def test_kinds_match_reference(self):
        want = Counter(k for k in map(classify, self.flows) if k)
        got = Counter(r["adm_kind"] for r in self.rows)
        self.assertEqual(got, want)
        self.assertGreater(want["conv"], 0)

    def test_l7_requests_without_forwarded_for_are_dropped(self):
        requests = [
            f
            for f in self.flows
            if f.get("Type") == "L7" and f["l7"].get("type") == "REQUEST"
        ]
        self.assertTrue(requests, "the sample has L7 requests")
        self.assertTrue(all(rightmost_xff(f) is None for f in requests))
        self.assertNotIn("l7", {r["adm_kind"] for r in self.rows})

    def test_conversation_tuples(self):
        want = Counter(tuple_of(f) for f in self.flows if classify(f) == "conv")
        got = Counter(
            (
                r["adm_src_ip"],
                r["adm_dest_ip"],
                r.get("adm_src_port"),
                r.get("adm_dest_port"),
                r.get("adm_transport"),
            )
            for r in self.rows
            if r["adm_kind"] == "conv"
        )
        self.assertEqual(got, want)

    def test_observer_and_cluster_from_node_name(self):
        nodes = {e["node_name"] for e in self.events}
        self.assertEqual(len(nodes), 1)
        cluster, node = next(iter(nodes)).split("/")
        self.assertEqual({r["adm_observer"] for r in self.rows}, {node})
        self.assertEqual({r["adm_scope_observer"] for r in self.rows}, {cluster})
        self.assertEqual(
            {r["adm_source"] for r in self.rows if r["adm_kind"] == "conv"}, {"hubble"}
        )

    def test_nanosecond_timestamps_parse(self):
        want = sorted(iso_epoch(f["time"]) for f in self.flows if classify(f) == "conv")
        got = sorted(
            float(r["adm_start"])
            for r in self.rows
            if r["adm_kind"] == "conv" and r.get("adm_start")
        )
        self.assertEqual(
            len(got), len(want), "adm_start missing for some conversations"
        )
        self.assertLess(max(abs(a - b) for a, b in zip(got, want)), 0.001)


if __name__ == "__main__":
    unittest.main()
