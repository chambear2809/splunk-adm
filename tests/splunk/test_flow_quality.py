"""Quality exclusions and diagnostic counts using real Splunk SPL and raw events."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab
import test_health


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class FlowQualityTest(unittest.TestCase):
    def test_normalized_validation_matrix(self):
        base = (
            '| makeresults | eval adm_source="netflow", adm_src_ip="10.0.0.1", '
            'adm_dest_ip="2001:db8::1", adm_observer="192.0.2.1", '
            'adm_scope_observer="192.0.2.1", adm_start=now()-10, adm_end=now(), '
            'adm_transport="tcp", adm_src_port=43000, adm_dest_port=443, '
            "adm_bytes_fwd=100, adm_bytes_rev=0, adm_packets=1 "
        )
        cases = [
            ('adm_src_ip="999.1.1.1"', "invalid_source_ip"),
            ('adm_dest_ip="hostname"', "invalid_destination_ip"),
            ('adm_observer=""', "missing_observer"),
            ('adm_observer="hostname"', "invalid_observer_ip"),
            ("adm_start=null()", "invalid_time"),
            ("adm_end=adm_start-1", "invalid_time"),
            ("adm_end=now()+3600", "invalid_time"),
            ('adm_transport=""', "missing_transport"),
            ("adm_dest_port=65536", "invalid_ports"),
            ("adm_src_port=1.5", "invalid_ports"),
            ("adm_dest_port=null()", "invalid_ports"),
            ("adm_bytes_fwd=-1", "invalid_counters"),
            ('adm_packets="bad"', "invalid_counters"),
            ("adm_sampling_invalid=1", "invalid_sampling"),
        ]
        arms = []
        for i, (mutation, _) in enumerate(cases):
            arms.append(f"{base} | eval case_id={i}, {mutation}")
        query = (
            arms[0]
            + "".join(" | append [ " + arm + " ]" for arm in arms[1:])
            + " | `adm_flow_quality`"
        )
        rows = lab.search(query, "0", "now")
        self.assertEqual(len(rows), len(cases))
        for row in rows:
            with self.subTest(case=cases[int(row["case_id"])][0]):
                self.assertEqual(row["adm_quality_status"], "excluded")
                self.assertIn(cases[int(row["case_id"])][1], row["adm_quality_errors"])
        rows = lab.search(base + "| `adm_flow_quality`", "0", "now")
        self.assertEqual(rows[0]["adm_quality_status"], "accepted")
        rows = lab.search(
            base
            + '| eval adm_transport="icmp", adm_src_port=null(), adm_dest_port=null(), '
            "adm_counter_missing=1, adm_sampling_missing=1 | `adm_flow_quality`",
            "0",
            "now",
        )
        self.assertEqual(rows[0]["adm_quality_status"], "accepted_with_warning")
        self.assertEqual(
            set(rows[0]["adm_quality_warnings"]),
            {"missing_counters", "unknown_sampling"},
        )

    def test_raw_exclusions_rollup_and_health_agree(self):
        token = "quality-" + uuid.uuid4().hex
        template = json.loads(
            (Path(__file__).resolve().parents[2] / "fixtures/raw/stream_netflow.ndjson")
            .read_text()
            .splitlines()[0]
        )
        mutations = [
            {},
            {"bytes": -10, "src_ip": "999.1.1.1"},
            {"exporter_sampling_interval": 0},
            {"timestamp": "not-a-time"},
            {"dest_port": 99999},
            {"bytes": None, "packets": None, "exporter_sampling_interval": None},
            {"exporter_sampling_interval": 10},
        ]
        for i, changes in enumerate(mutations):
            event = copy.deepcopy(template)
            event["source"] = token
            event["fields"] = {"adm_quality_test": token, "adm_case": str(i)}
            event["event"]["dest_port"] = 32123
            event["event"].update(changes)
            event["event"] = {k: v for k, v in event["event"].items() if v is not None}
            lab._hec_post(json.dumps(event).encode())
        deadline = time.monotonic() + 60
        query = f'| `adm_flows` | where adm_quality_test="{token}"'
        while True:
            rows = lab.search(query, "0", "+10y")
            if len(rows) == len(mutations) or time.monotonic() >= deadline:
                break
            time.sleep(1)
        self.assertEqual(len(rows), 7)
        by_case = {int(row["adm_case"]): row for row in rows}
        self.assertEqual(
            {
                i
                for i, row in by_case.items()
                if row["adm_quality_status"] == "excluded"
            },
            {1, 2, 3, 4},
        )
        self.assertEqual(float(by_case[6]["adm_bytes_fwd"]), 3000)
        # Filter candidates before aggregation without changing the installed macro.
        rollup = test_health.HealthSearchTest.definition(
            "adm_conversation_rollup"
        ).replace("`adm_flows`", f'`adm_flows` | where adm_quality_test="{token}"')
        aggregates = lab.search(rollup, "0", "+10y")
        self.assertEqual(sum(int(r["records"]) for r in aggregates), 3)
        self.assertEqual(sum(float(r.get("bytes_c2s", 0)) for r in aggregates), 3300)
        unknown_rollup = rollup.replace(
            f'adm_quality_test="{token}"',
            f'adm_quality_test="{token}" AND adm_case="5"',
        )
        unknown = lab.search(
            unknown_rollup
            + '| eval adm_row="conv", adm_keep=1, adm_c_id="a", adm_s_id="b", adm_c_state="resolved", adm_s_state="resolved" | `adm_graph_edges("payments","prod","cluster-a","payments")` | where adm_row="edge"',
            "0",
            "+10y",
        )
        self.assertEqual(len(unknown), 1)
        self.assertNotIn("bytes", unknown[0])
        health = test_health.HealthSearchTest.definition("adm_health_quality").replace(
            "search earliest=0", f'search source="{token}" earliest=0'
        )
        diagnostics = lab.search(health, "-24h", "now")
        summary = next(r for r in diagnostics if r["source"] == "all")
        self.assertEqual(summary["records"], "7")
        excluded = next(
            r
            for r in diagnostics
            if r["reason"] == "evaluated" and r["status"] == "excluded"
        )
        self.assertEqual(excluded["records"], "4")
        reasons = {r["reason"] for r in diagnostics}
        self.assertTrue(
            {
                "invalid_source_ip",
                "invalid_counters",
                "invalid_sampling",
                "invalid_time",
                "invalid_ports",
                "missing_counters",
                "unknown_sampling",
            }.issubset(reasons)
        )


if __name__ == "__main__":
    unittest.main()
