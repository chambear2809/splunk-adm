"""Evidence macro equivalence and argument validation in the disposable lab."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FLOW_FIELDS = "_time scope client_ip server_ip server_port transport direction_basis flow_source observer first_seen last_seen bytes_c2s bytes_s2c packets records observations acl_permits acl_drops conns conns_capped sampled"
TRACE_FIELDS = '_time trace_id span_id parent_span_id name kind status start_time end_time "service.name" "deployment.environment.name" "k8s.namespace.name" "k8s.cluster.name" "k8s.pod.uid" attributes'


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class DrilldownEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab

    @staticmethod
    def normalized(rows: list[dict]) -> list[str]:
        return sorted(json.dumps(row, sort_keys=True) for row in rows)

    def test_flow_macro_matches_real_summary_tuple(self) -> None:
        base = 'search `adm_index_summary` source="adm:conversation"'
        rows = self.lab.search(
            base
            + ' | where isnotnull(client_ip) AND isnotnull(server_ip) AND server_port>0 AND transport="tcp" | head 1',
            "0",
            "+10y",
        )
        self.assertTrue(rows, "raw fixtures must have indexed a conversation")
        row = rows[0]
        client, server = row["client_ip"], row["server_ip"]
        port = int(row["server_port"])
        direct = self.lab.search(
            base
            + f' client_ip={json.dumps(client)} server_ip={json.dumps(server)} server_port={port} transport="tcp" | fields {FLOW_FIELDS}',
            "0",
            "+10y",
        )
        evidence = self.lab.search(
            f'| `adm_flow_evidence({json.dumps(client)},{json.dumps(server)},{port},"tcp")`',
            "0",
            "+10y",
        )
        self.assertTrue(evidence)
        self.assertEqual(self.normalized(evidence), self.normalized(direct))

    def test_trace_macro_matches_real_fixture_trace(self) -> None:
        base = "search `adm_index_traces` `adm_traces_sourcetype`"
        rows = self.lab.search(base + " trace_id=* | head 1", "0", "+10y")
        self.assertTrue(rows, "raw OTel fixtures must contain a trace")
        trace = rows[0]["trace_id"]
        direct = self.lab.search(
            base + f" trace_id={json.dumps(trace)} | fields {TRACE_FIELDS}", "0", "+10y"
        )
        evidence = self.lab.search(
            f"| `adm_trace_evidence({json.dumps(trace)})`", "0", "+10y"
        )
        self.assertTrue(evidence)
        self.assertEqual(self.normalized(evidence), self.normalized(direct))

    def test_macro_rejects_injection_and_invalid_values(self) -> None:
        cases = []
        # Use harmless injected commands so an accidental validation bypass
        # cannot mutate the lab. Every argument position is tested.
        for value in [
            "10.0.0.1|stats count",
            "10.0.0.1`",
            "10.0.0.1$token$",
            "10.0.0.1\n",
            '10.0.0.1"',
            "999.0.0.1",
            "01.2.3.4",
            "2001:db8:::1",
            "1:2:3:4:5:6:7:8:9",
            "fe80::1%eth0",
        ]:
            for position in (0, 1):
                args = ["10.0.0.1", "10.0.0.2", 443, "tcp"]
                args[position] = value
                cases.append(
                    "| `adm_flow_evidence("
                    + ",".join(json.dumps(arg) for arg in args)
                    + ")`"
                )
        for value in ["0", "65536", "443.5", "443|stats count", "443\n"]:
            cases.append(
                f'| `adm_flow_evidence("10.0.0.1","10.0.0.2",{json.dumps(value)},"tcp")`'
            )
        for value in ["icmp", "tcp|stats count", "tcp\n", "TCP"]:
            cases.append(
                f'| `adm_flow_evidence("10.0.0.1","10.0.0.2",443,{json.dumps(value)})`'
            )
        for value in [
            "abc",
            "A" * 32,
            "0" * 33,
            "0" * 16 + "\n",
            "0" * 16 + "|stats count",
            "0" * 16 + "`",
            "0" * 16 + "$token$",
            "0" * 16 + '"',
        ]:
            cases.append(f"| `adm_trace_evidence({json.dumps(value)})`")
        for query in cases:
            with self.subTest(query=query):
                with self.assertRaises(RuntimeError):
                    self.lab.search(query, "0", "now")

    def test_valid_ipv6_and_port_boundaries_are_accepted(self) -> None:
        for client in [
            "::",
            "2001:db8::1",
            "2001:DB8::1",
            "::ffff:192.0.2.1",
            "1:2:3:4:5:6:7:8",
        ]:
            for port in (1, 65535):
                with self.subTest(client=client, port=port):
                    self.assertEqual(
                        self.lab.search(
                            f'| `adm_flow_evidence("{client}","2001:db8::2",{port},"udp")`',
                            "0",
                            "now",
                        ),
                        [],
                    )


if __name__ == "__main__":
    unittest.main()
