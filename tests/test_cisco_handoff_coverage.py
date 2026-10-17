"""V2 coverage metadata must preserve unresolved client handoff boundaries."""

import configparser
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CiscoHandoffCoverageContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.macros = configparser.ConfigParser(interpolation=None, strict=False)
        cls.macros.read_string(
            (ROOT / "splunk_app/splunk_adm/default/macros.conf")
            .read_text(encoding="utf-8")
            .replace("\\\n", "")
        )

    def test_coverage_runs_only_on_v2_before_connection_rows_are_aggregated(self):
        v1 = self.macros["adm_graph(4)"]["definition"]
        v2 = self.macros["adm_graph_v2(4)"]["definition"]
        self.assertNotIn("adm_graph_handoff_coverage_v2", v1)
        self.assertLess(
            v2.index("adm_graph_handoffs("),
            v2.index("adm_graph_handoff_coverage_v2"),
        )
        self.assertLess(
            v2.index("adm_graph_handoff_coverage_v2"),
            v2.index("adm_graph_edges("),
        )

    def test_coverage_counts_distinct_connections_and_requires_backend_evidence(self):
        definition = self.macros["adm_graph_handoff_coverage_v2"]["definition"]
        self.assertIn('dc(eval(if(adm_row=="hconn",adm_cid,null())))', definition)
        self.assertIn(
            'adm_row=="hconn" AND isnotnull(handoff_basis) AND mvcount(adm_targets)>0',
            definition,
        )
        self.assertIn("BY adm_fe_id", definition)
        self.assertIn(
            'adm_v2_handoff_determined==0,"unresolved",'
            'adm_v2_handoff_determined<adm_v2_handoff_total,"partial"',
            definition,
        )

    def test_coverage_enriches_frontend_nodes_without_rewriting_forwarding_edges(self):
        definition = self.macros["adm_graph_handoff_coverage_v2"]["definition"]
        self.assertIn('adm_row=="node_src" AND adm_v2_handoff_total>0', definition)
        for field in (
            "attr_handoff_coverage",
            "attr_handoff_connections",
            "attr_handoff_determined",
            "attr_handoff_unresolved",
        ):
            self.assertIn(f'"{field}"', definition)
        self.assertNotIn("forwards_to", definition)
        self.assertNotIn("confidence=", definition)

    def test_client_evidence_inputs_are_checked_before_handoff_consumption(self):
        v2 = self.macros["adm_graph_v2(4)"]["definition"]
        self.assertLess(
            v2.index("adm_graph_client_handoff_inputs_v2"),
            v2.index("adm_graph_handoffs("),
        )
        inputs = self.macros["adm_graph_client_handoff_inputs_v2"]["definition"]
        for expected in (
            'adm_row=="xlate"',
            'adm_row=="l7"',
            'flow_source=="hubble"',
            'adm_c_kind=="k8s_node"',
            "coalesce(conns_capped,0)==1",
            "coalesce(mvcount(adm_conns),0)==0",
            "AS adm_v2_handoff_input_incomplete",
        ):
            self.assertIn(expected, inputs)

    def test_client_evidence_uses_the_complete_edge_key_and_fail_closed_caps(self):
        v1 = self.macros["adm_graph(4)"]["definition"]
        v2 = self.macros["adm_graph_v2(4)"]["definition"]
        self.assertNotIn("adm_graph_client_handoffs_v2", v1)
        self.assertLess(
            v2.index("adm_graph_contracts("),
            v2.index("adm_graph_client_handoffs_v2"),
        )
        self.assertLess(
            v2.index("adm_graph_client_handoffs_v2"),
            v2.index("adm_graph_output("),
        )
        definition = self.macros["adm_graph_client_handoffs_v2"]["definition"]
        for expected in (
            "json_array(adm_fe_cid,adm_fe_id,tostring(server_port),transport)",
            "json_array(source,target,tostring(server_port),transport)",
            "mvcount(adm_ch_targets)==1",
            "mvcount(adm_ch_bases)==1",
            "coalesce(adm_ch_source_incomplete,1)!=0",
            "adm_ch_backends_read>=`adm_kv_max_rows`",
            "adm_ch_pods_read>=`adm_kv_max_rows`",
            "adm_ch_groups>64",
            "coalesce(mvcount(adm_ch_records),0)!=adm_ch_groups",
            "coalesce(mvcount(adm_ch_via),0)>64",
            "coalesce(mvcount(adm_ch_observers),0)>64",
        ):
            self.assertIn(expected, definition)
        self.assertNotIn('relationship=="forwards_to"', definition)
        self.assertNotIn("adm_pair_via", definition)

    def test_client_evidence_survives_public_graph_output(self):
        output = self.macros["adm_graph_output(4)"]["definition"]
        for field in (
            "client_handoff_coverage",
            "client_handoff_connections",
            "client_handoff_determined",
            "client_handoff_unresolved",
            "client_handoffs",
        ):
            self.assertIn(field, output)


if __name__ == "__main__":
    unittest.main()
