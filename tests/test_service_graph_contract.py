"""Service graph pipeline placement and captured namespace-leak regression."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"


class ServiceGraphContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = MACROS.read_text()
        cls.conf = {}
        for block in text.split("\n["):
            if "]\n" in block:
                name, body = block.lstrip("[").split("]\n", 1)
                cls.conf[name] = {"definition": body}

    def test_explicit_aliases_scope_before_counts_and_context(self):
        for name in ("adm_graph_service(4)", "adm_graph_service_v2(4)"):
            definition = self.conf[name]["definition"]
            self.assertLess(
                definition.index("adm_graph_handoffs"),
                definition.index("adm_graph_service_scope"),
            )
            self.assertLess(
                definition.index("adm_graph_service_scope"),
                definition.index("adm_graph_edges"),
            )
            self.assertLess(
                definition.index("adm_graph_edges"),
                definition.index("adm_graph_output"),
            )
        handoff = self.conf["adm_graph_handoffs(4)"]["definition"]
        self.assertLess(
            handoff.index("adm_graph_service_handoff_scope"),
            handoff.index('adm_row="fwd"'),
        )
        self.assertNotIn(
            "adm_graph_service_prepare", self.conf["adm_graph(4)"]["definition"]
        )
        self.assertNotIn(
            "adm_graph_service_prepare", self.conf["adm_graph_v2(4)"]["definition"]
        )

    def test_affinity_has_freshness_competitor_and_xlate_guards(self):
        prepare = self.conf["adm_graph_service_prepare(4)"]["definition"]
        self.assertIn('cluster="$cluster$" AND namespace="$namespace$"', prepare)
        scope = self.conf["adm_graph_service_handoff_scope"]["definition"]
        self.assertIn("adm_service_competitors", scope)
        self.assertIn("adm_service_binding_freshness", scope)
        self.assertIn("adm_service_xlegs", scope)
        self.assertIn("adm_service_same_env_read", scope)


if __name__ == "__main__":
    unittest.main()
