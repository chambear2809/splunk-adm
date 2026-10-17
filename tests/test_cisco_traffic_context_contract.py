"""Static guards for fail-closed traffic-context identity expansion."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"


class CiscoTrafficContextContractTest(unittest.TestCase):
    def test_history_cap_or_incomplete_expansion_rejects_whole_observation(self):
        content = MACROS.read_text(encoding="utf-8")
        start = content.index("[adm_graph_traffic_context_v2(4)]")
        end = content.find("\n[", start + 1)
        macro = content[start : end if end >= 0 else len(content)]

        incomplete_check = (
            "max(eval(if(isnull(adm_timeline_count) OR adm_timeline_count==0 "
            "OR adm_timeline_count>=`adm_identity_max_matches`,1,0))) "
            "AS adm_timeline_incomplete"
        )
        self.assertIn(incomplete_check, macro)
        self.assertIn("| where adm_timeline_incomplete==0", macro)
        self.assertIn(
            "max(eval(if(adm_timeline_actual!=adm_timeline_expected,1,0))) "
            "AS adm_timeline_expansion_incomplete",
            macro,
        )
        self.assertIn(
            "| where adm_timeline_expansion_incomplete==0 "
            "AND adm_timeline_total_actual==adm_timeline_total_expected",
            macro,
        )

        # These guards must run before selecting a particular latest history
        # row, otherwise filtering can hide a capped or dropped competitor.
        self.assertLess(
            macro.index("| where adm_timeline_incomplete==0"),
            macro.index("| where adm_client_event_time==adm_latest_client_event"),
        )
        self.assertLess(
            macro.index("| where adm_timeline_expansion_incomplete==0"),
            macro.index("| where adm_client_event_time==adm_latest_client_event"),
        )


if __name__ == "__main__":
    unittest.main()
