"""Regression tests for the opt-in conversation anomaly webhook alerts."""

import configparser
from pathlib import Path
import re
import unittest

APP = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm"

ANOMALY_ALERTS = (
    "ADM - Newly blocked production dependency",
    "ADM - Redundancy loss",
    "ADM - Unexpected new dependency",
)

ROLLUP_MACROS = (
    "adm_conversation_rollup",
    "adm_conversation_rollup_v2",
)

REFERENCED_SUMMARY_FIELDS = {
    "_time",
    "adm_record",
    "rollup_id",
    "scope_mapping_verified",
    "acl_drops",
    "observer",
    "client_ip",
    "server_ip",
    "server_port",
    "scope",
}


def _load_conf(relative_path: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    parser.read_string(
        (APP / relative_path).read_text(encoding="utf-8").replace("\\\n", "")
    )
    return parser


def _pipeline_stages(spl: str) -> list[str]:
    return [stage.strip() for stage in spl.split("|") if stage.strip()]


def _final_fields_projection(macro_definition: str) -> set[str]:
    stages = _pipeline_stages(macro_definition)
    self_fields_stages = [s for s in stages if re.match(r"^fields\s+", s)]
    if not self_fields_stages:
        raise AssertionError("Expected a final `fields` projection in rollup macro")
    final_stage = self_fields_stages[-1]
    tokens = final_stage.split()[1:]
    return {tok.strip(",") for tok in tokens if tok not in {"+", "-"}}


class AnomalyAlertsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.savedsearches = _load_conf("default/savedsearches.conf")
        cls.macros = _load_conf("default/macros.conf")

    def test_anomaly_alerts_parse_cleanly_and_ship_disabled(self) -> None:
        # Also verify standard configparser parsing without pre-stripping line continuations.
        raw_parser = configparser.RawConfigParser(strict=False)
        raw_parser.optionxform = str
        raw_parser.read(APP / "default/savedsearches.conf", encoding="utf-8")

        for name in ANOMALY_ALERTS:
            with self.subTest(alert=name):
                self.assertIn(name, self.savedsearches)
                self.assertIn(name, raw_parser)
                stanza = self.savedsearches[name]
                self.assertEqual(stanza.get("disabled"), "1")
                self.assertEqual(stanza.get("enableSched"), "0")
                self.assertEqual(stanza.get("action.webhook"), "0")
                self.assertEqual(stanza.get("dispatchAs"), "owner")
                self.assertNotIn("action.webhook.param.url", stanza)
                self.assertNotIn("alert.execute.cmd", stanza)

    def test_anomaly_alerts_filter_conversation_records_dedup_and_anchor_to_info_max_time(
        self,
    ) -> None:
        for name in ANOMALY_ALERTS:
            spl = self.savedsearches[name]["search"]
            stages = _pipeline_stages(spl)
            with self.subTest(alert=name):
                base_search = stages[0]
                self.assertIn("`adm_index_summary`", base_search)
                self.assertIn('source="adm:conversation"', base_search)
                self.assertIn('adm_record="conversation"', base_search)

                dedup_indices = [
                    i
                    for i, stage in enumerate(stages)
                    if "`adm_summary_dedup`" in stage
                ]
                stats_indices = [
                    i for i, stage in enumerate(stages) if stage.startswith("stats ")
                ]
                addinfo_indices = [
                    i for i, stage in enumerate(stages) if stage == "addinfo"
                ]
                info_max_indices = [
                    i for i, stage in enumerate(stages) if "info_max_time" in stage
                ]

                self.assertEqual(len(dedup_indices), 1)
                self.assertEqual(len(stats_indices), 1)
                self.assertEqual(len(addinfo_indices), 1)
                self.assertTrue(info_max_indices)
                self.assertLess(dedup_indices[0], stats_indices[0])
                self.assertLess(addinfo_indices[0], info_max_indices[0])

                # Must not anchor phase/lookback splits to wall-clock now().
                self.assertNotRegex(spl, r"\bnow\s*\(\s*\)")

    def test_newly_blocked_alert_uses_numeric_acl_drops_not_acl_action(self) -> None:
        stanza = self.savedsearches["ADM - Newly blocked production dependency"]
        spl = stanza["search"]
        self.assertEqual(stanza.get("dispatch.earliest_time"), "-130m@m")
        self.assertEqual(stanza.get("dispatch.latest_time"), "-10m@m")

        self.assertNotIn("acl_action", spl)
        self.assertIn("info_max_time-3600", spl)
        self.assertRegex(
            spl,
            r'phase=="now"\s+AND\s+(?:coalesce\()?tonumber\(acl_drops\)',
        )
        self.assertRegex(
            spl,
            r'phase=="then"\s+AND\s+(?:coalesce\()?tonumber\(acl_drops\)',
        )
        self.assertIn("by client_ip server_ip server_port scope", spl)
        self.assertIn("where blocked>0 AND prior_blocked=0", spl)

    def test_redundancy_loss_alert_splits_on_info_max_time_and_counts_observers(
        self,
    ) -> None:
        stanza = self.savedsearches["ADM - Redundancy loss"]
        spl = stanza["search"]
        self.assertEqual(stanza.get("dispatch.earliest_time"), "-130m@m")
        self.assertEqual(stanza.get("dispatch.latest_time"), "-10m@m")

        self.assertIn("info_max_time-3600", spl)
        self.assertIn(
            'dc(eval(if(phase=="then", observer, null()))) AS prior_observers', spl
        )
        self.assertIn('dc(eval(if(phase=="now", observer, null()))) AS observers', spl)
        self.assertIn("by client_ip server_ip server_port scope", spl)
        self.assertIn("where prior_observers>=2 AND observers=1", spl)

    def test_unexpected_new_dependency_keeps_info_max_time_in_scope_after_stats(
        self,
    ) -> None:
        stanza = self.savedsearches["ADM - Unexpected new dependency"]
        spl = stanza["search"]
        stages = _pipeline_stages(spl)
        self.assertEqual(stanza.get("dispatch.earliest_time"), "-24h")
        self.assertEqual(stanza.get("dispatch.latest_time"), "now")

        stats_idx = next(i for i, s in enumerate(stages) if s.startswith("stats "))
        addinfo_idx = next(i for i, s in enumerate(stages) if s == "addinfo")
        where_idx = next(i for i, s in enumerate(stages) if s.startswith("where "))

        # stats drops non-by/non-aggregated fields, so addinfo must run after stats
        # and before where so info_max_time is defined.
        self.assertLess(stats_idx, addinfo_idx)
        self.assertLess(addinfo_idx, where_idx)
        self.assertIn("where first>=info_max_time-4200", spl)
        self.assertIn(
            "fields - info_min_time info_max_time info_search_time info_sid",
            stages[-1],
        )

    def test_summary_dedup_macro_preserves_alert_fields(self) -> None:
        self.assertIn("adm_summary_dedup", self.macros)
        defn = self.macros["adm_summary_dedup"]["definition"]
        self.assertIn("dedup rollup_id keepempty=true", defn)
        self.assertNotRegex(defn, r"(?:^|\|)\s*(?:fields|table)\b")

    def test_referenced_summary_fields_are_emitted_by_both_conversation_rollups(
        self,
    ) -> None:
        for macro_name in ROLLUP_MACROS:
            with self.subTest(macro=macro_name):
                self.assertIn(macro_name, self.macros)
                emitted = _final_fields_projection(
                    self.macros[macro_name]["definition"]
                )
                self.assertNotIn("acl_action", emitted)
                missing = REFERENCED_SUMMARY_FIELDS - emitted
                self.assertEqual(
                    missing,
                    set(),
                    f"{macro_name} does not emit required summary fields: {sorted(missing)}",
                )


if __name__ == "__main__":
    unittest.main()
