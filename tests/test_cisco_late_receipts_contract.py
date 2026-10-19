"""Pure contract checks for receipt-qualified Catalyst topology/history."""

from __future__ import annotations

import configparser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def macro(name: str) -> str:
    config = configparser.RawConfigParser()
    config.read_string(
        (ROOT / "splunk_app/splunk_adm/default/macros.conf")
        .read_text()
        .replace("\\\n", "\n    ")
    )
    return config.get(name, "definition")


class CatalystLateReceiptContractTest(unittest.TestCase):
    def test_topology_reads_history_once_without_event_time_or_raw_fallback(self):
        observations = macro("adm_topology_client_observations")
        topology = macro("adm_topology_v2")
        self.assertEqual(topology.count("`adm_topology_client_observations`"), 1)
        self.assertEqual(
            observations.count("`adm_kv_read_all(adm_network_client_history)`"), 1
        )
        self.assertNotIn("adm_network_client_catalyst_raw", observations)
        self.assertIn("`adm_network_client_meraki_raw`", observations)
        self.assertIn("received_time<info_max_time", observations)
        self.assertIn("received_time+3600>=info_min_time", observations)
        self.assertIn("topology_observed_time=received_time", observations)
        self.assertIn("topology_observed_time=source_time", observations)

    def test_old_update_is_status_and_receipt_age_limits_attachment(self):
        graph = macro("adm_graph_traffic_context_v2(4)")
        observations = macro("adm_topology_client_observations")
        self.assertNotIn("adm_client_source_time>=adm_client_received-3600", graph)
        self.assertIn("last_seen<=adm_client_event_time+3600", graph)
        self.assertIn("adm_client_source_time<=adm_client_received+300", graph)
        self.assertIn(
            "adm_client_source_time>=adm_client_received-`adm_identity_retention`",
            graph,
        )
        self.assertIn('source_time_status IN ("current","stale")', observations)
        self.assertIn('history_coverage=="retained_evidence"', observations)
        self.assertIn("attr_source_time_status=adm_source_time_status", graph)
        self.assertIn("source_time_status", macro("adm_find_network_client(1)"))
        self.assertIn(
            "values(attr_source_time_status) AS attr_source_time_statuses",
            macro("adm_graph_v2(4)"),
        )

    def test_topology_next_receipt_ends_attachment_before_status_filter(self):
        observations = macro("adm_topology_client_observations")
        self.assertIn(
            "sort 0 source source_authority native_id -received_time", observations
        )
        self.assertIn(
            "streamstats current=f min(received_time) AS adm_later_received BY source source_authority native_id",
            observations,
        )
        self.assertIn(
            "max(eval(if(adm_later_received>received_time,adm_later_received,null()))) AS topology_next_received BY source source_authority native_id received_time",
            observations,
        )
        self.assertIn("topology_next_received>info_min_time", observations)
        self.assertLess(
            observations.index("AS topology_next_received"),
            observations.index("| eval topology_attachment_eligible="),
        )
        self.assertNotIn("mvmap(", observations)
        self.assertNotIn("values(received_time)", observations)
        topology = macro("adm_topology_v2")
        client_branch = topology.split('device_kind="network_client"', 1)[0].rsplit(
            "| appendpipe [", 1
        )[1]
        self.assertNotIn('attachment_status=="observed_snapshot"', client_branch)

    def test_graph_aggregation_preserves_status_before_node_projection(self):
        graph = macro("adm_graph_traffic_context_v2(4)")
        aggregation = graph.split("| stats count AS adm_valid_claims", 1)[1].split(
            "| where adm_valid_claims==1", 1
        )[0]
        self.assertIn(
            "first(adm_source_time_status) AS adm_source_time_status", aggregation
        )
        self.assertLess(
            graph.index("first(adm_source_time_status) AS adm_source_time_status"),
            graph.index("attr_source_time_status=adm_source_time_status"),
        )

    def test_topology_preserves_provenance_and_incomplete_diagnostics(self):
        topology = macro("adm_topology_v2")
        observations = macro("adm_topology_client_observations")
        for field in (
            "source_time",
            "received_time",
            "latest_received_time",
            "collected_time",
            "attachment_received_time",
            "source_time_status",
            "history_coverage",
        ):
            self.assertIn(f"latest({field}) AS {field}", topology)
            self.assertIn(field, topology.rsplit("| fields ", 1)[1])
        for guard in (
            "adm_history_read_complete==1",
            "history_rows<`adm_identity_max_matches`",
            "simultaneous_claims==1",
        ):
            self.assertIn(guard, observations)
        self.assertIn("No retained Catalyst client history", observations)
        self.assertIn("values(warnings) AS adm_client_history_warnings", topology)
        self.assertNotIn("collected_time=received_time", topology)

    def test_prune_preserves_current_replays_and_unknown_receipt_extrema(self):
        prune = macro("adm_network_client_history_prune")
        self.assertIn("max(adm_first_receipt,adm_last_receipt)", prune)
        self.assertIn("isnull(adm_retention_receipt) OR", prune)
        self.assertIn("adm_retention_receipt>=now()-`adm_identity_retention`", prune)
        self.assertIn("`adm_prune_maintenance`==1 AND adm_complete==1", prune)

    def test_replay_keeps_earliest_retained_receipt_and_site_fingerprint(self):
        history = macro("adm_network_client_history_build")
        self.assertIn(
            "received_time=min(coalesce(adm_old_received, adm_first_received), adm_first_received)",
            history,
        )
        self.assertIn("latest_received_time=max(", history)
        raw = macro("adm_network_client_catalyst_raw")
        self.assertIn(
            "event_fingerprint=sha256(json_array(source, source_authority, routing_domain,",
            raw,
        )
        self.assertNotIn("collected_time=_indextime", raw)


if __name__ == "__main__":
    unittest.main()
