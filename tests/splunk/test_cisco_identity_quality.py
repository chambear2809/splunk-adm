"""Targeted Cisco identity/time diagnostics; all payloads below are synthetic.

Most live cases evaluate shipped SPL over synthetic normalized rows. Isolated
permission and receipt cases add tagged synthetic events and temporary users,
searches and an unselected macro override; cleanups restore temporary resources.
No collector or controller is accessed. The enclosing lab owner purges events.
"""

from __future__ import annotations

import configparser
import json
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"


def definition(name: str) -> str:
    config = configparser.RawConfigParser()
    config.read_string(MACROS.read_text().replace("\\\n", "\n    "))
    return config.get(name, "definition")


def expanded_private_definition(name: str) -> str:
    return re.sub(
        r"`((?:adm_network_client_|adm_health_)[a-z0-9_]+)`",
        lambda match: expanded_private_definition(match.group(1)),
        definition(name),
    )


def seed(rows: list[dict]) -> str:
    return "| makeresults format=json data=" + json.dumps(json.dumps(rows))


class CiscoIdentityQualityContractTest(unittest.TestCase):
    def test_unidentified_observations_are_retained_without_native_identity(self):
        observed = expanded_private_definition(
            "adm_network_client_history_observations"
        )
        self.assertNotIn("where len(native_id)>0", observed)
        self.assertIn('native_id=coalesce(native_id, client_mac, "")', observed)
        self.assertIn('"missing_client_mac"', observed)
        self.assertNotIn("native_id=sha256", observed)

    def test_graph_requires_valid_mac_and_unqualified_quality(self):
        graph = definition("adm_graph_traffic_context_v2(4)")
        self.assertIn("adm_client_valid=if(isnotnull(adm_client_mac)", graph)
        self.assertIn("AND isnull(adm_client_quality_reason)", graph)
        self.assertLess(
            graph.index("| where adm_client_valid==1"),
            graph.index('relationship="traffic_observation"'),
        )

    def test_selected_probes_do_not_expand_unrelated_index_macros(self):
        source = expanded_private_definition("adm_health_source_netflow")
        quality = expanded_private_definition("adm_health_quality_netflow")
        for expression in (source, quality):
            self.assertNotIn("adm_index_catalyst", expression)
            self.assertNotIn("adm_index_meraki", expression)
            self.assertNotIn("adm_index_dcn", expression)
        for family in ("catalyst", "meraki"):
            expression = expanded_private_definition("adm_health_quality_" + family)
            other = "meraki" if family == "catalyst" else "catalyst"
            self.assertNotIn("adm_index_" + other, expression)
            self.assertIn("earliest=0 latest=+10y", expression)
            self.assertIn("_index_earliest=-24h _index_latest=now", expression)
        self.assertEqual(
            definition("adm_health_quality"), definition("adm_health_quality_v1_impl")
        )

    def test_topology_uses_indexed_receipt_without_replacing_source_time(self):
        guard = definition("adm_topology_client_observations")
        self.assertIn("received_time<info_max_time", guard)
        self.assertIn("`adm_kv_read_all(adm_network_client_history)`", guard)
        self.assertIn('source_time_status IN ("current","stale")', guard)
        self.assertIn("topology_observed_time=received_time", guard)
        topology = definition("adm_topology_v2")
        self.assertEqual(topology.count("`adm_topology_client_observations`"), 1)
        self.assertIn("link_time=topology_observed_time", topology)

    def test_find_exposes_bounded_history_and_unresolved_reasons(self):
        find = definition("adm_find_network_client(1)")
        self.assertIn("`adm_kv_read_all(adm_network_client_history)`", find)
        for term in (
            "diagnostic_status",
            "diagnostic_reason",
            "history_rows",
            "simultaneous_claims",
            "lookup cap",
            "Optional client IP",
            "Optional attachment device",
            "Optional SSID",
            "continuity across the gap",
        ):
            self.assertIn(term, find)
        self.assertLess(find.index("AS history_rows"), find.index('lower("$query$")'))

    def test_health_probes_cover_seven_days_and_split_network_sources(self):
        public = expanded_private_definition("adm_health_sources")
        self.assertEqual(
            public, expanded_private_definition("adm_health_sources_v1_impl")
        )
        self.assertEqual(public.count("_index_earliest=-7d"), 13)
        self.assertNotIn("_index_earliest=-24h", public)
        self.assertIn("probe_lookback_seconds=604800", public)
        for name in ("ACI", "Nexus Dashboard", "NX-OS", "Catalyst Center", "Meraki"):
            self.assertIn(f'name="{name}"', public)
        v2 = expanded_private_definition("adm_health_sources_v2")
        self.assertNotIn("has_mapped", v2)
        for field in (
            "mapped_records",
            "unmapped_records",
            "ambiguous_records",
            "unsupported_records",
            "incomplete_records",
        ):
            self.assertIn(field, v2)
        self.assertIn('mapped_records!=records,"incomplete"', v2)
        self.assertIn('adm_profile=="catalyst_sdwan_ipfix"', v2)
        self.assertNotIn("vendor_product", v2)
        jobs = definition("adm_health_jobs")
        self.assertIn("max(is_scheduled) AS is_scheduled", jobs)
        self.assertIn('is_scheduled==0,"unscheduled"', jobs)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoIdentityQualityLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tools"))
        from lab_lock import LabLock

        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run under tools/lab_lock.py")
        sys.path.insert(0, str(ROOT / "tests/splunk"))
        import lab

        cls.lab = lab

    def test_missing_mac_never_becomes_valid_without_a_flow_mac(self):
        graph = definition("adm_graph_traffic_context_v2(4)")
        expression = re.search(
            r"adm_client_valid=(.*?),\s*adm_client_id=", graph, re.S
        ).group(1)
        rows = [
            {
                "case_name": "valid_meraki",
                "adm_client_mac": "02:00:00:00:00:01",
                "adm_client_source": "meraki_association",
                "adm_client_status": "unresolved",
            },
            {
                "case_name": "missing_meraki",
                "adm_client_source": "meraki_association",
                "adm_client_status": "unresolved",
                "adm_client_quality_reason": "missing_client_mac",
            },
            {
                "case_name": "malformed_meraki",
                "adm_client_mac": "opaque-id",
                "adm_client_source": "meraki_association",
                "adm_client_status": "unresolved",
            },
            {
                "case_name": "missing_catalyst",
                "adm_client_source": "catalyst_client_snapshot",
                "adm_client_native": "opaque-id",
                "adm_client_type": "wired",
                "adm_connected_device_type": "Switch",
                "adm_client_interface": "GigabitEthernet1/0/1",
                "adm_client_status": "observed_snapshot",
            },
        ]
        result = self.lab.search(
            seed(rows) + f" | eval valid={expression} | table case_name valid",
            "1000",
            "2000",
        )
        self.assertEqual(
            {r["case_name"]: r["valid"] for r in result},
            {
                "valid_meraki": "1",
                "missing_meraki": "0",
                "malformed_meraki": "0",
                "missing_catalyst": "0",
            },
        )

    def test_catalyst_topology_is_not_available_before_indexed_receipt(self):
        rows = [
            {
                "native_id": "eligible",
                "source": "catalyst_client_snapshot",
                "source_time": 1300,
                "received_time": 1400,
            },
            {
                "native_id": "future_receipt",
                "source": "catalyst_client_snapshot",
                "source_time": 1300,
                "received_time": 1800,
            },
            {
                "native_id": "stale_source",
                "source": "catalyst_client_snapshot",
                "source_time": 1,
                "received_time": 4000,
            },
        ]
        query = definition("adm_topology_client_observations").replace(
            "`adm_kv_read_all(adm_network_client_history)`",
            seed([dict(row, adm_page=1, adm_complete=1) for row in rows]),
            1,
        )
        result = self.lab.search(
            query
            + " | where isnotnull(native_id) | table native_id source_time received_time topology_observed_time",
            "1000",
            "1600",
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["native_id"], "eligible")
        self.assertEqual(result[0]["source_time"], "1300")
        self.assertEqual(result[0]["topology_observed_time"], "1400")

    def test_find_reports_conflict_expiry_optional_fields_and_read_cap(self):
        base = {
            "source": "meraki_association",
            "source_authority": "synthetic-org/network",
            "client_ip": "192.0.2.10",
            "client_mac": "02:00:00:00:00:01",
            "native_id": "02:00:00:00:00:01",
            "attachment_status": "unresolved",
            "mapping_status": "mapped",
            "received_time": 1950,
            "adm_page": 1,
            "adm_complete": 1,
        }
        rows = [
            dict(
                base,
                _key="a",
                event_fingerprint="a",
                source_time=1900,
                attachment_device_id="ap-a",
            ),
            dict(
                base,
                _key="b",
                event_fingerprint="b",
                source_time=1900,
                attachment_device_id="ap-b",
            ),
            dict(
                base,
                _key="c",
                event_fingerprint="c",
                native_id="older",
                source_time=1000,
            ),
            dict(
                base,
                _key="d",
                event_fingerprint="d",
                native_id="unidentified",
                source_time=1900,
            ),
        ]
        rows[-1].pop("client_mac")
        query = (
            definition("adm_find_network_client(1)")
            .replace("`adm_kv_read_all(adm_network_client_history)`", seed(rows), 1)
            .replace("$query$", "192.0.2.10")
        )
        result = self.lab.search(query, "1000", "2000")
        indexed = {r["_key"]: r for r in result}
        self.assertEqual(indexed["a"]["diagnostic_status"], "conflict")
        self.assertEqual(indexed["b"]["simultaneous_claims"], "2")
        self.assertEqual(indexed["c"]["diagnostic_status"], "stale")
        self.assertIn("Optional SSID number", indexed["a"]["diagnostic_reason"])
        self.assertIn("valid client MAC", indexed["d"]["diagnostic_reason"])
        missing_receipt = dict(
            base,
            _key="missing-receipt",
            event_fingerprint="missing-receipt",
            source_time=1900,
        )
        missing_receipt.pop("received_time")
        query = (
            definition("adm_find_network_client(1)")
            .replace(
                "`adm_kv_read_all(adm_network_client_history)`",
                seed([missing_receipt]),
                1,
            )
            .replace("$query$", "192.0.2.10")
        )
        absent = self.lab.search(query, "1000", "2000")
        self.assertEqual(absent[0]["diagnostic_status"], "incomplete")
        self.assertIn(
            "Indexed receipt time is unavailable", absent[0]["diagnostic_reason"]
        )
        capped = [
            dict(
                base,
                _key="cap",
                event_fingerprint="cap",
                source_time=1900,
                adm_complete=0,
            )
        ]
        query = (
            definition("adm_find_network_client(1)")
            .replace("`adm_kv_read_all(adm_network_client_history)`", seed(capped), 1)
            .replace("$query$", "192.0.2.10")
        )
        result = self.lab.search(query, "1000", "2000")
        self.assertEqual({r["row_type"] for r in result}, {"network_client", "warning"})

    def test_unidentified_rows_survive_normalization_without_native_id(self):
        tail = definition("adm_network_client_normalize").split(
            "eval source_authority=", 1
        )[1]
        rows = [
            {
                "source": "meraki_association",
                "source_authority": "synthetic-org/network",
                "client_ip": "192.0.2.10",
                "source_time": 1900,
                "received_time": 1950,
                "event_fingerprint": "synthetic-fingerprint",
                "contract_version": 1,
                "domain_kind": "network",
            }
        ]
        result = self.lab.search(
            seed(rows) + " | eval source_authority=" + tail, "1000", "2000"
        )
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].get("_key"))
        self.assertFalse(result[0].get("native_id"))
        self.assertFalse(result[0].get("client_mac"))
        self.assertEqual(result[0]["quality_reason"], "missing_client_mac")
        self.assertEqual(result[0]["source_time"], "1900")

    def test_mixed_or_duplicate_profiles_are_not_reported_healthy(self):
        tail = definition("adm_health_network_profile_rows").split(
            "inputlookup strict=true adm_network_source_scope", 1
        )[1]
        mapped = {
            "mapping_key": "a",
            "source": "meraki_association",
            "mapping_status": "mapped",
            "duplicate_count": 1,
            "scope": "synthetic-scope",
            "cluster": "synthetic-cluster",
            "profile": "meraki_association",
        }
        mixed = [mapped, dict(mapped, mapping_key="b", mapping_status="unmapped")]
        result = self.lab.search(
            seed(mixed) + tail + ' | where name=="Version 2 source scope profiles"',
            "1000",
            "2000",
        )
        self.assertEqual(result[0]["status"], "incomplete")
        self.assertEqual(result[0]["mapped_records"], "1")
        self.assertEqual(result[0]["unmapped_records"], "1")
        standalone = dict(mapped, cluster="")
        # An explicit empty cluster is valid standalone scope evidence. It does
        # not authorize a Kubernetes destination join or a default cluster.
        query = seed([standalone]) + ' | eval cluster="" ' + tail
        result = self.lab.search(
            query + ' | where name=="Version 2 source scope profiles"', "1000", "2000"
        )
        self.assertEqual(result[0]["status"], "visible")
        self.assertEqual(result[0]["mapped_records"], "1")
        duplicated = [mapped, dict(mapped)]
        result = self.lab.search(
            seed(duplicated)
            + tail
            + ' | where name=="Version 2 source scope profiles"',
            "1000",
            "2000",
        )
        self.assertEqual(result[0]["status"], "ambiguous")
        self.assertEqual(result[0]["mapped_records"], "0")
        self.assertEqual(result[0]["ambiguous_records"], "2")

    def test_unnormalized_ipfix_authority_is_reported_incomplete(self):
        tail = definition("adm_health_network_profile_rows").split(
            "inputlookup strict=true adm_network_source_scope", 1
        )[1]
        row = {
            "mapping_key": "a",
            "source": "stream_ipfix",
            "source_authority": "2001:db8::1",
            "mapping_status": "mapped",
            "duplicate_count": 1,
            "scope": "synthetic-scope",
            "cluster": "synthetic-cluster",
            "profile": "standard_netflow",
        }
        for authority, status, mapped in (
            ("2001:db8::1", "visible", "1"),
            ("2001:DB8::1", "incomplete", "0"),
            (" 2001:db8::1", "incomplete", "0"),
        ):
            with self.subTest(authority=authority):
                result = self.lab.search(
                    seed([dict(row, source_authority=authority)])
                    + tail
                    + ' | where name=="Stream source scope profiles"',
                    "1000",
                    "2000",
                )
                self.assertEqual(result[0]["status"], status, result)
                self.assertEqual(result[0]["mapped_records"], mapped, result)

    def test_job_schedule_flag_is_independent_of_disabled_state(self):
        rows = [
            {"title": "ADM - synthetic manual", "disabled": "0", "is_scheduled": "0"},
            {
                "title": "ADM - synthetic scheduled",
                "disabled": "0",
                "is_scheduled": "1",
            },
            {"title": "ADM - synthetic disabled", "disabled": "1", "is_scheduled": "1"},
        ]
        query = definition("adm_health_jobs").replace(
            "rest /servicesNS/-/splunk_adm/saved/searches splunk_server=local count=0",
            seed(rows),
            1,
        )
        query = re.sub(
            r"\| append \[ search index=_internal.*?\]",
            "| append [| makeresults | where false()]",
            query,
            flags=re.S,
        )
        result = self.lab.search(query, "1000", "2000")
        observed = {row["name"]: row for row in result}
        self.assertEqual(observed["ADM - synthetic manual"]["status"], "unscheduled")
        self.assertEqual(observed["ADM - synthetic manual"]["is_scheduled"], "0")
        self.assertEqual(
            observed["ADM - synthetic scheduled"]["status"], "no_recent_run"
        )
        self.assertEqual(observed["ADM - synthetic disabled"]["status"], "disabled")

    def test_profile_families_do_not_inherit_unselected_configuration_failures(self):
        tail = definition("adm_health_network_profile_rows").split(
            "inputlookup strict=true adm_network_source_scope", 1
        )[1]
        common = {
            "duplicate_count": 1,
            "scope": "synthetic-scope",
            "cluster": "synthetic-cluster",
            "mapping_status": "mapped",
        }
        rows = [
            dict(
                common,
                mapping_key="catalyst",
                source="catalyst_client_snapshot",
                profile="catalyst_client_snapshot",
            ),
            dict(
                common,
                mapping_key="meraki",
                source="meraki_association",
                profile="meraki_association",
                mapping_status="unmapped",
            ),
            dict(
                common,
                mapping_key="unknown",
                source="unknown-source",
                profile="unknown-profile",
                mapping_status="mapped",
            ),
        ]
        result = self.lab.search(seed(rows) + tail, "1000", "2000")
        observed = {row["name"]: row for row in result}
        self.assertEqual(len(observed), 5)
        self.assertEqual(
            observed["Catalyst source scope profiles"]["status"], "visible"
        )
        self.assertEqual(observed["Catalyst source scope profiles"]["records"], "1")
        self.assertEqual(
            observed["Meraki source scope profiles"]["status"], "incomplete"
        )
        self.assertEqual(
            observed["Version 2 source scope profiles"]["status"], "incomplete"
        )
        self.assertEqual(
            observed["Version 2 source scope profiles"]["unsupported_records"], "1"
        )
        for name in ("Stream source scope profiles", "SD-WAN source scope profiles"):
            self.assertEqual(observed[name]["records"], "0")
            self.assertEqual(observed[name]["status"], "no_visible_records")

    def test_same_mac_across_organizations_and_late_roam_keep_scoped_source_timeline(
        self,
    ):
        graph = definition("adm_graph_traffic_context_v2(4)")
        stage = (
            "| eval adm_client_time="
            + graph.split("| eval adm_client_time=", 1)[1].split(
                "| lookup local=true adm_ip_identity ip AS destination_ip", 1
            )[0]
        )
        mac = "02:00:00:00:00:01"
        authorities = {
            "a": json.dumps(["synthetic-org-a", "network"], separators=(",", ":")),
            "b": json.dumps(["synthetic-org-b", "network"], separators=(",", ":")),
        }
        timeline = [
            ("a", 100, 1000, "192.0.2.10", "ap-a1"),
            ("a", 200, 900, "192.0.2.10", "ap-a2"),
            ("a", 300, 950, "192.0.2.11", "ap-a2"),
            ("b", 250, 960, "192.0.2.10", "ap-b"),
        ]
        flows = [
            ("before_roam", "a", 150, 151, "192.0.2.10"),
            ("after_roam", "a", 250, 251, "192.0.2.10"),
            ("after_move", "a", 350, 351, "192.0.2.11"),
            ("old_ip", "a", 350, 351, "192.0.2.10"),
            ("crossing_roam", "a", 199, 201, "192.0.2.10"),
            ("other_org", "b", 350, 351, "192.0.2.10"),
        ]
        rows = []
        for flow_id, flow_org, first, last, ip in flows:
            for org, event_time, received, client_ip, ap in timeline:
                rows.append(
                    {
                        "traffic_observation_id": flow_id,
                        "first_seen": first,
                        "last_seen": last,
                        "scope": "scope-" + flow_org,
                        "source_ip": ip,
                        "source_mac": mac,
                        "adm_client_source": "meraki_association",
                        "adm_client_authority": authorities[org],
                        "adm_client_native": mac,
                        "adm_client_mac": mac,
                        "adm_client_ip": client_ip,
                        "adm_client_scope": "scope-" + org,
                        "adm_client_cluster": "cluster-" + org,
                        "adm_client_mapping": "mapped",
                        "adm_client_source_time": event_time,
                        "adm_client_received": received,
                        "adm_timeline_event_key": org + str(event_time),
                        "adm_client_basis": "meraki_association_event",
                        "adm_client_status": "unresolved",
                        "adm_attachment_device_name": ap,
                    }
                )

        def run(cluster, payload):
            query = (
                seed(payload)
                + stage.replace("$cluster$", cluster)
                + " | table traffic_observation_id adm_client_id adm_attachment_device_name adm_client_source_time adm_client_received"
            )
            return {
                row["traffic_observation_id"]: row
                for row in self.lab.search(query, "0", "2000")
            }

        a = run("cluster-a", rows)
        self.assertEqual(set(a), {"before_roam", "after_roam", "after_move"})
        self.assertEqual(a["before_roam"]["adm_attachment_device_name"], "ap-a1")
        self.assertEqual(a["after_roam"]["adm_attachment_device_name"], "ap-a2")
        self.assertEqual(a["before_roam"]["adm_client_received"], "1000")
        self.assertEqual(a["before_roam"]["adm_client_source_time"], "100")
        self.assertEqual(a, run("cluster-a", list(reversed(rows))))
        b = run("cluster-b", rows)
        self.assertEqual(set(b), {"other_org"})
        self.assertEqual(b["other_org"]["adm_attachment_device_name"], "ap-b")
        self.assertNotEqual(
            a["after_roam"]["adm_client_id"], b["other_org"]["adm_client_id"]
        )

    def test_quality_classification_keeps_sdwan_unknown_and_history_totals_separate(
        self,
    ):
        quality = definition("adm_health_quality_stream_v2")
        expression = quality.split("| eval source=", 1)[1].split(", adm_reason=", 1)[0]
        rows = [
            {
                "tag": "sdwan",
                "adm_registered_profiles": "catalyst_sdwan_ipfix",
                "adm_profile": "catalyst_sdwan_ipfix",
            },
            {
                "tag": "stream",
                "adm_registered_profiles": "standard_netflow",
                "adm_profile": "standard_netflow",
            },
            {"tag": "unknown"},
            {
                "tag": "conflicting",
                "adm_registered_profiles": ["standard_netflow", "catalyst_sdwan_ipfix"],
                "adm_profile": "standard_netflow",
            },
        ]
        result = self.lab.search(
            seed(rows)
            + ' | eval adm_registered_profiles=if(tag=="conflicting",split("standard_netflow;catalyst_sdwan_ipfix",";"),adm_registered_profiles)'
            + " | eval source="
            + expression
            + " | table tag source",
            "1000",
            "2000",
        )
        self.assertEqual(
            {row["tag"]: row["source"] for row in result},
            {
                "sdwan": "sdwan_ipfix_v2",
                "stream": "stream_ipfix_v2",
                "unknown": "stream_ipfix_unclassified_v2",
                "conflicting": "stream_ipfix_unclassified_v2",
            },
        )
        tail = " | " + definition("adm_health_client_quality_counts")
        rows = [
            {"source": "meraki_association", "mapping_status": "mapped"},
            {
                "source": "meraki_association",
                "mapping_status": "unmapped",
                "quality_reason": "scope_unmapped",
            },
            {"source": "catalyst_client_snapshot", "mapping_status": "mapped"},
        ]
        result = self.lab.search(seed(rows) + tail, "1000", "2000")
        totals = {
            (row["source"], row["status"]): row["records"]
            for row in result
            if row["reason"] == "evaluated"
        }
        self.assertEqual(
            totals,
            {
                ("meraki_association", "mapped"): "1",
                ("meraki_association", "incomplete"): "1",
                ("catalyst_client_snapshot", "mapped"): "1",
            },
        )

    def test_selected_netflow_viewer_ignores_invalid_inaccessible_client_macro(self):
        import secrets
        import time
        import types
        import urllib.parse
        import test_permissions as permissions

        self.username = "adm_selected_viewer_" + secrets.token_hex(8)
        self.password = secrets.token_urlsafe(24)
        self.role = "adm_selected_role_" + secrets.token_hex(8)
        admin_password = self.lab.read_secrets()["SPLUNK_PASSWORD"]
        fixture_source = "synthetic-selected-netflow-" + secrets.token_hex(8)
        now = int(time.time())
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 2))
        fixture = {
            "index": "netflow",
            "sourcetype": "stream:netflow",
            "source": fixture_source,
            "time": now - 1,
            "event": {
                "timestamp": stamp,
                "endtime": stamp,
                "exporter_ip": "192.0.2.254",
                "src_ip": "192.0.2.201",
                "dest_ip": "192.0.2.202",
                "src_port": 55001,
                "dest_port": 443,
                "protoid": 6,
                "bytes": 1,
                "packets": 1,
                "exporter_sampling_interval": 1,
            },
        }
        self.lab._hec_post(json.dumps(fixture).encode())
        deadline = time.monotonic() + 60
        while True:
            count = self.lab.search(
                'index=netflow source="'
                + fixture_source
                + '" | stats count max(_indextime) AS receipt',
                "0",
                "+10y",
            )
            if count[0]["count"] == "1":
                break
            self.assertLess(
                time.monotonic(),
                deadline,
                "synthetic NetFlow probe fixture not indexed",
            )
            time.sleep(1)
        payload = urllib.parse.urlencode(
            {
                "name": self.role,
                "capabilities": "search",
                "srchIndexesAllowed": ["netflow"],
                "srchIndexesDisallowed": [
                    "cisco_meraki",
                    "cisco_catalyst",
                    "cisco_dc",
                    "_internal",
                    "_audit",
                ],
            },
            doseq=True,
        ).encode()
        status, _ = permissions._response(
            "POST", "/services/authorization/roles", "admin", admin_password, payload
        )
        self.assertIn(status, (200, 201))
        self.addCleanup(
            permissions.RestrictedViewerTest._delete_role, self.role, admin_password
        )
        self.lab._json(
            "POST",
            "/services/authorization/roles/" + self.role,
            {"capabilities": "search"},
        )
        payload = urllib.parse.urlencode(
            {"name": self.username, "password": self.password, "roles": self.role}
        ).encode()
        status, _ = permissions._response(
            "POST", "/services/authentication/users", "admin", admin_password, payload
        )
        self.assertIn(status, (200, 201))
        self.addCleanup(
            permissions.RestrictedViewerTest._delete_user, self.username, admin_password
        )
        self._viewer_json = types.MethodType(
            permissions.RestrictedViewerTest._viewer_json, self
        )
        self._delete_job = types.MethodType(
            permissions.RestrictedViewerTest._delete_job, self
        )
        viewer_search = types.MethodType(
            permissions.RestrictedViewerTest._viewer_search, self
        )
        macro_path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_meraki"
        )
        original = self.lab._json("GET", macro_path)["entry"][0]["content"][
            "definition"
        ]
        self.addCleanup(self.lab._json, "POST", macro_path, {"definition": original})
        self.lab._json(
            "POST",
            macro_path,
            {
                "definition": "index=cisco_meraki | adm_intentionally_invalid_unselected_command"
            },
        )
        with self.assertRaises(permissions.SearchRejected):
            viewer_search("| `adm_health_source_meraki`", 0, int(time.time()) + 1)
        # Freeze a closed receipt window for both callers. A moving `now`
        # boundary can otherwise include a newly indexed event in only one
        # result, even after the tagged fixture is visible in a raw search.
        index_upper = int(count[0]["receipt"]) + 1
        close_deadline = time.monotonic() + 5
        while time.time() <= index_upper:
            self.assertLess(
                time.monotonic(), close_deadline, "receipt window did not close"
            )
            time.sleep(0.05)
        # The role cannot read either client index. Even a syntactically invalid
        # unselected macro must not enter either selected NetFlow probe.
        for macro, lookback in (
            ("adm_health_source_netflow", 604800),
            ("adm_health_quality_netflow", 86400),
        ):
            template = expanded_private_definition(macro)
            self.assertEqual(template.count("_index_latest=now"), 1)
            lower = (
                "_index_earliest=-7d" if lookback == 604800 else "_index_earliest=-24h"
            )
            self.assertEqual(template.count(lower), 1)
            query = "| " + template.replace(
                "_index_latest=now", f"_index_latest={index_upper}"
            ).replace(lower, f"_index_earliest={index_upper - lookback}")
            self.assertNotIn("_index_latest=now", query)
            actual = viewer_search(query, 0, index_upper)
            expected = self.lab.search(query, "0", str(index_upper))
            self.assertCountEqual(actual, expected)
            if macro == "adm_health_source_netflow":
                self.assertEqual(len(actual), 1)
                self.assertEqual(actual[0]["name"], "NetFlow")
                self.assertEqual(actual[0]["status"], "ok")
                self.assertGreaterEqual(int(actual[0]["records"]), 1)
            else:
                self.assertTrue(actual)
                self.assertTrue(all(row["source"] == "netflow" for row in actual))
                self.assertGreaterEqual(
                    sum(
                        int(row["records"])
                        for row in actual
                        if row["reason"] == "evaluated"
                    ),
                    1,
                )

    def test_client_quality_uses_receipt_age_with_old_source_events(self):
        import time
        import uuid

        token = "synthetic-health-" + uuid.uuid4().hex
        now = int(time.time())
        old_event_time = now - 3 * 86400
        event = {
            "index": "cisco_catalyst",
            "sourcetype": "cisco:dnac:client",
            "source": token,
            "time": old_event_time,
            "event": {
                "id": token,
                "macAddress": "02:00:00:00:00:7f",
                "ipv4Address": "192.0.2.127",
                "type": "wired",
                "connectionStatus": "connected",
                "cisco_catalyst_host": token,
                "lastUpdatedTime": old_event_time * 1000,
            },
        }
        self.lab._hec_post(json.dumps(event).encode())
        deadline = time.monotonic() + 60
        while True:
            raw = self.lab.search(
                'index=cisco_catalyst source="'
                + token
                + '" | eval raw_time=_time | table raw_time _indextime',
                "0",
                "+10y",
            )
            if len(raw) == 1:
                break
            self.assertLess(
                time.monotonic(),
                deadline,
                "synthetic old-event health fixture not indexed",
            )
            time.sleep(1)
        receipt = int(raw[0]["_indextime"])
        # Query the actual source-local adapter/normalizer with one fixture;
        # the health receipt bound overrides the caller's narrow event window.
        template = expanded_private_definition("adm_health_quality_catalyst")
        self.assertIn("`adm_index_catalyst`", template)
        query = template.replace(
            "`adm_index_catalyst`", 'index=cisco_catalyst source="' + token + '"'
        )
        self.assertNotIn("`adm_index_catalyst`", query)
        dispatch_metadata = {}

        def run(at):
            # Exercise the actual ad-hoc probe invocation. Saved-search dispatch
            # imposes its saved event bounds before this query can override
            # them, and does not represent the application's search client.
            sid = self.lab._json(
                "POST",
                "/servicesNS/admin/splunk_adm/search/v2/jobs",
                {
                    "search": query,
                    "exec_mode": "blocking",
                    "earliest_time": "-1h",
                    "latest_time": "now",
                    "now": str(at),
                },
            )["sid"]
            self.addCleanup(self.lab._json, "DELETE", "/services/search/v2/jobs/" + sid)
            job = self.lab._wait_job(sid)
            dispatch_metadata.update(
                {
                    key: job.get(key)
                    for key in (
                        "earliestTime",
                        "latestTime",
                        "eventCount",
                        "scanCount",
                        "resultCount",
                    )
                }
            )
            return self.lab._results(sid)

        fresh = run(receipt + 60)
        self.assertEqual(
            sum(int(row["records"]) for row in fresh if row["reason"] == "evaluated"),
            1,
            f"receipt fixture {token}: source_time={old_event_time}, receipt={receipt}; dispatch={dispatch_metadata}; rows={fresh}",
        )
        expired = run(receipt + 25 * 3600)
        self.assertEqual(expired, [])
        # No rewrite of _time/_indextime supplied the result: the stored event
        # remains three days old and the indexed receipt remains newly observed.
        self.assertEqual(int(float(raw[0]["raw_time"])), old_event_time)
        self.assertGreaterEqual(receipt, now - 1)
