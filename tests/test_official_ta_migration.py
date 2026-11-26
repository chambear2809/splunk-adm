"""Unit tests for official unmodified Splunkbase TA migration support.

Covers:
1. Official Cisco DC Networking 2.0.10 (Splunkbase 7777) classInfo schema,
   compact JSON event parsing, fabric projection, BD->VRF resolution, and
   adm_aci_policy_build JSON + legacy KV action extraction.
2. Official Splunk Add-on for AppDynamics 3.3.0 (Splunkbase 3471)
   appdynamics_topology mapper (apps, tiers, nodes, backends, SIM IPs,
   external HEC node-IP overlay, fail-closed snapshot checks).
3. Official macros.conf stanzas and research/package-manifest.json hygiene.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "splunk_app" / "splunk_adm" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from adm_aci_lib.context import resolve_official_bd_vrf_context  # noqa: E402
from adm_aci_lib.fabric import project_official_fabric_snapshot  # noqa: E402
from adm_aci_lib.reader import (  # noqa: E402
    SearchError,
    normalize_apic_host,
    parse_official_class_event,
)
from adm_aci_lib.schema import (  # noqa: E402
    OFFICIAL_DCN_NETWORK_CLASSES,
    OFFICIAL_DCN_POLICY_COMPLETE_CLASSES,
    OFFICIAL_DCN_RECOMMENDED_CLASSINFO,
    OFFICIAL_DCN_SPLUNKBASE_ID,
    OFFICIAL_DCN_VERSION,
    official_apic_arguments,
)
from tools.appdynamics_topology import (  # noqa: E402
    AppDynamicsTopologyError,
    map_appdynamics_topology,
)

DCN_FIXTURE = ROOT / "fixtures" / "official_tas" / "cisco_dcn_2010_classinfo.ndjson"
APPD_FIXTURE = ROOT / "fixtures" / "official_tas" / "appdynamics_330_topology.ndjson"
MACROS_PATH = ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"
MANIFEST_PATH = ROOT / "research" / "package-manifest.json"


def _load_ndjson(path: pathlib.Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _extract_stanza(text: str, name: str) -> str:
    header = f"[{name}]"
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip() == header:
            start = idx
            break
    if start is None:
        raise AssertionError(f"missing stanza [{name}]")
    end = len(lines)
    for idx in range(start + 1, len(lines)):
        if re.match(r"^\[[^\]]+\]\s*$", lines[idx]):
            end = idx
            break
    return "\n".join(lines[start:end])


class OfficialDcNetworking2010Test(unittest.TestCase):
    def test_official_classinfo_catalog_includes_fvrsctx_and_passes_ta_regex(self):
        self.assertEqual(OFFICIAL_DCN_VERSION, "2.0.10")
        self.assertEqual(OFFICIAL_DCN_SPLUNKBASE_ID, "7777")
        self.assertIn("fvRsCtx", OFFICIAL_DCN_NETWORK_CLASSES)
        self.assertIn("fvRsBd", OFFICIAL_DCN_NETWORK_CLASSES)
        self.assertIn("fvBD", OFFICIAL_DCN_NETWORK_CLASSES)
        self.assertIn("fvCtx", OFFICIAL_DCN_NETWORK_CLASSES)
        self.assertIn("fvRsCtx", OFFICIAL_DCN_RECOMMENDED_CLASSINFO)
        self.assertIn("vzRsSubjFiltAtt", OFFICIAL_DCN_RECOMMENDED_CLASSINFO)
        args = official_apic_arguments(
            OFFICIAL_DCN_RECOMMENDED_CLASSINFO + OFFICIAL_DCN_POLICY_COMPLETE_CLASSES
        )
        tokens = args.split(" ")
        self.assertEqual(len(tokens), len(set(tokens)))
        ta_class_re = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
        for token in tokens:
            self.assertRegex(token, ta_class_re)

    def test_normalize_apic_host_and_parse_official_class_event(self):
        self.assertEqual(
            normalize_apic_host("APIC-LAB.EXAMPLE.TEST:443"),
            "apic-lab.example.test",
        )
        raw_lines = [
            line
            for line in DCN_FIXTURE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        parsed = [parse_official_class_event(line) for line in raw_lines]
        self.assertEqual(len(parsed), len(raw_lines))
        self.assertEqual(parsed[0]["class"], "topSystem")
        self.assertEqual(parsed[0]["apic_host"], "apic-lab.example.test")
        self.assertEqual(parsed[0]["dn"], "topology/pod-1/node-101/sys")
        self.assertEqual(parsed[0]["attributes"]["name"], "leaf-101")

    def test_parse_official_class_event_rejects_malformed_payloads(self):
        with self.assertRaises(ValueError):
            parse_official_class_event("not-json")
        with self.assertRaises(ValueError):
            parse_official_class_event(json.dumps({"apic_host": "apic", "dn": "x"}))
        with self.assertRaises(ValueError):
            parse_official_class_event(
                json.dumps({"apic_host": "apic", "component": "fvCtx"})
            )

    def test_project_official_fabric_snapshot_from_fixture(self):
        events = _load_ndjson(DCN_FIXTURE)
        projection = project_official_fabric_snapshot(
            events,
            authority="apic-lab",
            fabric="lab-fabric",
            scope="lab",
            expected_apic_host="APIC-LAB.EXAMPLE.TEST:443",
            as_of=1795705210.0,
        )
        self.assertEqual(projection["provenance"]["apic_host"], "apic-lab.example.test")
        self.assertEqual(projection["source_mode"], "official_dc_networking_classinfo")
        self.assertEqual(projection["qualification"], "unverified_single_pass")
        self.assertEqual(projection["traversal"], "not_observed")
        self.assertEqual(projection["device_count"], 2)
        self.assertEqual(projection["link_count"], 1)
        self.assertEqual(projection["routed_interface_count"], 1)
        self.assertEqual(projection["routed_interfaces"][0]["encap"], "vlan-100")
        self.assertEqual(
            projection["routed_interfaces"][0]["physical_source"],
            "l1PhysIf+ethpmPhysIf",
        )

    def test_project_official_fabric_snapshot_rejects_mixed_apic_hosts(self):
        events = _load_ndjson(DCN_FIXTURE)
        events.append(
            {
                "apic_host": "apic-other.example.test",
                "component": "topSystem",
                "dn": "topology/pod-1/node-102/sys",
                "id": "102",
                "role": "leaf",
            }
        )
        with self.assertRaises(ValueError):
            project_official_fabric_snapshot(
                events,
                authority="apic-lab",
                fabric="lab-fabric",
                scope="lab",
                expected_apic_host="apic-lab.example.test",
                as_of=1795705210.0,
            )

    def test_resolve_official_bd_vrf_context_from_fixture(self):
        events = _load_ndjson(DCN_FIXTURE)
        ctx = resolve_official_bd_vrf_context(
            events, expected_apic_host="APIC-LAB.EXAMPLE.TEST:443"
        )
        self.assertEqual(ctx["apic_host"], "apic-lab.example.test")
        self.assertEqual(ctx["source_mode"], "official_dc_networking_classinfo")
        self.assertEqual(ctx["qualification"], "unverified_single_pass")
        self.assertEqual(ctx["bd_vrf_count"], 1)
        self.assertEqual(ctx["epg_mapping_count"], 1)
        self.assertEqual(
            ctx["bd_vrf_mappings"][0]["vrf_dn"], "uni/tn-shop/ctx-prod-vrf"
        )
        self.assertEqual(
            ctx["epg_mappings"][0]["epg_dn"], "uni/tn-shop/ap-store/epg-frontend"
        )
        self.assertEqual(ctx["epg_mappings"][0]["vrf_name"], "prod-vrf")

    def test_resolve_official_bd_vrf_context_fails_closed_on_unformed_fvrsctx(self):
        events = _load_ndjson(DCN_FIXTURE)
        for ev in events:
            if ev["component"] == "fvRsCtx":
                ev["state"] = "missing-target"
        with self.assertRaises(SearchError):
            resolve_official_bd_vrf_context(
                events, expected_apic_host="apic-lab.example.test"
            )


class OfficialAppDynamics330TopologyTest(unittest.TestCase):
    def test_maps_official_topology_fixture_with_sim_and_missing_node_ips(self):
        events = _load_ndjson(APPD_FIXTURE)
        result = map_appdynamics_topology(events)
        self.assertEqual(result["source_mode"], "official_appdynamics_topology")
        self.assertEqual(result["controller_id"], "controller-lab.example.test")
        self.assertEqual(result["snapshot_id"], "snap-appd-20261126-01")
        self.assertEqual(result["application_count"], 1)
        self.assertEqual(result["tier_count"], 1)
        self.assertEqual(result["node_count"], 2)
        self.assertEqual(result["backend_count"], 2)

        app = result["applications"][0]
        nodes_by_id = {n["id"]: n for n in app["tiers"][0]["nodes"]}
        # Node 1001 has SIM server 5001 + eth0; loopback/link-local are filtered.
        self.assertEqual(
            nodes_by_id["1001"]["addresses"], ["198.51.100.21", "2001:db8::21"]
        )
        self.assertEqual(nodes_by_id["1001"]["ip_source"], "sim_network_interface")
        # Node 1002 has no SIM server/interface -> explicitly marked missing.
        self.assertEqual(nodes_by_id["1002"]["addresses"], [])
        self.assertEqual(
            nodes_by_id["1002"]["ip_source"], "not_reported_by_topology_input"
        )
        self.assertEqual(result["node_ip_coverage"]["sim_network_interface"], 1)
        self.assertEqual(result["node_ip_coverage"]["external_hec_collector"], 0)
        self.assertEqual(result["node_ip_coverage"]["missing"], 1)
        self.assertTrue(result["node_ip_coverage"]["node_ip_gap"])
        self.assertIn(
            "tools/export_appdynamics.py", result["node_ip_coverage"]["remediation"]
        )

        backends_by_id = {b["entity_id"]: b for b in app["backends"]}
        self.assertEqual(
            backends_by_id["42:9001"]["association_status"], "verified_node"
        )
        self.assertEqual(
            backends_by_id["42:9002"]["association_status"], "application_scope_only"
        )

    def test_external_hec_overlay_supplies_non_sim_node_ips(self):
        events = _load_ndjson(APPD_FIXTURE)
        result = map_appdynamics_topology(
            events,
            external_node_ips={"1002": ["198.51.100.22", "127.0.0.1"]},
        )
        nodes_by_id = {
            n["id"]: n for n in result["applications"][0]["tiers"][0]["nodes"]
        }
        self.assertEqual(nodes_by_id["1002"]["addresses"], ["198.51.100.22"])
        self.assertEqual(nodes_by_id["1002"]["ip_source"], "external_hec_collector")
        self.assertEqual(result["node_ip_coverage"]["sim_network_interface"], 1)
        self.assertEqual(result["node_ip_coverage"]["external_hec_collector"], 1)
        self.assertEqual(result["node_ip_coverage"]["missing"], 0)
        self.assertFalse(result["node_ip_coverage"]["node_ip_gap"])
        self.assertIsNone(result["node_ip_coverage"]["remediation"])

    def test_rejects_snapshot_timestamp_tie_fail_closed(self):
        events = _load_ndjson(APPD_FIXTURE)
        events.append(
            {
                "schema_version": 1,
                "source_system": "appdynamics",
                "controller_id": "controller-lab.example.test",
                "record_type": "entity",
                "observed_ts": 1795705200.0,
                "snapshot_id": "snap-appd-20261126-02-tie",
                "entity_kind": "application",
                "entity_id": "42",
                "name": "ShopApp",
            }
        )
        with self.assertRaises(AppDynamicsTopologyError):
            map_appdynamics_topology(events)


class OfficialMacrosAndManifestTest(unittest.TestCase):
    def test_macros_conf_has_official_ta_stanzas_and_safe_defaults(self):
        text = MACROS_PATH.read_text(encoding="utf-8")

        policy = _extract_stanza(text, "adm_aci_policy_build")
        self.assertIn("json_valid(_raw)", policy)
        self.assertIn('json_extract(_raw, "action")', policy)
        self.assertIn("adm_policy_json_action_key", policy)
        self.assertIn("adm_policy_action_token", policy)

        bd_vrf = _extract_stanza(text, "adm_aci_bd_vrf_map")
        for cls in ("fvRsBd", "fvBD", "fvRsCtx", "fvCtx"):
            self.assertIn(f'component="{cls}"', bd_vrf)
        self.assertIn('qualification="unverified_single_pass"', bd_vrf)

        appd_idx = _extract_stanza(text, "adm_index_appdynamics_topology")
        self.assertIn("definition = index=unconfigured_optional", appd_idx)
        self.assertIn("iseval = 0", appd_idx)

        appd_qual = _extract_stanza(text, "adm_appdynamics_topology_schema_qualified")
        self.assertIn("definition = 0", appd_qual)
        self.assertIn("iseval = 0", appd_qual)

        appd_ent = _extract_stanza(text, "adm_appdynamics_topology_entities")
        self.assertIn('sourcetype="appdynamics_topology"', appd_ent)
        self.assertIn("sim_network_interface", appd_ent)
        self.assertIn("not_reported_by_topology_input", appd_ent)

        mod_ta = _extract_stanza(text, "adm_health_modified_vendor_tas")
        self.assertIn('sourcetype="adm:aci_poll:v1"', mod_ta)
        self.assertIn('sourcetype="adm:aci_poll:v2"', mod_ta)
        self.assertIn('source="atlas:aci_poll"', mod_ta)
        self.assertIn('source="atlas_appdynamics_inventory*"', mod_ta)
        # External HEC collector uses source="appdynamics_inventory" and must not be flagged.
        self.assertNotIn('source="appdynamics_inventory"', mod_ta)

    def test_policy_action_json_regex_matches_single_action_and_rejects_deceptive(self):
        """Mirror the JSON key regex in adm_aci_policy_build against tricky payloads."""
        key_re = re.compile(r'(?:[{,])\s*"((?i:action))"\s*:')
        valid_permit = '{"component":"vzRsSubjFiltAtt","action":"permit","dn":"uni/x"}'
        valid_deny = '{"component":"vzRsSubjFiltAtt","action":"DENY","dn":"uni/x"}'
        duplicate = '{"action":"permit","action":"deny"}'
        deceptive = '{"some_action":"permit","description":"\\"action\\":\\"deny\\""}'
        self.assertEqual(len(key_re.findall(valid_permit)), 1)
        self.assertEqual(len(key_re.findall(valid_deny)), 1)
        self.assertEqual(len(key_re.findall(duplicate)), 2)
        self.assertEqual(len(key_re.findall(deceptive)), 0)

    def test_package_manifest_hygiene_and_historical_snapshots_preserved(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        packages = manifest["packages"]

        sec_3610 = [
            p
            for p in packages
            if p.get("title") == "Cisco Security Cloud" and p.get("version") == "3.6.10"
        ]
        self.assertEqual(len(sec_3610), 1)
        self.assertEqual(sec_3610[0].get("splunkbase_id"), "7404")

        dcn_2010 = [
            p
            for p in packages
            if p.get("splunkbase_id") == "7777" and p.get("version") == "2.0.10"
        ]
        self.assertEqual(len(dcn_2010), 1)
        self.assertTrue(dcn_2010[0].get("recommended_official_ta"))

        dcn_122 = [
            p
            for p in packages
            if p.get("splunkbase_id") == "7777" and p.get("version") == "1.2.2"
        ]
        self.assertEqual(len(dcn_122), 1)
        self.assertNotIn("candidate_overlay", dcn_122[0])
        self.assertEqual(
            dcn_122[0]["local_overlay"].get("lifecycle"), "historical_deprecated"
        )

        appd_330 = [
            p
            for p in packages
            if p.get("splunkbase_id") == "3471" and p.get("version") == "3.3.0"
        ]
        self.assertEqual(len(appd_330), 1)
        self.assertTrue(appd_330[0].get("recommended_official_ta"))
        self.assertEqual(
            appd_330[0]["local_overlay"].get("lifecycle"), "historical_deprecated"
        )

        # Historical snapshots must NOT be deleted before live validation & approval.
        self.assertTrue(
            (
                ROOT
                / "integrations/ta-releases/20261031-r1/dc-networking/manifest.json"
            ).is_file()
        )
        self.assertTrue(
            (
                ROOT / "integrations/ta-releases/20261031-r1/appdynamics/manifest.json"
            ).is_file()
        )
        self.assertTrue(
            (
                ROOT
                / "integrations/ta-releases/20261031-r2-candidate/dc-networking/manifest.json"
            ).is_file()
        )


if __name__ == "__main__":
    unittest.main()
