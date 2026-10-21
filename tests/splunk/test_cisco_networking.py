"""Static safety contracts for the Cisco networking adapters."""

from __future__ import annotations

import configparser
import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "splunk_app/splunk_adm/default"


def read_conf(name: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=False)
    parser.read_string((DEFAULT / name).read_text().replace("\\\n", ""))
    return parser


def expanded_private_definition(macros, name: str) -> str:
    value = macros.get(name, "definition")
    return re.sub(
        r"`((?:adm_network_client_|adm_health_)[a-z0-9_]+)`",
        lambda match: expanded_private_definition(macros, match.group(1)),
        value,
    )


def _macro_reference(ref: str) -> tuple[str, int]:
    """Return a macro reference's name and argument count."""
    ref = ref.strip()
    opening = ref.find("(")
    if opening < 0:
        return ref, 0
    name = ref[:opening].strip()
    depth = 0
    quote = None
    commas = 0
    has_argument = False
    for char in ref[opening + 1 :]:
        if quote:
            if char == quote:
                quote = None
            else:
                has_argument = has_argument or not char.isspace()
            continue
        if char in ("'", '"'):
            quote = char
            has_argument = True
        elif char == "(":
            depth += 1
            has_argument = True
        elif char == ")":
            if depth == 0:
                break
            depth -= 1
            has_argument = True
        elif char == "," and depth == 0:
            commas += 1
            has_argument = True
        elif not char.isspace():
            has_argument = True
    return name, commas + int(has_argument)


class CiscoNetworkingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.macros = read_conf("macros.conf")
        cls.searches = read_conf("savedsearches.conf")
        cls.collections = read_conf("collections.conf")
        cls.transforms = read_conf("transforms.conf")

    def test_public_surface_snapshots_match_the_shipped_macro_definitions(self):
        interface = json.loads(
            (ROOT / "research/cisco-pipeline-interface.json").read_text()
        )
        for surface in interface["public_surfaces"]:
            for value in surface.values():
                if not isinstance(value, dict) or "definition_sha256" not in value:
                    continue
                with self.subTest(surface=surface["surface"], macro=value["macro"]):
                    definition = self.macros.get(value["macro"], "definition")
                    self.assertEqual(value["definition"], definition)
                    self.assertEqual(
                        value["definition_sha256"],
                        hashlib.sha256(definition.encode()).hexdigest(),
                    )

    def test_new_indices_and_version_two_index_are_separate(self):
        self.assertEqual(
            self.macros.get("adm_index_catalyst", "definition"), "index=cisco_catalyst"
        )
        self.assertEqual(
            self.macros.get("adm_index_meraki", "definition"), "index=cisco_meraki"
        )
        self.assertEqual(
            self.macros.get("adm_index_summary_v2", "definition"),
            "index=adm_summary_v2",
        )
        self.assertEqual(
            self.macros.get("adm_summary_index_v2_name", "definition"), "adm_summary_v2"
        )
        self.assertEqual(
            self.macros.get("adm_data_contract_version", "definition"), "1"
        )
        self.assertEqual(
            self.macros.get("adm_summary_index_name", "definition"), "adm_summary"
        )

    def test_network_client_history_is_additive_and_source_qualified(self):
        fields = set(
            self.transforms.get("adm_network_client_history", "fields_list").split(", ")
        )
        self.assertTrue(
            {
                "_key",
                "contract_version",
                "source",
                "source_authority",
                "native_id",
                "client_mac",
                "client_ip",
                "scope",
                "cluster",
                "source_time",
                "received_time",
                "latest_received_time",
                "mapping_status",
            }.issubset(fields)
        )
        self.assertIn("adm_network_client_history", self.collections.sections())
        self.assertIn(
            "network_history", self.transforms.get("adm_ip_identity", "fields_list")
        )

    def test_source_scope_mapping_uses_all_seven_dimensions_and_no_default(self):
        transform = self.transforms.get("adm_network_source_scope", "fields_list")
        self.assertIn("mapping_key", transform)
        self.assertIn("duplicate_count", transform)
        for field in (
            "source",
            "source_authority",
            "domain_kind",
            "observation_domain_present",
            "observation_domain_id",
            "vpn_id",
            "routing_domain",
        ):
            self.assertIn(field, transform)
        definition = expanded_private_definition(
            self.macros, "adm_network_client_history_observations"
        )
        self.assertIn("mapping_key OUTPUT _key AS adm_mapping_keys", definition)
        self.assertIn('scope=if(mapping_status="mapped", scope, null())', definition)
        migration = self.searches.get("ADM - Migrate network source scope", "search")
        self.assertIn(
            "observation_domain_present observation_domain_id vpn_id routing_domain",
            migration,
        )
        self.assertIn(
            'mapping_key=sha256(json_array(tostring(coalesce(source,""))', migration
        )
        self.assertIn(
            "_key=sha256(json_array(mapping_key, scope, cluster, profile, mapping_status))",
            migration,
        )
        self.assertNotRegex(
            definition, r'adm_scope="default"|scope=coalesce\(scope,\s*"default"\)'
        )

    def test_ipfix_exporter_authority_and_domain_flag_are_normalized_on_both_sides(
        self,
    ):
        migration = self.searches.get("ADM - Migrate network source scope", "search")
        self.assertIn(
            'source_authority=if(source=="stream_ipfix", lower(trim(source_authority)), trim(source_authority))',
            migration,
        )
        self.assertIn('trim(observation_domain_present)=="1"', migration)
        self.assertIn(
            'adm_scope_authority=lower(trim(coalesce(adm_raw_exporter_ip, "")))',
            self.macros.get("adm_flows_netflow_v2", "definition"),
        )

    def test_network_client_timestamp_semantics_and_meraki_allowlist(self):
        definition = expanded_private_definition(
            self.macros, "adm_network_client_history_observations"
        )
        self.assertIn('sourcetype="meraki:accesspoints"', definition)
        self.assertIn(
            "spath input=_raw path=type output=adm_raw_event_type", definition
        )
        self.assertIn('lower(adm_raw_event_type)=="association"', definition)
        self.assertNotIn('type="association"', definition)
        self.assertIn("source_time=`adm_iso_time(occurredAt)`", definition)
        self.assertIn("received_time=_indextime", definition)
        self.assertIn("latest_received_time=_indextime", definition)
        self.assertIn("source_time=tonumber(lastUpdatedTime)/1000", definition)
        self.assertNotIn("collected_time=_indextime", definition)
        self.assertIn(
            "ssid_number=if(isnotnull(ssidNumber), tostring(ssidNumber), null())",
            definition,
        )
        self.assertIn(
            "native_id=if(isnotnull(id) AND len(trim(tostring(id)))>0", definition
        )
        self.assertIn(
            "min(received_time) AS adm_first_received",
            self.macros.get("adm_network_client_history_build", "definition"),
        )

    def test_stream_v2_adapter_requires_exact_profile_and_ignores_vendor_aliases(self):
        adapter = self.macros.get("adm_flows_netflow_v2", "definition")
        enrich = self.macros.get("adm_flow_enrich_v2", "definition")
        self.assertIn('sourcetype="stream:netflow"', adapter)
        self.assertIn("observation_domain_present", adapter)
        self.assertIn("vpn_id", adapter)
        self.assertIn("egress_overlay_session_id", adapter)
        self.assertIn("path=vpn_id output=adm_raw_vpn_id", adapter)
        self.assertIn("path=src_mac output=adm_raw_src_mac", adapter)
        self.assertIn(
            "source_mac=adm_source_mac",
            self.macros.get("adm_traffic_observations_v2", "definition"),
        )
        self.assertIn(
            'counter_semantics="unknown", metrics_authoritative=0',
            self.macros.get("adm_traffic_observations_v2", "definition"),
        )
        self.assertNotIn(
            "bytes_forward",
            self.macros.get("adm_traffic_observations_v2", "definition"),
        )
        self.assertNotIn(
            "packets_forward",
            self.macros.get("adm_traffic_observations_v2", "definition"),
        )
        self.assertNotIn(
            "sampling AS sampling",
            self.macros.get("adm_traffic_observations_v2", "definition"),
        )
        self.assertIn("metrics_authoritative", adapter)
        observation = self.macros.get("adm_traffic_observations_v2", "definition")
        self.assertIn("| fields - _raw _bkt _cd index", observation)
        self.assertIn(
            "raw_bytes raw_packets raw_sampling counter_semantics metrics_authoritative",
            observation,
        )
        adapter = self.macros.get("adm_flows_netflow_v2", "definition")
        self.assertIn('"flow_id", adm_flow_id, "sequence", adm_sequence', adapter)
        self.assertIn(
            '"ingress_overlay_session_id", if(isnotnull(ingress_overlay_session_id)',
            adapter,
        )
        self.assertIn(
            '"egress_overlay_session_id", if(isnotnull(egress_overlay_session_id)',
            adapter,
        )
        self.assertNotIn("tloc_", adapter)
        self.assertIn(
            '"interface_in", coalesce(adm_raw_ingress_interface, if(isnotnull(adm_raw_input_snmpidx)',
            adapter,
        )
        self.assertIn(
            '"interface_out", coalesce(adm_raw_egress_interface, if(isnotnull(adm_raw_output_snmpidx)',
            adapter,
        )
        json_line = next(
            line
            for line in observation.splitlines()
            if '"event_identity_status"' in line
        )
        self.assertIn('"unavailable")) | streamstats', json_line)
        self.assertIn(
            "adm_network_source_scope mapping_key AS adm_scope_mapping_key", enrich
        )
        self.assertIn('mvfind(adm_registered_duplicate_counts, "^1$")<0', enrich)
        self.assertIn("adm_mapping_rows==1", enrich)
        self.assertIn('adm_profile_status=="mapped"', enrich)
        self.assertIn(
            'adm_profile_matches>1 OR adm_scope_matches>1 OR adm_cluster_matches>1, "ambiguous"',
            enrich,
        )
        self.assertNotRegex(adapter + enrich, r"vendor_product|\baction\b")

    def test_v1_readers_and_writer_keep_legacy_defaults(self):
        self.assertIn(
            'adm_index_summary` source="adm:conversation"',
            self.macros.get("adm_graph_inputs(4)", "definition"),
        )
        self.assertIn(
            "adm_index_summary_v2",
            self.macros.get("adm_graph_inputs_v2(4)", "definition"),
        )
        self.assertIn(
            "adm_graph_inputs_v2", self.macros.get("adm_graph_v2(4)", "definition")
        )
        legacy_rollup = self.searches.get("ADM - Conversation rollup", "search")
        self.assertIn("adm_summary_index_name", legacy_rollup)
        legacy_netflow = self.macros.get("adm_flows_netflow", "definition")
        self.assertIn("adm_scope_observer=exporter_ip", legacy_netflow)
        self.assertNotIn("adm_scope_observer=adm_raw_exporter_ip", legacy_netflow)

    def test_v2_interface_identifiers_never_use_unscoped_inventory_aliases(self):
        enrichment = self.macros.get("adm_flow_enrich_v2", "definition")
        self.assertNotIn("adm_interfaces", enrichment)
        self.assertIn("coalesce(adm_raw_ingress_interface", enrichment)
        self.assertIn("coalesce(adm_raw_egress_interface", enrichment)
        self.assertIn('"ifIndex ".adm_in_ifindex', enrichment)
        self.assertIn(
            "lookup local=true adm_interfaces",
            self.macros.get("adm_flow_enrich", "definition"),
        )

    def test_v2_profiles_require_single_explicit_row_and_duplicate_count_one(self):
        enrich = self.macros.get("adm_flow_enrich_v2", "definition")
        history = expanded_private_definition(
            self.macros, "adm_network_client_history_observations"
        )
        self.assertIn("OUTPUT _key AS adm_registered_keys", enrich)
        self.assertIn("adm_mapping_rows==1", enrich)
        self.assertIn('mvindex(adm_registered_status,0)=="mapped"', enrich)
        self.assertIn('mvfind(adm_registered_duplicate_counts, "^1$")<0', enrich)
        self.assertIn('mvfind(adm_duplicate_counts, "^1$")<0', history)
        self.assertIn("mvcount(adm_mapping_status)==1", history)

    def test_v2_public_readers_preserve_implicit_search_contract(
        self,
    ):
        graph_inputs = self.macros.get("adm_graph_inputs_v2(4)", "definition")
        self.assertTrue(graph_inputs.startswith("("))
        self.assertFalse(
            self.macros.get("adm_topology_v2", "definition").startswith("search ")
        )
        conversation_writer = self.searches.get(
            "ADM - Conversation rollup v2", "search"
        )
        traffic_writer = self.searches.get(
            "ADM - Traffic observation rollup v2", "search"
        )
        self.assertTrue(
            conversation_writer.startswith("|")
        )  # rollup macro starts with multisearch
        self.assertFalse(
            traffic_writer.startswith("|")
        )  # traffic macro starts with index=...
        self.assertIn("collect index=", conversation_writer)
        self.assertIn("collect index=", traffic_writer)

    def test_v2_public_consumers_and_per_cluster_settings_are_separate(self):
        for macro in (
            "adm_graph_v2(4)",
            "adm_catalog_build_v2",
            "adm_catalog_writer_v2",
            "adm_find_v2(1)",
            "adm_health_sources_v2",
            "adm_flow_evidence_v2(4)",
            "adm_traffic_evidence_v2(4)",
        ):
            self.assertIn(macro, self.macros.sections())
        settings = self.macros.get("adm_graph_cluster_settings_v2(1)", "definition")
        self.assertIn("adm_cilium_cluster_settings", settings)
        self.assertIn("adm_s_cluster", settings)
        self.assertIn('"$requested_cluster$"', settings)
        self.assertNotIn("adm_cilium_lb_mode", settings)
        self.assertNotIn("adm_cilium_ingress_mode", settings)
        self.assertIn(
            "adm_graph_handoffs", self.macros.get("adm_graph_v2(4)", "definition")
        )
        self.assertIn(
            'adm_graph_cluster_settings_v2("$cluster$")',
            self.macros.get("adm_graph_v2(4)", "definition"),
        )
        self.assertIn(
            "network_client_history",
            self.macros.get("adm_graph_traffic_context_v2(4)", "definition"),
        )
        self.assertIn(
            '"correlated"',
            self.macros.get("adm_graph_traffic_context_v2(4)", "definition"),
        )

    def test_traffic_evidence_reader_maps_stored_summary_field_names(self):
        evidence = self.macros.get("adm_traffic_evidence_v2(4)", "definition")
        writer = self.macros.get("adm_traffic_observations_v2", "definition")
        stored_fields = set(re.findall(r"\| fields (?!-)([^|]*)", writer)[-1].split())
        for column, stored in (
            ("source", "adm_scope_source"),
            ("source_authority", "adm_scope_authority"),
            ("observation_domain_present", "adm_scope_observation_domain_present"),
            ("observation_domain_id", "adm_scope_observation_domain_id"),
            ("vpn_id", "adm_scope_vpn_id"),
            ("mapping_status", "adm_profile_status"),
        ):
            self.assertIn(f"{column}={stored}", evidence)
            self.assertIn(stored, stored_fields)
        self.assertIn("adm_traffic_observation", stored_fields)
        self.assertIn(
            'profile=json_extract(adm_traffic_observation, "profile")', evidence
        )
        self.assertLess(evidence.index("| eval "), evidence.index("| fields "))

    def test_invalid_traffic_is_retained_with_quality_but_never_correlated(self):
        observations = self.macros.get("adm_traffic_observations_v2", "definition")
        context = self.macros.get("adm_graph_traffic_context_v2(4)", "definition")
        for field in (
            "adm_quality_status",
            "adm_quality_errors",
            "adm_quality_warnings",
        ):
            self.assertIn(field, observations)
        self.assertIn('"quality_status", adm_quality_status', observations)
        self.assertIn(
            'adm_quality_status IN ("accepted","accepted_with_warning")', context
        )

    def test_v2_topology_inventory_uses_bounded_query_relative_time_and_valid_spl(self):
        topology = self.macros.get("adm_topology_v2", "definition")
        bounds = self.macros.get("adm_topology_inventory_time_bounds", "definition")
        self.assertIn("info_min_time-`adm_topology_inventory_lookback_seconds`", bounds)
        self.assertIn("latest=info_max_time", bounds)
        self.assertIn("adm_topology_inventory_time_bounds", topology)
        self.assertIn('adm_b_interface_raw="eth".s2."/".p2', topology)
        self.assertIn("a_interface=`adm_if_norm(adm_a_interface_raw)`", topology)
        self.assertIn("b_interface=`adm_if_norm(adm_b_interface_raw)`", topology)
        self.assertNotIn('adm_if_norm("eth".s', topology)
        self.assertNotIn('b_interface=`adm_if_norm("eth".s2."/".p2),', topology)

    def test_context_history_resolves_identity_timeline_before_ip_and_attachment_filters(
        self,
    ):
        context = self.macros.get("adm_graph_traffic_context_v2(4)", "definition")
        dedup = "dedup traffic_observation_id adm_client_source adm_client_authority adm_client_native"
        latest_claims = "dc(eval(if(adm_client_event_time==adm_latest_client_event, adm_timeline_event_key, null())))"
        self.assertLess(
            context.index(dedup),
            context.index(
                "lookup local=true adm_network_client_history source AS adm_client_source"
            ),
        )
        self.assertLess(
            context.index(latest_claims), context.index("adm_client_ip==source_ip")
        )
        self.assertIn("adm_latest_identity_claims==1", context)
        self.assertIn("last_seen<adm_next_client_event", context)
        self.assertIn(
            'lower(trim(source_mac))==lower(trim(coalesce(adm_client_mac,"")))', context
        )
        self.assertIn("first(counter_semantics) AS counter_semantics", context)
        self.assertIn("first(metrics_authoritative) AS metrics_authoritative", context)
        for expected_actual in (
            "adm_source_owner_actual==adm_source_owner_expected",
            "adm_client_candidate_actual==adm_client_candidate_expected",
            "adm_owner_actual==adm_owner_expected",
        ):
            self.assertIn(expected_actual, context)
        self.assertIn(
            "max(eval(if(adm_timeline_actual!=adm_timeline_expected,1,0))) "
            "AS adm_timeline_expansion_incomplete",
            context,
        )
        self.assertIn("adm_timeline_expansion_incomplete==0", context)
        self.assertIn("adm_timeline_total_actual==adm_timeline_total_expected", context)
        self.assertIn('"client_authority",adm_client_authority', context)
        self.assertIn("attachment_evidence", context)
        self.assertIn('"varied"', self.macros.get("adm_graph_v2(4)", "definition"))

    def test_topology_keeps_latest_display_values_and_overlay_provenance(self):
        topology = self.macros.get("adm_topology_v2", "definition")
        self.assertIn("latest(name) AS name", topology)
        self.assertIn("latest(mgmt_ip) AS mgmt_ip", topology)
        self.assertIn("values(evidence_kind) AS evidence_kind", topology)
        self.assertIn(
            "values(overlay_peer_system_ip) AS overlay_peer_system_ip", topology
        )
        self.assertIn(
            "mapping_status=case(mvcount(adm_scope_values)>1 OR mvcount(adm_cluster_values)>1",
            topology,
        )
        self.assertIn(
            '| append [ search `adm_index_dcn` sourcetype="cisco:dc:nexus9k" (component="nxversion" OR component="nxhostname")',
            topology,
        )

    def test_v2_health_and_missed_slots_expose_staged_quality_gaps(self):
        quality = expanded_private_definition(self.macros, "adm_health_quality_v2")
        missed_slots = self.macros.get("adm_health_missed_slots", "definition")
        for reason in (
            "profile_",
            "missing_stable_event_identity",
            "missing_source_time",
            "missing_source_mac",
            "missing_destination_mac",
            "missing_counters",
            "missing_sampling_metadata",
            "counter_semantics_unknown",
        ):
            self.assertIn(reason, quality)
        for name in (
            "ADM - Network client history builder",
            "ADM - Conversation rollup v2",
            "ADM - Traffic observation rollup v2",
            "ADM - Application catalog v2",
        ):
            self.assertIn(name, missed_slots)
        self.assertIn(
            "adm_health_sources_v1_impl",
            self.macros.get("adm_health_sources_v2", "definition"),
        )
        self.assertIn(
            "adm_health_quality_v1_impl",
            self.macros.get("adm_health_quality_v2", "definition"),
        )
        self.assertNotIn(
            "`adm_health_sources`",
            self.macros.get("adm_health_sources_v2", "definition"),
        )
        self.assertNotIn("`adm_health_quality`", quality)

    def test_macro_dependency_graph_has_no_recursive_expansion(self):
        import re

        sections = set(self.macros.sections())
        graph = {section: set() for section in sections}
        for section in sections:
            definition = self.macros.get(section, "definition", fallback="")
            for ref in re.findall(r"`([^`]+)`", definition):
                name, arity = _macro_reference(ref)
                candidate = f"{name}({arity})" if arity else name
                if candidate in sections:
                    graph[section].add(candidate)

        visiting = set()
        visited = set()

        def visit(node):
            if node in visiting:
                self.fail(f"recursive macro expansion detected at {node}")
            if node in visited:
                return
            visiting.add(node)
            for child in graph[node]:
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for section in graph:
            visit(section)

    def test_macro_reference_arity_handles_nested_and_quoted_commas(self):
        self.assertEqual(
            _macro_reference("adm_example(\"a,b\", coalesce(x, y), 'c,d')"),
            ("adm_example", 3),
        )
        self.assertEqual(_macro_reference("adm_example()"), ("adm_example", 0))
        self.assertEqual(_macro_reference("adm_example"), ("adm_example", 0))


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(
    __import__("os").environ.get("ADM_LAB") == "1", "requires disposable Splunk lab"
)
class CiscoNetworkingLabTest(unittest.TestCase):
    """Runtime checks for raw Cisco events and explicit seven-part scope mapping."""

    @classmethod
    def setUpClass(cls):
        import sys
        import time

        sys.path.insert(0, str(ROOT / "tests/splunk"))
        import lab

        cls.lab = lab
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                status = lab._json("GET", "/services/kvstore/status")["entry"][0][
                    "content"
                ]
                if status.get("current", {}).get("status") == "ready":
                    break
            except (lab.LabError, OSError, KeyError, IndexError):
                pass
            time.sleep(3)
        else:
            raise AssertionError(
                "KV store did not become ready for Cisco networking tests"
            )

    def setUp(self):
        import json
        import time
        import uuid

        self.token = "cisco-contract-" + uuid.uuid4().hex[:12]
        self.scope = self.token
        self.cluster = "contract-" + uuid.uuid4().hex[:10]
        self.exporter = (
            "198.18."
            + str(int(uuid.uuid4().hex[:4], 16) % 250)
            + "."
            + str(int(uuid.uuid4().hex[4:6], 16) % 250 + 1)
        )
        self.now = int(time.time()) - 10
        self.loaded = 0
        self._json = json
        self._seed_profiles(
            [
                self._profile("1", "0", "", "", "catalyst_campus_fnf"),
                self._profile("0", "", "", "", "standard_netflow"),
                self._profile("1", "7", "", "", "catalyst_campus_fnf"),
                self._profile("1", "7", "", "", "catalyst_sdwan_ipfix"),
            ]
        )
        self.addCleanup(self._cleanup)

    def _profile(self, present, domain, vpn, routing, profile):
        return {
            "source": "stream_ipfix",
            "source_authority": self.exporter,
            "domain_kind": "exporter",
            "observation_domain_present": present,
            "observation_domain_id": domain,
            "vpn_id": vpn,
            "routing_domain": routing,
            "scope": self.scope,
            "cluster": self.cluster,
            "mapping_status": "mapped",
            "profile": profile,
            "duplicate_count": 1,
        }

    def _seed_profiles(self, profiles):
        import json

        rows = json.dumps(json.dumps(profiles))
        result = self.lab.search(
            f"| makeresults format=json data={rows} "
            '| eval mapping_key=sha256(json_array(tostring(coalesce(source,"")),tostring(coalesce(source_authority,"")),tostring(coalesce(domain_kind,"")),tostring(coalesce(observation_domain_present,"")),tostring(coalesce(observation_domain_id,"")),tostring(coalesce(vpn_id,"")),tostring(coalesce(routing_domain,"")))), _key=sha256(json_array(mapping_key,scope,cluster,profile,mapping_status)) '
            "| fields _key mapping_key source source_authority domain_kind observation_domain_present observation_domain_id vpn_id routing_domain scope cluster mapping_status profile duplicate_count "
            "| outputlookup append=true key_field=_key adm_network_source_scope | stats count AS rows_written"
        )
        if not result or int(result[0].get("rows_written", 0)) != len(profiles):
            raise AssertionError(
                "source-scope profile outputlookup did not report the expected write count"
            )
        readback = self.lab.search(
            f'| inputlookup strict=true adm_network_source_scope | search source_authority="{profiles[0]["source_authority"]}" | stats count AS rows',
            "0",
            "+10y",
        )
        if not readback or int(readback[0].get("rows", 0)) != len(profiles):
            raise AssertionError("source-scope profile readback was incomplete")

    def _stream_event(self, domain_present, domain, sequence):
        from datetime import datetime, timezone

        timestamp = (
            datetime.fromtimestamp(self.now + sequence, timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        event = {
            "timestamp": timestamp,
            "endtime": timestamp,
            "netflow_version": 10,
            "src_ip": "10.250.0." + str(sequence),
            "dest_ip": "10.251.0.1",
            "src_port": 50000 + sequence,
            "dest_port": 443,
            "protoid": 6,
            "bytes": 100 + sequence,
            "packets": 2,
            "exporter_ip": self.exporter,
            "flow_id": str(sequence),
            "seqnumber": sequence,
        }
        if domain_present:
            event["observation_domain_id"] = domain
        return {
            "time": self.now + sequence,
            "host": "contract-exporter",
            "source": self.token,
            "sourcetype": "stream:netflow",
            "index": "netflow",
            "event": event,
        }

    def _load(self, events):
        import json
        import time

        self.lab._hec_post(
            ("\n".join(json.dumps(row) for row in events) + "\n").encode()
        )
        self.loaded += len(events)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = self.lab.search(
                f'index=netflow source="{self.token}" | stats count', "0", "+10y"
            )
            if rows and int(rows[0]["count"]) == self.loaded:
                return
            time.sleep(1)
        self.fail("contract test events did not become searchable")

    def _cleanup(self):
        import urllib.parse

        query = urllib.parse.urlencode(
            {"query": self._json.dumps({"scope": self.scope})}
        )
        for collection in ("adm_network_source_scope", "adm_network_client_history"):
            response = self.lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/{self.lab.APP}/storage/collections/data/{collection}?{query}",
            )
            response.close()

    def test_domain_zero_absent_duplicate_and_unknown_metrics_fail_closed(self):
        self._load(
            [
                self._stream_event(True, 0, 1),
                self._stream_event(False, None, 2),
                self._stream_event(True, 7, 3),
            ]
        )
        rows = self.lab.search(
            f'| `adm_flows_v2` | search adm_scope_authority="{self.exporter}" | table adm_src_port adm_scope_source adm_scope_authority adm_scope_domain_kind adm_scope_observation_domain_present adm_scope_observation_domain_id adm_scope_vpn_id adm_scope_routing_domain adm_scope_mapping_key adm_registered_keys adm_registered_scopes adm_registered_clusters adm_registered_profiles adm_registered_status adm_registered_duplicate_counts adm_profile_status adm_scope adm_quality_status adm_event_id',
            "0",
            "+10y",
        )
        by_port = {row.get("adm_src_port"): row for row in rows}
        zero = by_port["50001"]
        absent = by_port["50002"]
        duplicate = by_port["50003"]
        self.assertEqual(zero["adm_scope_observation_domain_present"], "1")
        self.assertEqual(zero["adm_scope_observation_domain_id"], "0")
        self.assertEqual(
            zero["adm_profile_status"],
            "mapped",
            f"zero-domain mapping diagnostic: {zero!r}",
        )
        self.assertEqual(zero["adm_scope"], self.scope)
        self.assertEqual(absent["adm_scope_observation_domain_present"], "0")
        self.assertEqual(
            absent["adm_profile_status"],
            "mapped",
            f"absent-domain mapping diagnostic: {absent!r}",
        )
        self.assertEqual(absent["adm_scope"], self.scope)
        self.assertEqual(duplicate["adm_profile_status"], "ambiguous")
        self.assertIsNone(duplicate.get("adm_scope"))

        observations = self.lab.search(
            f'`adm_traffic_observations_v2` | search adm_scope_authority="{self.exporter}" | table records adm_traffic_observation',
            "0",
            "+10y",
        )
        self.assertTrue(observations)
        for row in observations:
            evidence = self._json.loads(row["adm_traffic_observation"])
            self.assertEqual(evidence["counter_semantics"], "unknown")
            self.assertEqual(evidence["metrics_authoritative"], "0")
            self.assertEqual(evidence["records"], 1)

    def test_mixed_case_ipv6_exporter_maps_to_its_lowercase_registered_authority(
        self,
    ):
        import uuid

        exporter = "2001:DB8::ABCD:" + uuid.uuid4().hex[:4].upper()
        profile = self._profile("0", "", "", "", "standard_netflow")
        profile["source_authority"] = exporter.lower()
        self._seed_profiles([profile])
        event = self._stream_event(False, None, 4)
        event["event"]["exporter_ip"] = exporter
        self._load([event])
        rows = self.lab.search(
            f'| `adm_flows_v2` | search adm_scope_authority="{exporter.lower()}" | table adm_scope_authority adm_profile_status adm_scope adm_traffic_observation',
            "0",
            "+10y",
        )
        self.assertEqual(len(rows), 1, rows)
        evidence = self._json.loads(rows[0]["adm_traffic_observation"])
        self.assertEqual(evidence["source_authority"], exporter.lower())
        self.assertEqual(evidence["exporter_ip"], exporter)
        self.assertEqual(rows[0]["adm_scope_authority"], exporter.lower())
        self.assertEqual(rows[0]["adm_profile_status"], "mapped", rows[0])
        self.assertEqual(rows[0]["adm_scope"], self.scope)

    def test_raw_interfaces_and_ifindex_do_not_inherit_unscoped_inventory_names(self):
        inventory = {
            "_key": self.token,
            "device_ip": self.exporter,
            "device": "unrelated-fabric-device",
            "ifindex": "17",
            "interface": "unrelated-interface-name",
        }
        endpoint = (
            f"/servicesNS/nobody/{self.lab.APP}/storage/collections/data/"
            f"adm_interfaces/{self.token}"
        )

        def cleanup_inventory():
            self.lab._mgmt("DELETE", endpoint).close()

        self.addCleanup(cleanup_inventory)
        self.lab.search(
            "| makeresults format=json data="
            + json.dumps(json.dumps([inventory]))
            + " | outputlookup append=true key_field=_key adm_interfaces"
        )
        records = [self._stream_event(True, 0, 1), self._stream_event(False, None, 2)]
        for record in records:
            record["event"].update(input_snmpidx=17, output_snmpidx=19)
        records[0]["event"].update(ingress_interface=27, egress_interface=29)
        self._load(records)
        rows = self.lab.search(
            f'`adm_traffic_observations_v2` | search adm_scope_authority="{self.exporter}"'
            " | table source_port adm_traffic_observation",
            "0",
            "+10y",
        )
        observed = {
            row["source_port"]: json.loads(row["adm_traffic_observation"])
            for row in rows
        }
        self.assertEqual(set(observed), {"50001", "50002"})
        self.assertEqual(str(observed["50001"]["interface_in"]), "27")
        self.assertEqual(str(observed["50001"]["interface_out"]), "29")
        self.assertEqual(observed["50002"]["interface_in"], "ifIndex 17")
        self.assertEqual(observed["50002"]["interface_out"], "ifIndex 19")
        self.assertTrue(
            all(
                "unrelated-interface-name" not in json.dumps(row)
                for row in observed.values()
            )
        )

    def test_meraki_raw_association_type_and_missing_authority_are_retained_unresolved(
        self,
    ):
        import json

        now = self.now
        good = {
            "type": "association",
            "organizationId": self.token,
            "networkId": "network-" + self.token,
            "occurredAt": __import__("datetime")
            .datetime.fromtimestamp(now, __import__("datetime").timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "clientMac": "02:aa:bb:cc:dd:01",
            "eventData": {"client_mac": "02:aa:bb:cc:dd:01"},
        }
        no_org = dict(good)
        no_org.pop("organizationId")
        events = [
            {
                "time": now,
                "host": self.token,
                "source": self.token,
                "sourcetype": "meraki:accesspoints",
                "index": "cisco_meraki",
                "event": good,
            },
            {
                "time": now + 1,
                "host": self.token,
                "source": self.token,
                "sourcetype": "meraki:accesspoints",
                "index": "cisco_meraki",
                "event": no_org,
            },
        ]
        self.lab._hec_post(
            ("\n".join(json.dumps(row) for row in events) + "\n").encode()
        )
        import time

        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            indexed = self.lab.search(
                f'index=cisco_meraki source="{self.token}" | stats count', "0", "+10y"
            )
            if indexed and int(indexed[0]["count"]) == len(events):
                break
            time.sleep(1)
        else:
            self.fail("Meraki contract events did not become searchable")
        rows = self.lab.search(
            '| `adm_network_client_history_observations` | search native_id="02:aa:bb:cc:dd:01" | table source event_type client_ip source_authority mapping_status quality_reason',
            "0",
            "+10y",
        )
        self.assertGreaterEqual(len(rows), 2)
        self.assertTrue(all(row.get("source") == "meraki_association" for row in rows))
        self.assertTrue(all(row.get("event_type") == "association" for row in rows))
        self.assertTrue(all(not row.get("client_ip") for row in rows))
        self.assertTrue(
            any(row.get("quality_reason") == "missing_source_authority" for row in rows)
        )
