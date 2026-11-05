"""Static contract of the pair/device trace and identity macros fixed after the
2026-11-04 live scenarios (docs/operators/LIVE_SCENARIOS.md). The behavior is
exercised against Splunk by tests/splunk/test_live_scenario_gaps.py."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"


def stanzas() -> dict[str, str]:
    out: dict[str, str] = {}
    text = MACROS.read_text()
    for m in re.finditer(
        r"^\[(?P<name>[^\]]+)\]\n(?P<body>.*?)(?=^\[|\Z)", text, re.M | re.S
    ):
        out[m.group("name")] = m.group("body")
    return out


def definition(body: str) -> str:
    m = re.search(r"^definition = (.*?)(?=^\w+ = |\Z)", body, re.M | re.S)
    assert m, body[:80]
    return m.group(1).replace("\\\n", "\n")


def closure(macros: dict[str, str], root: str) -> set[str]:
    seen, stack = set(), [root]
    while stack:
        name = stack.pop()
        if name in seen or name not in macros:
            continue
        seen.add(name)
        for call in re.findall(r"`([^`]+)`", definition(macros[name])):
            m = re.match(r"^(\w+)\((.*)\)$", call, re.S)
            stack.append(f"{m.group(1)}({len(m.group(2).split(','))})" if m else call)
    return seen


class PathTraceMacroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = stanzas()
        cls.d = {k: definition(v) for k, v in cls.m.items() if "definition = " in v}

    def test_acl_first_poll_matches_the_graph_acllog_filter(self):
        graph = self.d["adm_flows_acllog"]
        path = self.d["adm_path_acl_first_poll"]
        self.assertIn("adm_acl_age>=-60 AND adm_acl_age<=`adm_poll_interval`+60", graph)
        self.assertIn("adm_acl_age>=-60 AND adm_acl_age<=`adm_poll_interval`+60", path)
        self.assertIn('adm_acl_key=if(adm_kind=="aci_acllog", apic_host."|".dn', path)
        self.assertIn("dedup adm_acl_key keepempty=true", path)
        self.assertIn("adm_start>=info_min_time", path)
        self.assertTrue(
            self.d["adm_path_flow_normalize"]
            .rstrip()
            .endswith("`adm_path_acl_first_poll`")
        )

    def test_device_flows_cap_counts_normalized_records(self):
        body = self.d["adm_device_flows(1)"]
        self.assertLess(
            body.index("`adm_path_flow_normalize`"),
            body.index("head (adm_seq<=`adm_path_trace_limit`+1)"),
        )
        self.assertIn("`adm_index_hubble` `adm_hubble_sourcetypes`", body)
        self.assertIn("drop_reasons", body)

    def test_device_flows_cap_applies_after_the_device_filter(self):
        # Free-text Hubble/ND matches for other devices must not consume the
        # cap; records_capped comes from the device records actually read.
        body = self.d["adm_device_flows(1)"]
        order = [
            "| where adm_hit==1",
            "| streamstats count AS adm_seq",
            "| head (adm_seq<=`adm_path_trace_limit`+1)",
            "| eventstats max(adm_seq) AS adm_read",
            "| where adm_seq<=`adm_path_trace_limit`",
            "records_capped=if(adm_read>`adm_path_trace_limit`, 1, 0)",
            "max(records_capped) AS records_capped by src dst adm_dport protocol",
        ]
        positions = [body.index(x) for x in order]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("total_flows>=`adm_path_trace_limit`", body)
        self.assertEqual(body.count("head `adm_path_trace_limit`"), 0)

    def test_resolve_value_is_validated_literal(self):
        body = self.m["adm_path_trace_resolve(1)"]
        rule = re.search(r'^validation = match\(value, "(.*)"\)$', body, re.M)
        self.assertIsNotNone(rule)
        self.assertTrue(rule.group(1).endswith("\\z"))
        pattern = re.compile(rule.group(1).replace("\\z", r"\Z"))
        for good in ("10.0.0.1", "fe80::1", "win-client-01", "vm@host", "a[0]"):
            self.assertTrue(pattern.match(good), good)
        for bad in ('a"b', "a b", "a*", "-x", "a\n", "a,b", "a$b", "a`b", "x" * 256):
            self.assertFalse(pattern.match(bad), bad)
        self.assertIn("errormsg = ", body)
        # Called as "| `adm_path_trace_resolve(...)`": its body must not add
        # a second leading pipe ("| | inputlookup" fails to parse).
        self.assertTrue(
            self.d["adm_path_trace_resolve(1)"].startswith("inputlookup "), body
        )

    def test_l3out_paths_and_subnets_are_bounded_separately(self):
        body = self.d["adm_l3out_path_evidence(2)"]
        self.assertIn("streamstats count AS adm_rank by row_type", body)
        self.assertIn("eventstats count AS adm_rows by row_type", body)
        self.assertIn("where adm_rank<=`adm_l3out_path_limit`", body)
        self.assertIn("truncated=if(adm_rows>`adm_l3out_path_limit`, 1, 0)", body)
        self.assertNotIn("| head `adm_l3out_path_limit`", body)
        # Paths of an L3Out with a matching subnet sort before other paths.
        self.assertLess(
            body.index("AS adm_hit_l3outs"), body.index("sort 0 row_type adm_prio")
        )
        self.assertIn(
            " truncated \\\n| fields - _*", self.m["adm_l3out_path_evidence(2)"]
        )

    def test_port_channels_use_only_the_newest_poll(self):
        body = self.d["adm_impact_port_channels"]
        order = [
            "eval adm_rank=if(adm_after==1, _time, 0-_time)",
            "eventstats min(adm_rank) AS adm_best by apic_host component",
            "where adm_rank-adm_best<`adm_poll_interval`/2",
            "dedup apic_host component dn",
        ]
        positions = [body.index(x) for x in order]
        self.assertEqual(positions, sorted(positions))

    def test_new_trace_and_impact_validations_anchor_at_end_of_string(self):
        for name in (
            "adm_impact_flows(2)",
            "adm_impact_flows_raw(2)",
            "adm_impact_flows_summary(2)",
            "adm_impact_element(2)",
            "adm_impact_element(3)",
            "adm_impact_members(1)",
            "adm_fabric_path_evidence(2)",
            "adm_l3out_path_evidence(2)",
            "adm_path_trace(2)",
            "adm_path_pod_nodes(2)",
            "adm_path_trace_resolve(1)",
            "adm_device_flows(1)",
            "adm_qualified_rollup(1)",
        ):
            rule = re.search(r"^validation = (.*)$", self.m[name], re.M).group(1)
            with self.subTest(name=name):
                self.assertNotIn('$"', rule)
                self.assertIn('\\z"', rule)

    def test_impact_endpoints_are_ip_literals_or_none(self):
        rule = re.search(
            r'match\(endpoints, "(.*?)"\)', self.m["adm_impact_element(2)"]
        ).group(1)
        pattern = re.compile(rule.replace("\\z", r"\Z"))
        for good in ("-", "10.0.0.1", "10.0.0.1;fe80::1", ";".join(["10.0.0.1"] * 256)):
            self.assertTrue(pattern.match(good), good)
        for bad in ("1-2", "--", "", "10.0.0.1;-", "a", ";".join(["10.0.0.1"] * 257)):
            self.assertFalse(pattern.match(bad), bad)

    def test_pair_trace_reads_hubble_and_names_services(self):
        body = self.d["adm_path_trace(2)"]
        self.assertIn(
            "`adm_index_hubble` `adm_hubble_sourcetypes` TERM($src$) TERM($dst$)", body
        )
        self.assertLess(
            body.index('direction=if(src=="$src$"'),
            body.index("`adm_path_service_port`"),
        )
        for field in (
            "services",
            "client_ports",
            "drop_services",
            "drop_reasons",
            "audits",
        ):
            self.assertIn(f"AS {field}", body)
        self.assertEqual(body.count("`adm_path_pod_nodes($src$,$dst$)`"), 2)
        self.assertIn("cluster namespace node valid_from valid_to", body)

    def test_hubble_fields_keep_every_verdict(self):
        norm = self.d["adm_path_flow_normalize"]
        self.assertIn(
            'adm_hp_verdict=="DROPPED" OR adm_hp_verdict=="ERROR"), "drop"', norm
        )
        self.assertIn('adm_hp_verdict=="AUDIT", "audit"', norm)
        fields = self.d["adm_path_hubble_fields"]
        for path in (
            "flow.verdict",
            "flow.drop_reason_desc",
            "flow.node_name",
            "flow.source.pod_name",
        ):
            self.assertIn(f'spath(_raw, "{path}")', fields)
        # The graph's Hubble evidence still keeps forwarded flows only.
        self.assertIn('adm_h_native_verdict=="FORWARDED"', self.d["adm_flows_hubble"])

    def test_service_side_prefers_the_port_with_more_peers(self):
        body = self.d["adm_path_service_port"]
        self.assertIn(
            "eventstats dc(adm_sport) AS adm_d_peers by dst adm_dport protocol", body
        )
        order = [
            'adm_hp_reply=="true", "src"',
            'adm_d_peers>adm_s_peers, "dst"',
            'adm_dport<1024 AND adm_sport>=1024, "dst"',
            'adm_dport<32768 AND adm_sport>=32768, "dst"',
            'adm_sport<adm_dport, "src"',
        ]
        self.assertEqual(sorted(order, key=body.index), order)

    def test_new_macros_stay_outside_the_captured_graph(self):
        captured = closure(self.m, "adm_graph(4)")
        for name in (
            "adm_path_flow_normalize",
            "adm_path_hubble_fields",
            "adm_path_acl_first_poll",
            "adm_path_service_port",
            "adm_path_pod_nodes(2)",
            "adm_identity_k8s_raw",
            "adm_identity_pod_absence",
            "adm_identity_observations",
        ):
            self.assertIn(name, self.m)
            self.assertNotIn(name, captured)


class IdentityMacroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        m = stanzas()
        cls.obs = definition(m["adm_identity_observations"])
        cls.raw = definition(m["adm_identity_k8s_raw"])
        cls.absence = definition(m["adm_identity_pod_absence"])

    def test_pod_fields_come_from_raw_before_automatic_extraction(self):
        self.assertLess(
            self.obs.index("`adm_identity_k8s_raw`"),
            self.obs.index("adm_type=coalesce("),
        )
        for field in (
            "adm_j_type",
            "adm_j_uid",
            "adm_j_pod_ips",
            "adm_j_pod_ip",
            "adm_j_node",
            "adm_j_host_ip",
            "adm_j_started",
        ):
            self.assertRegex(self.obs, rf"coalesce\((?:adm_j_\w+, )*{field}, ")
        for path in (
            "type",
            "object.status.podIP",
            "status.podIPs{}.ip",
            "object.spec.nodeName",
        ):
            self.assertIn(f'"{path}"', self.raw)

    def test_live_shaped_watch_event_puts_type_and_ip_after_10240_characters(self):
        # Shape of the live teastore events: {"object": {...}, "type": ...}
        # with the pod status at the end of the object.
        sample = json.loads(
            (ROOT / "fixtures/raw/kube_object_pods.ndjson").read_text().splitlines()[0]
        )
        obj = sample["event"]["object"]
        obj["spec"]["initContainers"] = [
            {
                "name": "otel",
                "env": [{"name": f"V{i}", "value": "x" * 60} for i in range(160)],
            }
        ]
        raw = json.dumps({"object": obj, "type": "DELETED"})
        self.assertGreater(len(raw), 10240)
        self.assertGreater(raw.index('"status"'), 10240)
        self.assertGreater(raw.index('"type": "DELETED"'), 10240)

    def test_absence_requires_a_complete_snapshot(self):
        for rule in (
            'adm_s_schema=="application_atlas.k8s_pod_node_snapshot.v1"',
            'adm_s_complete=="true" AND adm_s_ns=="all"',
            "adm_manifests==1",
            "adm_objects==adm_expected",
            "adm_fps==adm_expected",
            "adm_uids==adm_expected",
            "adm_times==1",
            "tonumber(last_seen)<adm_snap_t",
            "NOT `adm_mv_has(adm_present, entity_id)`",
        ):
            self.assertIn(rule, self.absence)
        self.assertIn('entity_kind="pod" source="k8s_pods"', self.absence)
        # A later observation in the same run keeps the pod open.
        self.assertIn("adm_absent_at>last_seen, adm_absent_at", self.obs)


if __name__ == "__main__":
    unittest.main()
