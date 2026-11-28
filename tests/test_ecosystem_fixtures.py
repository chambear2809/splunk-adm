"""Grounding and shipped-default checks for ecosystem traffic evidence fixtures."""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "gen_ecosystem_fixtures", ROOT / "tools" / "gen_ecosystem_fixtures.py"
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

# Splunk_TA_paloalto 6.2.0 lookups/pan_vendor_actions.csv vendor_action column.
PAN_TA_VENDOR_ACTIONS = {
    "alert",
    "allow",
    "block",
    "block-ip",
    "block-url",
    "block-continue",
    "continue",
    "deny",
    "drop",
    "drop-all-packets",
    "drop-packet",
    "Failed",
    "forward",
    "reset-both",
    "reset-client",
    "reset-server",
    "sinkhole",
    "Succeeded",
    "wildfire-upload-skip",
    "wildfire-upload-success",
    "wildfire-upload-fail",
    "unknown",
}
FORTIOS_TRAFFIC_ACTIONS = {
    "deny",
    "accept",
    "start",
    "dns",
    "ip-conn",
    "close",
    "timeout",
    "client-rst",
    "server-rst",
}


def _events(name: str) -> list[dict]:
    path = ROOT / "fixtures" / "raw-ecosystem" / name
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


class EcosystemFixtureTests(unittest.TestCase):
    def test_committed_fixtures_match_generator(self):
        self.assertEqual(gen.main(["--check"]), 0)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(gen.main(["--output-dir", directory]), 0)
            for name in gen.render():
                self.assertEqual(
                    (Path(directory) / name).read_text("utf-8"),
                    (ROOT / "fixtures" / "raw-ecosystem" / name).read_text("utf-8"),
                )

    def test_pan_events_follow_ta_extract_traffic_order(self):
        self.assertEqual(len(gen.PAN_TRAFFIC_FIELDS), 61)
        for envelope in _events("pan_traffic.ndjson"):
            values = envelope["event"].split(",")
            self.assertEqual(len(values), len(gen.PAN_TRAFFIC_FIELDS))
            fields = dict(zip(gen.PAN_TRAFFIC_FIELDS, values))
            self.assertEqual(fields["type"], "TRAFFIC")
            self.assertIn(fields["log_subtype"], {"start", "end", "drop", "deny"})
            self.assertIn(fields["action"], PAN_TA_VENDOR_ACTIONS)
            self.assertEqual(envelope["sourcetype"], "pan:traffic")
            generated = datetime.strptime(
                fields["generated_time"], "%Y/%m/%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            self.assertEqual(envelope["time"], int(generated.timestamp()))
        with self.assertRaises(ValueError):
            gen.pan_event(nat_source="203.0.113.1")

    def test_fortigate_events_use_documented_keys_and_eventtime(self):
        pair = re.compile(r'([a-z]+)=("[^"]*"|[^ ]+)')
        sourcetypes = set()
        for envelope in _events("fortigate_traffic.ndjson"):
            sourcetypes.add(envelope["sourcetype"])
            pairs = pair.findall(envelope["event"])
            keys = [key for key, _ in pairs]
            self.assertEqual(len(keys), len(set(keys)))
            self.assertLessEqual(set(keys), set(gen.FORTIOS_TRAFFIC_KEYS))
            values = {key: value.strip('"') for key, value in pairs}
            self.assertEqual(values["type"], "traffic")
            self.assertIn(values["action"], FORTIOS_TRAFFIC_ACTIONS)
            self.assertRegex(values["eventtime"], r"^\d{19}$")
            self.assertEqual(envelope["time"], int(values["eventtime"]) // 10**9)
        self.assertEqual(sourcetypes, {"fgt_traffic", "fortigate_traffic"})
        with self.assertRaises(ValueError):
            gen.forti_event(natsrc="203.0.113.1")

    def test_f5_events_follow_the_documented_irule_key_order(self):
        key = re.compile(r"(?:^<190>|,)([a-z_0-9]+)=")
        for envelope in _events("f5_ltm_http.ndjson"):
            keys = key.findall(envelope["event"].split('"', 1)[0])
            message = envelope["event"]
            self.assertTrue(message.startswith("<190>,f5_irule=Splunk-iRule-"))
            self.assertTrue(message.endswith("\r\n"))
            failed = "Splunk-iRule-LB_FAILED" in message
            expected = gen.F5_LB_FAILED_KEYS if failed else gen.F5_IRULE_KEYS
            self.assertEqual(keys, list(expected[: len(keys)]))
            self.assertEqual(
                envelope["sourcetype"],
                "f5:bigip:ltm:lb:failed:irule" if failed else "f5:bigip:ltm:http:irule",
            )
        with self.assertRaises(ValueError):
            gen.f5_event(snat_ip="203.0.113.1")

    def test_aws_lines_follow_documented_field_positions(self):
        self.assertEqual(len(gen.ALB_FIELDS), 36)
        self.assertEqual(len(gen.NLB_FIELDS), 26)
        token = re.compile(r'"[^"]*"|\S+')
        for envelope in _events("aws_elb_access.ndjson"):
            fields = token.findall(envelope["event"])
            self.assertEqual(envelope["sourcetype"], "aws:elb:accesslogs")
            if fields[0] == "tls":
                self.assertEqual(len(fields), len(gen.NLB_FIELDS))
                self.assertEqual(fields[1], "3.0")
            else:
                self.assertIn(len(fields), {29, 36})
                self.assertIn(fields[0], {"http", "https", "h2", "grpcs", "ws", "wss"})
                self.assertTrue(fields[2].startswith("app/"))
        with self.assertRaises(ValueError):
            gen.alb_line(snat="203.0.113.1")
        with self.assertRaises(ValueError):
            gen.nlb_line(target_port="10.0.0.1:80")

    def test_azure_records_use_documented_keys_and_tuple_widths(self):
        shapes = []
        for envelope in _events("azure_vnet_flow.ndjson"):
            body = json.loads(envelope["event"])
            records = body.get("records", [body])
            shapes.append(len(records))
            for record in records:
                self.assertLessEqual(set(record), set(gen.AZURE_RECORD_KEYS))
                self.assertEqual(record["category"], "FlowLogFlowEvent")
                width = {4: 13, 5: 16}[record["flowLogVersion"]]
                for flow in record["flowRecords"]["flows"]:
                    for group in flow["flowGroups"]:
                        for item in group["flowTuples"]:
                            parts = item.split(",")
                            self.assertEqual(len(parts), width)
                            self.assertIn(parts[7], {"B", "C", "E", "D"})
                            self.assertIn(parts[6], {"I", "O"})
        self.assertEqual(shapes, [1, 1, 2])
        with self.assertRaises(ValueError):
            gen.azure_tuple(nat_ip="203.0.113.1")

    def test_gcp_entries_use_documented_vpc_flow_fields(self):
        shapes = set()
        for envelope in _events("gcp_vpc_flow.ndjson"):
            body = json.loads(envelope["event"])
            shapes.add("data" if "data" in body else "entry")
            entry = body.get("data", body)
            self.assertLessEqual(set(entry), gen.GCP_LOG_ENTRY_KEYS)
            self.assertTrue(
                entry["logName"].endswith("/logs/compute.googleapis.com%2Fvpc_flows")
            )
            payload = entry["jsonPayload"]
            self.assertLessEqual(set(payload), gen.GCP_PAYLOAD_KEYS)
            self.assertLessEqual(set(payload["connection"]), gen.GCP_CONNECTION_KEYS)
            self.assertIn(payload["reporter"], {"SRC", "DEST"})
            if "nat_ip" in payload["connection"]:
                self.assertEqual(payload["reporter"], "SRC")
            if "disposition" in payload:
                self.assertEqual(payload["disposition"], "DROPPED")
                self.assertNotIn("bytes_sent", payload)
        self.assertEqual(shapes, {"data", "entry"})
        with self.assertRaises(ValueError):
            gen.gcp_entry(gen.BASE, {"connection": {"src_nat": "1"}})


class EcosystemShippedDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.registry = json.loads(
            (ROOT / "config" / "deployment-health.json").read_text("utf-8")
        )
        self.macros = (ROOT / "splunk_app/splunk_adm/default/macros.conf").read_text(
            "utf-8"
        )

    def _setting(self, stanza: str, key: str) -> str:
        body = re.search(
            rf"^\[{re.escape(stanza)}\]\n(.*?)(?=^\[|\Z)",
            self.macros,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(body, stanza)
        value = re.search(rf"^{key}\s*=\s*(.*)$", body.group(1), re.MULTILINE)
        self.assertIsNotNone(value, f"{stanza}.{key}")
        return value.group(1).strip()

    def test_registry_marks_sources_optional_with_no_background_probe(self):
        sources = {source["id"]: source for source in self.registry["sources"]}
        for source_id, kind, macro in (
            ("pan_traffic", "pan_firewall", "adm_index_pan"),
            ("fortigate_traffic", "fortigate_firewall", "adm_index_fortigate"),
            ("f5_ltm_http", "f5_bigip", "adm_index_f5"),
            ("aws_elb_access", "aws_elb", "adm_index_aws"),
            ("azure_vnet_flow", "azure_vnet_flow", "adm_index_azure"),
            ("gcp_vpc_flow", "gcp_vpc_flow", "adm_index_gcp"),
        ):
            source = sources[source_id]
            self.assertEqual(source["readinessImpact"], "optional_evidence")
            self.assertEqual(source["probeMacro"], "")
            self.assertEqual(source["observerKinds"], [kind])
            self.assertEqual(source["indexMacros"], [macro])
            self.assertFalse(
                any(source_id in job["sourceIds"] for job in self.registry["jobs"])
            )

    def test_index_selectors_and_schema_gates_ship_disabled(self):
        for name in (
            "adm_index_pan",
            "adm_index_fortigate",
            "adm_index_f5",
            "adm_index_aws",
            "adm_index_azure",
            "adm_index_gcp",
            "adm_index_intersight",
            "adm_index_sflow",
            "adm_index_fmc_policy",
            "adm_index_netmetrics",
            "adm_index_ise",
            "adm_index_infoblox",
            "adm_index_otel_metrics",
            "adm_index_cloud_transit",
            "adm_index_arista",
            "adm_index_juniper",
            "adm_index_checkpoint",
            "adm_index_nsx",
            "adm_index_netscaler",
            "adm_index_aruba",
            "adm_index_win_ddi",
            "adm_index_asa",
            "adm_index_sase",
            "adm_index_nginx",
            "adm_index_cloudflare",
            "adm_index_mcd",
        ):
            self.assertEqual(
                self._setting(name, "definition"), "index=unconfigured_optional"
            )
        for name in (
            "adm_pan_traffic_schema_qualified",
            "adm_fortigate_traffic_schema_qualified",
            "adm_f5_ltm_irule_schema_qualified",
            "adm_aws_elb_access_schema_qualified",
            "adm_azure_vnet_flow_schema_qualified",
            "adm_gcp_vpc_flow_schema_qualified",
        ):
            self.assertEqual(self._setting(name, "definition"), "0")
            self.assertEqual(self._setting(name, "iseval"), "0")


if __name__ == "__main__":
    unittest.main()
