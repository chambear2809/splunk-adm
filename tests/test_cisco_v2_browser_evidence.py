"""Pure Node evidence bindings; no browser, Docker, credentials or Splunk."""

import copy
import csv
import io
import json
from pathlib import Path
import subprocess
import unittest


HELPER = Path(__file__).parent / "splunk/cisco-v2-evidence.mjs"
RUN = """
const { selectScenarioEvidence, assertScenarioCsv, assertOriginalEvidence, csvRecords } = await import(process.argv[1]);
let input = ''; for await (const chunk of process.stdin) input += chunk;
const value = JSON.parse(input);
try {
  if (value.evidenceComparison) {
    const {actual, raw, kind} = value.evidenceComparison;
    assertOriginalEvidence(actual, raw, kind);
    process.stdout.write(JSON.stringify({ok:true}));
    process.exit(0);
  }
  const selected = selectScenarioEvidence(value.graph, value.scenario);
  if (value.context !== undefined)
    assertScenarioCsv(value.context, value.flows, selected, value.graph, value.scenario);
  process.stdout.write(JSON.stringify({ok:true, mac:selected.client.id,
    ip:selected.ipClient.id, reason:selected.ipClient.reason,
    edge:selected.connection.id,
    ...(value.returnParsedContext ? {context:csvRecords(value.context)} : {})}));
} catch (error) { process.stdout.write(JSON.stringify({ok:false,error:error.message})); }
"""


class CiscoV2BrowserEvidenceTest(unittest.TestCase):
    @staticmethod
    def fixture():
        scenario = {
            "clientId": "network_client:mac",
            "clientMac": "02:61:00:00:00:20",
            "clientIp": "10.61.0.20",
            "scope": "campus-aci",
            "cluster": "cluster-a",
            "sourceAuthority": "https://controller.example.invalid",
            "attachmentDeviceId": "catalyst:switch",
            "attachmentBasis": "catalyst_client_snapshot",
            "handoffRows": [
                {
                    "client_ip": "10.61.0.20",
                    "scope": "campus-aci",
                    "adm_fe_id": "service",
                    "adm_cport": "54120",
                    "adm_ct": "100",
                    "adm_cend": "101",
                    "server_port": "8080",
                    "transport": "tcp",
                    "handoff_basis": "hubble_client_tuple",
                    "adm_targets": ["pod:cluster-a/backend"],
                    "via_node": ["receiver-a"],
                    "adm_mT": [
                        "54120|100|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101|tcp"
                    ],
                    "adm_cid": "own-connection",
                    "adm_cands": [
                        "shop/checkout-api|backend|10.1.0.2|8080|receiver-a|90|-|http|tcp"
                    ],
                }
            ],
        }
        traffic = {
            "source": "stream_ipfix",
            "source_authority": "192.0.2.1",
            "record_fingerprint": "fingerprint",
            "scope": "campus-aci",
            "cluster": "cluster-a",
            "source_ip": "10.61.0.20",
            "destination_ip": "10.50.0.20",
            "source_port": 54120,
            "destination_port": 8080,
            "transport": "tcp",
            "first_seen": 100,
            "last_seen": 101,
        }
        attachment = {
            "client_authority": scenario["sourceAuthority"],
            "client_native_id": scenario["clientMac"],
            "device_id": scenario["attachmentDeviceId"],
            "basis": scenario["attachmentBasis"],
        }
        graph = {
            "nodes": [
                {
                    "id": scenario["clientId"],
                    "endpoint_kind": "network_client",
                    "addresses": [scenario["clientIp"]],
                    "attributes": {
                        "client_mac": scenario["clientMac"],
                        "scope": scenario["scope"],
                    },
                },
                {
                    "id": "ip:campus-aci/10.61.0.20",
                    "label": scenario["clientIp"],
                    "endpoint_kind": "unresolved",
                    "addresses": [scenario["clientIp"]],
                    "reason": "No identity record covers this IP in scope campus-aci",
                    "attributes": {"scope": scenario["scope"]},
                },
                {
                    "id": "service",
                    "label": "Checkout API",
                    "cluster": "cluster-a",
                    "endpoint_kind": "k8s_service",
                    "addresses": ["10.50.0.20"],
                    "namespace": "shop",
                    "attributes": {"service": "checkout-api"},
                },
                {
                    "id": "pod:cluster-a/backend",
                    "label": 'pod "checkout"',
                    "cluster": "cluster-a",
                    "addresses": ["10.1.0.2"],
                },
            ],
            "edges": [
                {
                    "id": "observation",
                    "relationship": "traffic_observation",
                    "source": scenario["clientId"],
                    "target": "service",
                    "scope": scenario["scope"],
                    "cluster": scenario["cluster"],
                    "source_port": 54120,
                    "destination_port": 8080,
                    "transport": "tcp",
                    "traffic_observations": [traffic],
                    "attachment_evidence": [attachment],
                },
                {
                    "id": "conversation",
                    "relationship": "communicates_with",
                    "source": "ip:campus-aci/10.61.0.20",
                    "target": "service",
                    "server_port": 8080,
                    "transport": "tcp",
                    "client_handoff_coverage": "complete",
                    "client_handoff_unresolved": 0,
                    "client_handoffs": [
                        {
                            "target": "pod:cluster-a/backend",
                            "basis": "hubble_client_tuple",
                            "connections": 1,
                            "receiving_nodes": ["receiver-a"],
                            "observers": ["hubble:receiver-a"],
                        }
                    ],
                },
                {
                    "id": "aggregate",
                    "relationship": "forwards_to",
                    "source": "service",
                    "target": "pod:cluster-a/backend",
                    "confidence": "observed",
                },
            ],
        }
        scenario["observationRecords"] = [
            {
                "id": "observation",
                "target": "service",
                "traffic": [copy.deepcopy(traffic)],
                "attachments": [copy.deepcopy(attachment)],
            }
        ]
        return {"graph": graph, "scenario": scenario}

    def run_helper(self, value):
        result = subprocess.run(
            ["node", "--input-type=module", "-e", RUN, HELPER.resolve().as_uri()],
            input=json.dumps(value),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def as_csv(rows):
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        return stream.getvalue()

    def with_exports(self, value):
        edge = value["graph"]["edges"][0]
        context = []
        for kind, records in (
            ("traffic_observation", edge["traffic_observations"]),
            ("attachment_evidence", edge["attachment_evidence"]),
        ):
            for record in records:
                context.append(
                    {
                        "edge_id": edge["id"],
                        "source_id": edge["source"],
                        "target_id": edge["target"],
                        "evidence_kind": kind,
                        "source_authority": record.get("source_authority", ""),
                        "client_authority": record.get("client_authority", ""),
                        "evidence_json": json.dumps(record, separators=(",", ":")),
                    }
                )
        flow = {
            "client_ip": "10.61.0.20",
            "client_name": "10.61.0.20",
            "server_name": "Checkout API",
            "port": "8080",
            "transport": "tcp",
            "client_kind": "Unknown IP",
            "identity": "Unknown IP",
            "client_attachment_authority": "",
            "client_attachment_device_id": "",
            "handoff": "Hubble: same client tuple (1)",
            "backend": 'pod "checkout" (1 connections; Hubble: same client tuple (1))',
        }
        value.update(context=self.as_csv(context), flows=self.as_csv([flow]))
        return value, context, flow

    def test_distinct_mac_and_ip_contracts_and_exact_csv_records(self):
        value, _, _ = self.with_exports(self.fixture())
        result = self.run_helper(value)
        self.assertTrue(result["ok"], result)
        self.assertNotEqual(result["mac"], result["ip"])
        self.assertIn("No identity record", result["reason"])

    @staticmethod
    def normalized_fixture():
        value = CiscoV2BrowserEvidenceTest.fixture()
        actual = value["graph"]["edges"][0]["traffic_observations"][0]
        raw = value["scenario"]["observationRecords"][0]["traffic"][0]
        # Reproduce the reported raw query/export representation differences.
        for field, number in (
            ("flow_id", 47001),
            ("observation_domain_id", 701),
            ("routing_domain", 20),
            ("vpn_id", 20),
            ("sequence", 1001),
            ("ingress_overlay_session_id", 90101),
            ("egress_overlay_session_id", 90201),
        ):
            raw[field], actual[field] = number, str(number)
        raw["source_authority"], actual["source_authority"] = 192, "192"
        raw["metrics_authoritative"], actual["metrics_authoritative"] = "0", False
        raw.update(observation_point="", quality_errors="Null", collected_time=None)
        raw.update(raw_sampling=0, records=0, observation_domain_present=0)
        actual.update(raw_sampling=0, records=0, observation_domain_present=0)
        attachment = value["scenario"]["observationRecords"][0]["attachments"][0]
        attachment.update(device_serial="", collected_time=None, device_name="Null")
        return value

    def test_explicit_raw_to_export_normalization_and_exact_canonical_csv(self):
        value, _, _ = self.with_exports(self.normalized_fixture())
        self.assertTrue(self.run_helper(value)["ok"])
        # The other documented metric literal is equally explicit.
        value["scenario"]["observationRecords"][0]["traffic"][0][
            "metrics_authoritative"
        ] = "1"
        value["graph"]["edges"][0]["traffic_observations"][0][
            "metrics_authoritative"
        ] = True
        value, _, _ = self.with_exports(value)
        self.assertTrue(self.run_helper(value)["ok"])

    def test_csv_authority_round_trips_quotes_commas_newlines_and_rejects_changes(self):
        for authority in (
            '["org-demo","network-demo"]',
            'org,"quoted"',
            'org,"quoted"\nnetwork\r\nnext',
        ):
            value = self.fixture()
            value["scenario"]["sourceAuthority"] = authority
            value["graph"]["nodes"][0]["attributes"]["source_authority"] = authority
            edge = value["graph"]["edges"][0]
            raw = value["scenario"]["observationRecords"][0]
            edge["traffic_observations"][0]["source_authority"] = authority
            raw["traffic"][0]["source_authority"] = authority
            edge["attachment_evidence"][0]["client_authority"] = authority
            raw["attachments"][0]["client_authority"] = authority
            value, context, _ = self.with_exports(value)
            value["returnParsedContext"] = True
            with self.subTest(authority=authority):
                result = self.run_helper(value)
                self.assertTrue(result["ok"], result)
                traffic, attachment = result["context"]
                self.assertEqual(traffic["source_authority"], authority)
                self.assertEqual(attachment["client_authority"], authority)
                self.assertEqual(
                    json.loads(attachment["evidence_json"])["client_authority"],
                    authority,
                )
                # The actual encoded CSV can double quotes and embed newlines;
                # retaining the original semantic value is the requirement.
                if '"' in authority:
                    self.assertNotIn(authority, value["context"])
            for mutate in ("changed", "omitted"):
                changed = copy.deepcopy(value)
                changed_context = copy.deepcopy(context)
                record = json.loads(changed_context[1]["evidence_json"])
                if mutate == "changed":
                    record["client_authority"] = 'another,"organization"'
                else:
                    record.pop("client_authority")
                changed_context[1]["evidence_json"] = json.dumps(record)
                # Correct flattened authority cannot launder an altered record.
                changed["context"] = self.as_csv(changed_context)
                with self.subTest(authority=authority, mutation=mutate):
                    self.assertFalse(self.run_helper(changed)["ok"])

    def test_flattened_authorities_must_match_json_and_opposite_kind_stays_blank(self):
        for index, field, replacement in (
            (0, "source_authority", "wrong-exporter"),
            (0, "source_authority", ""),
            (1, "client_authority", "wrong-controller"),
            (1, "client_authority", ""),
            (0, "client_authority", "unexpected-controller"),
            (1, "source_authority", "unexpected-exporter"),
        ):
            value, context, _ = self.with_exports(self.fixture())
            original_json = context[index]["evidence_json"]
            context[index][field] = replacement
            value["context"] = self.as_csv(context)
            self.assertEqual(context[index]["evidence_json"], original_json)
            with self.subTest(row=index, field=field, replacement=replacement):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_canonical_graph_must_not_contain_raw_representation_or_empty_members(self):
        for update in (
            {"flow_id": 47001},
            {"metrics_authoritative": "0"},
            {"observation_point": ""},
            {"quality_errors": "Null"},
            {"collected_time": None},
        ):
            value = self.normalized_fixture()
            value["graph"]["edges"][0]["traffic_observations"][0].update(update)
            with self.subTest(update=update):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_normalization_rejects_malformed_raw_types_and_unknown_fields(self):
        for update in (
            {"flow_id": True},
            {"flow_id": 2**53},
            {"flow_id": 1.5},
            {"routing_domain": []},
            {"metrics_authoritative": 0},
            {"metrics_authoritative": "false"},
            {"first_seen": "100"},
            {"raw_packets": -1},
            {"quality_status": "unverified"},
            {"unexpected_provenance": ""},
            {"received_time": False},
        ):
            value = self.normalized_fixture()
            value["scenario"]["observationRecords"][0]["traffic"][0].update(update)
            with self.subTest(update=update):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_normalization_does_not_drop_or_coerce_changed_material_evidence(self):
        for update in (
            {"flow_id": "47002"},
            {"flow_id": "047001"},
            {"observation_domain_id": "702"},
            {"routing_domain": "21"},
            {"vpn_id": "21"},
            {"source_authority": "another-exporter"},
            {"metrics_authoritative": True},
            {"source_ip": "10.61.0.21"},
            {"first_seen": 100.5},
            {"record_fingerprint": "another-fingerprint"},
            {"observation_point": "new-assertion"},
            {"raw_sampling": "0"},
            {"records": "0"},
        ):
            value = self.normalized_fixture()
            value["graph"]["edges"][0]["traffic_observations"][0].update(update)
            with self.subTest(update=update):
                self.assertFalse(self.run_helper(value)["ok"])
        for field in ("flow_id", "metrics_authoritative", "raw_sampling", "records"):
            value = self.normalized_fixture()
            value["graph"]["edges"][0]["traffic_observations"][0].pop(field)
            with self.subTest(omitted=field):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_attachment_omissions_are_bounded_and_retained_types_remain_exact(self):
        for update in (
            {"client_authority": "another-controller"},
            {"device_id": "another-switch"},
            {"status": "new-status"},
            {"collected_time": 100},
            {"device_name": ""},
            {"unexpected_provenance": ""},
        ):
            value = self.normalized_fixture()
            value["graph"]["edges"][0]["attachment_evidence"][0].update(update)
            with self.subTest(update=update):
                self.assertFalse(self.run_helper(value)["ok"])
        for actual, raw in (
            ({"event_time": 100}, {"event_time": "100"}),
            ({"ssid_number": 1}, {"ssid_number": "1"}),
            ({"event_time": -1}, {"event_time": -1}),
            ({"event_time": "not-time"}, {"event_time": "not-time"}),
            ({"client_native_id": 123}, {"client_native_id": 123}),
        ):
            with self.subTest(actual=actual, raw=raw):
                self.assertFalse(
                    self.run_helper(
                        {
                            "evidenceComparison": {
                                "kind": "attachments",
                                "actual": [actual],
                                "raw": [raw],
                            }
                        }
                    )["ok"]
                )

    def test_context_csv_remains_exact_to_canonical_graph_after_raw_normalization(self):
        value, context, _ = self.with_exports(self.normalized_fixture())
        original = json.loads(context[0]["evidence_json"])
        self.assertIs(original["metrics_authoritative"], False)
        original["metrics_authoritative"] = "0"
        context[0]["evidence_json"] = json.dumps(original)
        value["context"] = self.as_csv(context)
        self.assertFalse(self.run_helper(value)["ok"])

    def test_records_and_array_order_cannot_be_lost_or_replaced(self):
        for actual, raw in (
            (None, []),
            ([None], [None]),
            ([["nested"]], [["nested"]]),
            ([{"flow_id": "1"}], [{"flow_id": 1}, {"flow_id": 2}]),
            ([{"flow_id": "2"}, {"flow_id": "1"}], [{"flow_id": 1}, {"flow_id": 2}]),
        ):
            with self.subTest(actual=actual, raw=raw):
                self.assertFalse(
                    self.run_helper(
                        {
                            "evidenceComparison": {
                                "kind": "traffic",
                                "actual": actual,
                                "raw": raw,
                            }
                        }
                    )["ok"]
                )

    def test_other_client_scope_tuple_time_and_aggregate_substitution_are_rejected(
        self,
    ):
        for index, mutate in enumerate(
            (
                lambda v: v["graph"]["nodes"][1].update(addresses=["10.61.0.21"]),
                lambda v: v["graph"]["nodes"][1]["attributes"].update(
                    scope="another-scope"
                ),
                lambda v: v["scenario"]["handoffRows"][0].update(
                    client_ip="10.61.0.21"
                ),
                lambda v: v["scenario"]["handoffRows"][0].update(scope="another-scope"),
                lambda v: v["scenario"]["handoffRows"][0].update(adm_cport="54121"),
                lambda v: v["scenario"]["handoffRows"][0].update(server_port="8443"),
                lambda v: v["scenario"]["handoffRows"][0].update(transport="udp"),
                lambda v: v["scenario"]["handoffRows"][0].update(
                    adm_ct="102", adm_cend="103"
                ),
                lambda v: v["graph"]["edges"][1].pop("client_handoffs"),
                lambda v: v["graph"]["edges"][1]["client_handoffs"][0].update(
                    receiving_nodes=["aggregate-receiver"]
                ),
                lambda v: v["graph"]["edges"][1]["client_handoffs"][0].update(
                    observers=["hubble:another-client-observer"]
                ),
                lambda v: v["graph"]["edges"][1]["client_handoffs"][0].update(
                    connections=2
                ),
                lambda v: v["graph"]["edges"][1]["client_handoffs"][0].update(
                    target="pod:other/backend"
                ),
                lambda v: v["graph"]["nodes"][1].pop("reason"),
                lambda v: v["graph"]["nodes"][1]["attributes"].update(
                    client_mac="02:61:00:00:00:20"
                ),
                lambda v: v["graph"]["edges"][0]["traffic_observations"][0].update(
                    source_authority="another-exporter"
                ),
            )
        ):
            value = self.fixture()
            mutate(value)
            with self.subTest(case=index):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_csv_cannot_substitute_another_mac_record_or_promote_ip_identity(self):
        for case in (
            "another-observation",
            "promoted-ip",
            "other-flow",
            "aggregate-count",
            "extra-backend",
        ):
            value, context, flow = self.with_exports(self.fixture())
            if case == "another-observation":
                context[0]["source_id"] = "network_client:other"
                value["context"] = self.as_csv(context)
            elif case == "aggregate-count":
                flow["handoff"] = "Hubble: same client tuple (2)"
                value["flows"] = self.as_csv([flow])
            elif case == "extra-backend":
                flow["backend"] += "; another-client-pod (received on other-node)"
                value["flows"] = self.as_csv([flow])
            else:
                flow.update(
                    {"client_attachment_authority": "controller"}
                    if case == "promoted-ip"
                    else {"client_ip": "10.61.0.21"}
                )
                value["flows"] = self.as_csv([flow])
            with self.subTest(case=case):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_original_backend_tuple_must_match_connection_port_time_transport_target_receiver(
        self,
    ):
        for tuple_value in (
            "59999|10000|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|10001|udp",
            "59999|100|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101|tcp",
            "54120|10000|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|10001|tcp",
            "54120|100|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101|udp",
            "54120|100|10.1.0.2:8080|pod:other/backend|receiver-a|101|tcp",
            "54120|100|10.1.0.2:8080|pod:cluster-a/backend|other-node|101|tcp",
            "54120|100|10.1.0.3:8080|pod:cluster-a/backend|receiver-a|101|tcp",
            "54120|100|10.1.0.2:99999|pod:cluster-a/backend|receiver-a|101|tcp",
            "54120|100|10.1.0.2:8443|pod:cluster-a/backend|receiver-a|101|tcp",
            "54120|NaN|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101|tcp",
            "54120|102|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101|tcp",
            "54120|100|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101|tcp|extra",
            "54120|100|10.1.0.2:8080|pod:cluster-a/backend|receiver-a|101",
        ):
            value = self.fixture()
            value["scenario"]["handoffRows"][0]["adm_mT"] = [tuple_value]
            with self.subTest(tuple=tuple_value):
                self.assertFalse(self.run_helper(value)["ok"])

    def test_service_mapping_accepts_real_port_translation_and_rejects_other_mapping(
        self,
    ):
        value, _, _ = self.with_exports(self.fixture())
        row = value["scenario"]["handoffRows"][0]
        # Frontend 8080 maps to backend 8443, proven by the same EndpointSlice
        # candidate selected for this Service and the original Hubble tuple.
        row["adm_mT"] = [row["adm_mT"][0].replace(":8080|", ":8443|")]
        row["adm_cands"] = [
            "shop/checkout-api|backend|10.1.0.2|8443|receiver-a|90|102|http|tcp"
        ]
        self.assertTrue(self.run_helper(value)["ok"])
        for candidate in (
            "shop/checkout-api|backend|10.1.0.2|8080|receiver-a|90|102|http|tcp",
            "shop/another-service|backend|10.1.0.2|8443|receiver-a|90|102|http|tcp",
            "shop/checkout-api|other-pod|10.1.0.2|8443|receiver-a|90|102|http|tcp",
            "shop/checkout-api|backend|10.1.0.3|8443|receiver-a|90|102|http|tcp",
            "shop/checkout-api|backend|10.1.0.2|8443|receiver-a|90|102|http|udp",
            "shop/checkout-api|backend|10.1.0.2|8443|receiver-a|102|-|http|tcp",
            "shop/checkout-api|backend|10.1.0.2|8443|receiver-a|90|100|http|tcp",
            "shop/checkout-api|backend|10.1.0.2|8443|receiver-a|90|-|http",
        ):
            changed = copy.deepcopy(value)
            changed["scenario"]["handoffRows"][0]["adm_cands"] = [candidate]
            with self.subTest(candidate=candidate):
                self.assertFalse(self.run_helper(changed)["ok"])
