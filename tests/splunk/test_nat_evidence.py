"""Same-event FTD NAT evidence tests for the disposable Splunk lab.

The fixture is synthetic and validates local parsing only; it is not proof of
live FMC/FTD eStreamer emission. Run with the task-owned lab environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
import unittest
import urllib.parse
import uuid

import lab


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "raw-nat-ftd" / "ftd_connection_nat.ndjson"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class NatEvidenceTest(unittest.TestCase):
    """Verify tuple preservation does not add traffic or handoff rows."""

    def setUp(self) -> None:
        self.token = "nat-evidence-" + uuid.uuid4().hex[:12]
        self.start = int(time.time()) - 30
        self.scopes = {
            "base": self.token + "-base",
            "nat": self.token + "-nat",
            "mapped": self.token + "-mapped",
            "time_format": self.token + "-time-format",
            "cap": self.token + "-cap",
            "multi": self.token + "-multi",
            "port": self.token + "-port",
            "port_high": self.token + "-port-high",
            "sentinel": self.token + "-sentinel",
            "unspecified": self.token + "-unspecified",
            "unspecified_expanded": self.token + "-unspecified-expanded",
            "port_format": self.token + "-port-format",
            "invalid_ip": self.token + "-invalid-ip",
            "protocol": self.token + "-protocol",
            "unchanged": self.token + "-unchanged",
            "eventtype": self.token + "-eventtype",
            "unmapped": self.token + "-unmapped",
        }
        self.devices = {
            "base": "192.0.2.10",
            "nat": "192.0.2.11",
            "mapped": "192.0.2.23",
            "time_format": "192.0.2.24",
            "cap": "192.0.2.12",
            "multi": "192.0.2.13",
            "port": "192.0.2.14",
            "port_high": "192.0.2.26",
            "sentinel": "192.0.2.15",
            "unspecified": "192.0.2.19",
            "unspecified_expanded": "192.0.2.25",
            "port_format": "192.0.2.20",
            "invalid_ip": "192.0.2.21",
            "protocol": "192.0.2.22",
            "unchanged": "192.0.2.16",
            "eventtype": "192.0.2.17",
            "unmapped": "192.0.2.18",
        }
        self.addCleanup(self.cleanup_scopes)
        self.register_scopes()
        self.load_events()
        self.wait_for_events()

    def cleanup_scopes(self) -> None:
        query = urllib.parse.urlencode(
            {"query": json.dumps({"scope": {"$in": list(self.scopes.values())}})}
        )
        response = lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{lab.APP}/storage/collections/data/adm_observer_scope?{query}",
        )
        response.close()

    def register_scopes(self) -> None:
        rows = [
            {
                "observer_kind": "firewall",
                "observer": self.devices[name],
                "scope": self.scopes[name],
                "cluster": "",
            }
            for name in self.scopes
            if name != "unmapped"
        ]
        payload = json.dumps(json.dumps(rows))
        lab.search(
            f"| makeresults format=json data={payload} "
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            "_key=sha256(json_array(observer_kind, observer)) "
            "| fields _key observer_kind observer scope cluster "
            "| outputlookup append=true key_field=_key adm_observer_scope"
        )

    def load_events(self) -> None:
        template = json.loads(FIXTURE.read_text("utf-8").splitlines()[0])
        base_event = json.loads(template["event"])
        events = [self.envelope("base", base_event, 1, nat=False)]
        events.append(self.envelope("nat", base_event, 2, nat=True))
        mapped = self.envelope("mapped", base_event, 13, nat=True)
        mapped_event = json.loads(mapped["event"])
        mapped_event["NAT_InitiatorIP"] = "::ffff:192.0.2.44"
        mapped["event"] = json.dumps(mapped_event, separators=(",", ":"))
        events.append(mapped)
        malformed_time = self.envelope("time_format", base_event, 14, nat=True)
        malformed_time_event = json.loads(malformed_time["event"])
        malformed_time_event["FirstPacketSecond"] = f"{self.start}.5"
        malformed_time["event"] = json.dumps(
            malformed_time_event, separators=(",", ":")
        )
        events.append(malformed_time)
        events.extend(
            self.envelope("cap", base_event, 100 + index, nat=True)
            for index in range(33)
        )

        multivalue = self.envelope("multi", base_event, 3, nat=True)
        multivalue_event = json.loads(multivalue["event"])
        multivalue_event["NAT_InitiatorPort"] = [35000, 35001]
        multivalue["event"] = json.dumps(multivalue_event, separators=(",", ":"))
        events.append(multivalue)
        invalid_port = self.envelope("port", base_event, 4, nat=True)
        invalid_event = json.loads(invalid_port["event"])
        invalid_event["NAT_InitiatorPort"] = 0
        invalid_port["event"] = json.dumps(invalid_event, separators=(",", ":"))
        events.append(invalid_port)
        high_port = self.envelope("port_high", base_event, 16, nat=True)
        high_port_event = json.loads(high_port["event"])
        high_port_event["NAT_InitiatorPort"] = 65536
        high_port["event"] = json.dumps(high_port_event, separators=(",", ":"))
        events.append(high_port)
        sentinel_ip = self.envelope("sentinel", base_event, 5, nat=True)
        sentinel_event = json.loads(sentinel_ip["event"])
        sentinel_event["NAT_ResponderIP"] = "255.255.255.255"
        sentinel_ip["event"] = json.dumps(sentinel_event, separators=(",", ":"))
        events.append(sentinel_ip)
        unspecified_ip = self.envelope("unspecified", base_event, 9, nat=True)
        unspecified_event = json.loads(unspecified_ip["event"])
        unspecified_event["NAT_ResponderIP"] = "0.0.0.0"
        unspecified_ip["event"] = json.dumps(unspecified_event, separators=(",", ":"))
        events.append(unspecified_ip)
        unspecified_expanded = self.envelope(
            "unspecified_expanded", base_event, 15, nat=True
        )
        unspecified_expanded_event = json.loads(unspecified_expanded["event"])
        unspecified_expanded_event["NAT_ResponderIP"] = "0:0:0:0:0:0:0:0"
        unspecified_expanded["event"] = json.dumps(
            unspecified_expanded_event, separators=(",", ":")
        )
        events.append(unspecified_expanded)
        malformed_port = self.envelope("port_format", base_event, 10, nat=True)
        malformed_port_event = json.loads(malformed_port["event"])
        malformed_port_event["NAT_InitiatorPort"] = "35000.0"
        malformed_port["event"] = json.dumps(
            malformed_port_event, separators=(",", ":")
        )
        events.append(malformed_port)
        invalid_ip = self.envelope("invalid_ip", base_event, 11, nat=True)
        invalid_ip_event = json.loads(invalid_ip["event"])
        invalid_ip_event["NAT_InitiatorIP"] = "999.0.0.1"
        invalid_ip["event"] = json.dumps(invalid_ip_event, separators=(",", ":"))
        events.append(invalid_ip)
        unsupported_protocol = self.envelope("protocol", base_event, 12, nat=True)
        unsupported_event = json.loads(unsupported_protocol["event"])
        unsupported_event["Protocol"] = "GRE"
        unsupported_protocol["event"] = json.dumps(
            unsupported_event, separators=(",", ":")
        )
        events.append(unsupported_protocol)
        unchanged = self.envelope("unchanged", base_event, 6, nat=True)
        unchanged_event = json.loads(unchanged["event"])
        for source, translated in (
            ("InitiatorIP", "NAT_InitiatorIP"),
            ("InitiatorPort", "NAT_InitiatorPort"),
            ("ResponderIP", "NAT_ResponderIP"),
            ("ResponderPort", "NAT_ResponderPort"),
        ):
            unchanged_event[translated] = unchanged_event[source]
        unchanged["event"] = json.dumps(unchanged_event, separators=(",", ":"))
        events.append(unchanged)
        multivalue_type = self.envelope("eventtype", base_event, 7, nat=True)
        multivalue_type_event = json.loads(multivalue_type["event"])
        multivalue_type_event["EventType"] = ["ConnectionEvent", "OtherEvent"]
        multivalue_type["event"] = json.dumps(
            multivalue_type_event, separators=(",", ":")
        )
        events.append(multivalue_type)
        events.append(self.envelope("unmapped", base_event, 8, nat=True))

        body = (
            b"\n".join(
                json.dumps(event, separators=(",", ":")).encode() for event in events
            )
            + b"\n"
        )
        lab._hec_post(body)
        self.loaded = len(events)

    def envelope(
        self, name: str, template: dict, connection_id: int, *, nat: bool
    ) -> dict:
        event = dict(template)
        event["FirstPacketSecond"] = self.start
        event["DeviceIP"] = self.devices[name]
        event["ConnectionID"] = connection_id
        if not nat:
            for key in (
                "NAT_InitiatorIP",
                "NAT_InitiatorPort",
                "NAT_ResponderIP",
                "NAT_ResponderPort",
                "OriginalInitiatorIP",
            ):
                event.pop(key, None)
        return {
            "time": self.start,
            "host": self.devices[name],
            "source": self.token,
            "sourcetype": "cisco:sfw:estreamer",
            "index": "cisco_secure_fw",
            "event": json.dumps(event, separators=(",", ":")),
        }

    def wait_for_events(self) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = lab.search(
                f'index=cisco_secure_fw source="{self.token}" | stats count AS count',
                self.start - 60,
                self.start + 600,
            )
            if rows and int(rows[0]["count"]) == self.loaded:
                return
            time.sleep(1)
        self.fail("FTD NAT fixture events did not become searchable")

    def rollups(self) -> dict[str, dict]:
        rows = lab.search(
            "| `adm_conversation_rollup` "
            f'| where scope IN ("{self.scopes["base"]}","{self.scopes["nat"]}","{self.scopes["mapped"]}","{self.scopes["time_format"]}","{self.scopes["cap"]}","{self.scopes["multi"]}","{self.scopes["port"]}","{self.scopes["port_high"]}","{self.scopes["sentinel"]}","{self.scopes["unspecified"]}","{self.scopes["unspecified_expanded"]}","{self.scopes["port_format"]}","{self.scopes["invalid_ip"]}","{self.scopes["protocol"]}","{self.scopes["unchanged"]}","{self.scopes["eventtype"]}") OR like(scope,"unmapped:%") '
            "| table adm_record scope client_ip server_ip server_port transport "
            "bytes_c2s bytes_s2c packets records nat_observations nat_observations_truncated",
            self.start - 60,
            self.start + 600,
        )
        return {row["scope"]: row for row in rows}

    def test_explicit_tuples_are_metadata_only_and_reject_ambiguous_values(self):
        rows = self.rollups()
        self.assertEqual(len(rows), len(self.scopes))
        base = rows[self.scopes["base"]]
        nat = rows[self.scopes["nat"]]
        self.assertEqual(base["adm_record"], "conversation")
        self.assertEqual(nat["adm_record"], "conversation")
        for field in (
            "client_ip",
            "server_ip",
            "server_port",
            "transport",
            "bytes_c2s",
            "bytes_s2c",
            "packets",
            "records",
        ):
            self.assertEqual(nat[field], base[field], field)
        self.assertEqual(int(nat["records"]), 1)
        self.assertEqual(int(nat["packets"]), 5)
        self.assertEqual(int(nat["bytes_c2s"]), 620)
        self.assertEqual(int(nat["bytes_s2c"]), 4800)
        observation = json.loads(nat["nat_observations"])[0]
        self.assertEqual(observation["source_authority"], "cisco:sfw:estreamer")
        self.assertEqual(observation["scope"], self.scopes["nat"])
        self.assertTrue(observation["scope_mapping_verified"])
        self.assertEqual(observation["device_ip"], self.devices["nat"])
        self.assertRegex(observation["event_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(observation["event_time"], self.start)
        self.assertGreaterEqual(observation["received_time"], observation["event_time"])
        self.assertEqual(observation["protocol"], "tcp")
        self.assertEqual(observation["direction"], "initiator_to_responder")
        self.assertEqual(observation["reported_initiator_ip"], "198.51.100.8")
        self.assertEqual(observation["reported_initiator_port"], 51400)
        self.assertEqual(observation["translated_initiator_ip"], "192.0.2.44")
        self.assertEqual(observation["translated_initiator_port"], 35000)
        self.assertEqual(observation["reported_responder_ip"], "203.0.113.10")
        self.assertEqual(observation["translated_responder_ip"], "203.0.113.10")
        self.assertIn("reported_original_initiator_ip", observation)
        self.assertEqual(observation["reported_original_initiator_ip"], "198.51.100.8")
        self.assertNotIn("original_initiator_port", observation)
        self.assertNotIn("nat_observations", base)

        mapped = rows[self.scopes["mapped"]]
        mapped_observation = json.loads(mapped["nat_observations"])[0]
        self.assertEqual(mapped_observation["translated_initiator_ip"], "192.0.2.44")

        for name in (
            "multi",
            "port",
            "port_high",
            "sentinel",
            "unspecified",
            "unspecified_expanded",
            "port_format",
            "invalid_ip",
            "protocol",
            "time_format",
            "unchanged",
            "eventtype",
        ):
            with self.subTest(name=name):
                row = rows[self.scopes[name]]
                self.assertEqual(row["adm_record"], "conversation")
                self.assertNotIn("nat_observations", row)

        unmapped = [row for scope, row in rows.items() if scope.startswith("unmapped:")]
        self.assertEqual(len(unmapped), 1)
        self.assertNotIn("nat_observations", unmapped[0])

        capped = rows[self.scopes["cap"]]
        self.assertEqual(int(capped["records"]), 33)
        self.assertEqual(int(capped["packets"]), 165)
        self.assertEqual(int(capped["bytes_c2s"]), 33 * 620)
        self.assertEqual(int(capped["bytes_s2c"]), 33 * 4800)
        self.assertEqual(len(json.loads(capped["nat_observations"])), 32)
        self.assertEqual(str(capped["nat_observations_truncated"]), "1")

    def test_nat_observation_alone_does_not_create_a_backend_handoff(self):
        row = self.rollups()[self.scopes["nat"]]
        literal = json.dumps(row["nat_observations"])
        connection = f"51400@{self.start}@{self.start}"
        results = lab.search(
            f'| makeresults | eval adm_row="conv", adm_keep=1, scope="nat-scope", '
            f'client_ip="198.51.100.8", server_ip="203.0.113.10", server_port=443, transport="tcp", '
            f'adm_c_kind="client", adm_s_kind="k8s_service", adm_c_id="client:nat-test", '
            f'adm_s_id="service:nat-cluster/default/nat-app", adm_s_name="nat-app", adm_s_ns="default", '
            f'adm_conns="{connection}", nat_observations={literal} | addinfo '
            '| `adm_graph_handoffs("nat-app","prod","nat-cluster","default")` '
            '| stats count(eval(adm_row=="fwd")) AS backend_handoffs',
        )
        self.assertEqual(int(results[0]["backend_handoffs"]), 0)

    def test_graph_nat_evidence_uses_half_open_event_time_window(self):
        selected_start = (self.start // 300) * 300 + 60
        selected_end = selected_start + 3
        event_times = [
            selected_start - 1,
            selected_start,
            selected_end - 1,
            selected_end,
        ]
        self.assertEqual(
            {event_time // 300 for event_time in event_times}, {selected_start // 300}
        )

        def filtered_events(window_end: float, selected_events: list[int]) -> list[int]:
            observations = [
                {"event_time": event_time, "event_fingerprint": f"event-{index}"}
                for index, event_time in enumerate(selected_events)
            ]
            encoded = json.dumps(observations, separators=(",", ":"))
            literal = json.dumps(encoded)
            rows = lab.search(
                "| makeresults "
                f"| eval _time={selected_start}, nat_observations={literal} "
                "| addinfo | spath input=nat_observations output=adm_nat_contexts path={} "
                "| `adm_nat_filter_window` | mvexpand adm_nat_contexts "
                '| eval event_time=tonumber(json_extract(adm_nat_contexts,"event_time")) '
                "| where isnotnull(event_time) | table event_time",
                selected_start,
                window_end,
            )
            return sorted(int(row["event_time"]) for row in rows)

        self.assertEqual(
            filtered_events(selected_end, event_times),
            [selected_start, selected_end - 1],
        )
        self.assertEqual(
            filtered_events(selected_end + 0.0005, [selected_start, selected_end]),
            [selected_start, selected_end],
        )
