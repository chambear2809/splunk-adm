"""Same-event FTD NAT evidence tests for the disposable Splunk lab.

The fixture is synthetic and validates local parsing only; it is not proof of
live FMC/FTD eStreamer emission. Run with the task-owned lab environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import hashlib
import subprocess
import time
import unittest
import urllib.parse
import uuid

import lab


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "raw-nat-ftd" / "ftd_connection_nat.ndjson"
OTEL_FIXTURE = ROOT / "fixtures" / "raw" / "otel_traces.ndjson"
FRONTEND_VALIDATOR = ROOT / "tests" / "splunk" / "validate_nat_graph.mjs"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class NatEvidenceTest(unittest.TestCase):
    """Verify tuple preservation does not add traffic or handoff rows."""

    _used_device_ips: set[str] = set()

    def setUp(self) -> None:
        self.token = "nat-evidence-" + uuid.uuid4().hex[:12]
        self.start = int(time.time()) - 30
        self.scopes = {
            "base": self.token + "-base",
            "nat": self.token + "-nat",
            "mapped": self.token + "-mapped",
            "reported_invalid": self.token + "-reported-invalid",
            "ipv6_compressed": self.token + "-ipv6-compressed",
            "ipv6_case": self.token + "-ipv6-case",
            "ipv6_changed": self.token + "-ipv6-changed",
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
        device_names = list(self.scopes)
        device_names += ["graph_base", "graph_cap", "graph_window"]
        address_pool = [
            f"{prefix}.{last_octet}"
            for prefix in ("192.0.2", "198.51.100")
            for last_octet in range(128, 255)
        ]
        seed = int(hashlib.sha256(self.token.encode()).hexdigest(), 16)
        selected_devices = None
        for attempt in range(len(address_pool)):
            offset = (seed + attempt) % len(address_pool)
            candidates = [
                address_pool[(offset + index) % len(address_pool)]
                for index in range(len(device_names))
            ]
            if not self._used_device_ips.intersection(candidates):
                selected_devices = candidates
                self._used_device_ips.update(candidates)
                break
        if selected_devices is None:
            self.fail("test observer IP pool is exhausted")
        all_devices = dict(zip(device_names, selected_devices, strict=True))
        self.devices = {name: all_devices[name] for name in self.scopes}
        self.graph_devices = {
            name: all_devices["graph_" + name] for name in ("base", "cap", "window")
        }
        self.addCleanup(self.cleanup_scopes)
        self.register_scopes()
        self.load_events()
        self.wait_for_events()

    def cleanup_scopes(self) -> None:
        graph_scope = getattr(self, "graph_scope", None)
        scopes = list(self.scopes.values())
        if graph_scope:
            scopes.append(graph_scope)
        query = urllib.parse.urlencode(
            {"query": json.dumps({"scope": {"$in": scopes}})}
        )
        response = lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{lab.APP}/storage/collections/data/adm_observer_scope?{query}",
        )
        response.close()
        identity_keys = getattr(self, "graph_identity_keys", [])
        if identity_keys:
            identity_query = urllib.parse.urlencode(
                {"query": json.dumps({"_key": {"$in": identity_keys}})}
            )
            response = lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/{lab.APP}/storage/collections/data/adm_ip_identity?{identity_query}",
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
        reported_invalid = self.envelope("reported_invalid", base_event, 18, nat=True)
        reported_invalid_event = json.loads(reported_invalid["event"])
        reported_invalid_event["InitiatorIP"] = "not-an-ip"
        reported_invalid["event"] = json.dumps(
            reported_invalid_event, separators=(",", ":")
        )
        events.append(reported_invalid)
        mapped = self.envelope("mapped", base_event, 13, nat=True)
        mapped_event = json.loads(mapped["event"])
        mapped_event["NAT_InitiatorIP"] = "::ffff:192.0.2.44"
        mapped["event"] = json.dumps(mapped_event, separators=(",", ":"))
        events.append(mapped)
        for index, (name, reported_ip, translated_ip) in enumerate(
            (
                (
                    "ipv6_compressed",
                    "2001:db8::1",
                    "2001:0db8:0:0:0:0:0:1",
                ),
                ("ipv6_case", "2001:DB8::1", "2001:db8::1"),
                ("ipv6_changed", "2001:db8::1", "2001:db8::2"),
            ),
            start=17,
        ):
            ipv6 = self.envelope(name, base_event, index, nat=True)
            ipv6_event = json.loads(ipv6["event"])
            ipv6_event["InitiatorIP"] = reported_ip
            ipv6_event["NAT_InitiatorIP"] = translated_ip
            ipv6_event["NAT_InitiatorPort"] = ipv6_event["InitiatorPort"]
            ipv6_event["OriginalInitiatorIP"] = reported_ip
            ipv6["event"] = json.dumps(ipv6_event, separators=(",", ":"))
            events.append(ipv6)
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

    def wait_for_exact_search_count(
        self, spl: str, earliest: float, latest: float, expected: int, label: str
    ) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = lab.search(spl, earliest, latest)
            count = int(rows[0]["count"]) if rows else 0
            if count == expected:
                return
            if count > expected:
                self.fail(f"{label} count is {count}, expected exactly {expected}")
            time.sleep(1)
        self.fail(f"{label} did not reach exactly {expected} searchable rows")

    def rollups(self) -> dict[str, dict]:
        rows = lab.search(
            "| `adm_conversation_rollup` "
            f"| where scope IN ({','.join(json.dumps(scope) for name, scope in self.scopes.items() if name not in ('unmapped', 'reported_invalid'))}) OR observer={json.dumps('ftd:' + self.devices['unmapped'])} "
            "| table adm_record scope client_ip server_ip server_port transport "
            "observer bytes_c2s bytes_s2c packets records nat_observations nat_observations_truncated",
            self.start - 60,
            self.start + 600,
        )
        return {row["scope"]: row for row in rows}

    def test_explicit_tuples_are_metadata_only_and_reject_ambiguous_values(self):
        rows = self.rollups()
        self.assertEqual(len(rows), len(self.scopes) - 1)
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
        ipv6_changed = rows[self.scopes["ipv6_changed"]]
        ipv6_observation = json.loads(ipv6_changed["nat_observations"])[0]
        self.assertEqual(ipv6_observation["reported_initiator_ip"], "2001:db8::1")
        self.assertEqual(ipv6_observation["translated_initiator_ip"], "2001:db8::2")

        for name in (
            "multi",
            "port",
            "port_high",
            "ipv6_compressed",
            "ipv6_case",
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

        bad_reported = lab.search(
            "| `adm_flows` "
            f"| where adm_observer={json.dumps(self.devices['reported_invalid'])} "
            "| table adm_quality_status adm_ftd_nat_ips_valid adm_ftd_nat_changed adm_nat_observation",
            self.start - 60,
            self.start + 600,
        )
        self.assertEqual(len(bad_reported), 1)
        self.assertEqual(bad_reported[0]["adm_quality_status"], "excluded")
        self.assertEqual(str(bad_reported[0]["adm_ftd_nat_ips_valid"]), "0")
        self.assertEqual(str(bad_reported[0]["adm_ftd_nat_changed"]), "0")
        self.assertNotIn("adm_nat_observation", bad_reported[0])

        unmapped = [
            row
            for row in rows.values()
            if row["observer"] == "ftd:" + self.devices["unmapped"]
        ]
        self.assertEqual(len(unmapped), 1)
        self.assertTrue(unmapped[0]["scope"].startswith("unmapped:"))
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

        def filtered_events(
            window_end: float, selected_events: list[int]
        ) -> tuple[list[int], float]:
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
                "| where isnotnull(event_time) | table event_time info_max_time",
                selected_start,
                window_end,
            )
            return (
                sorted(int(row["event_time"]) for row in rows),
                float(rows[0]["info_max_time"]),
            )

        self.assertEqual(
            filtered_events(selected_end, event_times)[0],
            [selected_start, selected_end - 1],
        )
        submillisecond_events, native_end = filtered_events(
            selected_end + 0.0005, [selected_start, selected_end]
        )
        self.assertEqual(
            submillisecond_events,
            [
                event_time
                for event_time in (selected_start, selected_end)
                if event_time < native_end
            ],
        )
        self.assertEqual(native_end, selected_end)

    def _graph_test_event(
        self,
        template: dict,
        device_ip: str,
        event_time: int,
        connection_id: int,
        server_ip: str,
        *,
        initiator_ip: str = "198.51.100.8",
        nat: bool,
    ) -> dict:
        envelope = self.envelope("base", template, connection_id, nat=nat)
        event = json.loads(envelope["event"])
        event.update(
            {
                "DeviceIP": device_ip,
                "FirstPacketSecond": event_time,
                "InitiatorIP": initiator_ip,
                "InitiatorPort": 51400,
                "ResponderIP": server_ip,
                "ResponderPort": 443,
            }
        )
        if nat:
            event.update(
                {
                    "NAT_InitiatorIP": "192.0.2.44",
                    "NAT_InitiatorPort": 35000,
                    "NAT_ResponderIP": server_ip,
                    "NAT_ResponderPort": 443,
                    "OriginalInitiatorIP": initiator_ip,
                }
            )
        else:
            for key in (
                "NAT_InitiatorIP",
                "NAT_InitiatorPort",
                "NAT_ResponderIP",
                "NAT_ResponderPort",
                "OriginalInitiatorIP",
            ):
                event.pop(key, None)
        envelope.update(
            {
                "time": event_time,
                "host": device_ip,
                "event": json.dumps(event, separators=(",", ":")),
            }
        )
        return envelope

    def _register_graph_inputs(
        self, device_ips: dict[str, str], event_time: int, cluster: str
    ) -> None:
        """Add one isolated routing scope and two TA-shaped Pod identities."""
        self.graph_scope = f"{self.token}-graph"
        self.graph_identity_keys = []
        scope_rows = [
            {
                "observer_kind": "firewall",
                "observer": device_ip,
                "scope": self.graph_scope,
                "cluster": "",
            }
            for device_ip in device_ips.values()
        ]
        scope_data = json.dumps(json.dumps(scope_rows, separators=(",", ":")))
        lab.search(
            f"| makeresults format=json data={scope_data} "
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            "_key=sha256(json_array(observer_kind, observer)) "
            "| fields _key observer_kind observer scope cluster "
            "| outputlookup append=true key_field=_key adm_observer_scope"
        )

        identities = []
        for suffix, address in (("cap", "10.42.0.20"), ("window", "10.42.0.21")):
            entity_id = f"{self.token}-{suffix}"
            identities.append(
                {
                    "source": "k8s_pods",
                    "entity_kind": "pod",
                    "entity_id": entity_id,
                    "entity_name": f"nat-{suffix}",
                    "ip": address,
                    "scope": self.graph_scope,
                    "scope_mapping_verified": 1,
                    "cluster": cluster,
                    "namespace": "shop",
                    "node": "node-nat-test",
                    "priority": 1,
                    "valid_from": event_time - 600,
                    "first_seen": event_time - 600,
                    "last_seen": event_time + 600,
                    "ek": f"pod:{cluster}/{entity_id}",
                }
            )
        identity_data = json.dumps(json.dumps(identities, separators=(",", ":")))
        lab.search(
            f"| makeresults format=json data={identity_data} "
            "| eval _key=sha256(json_array(scope, ip, entity_id)) "
            "| `adm_identity_desc` "
            "| fields _key ip scope scope_mapping_verified source entity_kind "
            "entity_id entity_name priority valid_from valid_to valid_end first_seen "
            "last_seen cluster namespace node ek desc "
            "| outputlookup append=true key_field=_key adm_ip_identity"
        )
        self.graph_identity_keys = [
            row["_key"]
            for row in lab.search(
                "| inputlookup adm_ip_identity "
                f"| search scope={json.dumps(self.graph_scope)} "
                "| table _key"
            )
        ]
        self.assertEqual(len(self.graph_identity_keys), len(identities))

    def _frontend_graphs(self, cases: list[dict]) -> list[dict]:
        payload = json.dumps({"cases": cases}, separators=(",", ":"))
        result = subprocess.run(
            ["node", str(FRONTEND_VALIDATOR)],
            cwd=ROOT,
            input=payload,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"rowsToGraph validation failed: {result.stderr.strip()}",
        )
        try:
            graphs = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"rowsToGraph validator returned invalid JSON: {error}")
        self.assertEqual(len(graphs), len(cases))
        return graphs

    def test_adm_graph_nat_cap_and_fractional_window_reach_frontend_without_new_edges(
        self,
    ):
        template_row = json.loads(FIXTURE.read_text("utf-8").splitlines()[0])
        template = json.loads(template_row["event"])
        bucket_start = (int(time.time()) // 300) * 300
        event_time = min(max(int(time.time()), bucket_start + 10), bucket_start + 297)
        cluster = f"nat-{uuid.uuid4().hex[:12]}"
        devices = self.graph_devices
        self._register_graph_inputs(devices, event_time, cluster)

        events = [
            self._graph_test_event(
                template,
                devices["base"],
                event_time - 1,
                1000 + index,
                "10.42.0.20",
                initiator_ip="198.51.100.8",
                nat=False,
            )
            for index in range(33)
        ]
        events.extend(
            self._graph_test_event(
                template,
                devices["cap"],
                event_time - 1,
                2000 + index,
                "10.42.0.20",
                initiator_ip="198.51.100.9",
                nat=True,
            )
            for index in range(33)
        )
        events.extend(
            self._graph_test_event(
                template,
                devices["window"],
                observed_time,
                3000 + index,
                "10.42.0.21",
                initiator_ip="198.51.100.10",
                nat=True,
            )
            for index, observed_time in enumerate(
                (event_time - 1, event_time, event_time + 1)
            )
        )

        root = json.loads(OTEL_FIXTURE.read_text("utf-8").splitlines()[0])
        root["time"] = bucket_start + 5
        root["source"] = self.token
        root_event = root["event"]
        if isinstance(root_event, str):
            root_event = json.loads(root_event)
        root_trace_id = uuid.uuid4().hex
        root_event.update(
            {
                "trace_id": root_trace_id,
                "span_id": uuid.uuid4().hex[:16],
                "parent_span_id": "",
                "start_time": (bucket_start + 5) * 1_000_000_000,
                "end_time": (bucket_start + 5) * 1_000_000_000 + 100_000_000,
            }
        )
        root_fields = dict(root["fields"])
        root_fields.update(
            {
                "service.name": "frontend",
                "deployment.environment.name": "demo",
                "k8s.cluster.name": cluster,
                "k8s.namespace.name": "shop",
                "k8s.pod.uid": f"{self.token}-frontend",
            }
        )
        root["event"] = json.dumps(root_event, separators=(",", ":"))
        root["fields"] = root_fields

        body = (
            b"\n".join(
                json.dumps(event, separators=(",", ":")).encode()
                for event in [*events, root]
            )
            + b"\n"
        )
        lab._hec_post(body)
        self.loaded += len(events)
        self.wait_for_events()
        self.wait_for_exact_search_count(
            f"index=otel_traces source={json.dumps(self.token)} "
            f"trace_id={json.dumps(root_trace_id)} | stats count AS count",
            bucket_start,
            bucket_start + 300,
            1,
            "TA-shaped OTel root span",
        )

        scopes_literal = json.dumps(self.graph_scope)
        lab.search(
            "| `adm_conversation_rollup` "
            f"| where scope IN ({scopes_literal}) "
            '| collect index=`adm_summary_index_name` source="adm:conversation"',
            bucket_start,
            bucket_start + 300,
        )
        self.wait_for_exact_search_count(
            'search `adm_index_summary` source="adm:conversation" '
            f"scope={json.dumps(self.graph_scope)} | stats count AS count",
            bucket_start,
            bucket_start + 300,
            3,
            "graph-test conversation summaries",
        )

        args = {
            "service": "frontend",
            "environment": "demo",
            "cluster": cluster,
            "namespace": "shop",
        }

        def graph_rows(latest: float) -> list[dict]:
            return lab.search(
                '| `adm_graph("frontend","demo","' + cluster + '","shop")`',
                bucket_start,
                latest,
            )

        full_rows = graph_rows(bucket_start + 300)
        fractional_rows = graph_rows(event_time + 0.5)
        exact_rows = graph_rows(event_time)
        full, fractional, exact = self._frontend_graphs(
            [
                {"rows": full_rows, "args": args},
                {"rows": fractional_rows, "args": args},
                {"rows": exact_rows, "args": args},
            ]
        )

        def communication_edges(graph: dict) -> list[dict]:
            return [
                edge
                for edge in graph["edges"]
                if edge["relationship"] == "communicates_with"
            ]

        full_edges = communication_edges(full)
        base_edges = [
            edge
            for edge in full_edges
            if edge["target"] == f"pod:{cluster}/{self.token}-cap"
            and not edge.get("nat_observations")
        ]
        cap_edges = [
            edge
            for edge in full_edges
            if edge["target"] == f"pod:{cluster}/{self.token}-cap"
            and edge.get("nat_observations_truncated")
        ]
        window_edges = [
            edge
            for edge in full_edges
            if edge["target"] == f"pod:{cluster}/{self.token}-window"
        ]
        self.assertEqual(len(base_edges), 1)
        self.assertEqual(len(cap_edges), 1)
        self.assertEqual(len(window_edges), 1)
        self.assertEqual(len(full_edges), 3)
        self.assertEqual(
            {edge["relationship"] for edge in full["edges"]},
            {"communicates_with"},
            "FTD translation evidence must not invent forwards_to/backend edges",
        )
        self.assertFalse(
            any(
                "192.0.2.44" in node["id"] or "192.0.2.44" in node.get("addresses", [])
                for node in full["nodes"]
            ),
            "a translated initiator is evidence, not a new endpoint node",
        )
        base_edge, cap_edge = base_edges[0], cap_edges[0]
        self.assertEqual(base_edge["count"], 1)
        self.assertEqual(cap_edge["count"], 1)
        self.assertEqual(base_edge["bytes"], 33 * (620 + 4800))
        self.assertEqual(cap_edge["bytes"], base_edge["bytes"])
        self.assertEqual(len(cap_edge["nat_observations"]), 32)
        self.assertTrue(cap_edge["nat_observations_truncated"])
        self.assertEqual(
            {item["scope"] for item in cap_edge["nat_observations"]},
            {self.graph_scope},
        )
        self.assertTrue(
            all(
                item["source_authority"] == "cisco:sfw:estreamer"
                and item["event_time"] == event_time - 1
                for item in cap_edge["nat_observations"]
            )
        )
        self.assertEqual(full["nat_event_window"]["start"], bucket_start)
        self.assertEqual(full["nat_event_window"]["end"], bucket_start + 300)

        def window_observations(graph: dict) -> list[dict]:
            matching_edges = [
                edge
                for edge in communication_edges(graph)
                if edge["target"] == f"pod:{cluster}/{self.token}-window"
            ]
            self.assertEqual(len(matching_edges), 1)
            return matching_edges[0].get("nat_observations", [])

        fractional_observations = window_observations(fractional)
        exact_observations = window_observations(exact)
        self.assertEqual(
            sorted(item["event_time"] for item in fractional_observations),
            [event_time - 1, event_time],
        )
        self.assertEqual(
            sorted(item["event_time"] for item in exact_observations),
            [event_time - 1],
        )
        self.assertEqual(fractional["nat_event_window"]["start"], bucket_start)
        self.assertEqual(fractional["nat_event_window"]["end"], event_time + 0.5)
        self.assertEqual(exact["nat_event_window"]["end"], event_time)
