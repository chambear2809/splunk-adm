"""Receipt/history regressions, executed only by the exclusive lab owner.

Matrix cases evaluate the actual shipped SPL with normalized synthetic rows.
The raw case indexes uniquely tagged TA-shaped data, resolves its exact profile,
stages history, then exercises the unmodified topology and Find searches.
"""

from __future__ import annotations

import configparser
import json
import os
import hashlib
import re
from pathlib import Path
import sys
import time
import unittest
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import LabLock  # noqa: E402


def definition(name: str) -> str:
    config = configparser.RawConfigParser()
    config.read_string(
        (ROOT / "splunk_app/splunk_adm/default/macros.conf")
        .read_text()
        .replace("\\\n", "\n    ")
    )
    return config.get(name, "definition")


def seed(rows: list[dict]) -> str:
    return "| makeresults format=json data=" + json.dumps(json.dumps(rows))


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CatalystLateReceiptLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run under tools/lab_lock.py")
        import lab

        cls.lab = lab

    def _installed(self, name):
        encoded = urllib.parse.quote(name, safe="")
        return self.lab._json(
            "GET", f"/servicesNS/nobody/{self.lab.APP}/configs/conf-macros/{encoded}"
        )["entry"][0]["content"]["definition"]

    def test_shipped_graph_aggregation_preserves_stale_source_status(self):
        graph = self._installed("adm_graph_traffic_context_v2(4)")
        status = re.search(
            r"adm_source_time_status=(case\(.*?\)),\s*(?:\\\s*)?adm_client_id=",
            graph,
            re.DOTALL,
        )
        self.assertIsNotNone(status, "installed context status expression is missing")
        projection = (
            "| stats count AS adm_valid_claims"
            + graph.split("| stats count AS adm_valid_claims", 1)[1]
        )
        rows = [
            dict(
                traffic_observation_id=name,
                adm_client_id="client-" + name,
                adm_owner_keys="owner-" + name,
                adm_owner_id="backend-" + name,
                adm_client_source="catalyst_client_snapshot",
                adm_client_source_time=source_time,
                adm_client_received=1_000_000,
                source_ip="192.0.2.1",
                records=1,
            )
            for name, source_time in (("current", 999_999), ("stale", 740_800))
        ]
        result = self.lab.search(
            seed(rows)
            + " | eval adm_source_time_status="
            + status.group(1)
            + projection.replace("$cluster$", "cluster-a"),
            "0",
            "2000000",
        )
        nodes = {row["id"]: row for row in result if row.get("row_type") == "node"}
        self.assertEqual(set(nodes), {"client-current", "client-stale"}, result)
        for name, source_time in (("current", 999_999), ("stale", 740_800)):
            node = nodes["client-" + name]
            self.assertEqual(node.get("attr_source_time_status"), name, result)
            self.assertEqual(float(node["attr_source_time"]), source_time)
            self.assertEqual(float(node["attr_received_time"]), 1_000_000)
            self.assertNotIn("attr_collected_time", node)

    def test_shipped_topology_ends_old_attachment_at_every_next_receipt(self):
        topology = self._installed("adm_topology_v2")
        observations = self._installed("adm_topology_client_observations")
        observations = observations.split(
            "| append [search `adm_network_client_meraki_raw`", 1
        )[0]
        common = dict(
            mapping_status="mapped",
            scope="transition-scope",
            cluster="transition-cluster",
            routing_domain="transition-domain",
            client_ip="192.0.2.10",
            attachment_basis="catalyst_client_snapshot",
            attachment_device_id="switch-a",
            attachment_device_name="switch-a",
            attachment_device_mac="02:00:00:00:03:01",
        )
        old = self._row("transition", receipt=1_000_000, **common)
        for name, changes, expected_switch in (
            ("disconnect", dict(attachment_status="disconnected_snapshot"), None),
            (
                "move",
                dict(
                    attachment_device_id="switch-b",
                    attachment_device_name="switch-b",
                    attachment_device_mac="02:00:00:00:03:02",
                ),
                "switch-b",
            ),
            ("incomplete", dict(attachment_status="incomplete_snapshot"), None),
            ("malformed", dict(source_time="bad-clock"), None),
            ("conflict", dict(attachment_device_id="switch-b"), None),
        ):
            with self.subTest(transition=name):
                transition = dict(
                    old,
                    received_time=1_000_060,
                    latest_received_time=1_000_060,
                    **changes,
                )
                rows = [old, transition]
                if name == "conflict":
                    rows.append(dict(transition, attachment_device_id="switch-c"))
                # Replace only the history read. All receipt eligibility,
                # topology projection, qualification and aggregation are the
                # effective installed SPL, not copies of its predicates.
                helper = observations.replace(
                    "`adm_kv_read_all(adm_network_client_history)`", seed(rows), 1
                )
                query = topology.replace(
                    "`adm_topology_client_observations`",
                    helper.lstrip().removeprefix("|"),
                    1,
                )
                result = self.lab.search(query, "1000120", "1000180")
                clients = [
                    row for row in result if row.get("device_kind") == "network_client"
                ]
                self.assertEqual(len(clients), 1, result)
                self.assertEqual(int(clients[0]["received_time"]), 1_000_060, result)
                self.assertFalse(
                    any(row.get("device_id") == "switch-a" for row in result), result
                )
                links = [row for row in result if row.get("row_type") == "link"]
                if expected_switch:
                    self.assertEqual(len(links), 1, result)
                    self.assertEqual(links[0]["b_device"], expected_switch, result)
                else:
                    self.assertEqual(links, [], result)
                    self.assertTrue(
                        any(
                            "unresolved" in str(row.get("warnings", ""))
                            for row in result
                        ),
                        result,
                    )

    def _observations(self, rows, earliest=1_000_000, latest=1_000_100):
        query = definition("adm_topology_client_observations")
        query = query.replace(
            "`adm_kv_read_all(adm_network_client_history)`",
            rows
            if isinstance(rows, str)
            else seed(rows)
            if rows
            else "| makeresults | where false()",
            1,
        )
        # This matrix isolates history semantics; raw Meraki is tested below
        # against the unchanged adapter in a separate dispatched search.
        query = query.split("| append [search `adm_network_client_meraki_raw`", 1)[0]
        return self.lab.search(query, str(earliest), str(latest))

    @staticmethod
    def _row(name, receipt=1_000_020, source_time=1_000_000 - 3 * 86400, **changes):
        row = dict(
            adm_page=1,
            adm_complete=1,
            source="catalyst_client_snapshot",
            source_authority="synthetic-controller",
            native_id=name,
            event_fingerprint=name,
            source_time=source_time,
            received_time=receipt,
            latest_received_time=receipt,
            client_mac="02:00:00:00:01:01",
            client_type="wired",
            attachment_status="observed_snapshot",
            connected_device_type="Switch",
            interface="port-a",
        )
        row.update(changes)
        return row

    def test_receipt_window_source_age_skew_and_missing_time(self):
        rows = [
            self._row("inside"),
            self._row("before", receipt=999_990),
            self._row("expired", receipt=996_399),
            self._row("after", receipt=1_000_100),
            self._row("very_old", source_time=1),
            self._row("ahead", source_time=1_000_321),
            self._row("malformed", source_time="bad-clock"),
        ]
        result = {
            r["native_id"]: r for r in self._observations(rows) if r.get("native_id")
        }
        self.assertEqual(
            set(result), {"inside", "before", "very_old", "ahead", "malformed"}
        )
        for name in ("inside", "before"):
            self.assertEqual(result[name]["topology_attachment_eligible"], "1")
            self.assertEqual(result[name]["source_time_status"], "stale")
            self.assertNotIn("collected_time", result[name])
        for name in ("very_old", "ahead", "malformed"):
            self.assertEqual(result[name]["topology_attachment_eligible"], "0")
        self.assertEqual(result["very_old"]["history_coverage"], "unconfirmed")
        self.assertEqual(result["ahead"]["source_time_status"], "ahead")
        self.assertEqual(result["malformed"]["source_time_status"], "missing")

    def test_conflicts_caps_incomplete_and_missing_prerequisite_are_visible(self):
        conflict = [
            self._row("same", event_fingerprint="a", interface="port-a"),
            self._row("same", event_fingerprint="b", interface="port-b"),
        ]
        result = self._observations(conflict)
        self.assertTrue(
            all(
                r["topology_attachment_eligible"] == "0"
                for r in result
                if r.get("native_id")
            )
        )
        self.assertTrue(
            any("unresolved" in r.get("topology_warning", "") for r in result)
        )
        capped = seed([self._row("capped")]) + (
            " | eval adm_cap_index=mvrange(0,1000) | mvexpand adm_cap_index "
            '| eval interface="port-".adm_cap_index, event_fingerprint=tostring(adm_cap_index), _key="cap-".adm_cap_index'
        )
        result = self._observations(capped)
        capped_rows = [row for row in result if row.get("native_id")]
        self.assertEqual(len(capped_rows), 1000)
        self.assertEqual({row["history_rows"] for row in capped_rows}, {"1000"})
        self.assertTrue(
            all(row["topology_attachment_eligible"] == "0" for row in capped_rows)
        )
        incomplete = self._row("partial", adm_complete=0)
        result = self._observations([incomplete])
        self.assertTrue(
            any("read is incomplete" in r.get("topology_warning", "") for r in result)
        )
        empty = self._observations([])
        self.assertTrue(
            any(
                "No retained Catalyst client history" in r.get("topology_warning", "")
                for r in empty
            )
        )

    def test_legacy_new_keys_share_earliest_receipt_but_domains_stay_distinct(self):
        raw = definition("adm_network_client_catalyst_raw")
        adapter_tail = "| spath" + raw.split("| spath", 1)[1]
        inputs = []
        for authority, site in (
            ("controller-a", "site-a"),
            ("controller-a", "site-b"),
            ("controller-b", "site-a"),
        ):
            inputs.append(
                dict(
                    _raw=json.dumps({"type": "wired"}),
                    _indextime=1_000_020,
                    cisco_catalyst_host=authority,
                    siteId=site,
                    id="same",
                    macAddress="02:00:00:00:01:01",
                    ipv4Address="192.0.2.10",
                    lastUpdatedTime=999_000_000,
                    connectionStatus="connected",
                    **{
                        "connectedNetworkDevice.connectedNetworkDeviceType": "Switch",
                        "connectedNetworkDevice.interfaceName": "port-a",
                    },
                )
            )
        fingerprints = self.lab.search(
            seed(inputs)
            + adapter_tail
            + " | table source_authority routing_domain event_fingerprint source_time received_time",
            "1000000",
            "1000100",
        )
        self.assertEqual(len(fingerprints), 3)
        self.assertEqual(len({row["event_fingerprint"] for row in fingerprints}), 3)
        old = self._row(
            "same",
            receipt=999_990,
            event_fingerprint="legacy",
            routing_domain="site-a",
            scope="scope-a",
            cluster="cluster-a",
            _key="legacy",
        )
        new = dict(
            old,
            received_time=1_000_020,
            latest_received_time=1_000_020,
            event_fingerprint="new",
            _key="new",
        )
        other = dict(
            new,
            routing_domain="site-b",
            scope="scope-b",
            cluster="cluster-b",
            _key="other",
        )
        rows = self._observations([new, other, old])
        actual = [row for row in rows if row.get("native_id")]
        self.assertEqual(len(actual), 2)
        by_site = {row["routing_domain"]: row for row in actual}
        self.assertEqual(by_site["site-a"]["received_time"], "999990")
        self.assertEqual(by_site["site-a"]["latest_received_time"], "1000020")
        self.assertEqual(by_site["site-b"]["received_time"], "1000020")
        # Identical native IDs across dimensions never collapse into one claim.
        self.assertEqual({row["scope"] for row in actual}, {"scope-a", "scope-b"})
        expired = self._observations(
            [dict(old, received_time=996_399), dict(new, received_time=1_000_020)]
        )
        self.assertFalse(
            any(row.get("native_id") for row in expired),
            "a retained replay restarted eligibility",
        )

    def test_receipt_timeline_moves_replay_order_and_exact_dimensions(self):
        graph = definition("adm_graph_traffic_context_v2(4)")
        stage = (
            "| eval adm_client_time="
            + graph.split("| eval adm_client_time=", 1)[1].split(
                "| lookup local=true adm_ip_identity ip AS destination_ip", 1
            )[0]
        )
        common = dict(
            adm_client_source="catalyst_client_snapshot",
            adm_client_authority="controller-a",
            adm_client_native="native",
            adm_client_mac="02:00:00:00:01:01",
            adm_client_cluster="cluster-a",
            adm_client_scope="scope-a",
            adm_client_mapping="mapped",
            adm_client_basis="catalyst_client_snapshot",
            adm_client_status="observed_snapshot",
            adm_client_type="wired",
            adm_connected_device_type="Switch",
            adm_client_interface="GigabitEthernet1/0/1",
            adm_client_source_time=1_000_000 - 3 * 86400,
        )
        timeline = [
            dict(
                common,
                adm_client_received=1_000_000,
                adm_client_ip="192.0.2.10",
                adm_timeline_event_key="old",
            ),
            dict(
                common,
                adm_client_received=1_000_050,
                adm_client_ip="192.0.2.11",
                adm_timeline_event_key="move",
            ),
        ]
        rows = []
        for name, first, last, ip, scope in (
            ("before_receipt", 999_999, 999_999, "192.0.2.10", "scope-a"),
            ("before_move", 1_000_010, 1_000_011, "192.0.2.10", "scope-a"),
            ("cross_move", 1_000_049, 1_000_051, "192.0.2.10", "scope-a"),
            ("new_ip", 1_000_060, 1_000_061, "192.0.2.11", "scope-a"),
            ("old_ip", 1_000_060, 1_000_061, "192.0.2.10", "scope-a"),
            ("wrong_scope", 1_000_010, 1_000_011, "192.0.2.10", "scope-b"),
            ("expired", 1_003_651, 1_003_652, "192.0.2.11", "scope-a"),
        ):
            rows.extend(
                dict(
                    r,
                    traffic_observation_id=name,
                    first_seen=first,
                    last_seen=last,
                    source_ip=ip,
                    scope=scope,
                )
                for r in timeline
            )
        query = (
            seed(rows)
            + " | addinfo "
            + stage.replace("$cluster$", "cluster-a")
            + " | table traffic_observation_id adm_client_source_time adm_client_received adm_source_time_status"
        )
        result = self.lab.search(query, "0", "2000000")
        self.assertEqual(
            {r["traffic_observation_id"] for r in result}, {"before_move", "new_ip"}
        )
        self.assertTrue(all(r["adm_source_time_status"] == "stale" for r in result))
        reversed_result = self.lab.search(
            seed(list(reversed(rows)))
            + " | addinfo "
            + stage.replace("$cluster$", "cluster-a")
            + " | table traffic_observation_id adm_client_source_time adm_client_received adm_source_time_status",
            "0",
            "2000000",
        )
        self.assertCountEqual(result, reversed_result)
        wrong_cluster = self.lab.search(
            seed(rows) + " | addinfo " + stage.replace("$cluster$", "cluster-b"),
            "0",
            "2000000",
        )
        self.assertEqual(wrong_cluster, [])

    def test_raw_old_source_receipt_normalization_history_topology_find_and_replay(
        self,
    ):
        token = "late-receipt-" + uuid.uuid4().hex[:12]
        profile = dict(
            source="catalyst_client_snapshot",
            source_authority=token,
            domain_kind="controller",
            observation_domain_present="0",
            observation_domain_id="",
            vpn_id="",
            routing_domain=token,
            scope=token,
            cluster=token,
            profile="catalyst_client_snapshot",
            mapping_status="mapped",
            duplicate_count=1,
        )
        payload = json.dumps(json.dumps([profile]))
        profile_keys = (
            "source",
            "source_authority",
            "domain_kind",
            "observation_domain_present",
            "observation_domain_id",
            "vpn_id",
            "routing_domain",
        )
        key_arguments = ",".join(
            f'tostring(coalesce({field}, ""))' for field in profile_keys
        )
        fields = " ".join(sorted(profile))
        seeded = self.lab.search(
            f"| makeresults format=json data={payload} | eval mapping_key=sha256(json_array({key_arguments})) | eval _key=sha256(mapping_key) | fields _key mapping_key {fields} | outputlookup append=true key_field=_key adm_network_source_scope | table _key",
            "0",
            "+10y",
        )

        def cleanup(collection, query):
            encoded = urllib.parse.urlencode({"query": json.dumps(query)})
            self.lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/{self.lab.APP}/storage/collections/data/{collection}?{encoded}",
            ).close()

        self.addCleanup(
            cleanup, "adm_network_source_scope", {"_key": seeded[0]["_key"]}
        )
        self.addCleanup(
            cleanup, "adm_network_client_history", {"source_authority": token}
        )
        installed_build = self.lab._json(
            "GET",
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_network_client_history_build",
        )["entry"][0]["content"]["definition"]
        build_suffix = installed_build.split(
            "`adm_network_client_history_observations`", 1
        )[1]
        old = int(time.time()) - 3 * 86400
        event = dict(
            index="cisco_catalyst",
            sourcetype="cisco:dnac:client",
            source=token,
            time=old,
            event=dict(
                id=token,
                macAddress="02:00:00:00:02:01",
                ipv4Address="192.0.2.211",
                type="wired",
                connectionStatus="connected",
                cisco_catalyst_host=token,
                siteId=token,
                lastUpdatedTime=old * 1000,
                connectedNetworkDevice=dict(
                    connectedNetworkDeviceType="Switch",
                    interfaceName="GigabitEthernet1/0/9",
                    connectedNetworkDeviceMac="02:00:00:00:03:01",
                    connectedNetworkDeviceName=token + "-switch",
                ),
            ),
        )

        def load_and_wait(expected):
            self.lab._hec_post(json.dumps(event).encode())
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                raw = self.lab.search(
                    f'index=cisco_catalyst source="{token}" | stats count min(_indextime) AS receipt max(_indextime) AS latest_receipt',
                    "0",
                    "+10y",
                )
                if int(raw[0].get("count", 0)) == expected:
                    return raw[0]
                time.sleep(0.25)
            self.fail("tagged Catalyst fixture was not indexed")

        raw = load_and_wait(1)
        receipt = int(raw["receipt"])
        window = (str(receipt - 1), str(receipt + 60))
        # Before staging, no raw fallback may claim receipt-qualified topology.
        before = self.lab.search(
            f'`adm_topology_v2` | where device_authority="{token}"', *window
        )
        self.assertEqual(before, [])
        observed = self.lab.search(
            f'| `adm_network_client_history_observations` | where source_authority="{token}"',
            "0",
            "+15m",
        )
        self.assertEqual(len(observed), 1)
        self.assertEqual(float(observed[0]["source_time"]), old)
        self.assertEqual(int(observed[0]["received_time"]), receipt)
        self.assertEqual(
            observed[0].get("mapping_status"),
            "mapped",
            {
                key: observed[0].get(key)
                for key in (
                    "source_authority",
                    "routing_domain",
                    "mapping_status",
                    "quality_reason",
                    "scope",
                    "cluster",
                )
            },
        )
        self.assertEqual(observed[0].get("scope"), token)
        self.lab.search(
            f'| `adm_network_client_history_observations` | where source_authority="{token}" '
            + build_suffix,
            "0",
            "+15m",
        )

        def topology():
            return self.lab.search(
                f'`adm_topology_v2` | where device_authority="{token}" OR a_device_name="02:00:00:00:02:01"',
                *window,
            )

        result = topology()
        clients = [r for r in result if r.get("device_kind") == "network_client"]
        self.assertEqual(len(clients), 1, result)
        self.assertEqual(float(clients[0]["source_time"]), old)
        self.assertEqual(int(clients[0]["received_time"]), receipt)
        self.assertEqual(clients[0]["source_time_status"], "stale")
        self.assertNotIn("collected_time", clients[0])
        self.assertTrue(any(r.get("row_type") == "link" for r in result), result)
        find = self.lab.search(f'| `adm_find_network_client("{token}")`', *window)
        self.assertEqual(len(find), 1)
        self.assertEqual(find[0]["diagnostic_status"], "evidence_only")
        self.assertIn("record-update time is old", find[0]["diagnostic_reason"])
        self.assertEqual(
            self.lab.search(
                f'`adm_topology_v2` | where device_authority="{token}"',
                str(receipt - 60),
                str(receipt),
            ),
            [],
        )
        # Join the raw Catalyst history through the real graph context macro.
        # Traffic and backend rows are disposable, explicit synthetic evidence;
        # they do not substitute aggregate backend evidence for this client.
        namespace = "late-test"
        target_ip = "192.0.2.212"
        target_key = token + "-backend"
        settings_key = token + "-settings"
        for collection, row in (
            (
                "adm_ip_identity",
                dict(
                    _key=target_key,
                    ip=target_ip,
                    scope=token,
                    cluster=token,
                    namespace=namespace,
                    entity_kind="pod",
                    entity_id=target_key,
                    entity_name="late-backend",
                    valid_from=receipt - 10,
                    valid_end=receipt + 3600,
                ),
            ),
            (
                "adm_cilium_cluster_settings",
                dict(
                    _key=settings_key,
                    cluster=token,
                    mapping_status="mapped",
                    lb_mode="snat",
                    ingress_mode="dedicated",
                    l2announcements_enabled=0,
                ),
            ),
        ):
            self.addCleanup(cleanup, collection, {"_key": row["_key"]})
            self.lab.search(
                seed([row])
                + f" | outputlookup append=true key_field=_key {collection}",
                "0",
                "+15m",
            )
        traffic = dict(
            _time=receipt // 300 * 300,
            contract_version=2,
            adm_record="traffic_observation",
            rollup_id=hashlib.sha256(token.encode()).hexdigest(),
            cluster=token,
            scope=token,
            adm_profile_status="mapped",
            adm_quality_status="accepted",
            source_ip="192.0.2.211",
            destination_ip=target_ip,
            source_mac="02:00:00:00:02:01",
            source_port=55000,
            destination_port=443,
            server_port=443,
            transport="tcp",
            first_seen=receipt + 5,
            last_seen=receipt + 6,
            records=1,
            counter_semantics="unknown",
            metrics_authoritative=0,
            traffic_observations="[]",
        )
        self.lab.search(
            seed([traffic])
            + " | fields - _raw _bkt _cd index | collect index=adm_summary_v2 source=adm:traffic_observation",
            "0",
            "+15m",
        )
        summary_query = (
            'index=adm_summary_v2 source="adm:traffic_observation" '
            f'rollup_id="{traffic["rollup_id"]}" | table _time scope cluster adm_record contract_version adm_profile_status records rollup_id source_ip destination_ip'
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            summary = self.lab.search(
                summary_query, str(receipt // 300 * 300), str(receipt + 60)
            )
            if summary:
                break
            time.sleep(0.25)
        self.assertEqual(
            len(summary),
            1,
            "synthetic traffic summary did not become searchable with production KV field extraction",
        )
        for field in (
            "scope",
            "cluster",
            "adm_record",
            "adm_profile_status",
            "rollup_id",
            "source_ip",
            "destination_ip",
        ):
            self.assertEqual(summary[0].get(field), traffic[field], summary)
        self.assertEqual(int(summary[0]["records"]), 1)
        self.assertEqual(int(summary[0]["contract_version"]), 2)
        context_query = (
            f'`adm_graph_traffic_context_v2("{token}","test","{token}","{namespace}")`'
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            context = self.lab.search(
                context_query, str(receipt // 300 * 300), str(receipt + 60)
            )
            edges = [row for row in context if row.get("row_type") == "edge"]
            if edges:
                break
            time.sleep(0.25)
        self.assertEqual(len(edges), 1, context)
        attachment = json.loads(edges[0]["attachment_evidence"])[0]
        self.assertEqual(int(attachment["event_time"]), old)
        self.assertEqual(int(attachment["received_time"]), receipt)
        self.assertIsNone(attachment.get("collected_time"))
        nodes = [row for row in context if row.get("row_type") == "node"]
        self.assertEqual(len(nodes), 1, context)
        self.assertEqual(nodes[0]["attr_source_time_status"], "stale")
        # The same selected client loses its context when its own backend
        # evidence is absent, even if other app/backend rows exist in the lab.
        cleanup("adm_ip_identity", {"_key": target_key})
        self.assertEqual(
            self.lab.search(
                context_query, str(receipt // 300 * 300), str(receipt + 60)
            ),
            [],
        )
        load_and_wait(2)
        self.lab.search(
            f'| `adm_network_client_history_observations` | where source_authority="{token}" '
            + build_suffix,
            "0",
            "+15m",
        )
        retained = self.lab.search(
            f'| inputlookup adm_network_client_history | where source_authority="{token}"',
            "0",
            "+10y",
        )
        self.assertEqual(len(retained), 1)
        self.assertEqual(int(retained[0]["received_time"]), receipt)
        self.assertGreaterEqual(int(retained[0]["latest_received_time"]), receipt)
        replayed = [r for r in topology() if r.get("device_kind") == "network_client"]
        self.assertEqual(len(replayed), 1)
        self.assertEqual(replayed[0]["received_time"], clients[0]["received_time"])
        self.assertEqual(replayed[0]["source_time"], clients[0]["source_time"])
