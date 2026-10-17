"""Combined Cisco client paths from actual local Splunk searches.

The raw data is synthetic and TA-grounded. No collector/exporter validation is
claimed. The enclosing test runner must hold the complete disposable lab lock.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from capture_networking_fixtures import (  # noqa: E402
    APPS,
    handoff_query,
    require_client,
    require_handoff,
    search,
)
from lab_lock import LabLock  # noqa: E402
from load_networking_lab import dispatch, initialize  # noqa: E402


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoCombinedPathsLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")
        sys.path.insert(0, str(ROOT / "tests/splunk"))
        import lab

        cls.lab = lab
        cls.initialized = initialize(
            ROOT / "dist/networking-path-tests",
            ROOT / "dist/networking-path-tests/initialization.json",
            regenerate=True,
        )
        cls.window = tuple(
            cls.initialized["window"][name] for name in ("earliest", "latest")
        )
        cls.build_window = tuple(
            cls.initialized["build_window"][name] for name in ("earliest", "latest")
        )
        cls.graphs = cls.read_graphs()

    @classmethod
    def read_graphs(cls):
        return {
            platform: search(
                cls.lab,
                f'| search `adm_graph_v2("checkout","demo","{cluster}","shop")`',
                *cls.window,
            )[0]
            for platform, cluster in (
                ("aci", "cilium-aci-east"),
                ("nxos", "cilium-nxos-west"),
            )
        }

    def test_both_clients_have_their_own_observed_frontend_backend_chain(self):
        for platform, rows in self.graphs.items():
            with self.subTest(platform=platform):
                require_client(rows, platform)
                handoffs, _ = search(self.lab, handoff_query(platform), *self.window)
                require_handoff(rows, handoffs, platform)
                nodes = {row["id"] for row in rows if row.get("row_type") == "node"}
                self.assertEqual(
                    len(nodes), sum(row.get("row_type") == "node" for row in rows)
                )
                for edge in (row for row in rows if row.get("row_type") == "edge"):
                    self.assertIn(edge["source"], nodes)
                    self.assertIn(edge["target"], nodes)

    def test_wireless_flow_uses_the_second_observed_ap_after_roaming(self):
        clients = [
            row
            for row in self.graphs["nxos"]
            if row.get("endpoint_kind") == "network_client"
            and row.get("attr_client_mac") == "02:71:00:00:00:20"
        ]
        self.assertEqual(len(clients), 1)
        client = clients[0]
        self.assertEqual(client.get("attr_attachment_device_name"), "MR-NXOS-02")
        self.assertEqual(client.get("attr_device_serial"), "Q2XX-DEMO-0002")
        self.assertEqual(str(client.get("attr_ssid_number")), "1")
        self.assertEqual(client.get("attr_attachment_basis"), "meraki_association_flow")
        # The TA event contains an SSID number; no source provides an SSID name.
        self.assertFalse(client.get("attr_ssid_name"))

    def test_later_address_reuse_keeps_the_second_client_identity(self):
        clients = {
            row.get("attr_client_mac"): row
            for row in self.graphs["nxos"]
            if row.get("endpoint_kind") == "network_client"
        }
        primary = clients["02:71:00:00:00:20"]
        reused = clients["02:71:00:00:00:21"]
        self.assertNotEqual(primary["id"], reused["id"])
        self.assertEqual(primary["addresses"], reused["addresses"])
        self.assertEqual(reused["attr_device_serial"], "Q2XX-DEMO-0001")
        self.assertEqual(reused["attr_attachment_basis"], "meraki_association_flow")

    def test_flow_observations_preserve_unknown_counter_semantics(self):
        observed = 0
        for graph in self.graphs.values():
            for row in graph:
                if row.get("relationship") != "traffic_observation":
                    continue
                payload = row.get("traffic_observations")
                values = json.loads(payload) if isinstance(payload, str) else payload
                self.assertIsInstance(values, list)
                for observation in values:
                    self.assertIsInstance(observation, dict)
                    self.assertEqual(observation["counter_semantics"], "unknown")
                    self.assertEqual(str(observation["metrics_authoritative"]), "0")
                    self.assertEqual(int(observation["records"]), 1)
                    observed += 1
        self.assertGreaterEqual(observed, 3)  # campus, SD-WAN, MS390

    def test_missing_hubble_backend_tuple_does_not_create_observed_handoff(self):
        """Keep the frontend evidence while withholding only matching backend proof."""
        macro_path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_summary_v2"
        )
        original = self.lab._json("GET", macro_path)["entry"][0]["content"][
            "definition"
        ]
        self.addCleanup(
            self.lab._json,
            "POST",
            macro_path,
            {"definition": original},
        )

        for platform, (cluster, client_ip, scope) in APPS.items():
            with self.subTest(platform=platform):
                port = 54120 if platform == "aci" else 55220
                raw = self.lab.search(
                    'index=cilium_hubble sourcetype="cilium:hubble:flow" '
                    f'"{client_ip}" "10.42.1.20" "{port}" "8080" '
                    "| spath input=_raw path=flow.IP.source output=source_ip "
                    "| spath input=_raw path=flow.IP.destination output=server_ip "
                    "| spath input=_raw path=flow.l4.TCP.source_port output=source_port "
                    "| spath input=_raw path=flow.l4.TCP.destination_port output=server_port "
                    f'| where source_ip="{client_ip}" AND server_ip="10.42.1.20" '
                    f"AND source_port={port} AND server_port=8080 | stats count",
                    *self.build_window,
                )
                self.assertTrue(raw and int(raw[0]["count"]) > 0)

                baseline = self.graphs[platform]
                endpoint_slices = self.lab.search(
                    f'| inputlookup adm_service_backends | search cluster="{cluster}" '
                    'namespace="shop" | stats count',
                    *self.build_window,
                )
                self.assertTrue(
                    endpoint_slices and int(endpoint_slices[0]["count"]) > 0,
                    "positive control lacks EndpointSlice backend rows",
                )
                positive_handoffs, _ = search(
                    self.lab, handoff_query(platform), *self.window
                )
                require_handoff(baseline, positive_handoffs, platform)

                def read_backend_candidates():
                    return search(
                        self.lab,
                        f'| search `adm_graph_inputs_v2("checkout","demo","{cluster}","shop")` '
                        '| search adm_row="backend" service="checkout" '
                        "| table cluster namespace service pod_uid ip target_port valid_from valid_end",
                        *self.window,
                    )[0]

                baseline_candidates = read_backend_candidates()
                self.assertTrue(
                    baseline_candidates,
                    "positive control lacks stage-1 EndpointSlice candidates",
                )
                baseline_nodes = {
                    row["id"]: row for row in baseline if row.get("row_type") == "node"
                }
                client_nodes = {
                    row["id"]
                    for row in baseline
                    if row.get("endpoint_kind") == "network_client"
                    and row.get("attr_scope") == scope
                    and row.get("attr_client_mac")
                    == {"aci": "02:61:00:00:00:20", "nxos": "02:71:00:00:00:20"}[
                        platform
                    ]
                }
                frontends = {
                    row["target"]
                    for row in baseline
                    if row.get("row_type") == "edge"
                    and row.get("relationship")
                    in ("communicates_with", "traffic_observation")
                    and row.get("source") in client_nodes
                    and baseline_nodes.get(row.get("target"), {}).get("endpoint_kind")
                    == "k8s_service"
                }
                self.assertTrue(
                    frontends, "positive client-to-frontend evidence missing"
                )

                definition = (
                    '(index=adm_summary_v2 NOT (source="adm:conversation" '
                    'flow_source="hubble" '
                    f'client_ip="{client_ip}" server_ip="10.42.1.20" '
                    f'server_port=8080 transport="tcp"))'
                )
                self.lab._json("POST", macro_path, {"definition": definition})
                args = '"checkout","demo","' + cluster + '","shop"'
                filtered_graph, _ = search(
                    self.lab,
                    f"| search `adm_graph_v2({args})`",
                    *self.window,
                )
                filtered_handoffs, _ = search(
                    self.lab, handoff_query(platform), *self.window
                )
                all_handoffs_query = (
                    f'| search `adm_graph_inputs_v2("checkout","demo","{cluster}","shop")` '
                    f'| `adm_graph_cluster_settings_v2("{cluster}")` '
                    f'| `adm_graph_resolve("checkout","demo","{cluster}","shop")` '
                    f'| `adm_graph_cluster_settings_v2("{cluster}")` '
                    f'| `adm_graph_handoffs("checkout","demo","{cluster}","shop")` '
                    f'| where adm_row="hconn" AND scope="{scope}" '
                    "| table client_ip scope adm_cport adm_fe_id adm_targets handoff_basis "
                    "server_port transport"
                )
                all_handoffs, _ = search(self.lab, all_handoffs_query, *self.window)
                self.assertTrue(
                    any(
                        row.get("endpoint_kind") == "network_client"
                        and row.get("attr_scope") == scope
                        for row in filtered_graph
                    ),
                    "client identity disappeared with the withheld backend tuple",
                )
                self.assertTrue(
                    any(
                        row.get("row_type") == "edge"
                        and row.get("source") in client_nodes
                        and row.get("target") in frontends
                        and row.get("relationship")
                        in ("communicates_with", "traffic_observation")
                        for row in filtered_graph
                    ),
                    "client-to-frontend evidence disappeared",
                )
                self.assertTrue(
                    any(
                        row.get("endpoint_kind") == "k8s_service"
                        and row.get("cluster") == cluster
                        for row in filtered_graph
                    ),
                    "frontend service identity disappeared",
                )
                # Pod candidates are retained as stage-1 backend evidence and
                # summarized on the frontend. They are not necessarily emitted
                # as graph nodes when no supported handoff resolves to one.
                backend_candidates = read_backend_candidates()
                self.assertTrue(
                    backend_candidates,
                    "EndpointSlice backend candidate evidence disappeared",
                )
                self.assertEqual(backend_candidates, baseline_candidates)
                self.assertTrue(
                    all(
                        row.get("cluster") == cluster
                        and row.get("namespace") == "shop"
                        and row.get("pod_uid")
                        and row.get("ip")
                        for row in backend_candidates
                    ),
                    "retained backend candidate lacks its pod identity and address",
                )
                retained_endpoint_slices = self.lab.search(
                    f'| inputlookup adm_service_backends | search cluster="{cluster}" '
                    'namespace="shop" | stats count',
                    *self.build_window,
                )
                self.assertEqual(retained_endpoint_slices, endpoint_slices)
                remaining_handoffs = [
                    row
                    for row in filtered_graph
                    if row.get("row_type") == "edge"
                    and row.get("relationship") == "forwards_to"
                    and row.get("source") in frontends
                ]
                selected_handoffs = [
                    row
                    for row in filtered_handoffs
                    if row.get("client_ip") == client_ip
                    and str(row.get("adm_cport")) == str(port)
                    and row.get("adm_fe_id") in frontends
                ]
                self.assertEqual(
                    len(selected_handoffs),
                    1,
                    "the selected client connection lost its explicit handoff result",
                )
                selected_handoff = selected_handoffs[0]
                selected_targets = selected_handoff.get("adm_targets")
                self.assertFalse(
                    selected_targets,
                    "withheld Hubble tuple still selected a backend target",
                )
                self.assertNotEqual(
                    selected_handoff.get("handoff_basis"),
                    "hubble_client_tuple",
                    "withheld Hubble tuple still claimed an observed selected handoff",
                )

                def handoff_targets(row):
                    value = row.get("adm_targets")
                    if isinstance(value, list):
                        return {str(target) for target in value}
                    if isinstance(value, str) and value.startswith("["):
                        try:
                            decoded = json.loads(value)
                        except json.JSONDecodeError:
                            return {value}
                        if isinstance(decoded, list):
                            return {str(target) for target in decoded}
                    return {str(value)} if value else set()

                for edge in remaining_handoffs:
                    if edge.get("confidence") == "observed":
                        unrelated_support = [
                            row
                            for row in all_handoffs
                            if row.get("adm_fe_id") == edge.get("source")
                            and edge.get("target") in handoff_targets(row)
                            and (
                                row.get("client_ip") != client_ip
                                or str(row.get("adm_cport")) != str(port)
                            )
                            and row.get("handoff_basis")
                        ]
                        self.assertTrue(
                            unrelated_support,
                            "an aggregate observed edge lacks an independent connection proof",
                        )
                        continue
                    self.assertEqual(edge.get("confidence"), "inferred")
                    evidence = edge.get("evidence")
                    if isinstance(evidence, str):
                        evidence = [evidence]
                    self.assertIn("time_inferred", evidence or [])

                selected_frontend_nodes = [
                    row
                    for row in filtered_graph
                    if row.get("row_type") == "node" and row.get("id") in frontends
                ]
                self.assertEqual(len(selected_frontend_nodes), len(frontends))
                for frontend in selected_frontend_nodes:
                    represented = [
                        row
                        for row in all_handoffs
                        if row.get("adm_fe_id") == frontend.get("id")
                    ]
                    determined = [
                        row
                        for row in represented
                        if row.get("handoff_basis") and handoff_targets(row)
                    ]
                    unresolved_count = len(represented) - len(determined)
                    self.assertGreaterEqual(
                        unresolved_count,
                        1,
                        "selected frontend did not expose the unresolved client connection",
                    )
                    self.assertEqual(
                        int(frontend.get("attr_handoff_connections", -1)),
                        len(represented),
                    )
                    self.assertEqual(
                        int(frontend.get("attr_handoff_determined", -1)),
                        len(determined),
                    )
                    self.assertEqual(
                        int(frontend.get("attr_handoff_unresolved", -1)),
                        unresolved_count,
                    )
                    expected_coverage = (
                        "unresolved"
                        if not determined
                        else "partial"
                        if unresolved_count
                        else "complete"
                    )
                    self.assertEqual(
                        frontend.get("attr_handoff_coverage"), expected_coverage
                    )
                    if platform == "aci":
                        self.assertEqual(expected_coverage, "partial")
                        self.assertGreater(
                            len(determined),
                            0,
                            "the independent ACI client connection was not counted",
                        )
                    else:
                        self.assertIn(expected_coverage, ("partial", "unresolved"))
                if not remaining_handoffs:
                    service_nodes = [
                        row
                        for row in filtered_graph
                        if row.get("row_type") == "node" and row.get("id") in frontends
                    ]
                    self.assertTrue(service_nodes)
                    self.assertTrue(
                        all(
                            row.get("attr_handoff") == "service_only"
                            for row in service_nodes
                        ),
                        "unresolved frontend boundary was not labeled service_only",
                    )
                    self.assertTrue(
                        any(
                            int(row.get("attr_candidates", 0)) > 0
                            for row in service_nodes
                        ),
                        "unresolved frontend did not preserve its EndpointSlice candidates",
                    )
                remaining = self.lab.search(
                    f'| search `adm_graph_inputs_v2("checkout","demo","{cluster}","shop")` '
                    '| search adm_row="conv" flow_source="hubble" '
                    f'client_ip!="{client_ip}" | stats count',
                    *self.window,
                )
                self.assertTrue(
                    remaining and int(remaining[0]["count"]) > 0,
                    "the query-time exclusion removed unrelated Hubble activity",
                )

    def test_raw_stream_observations_are_retained_even_when_unmapped(self):
        rows, _ = search(
            self.lab,
            'index=adm_summary_v2 source="adm:traffic_observation" contract_version=2 '
            "| dedup rollup_id | stats sum(records) AS records by adm_profile_status",
            *self.build_window,
        )
        self.assertEqual(sum(int(row["records"]) for row in rows), 39)
        self.assertTrue(any(row["adm_profile_status"] != "mapped" for row in rows))

    def test_replayed_closed_slice_preserves_history_and_graph_counts(self):
        before, _ = search(
            self.lab,
            "| inputlookup adm_network_client_history | stats count dc(_key) AS keys",
            *self.build_window,
        )
        for name in (
            "ADM - Network client history builder",
            "ADM - Conversation rollup v2",
            "ADM - Traffic observation rollup v2",
        ):
            dispatch(
                self.lab,
                name,
                tuple(self.initialized["index_window"]),
                self.build_window,
            )
        after, _ = search(
            self.lab,
            "| inputlookup adm_network_client_history | stats count dc(_key) AS keys",
            *self.build_window,
        )
        self.assertEqual(before, after)
        self.assertEqual(before[0]["count"], before[0]["keys"])

        # Explicit IDs/metrics are compared, not a newly hand-authored fixture.
        def shape(rows):
            return sorted(
                (
                    str(row.get("row_type")),
                    str(row.get("id")),
                    str(row.get("count")),
                    str(row.get("records")),
                    str(row.get("traffic_observations")),
                )
                for row in rows
            )

        replay = self.read_graphs()
        for platform in self.graphs:
            self.assertEqual(shape(self.graphs[platform]), shape(replay[platform]))

    def test_z_invalid_flow_records_are_visible_but_never_correlated(self):
        raw_dir = ROOT / "dist/networking-path-tests"
        template = json.loads(
            (raw_dir / "meraki_ms390_ipfix.ndjson").read_text().splitlines()[0]
        )
        clones = [json.loads(json.dumps(template)) for _ in range(3)]
        clones[0]["event"]["src_port"] = 70000
        clones[1]["event"]["src_port"] = 55223
        end = datetime.fromisoformat(
            template["event"]["endtime"].replace("Z", "+00:00")
        )
        clones[1]["event"]["timestamp"] = (
            (end + timedelta(seconds=1))
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        clones[2]["event"]["src_port"] = 55224
        clones[2]["event"]["packets"] = -1
        path = raw_dir / "invalid-flow-clones.ndjson"
        path.write_text("".join(json.dumps(row) + "\n" for row in clones))
        start = int(time.time()) - 1
        self.assertEqual(self.lab.load([path]), 3)
        deadline = time.monotonic() + 90
        while True:
            raw, _ = search(
                self.lab,
                'index=netflow sourcetype="stream:netflow" '
                "| spath input=_raw path=src_port output=raw_port "
                "| where raw_port IN (70000,55223,55224) | stats count by raw_port",
                *self.build_window,
            )
            if {int(row["raw_port"]): int(row["count"]) for row in raw} == {
                70000: 1,
                55223: 1,
                55224: 1,
            }:
                break
            if time.monotonic() >= deadline:
                self.fail("invalid-flow clones were not all indexed")
            time.sleep(1)
        dispatch(
            self.lab,
            "ADM - Traffic observation rollup v2",
            (start, int(time.time()) + 1),
            self.build_window,
        )
        rows, _ = search(
            self.lab,
            'index=adm_summary_v2 source="adm:traffic_observation" '
            '| where source_ip=="10.71.0.20" AND source_port IN (70000,55223,55224) '
            "| dedup rollup_id | table rollup_id source_port adm_quality_status adm_quality_errors",
            *self.build_window,
        )
        self.assertEqual(len(rows), 3)
        expected = {
            70000: "invalid_ports",
            55223: "invalid_time",
            55224: "invalid_counters",
        }
        for row in rows:
            self.assertEqual(row["adm_quality_status"], "excluded")
            errors = row["adm_quality_errors"]
            self.assertIn(expected[int(row["source_port"])], errors)
        for graph in self.read_graphs().values():
            for row in graph:
                if row.get("relationship") != "traffic_observation":
                    continue
                payload = row.get("traffic_observations")
                observations = (
                    json.loads(payload) if isinstance(payload, str) else payload
                )
                for observation in observations:
                    if observation.get("source_ip") == "10.71.0.20":
                        self.assertNotIn(int(observation["source_port"]), expected)
