"""Guard the evidence boundary of captured Cisco demo fixtures."""

import unittest
from unittest.mock import patch
from types import SimpleNamespace
import hashlib
import json
import os
from pathlib import Path
import tempfile

from tools.capture_networking_fixtures import (
    capture,
    require_client,
    require_complete,
    require_handoff,
    require_local_lab,
    require_topology,
    evidence_fingerprints,
    validate_window,
)


class CaptureNetworkingTest(unittest.TestCase):
    def test_relative_raw_directory_reaches_capture_with_bound_provenance(self):
        root = Path(__file__).resolve().parents[1]
        raw = Path(os.path.relpath(root / "fixtures/raw-networking"))
        with tempfile.TemporaryDirectory() as directory:
            initialization = Path(directory) / "initialization.json"
            initialization.write_text(
                json.dumps(
                    {
                        "fingerprints": {},
                        "window": {"earliest": "1", "latest": "2"},
                        "qualification": "synthetic",
                        "scenario_window": {},
                        "build_window": {},
                        "indexed_counts": {},
                        "index_window": [],
                        "builders": [],
                    }
                )
            )
            with (
                patch.dict("sys.modules", {"lab": SimpleNamespace()}),
                patch(
                    "tools.capture_networking_fixtures.evidence_fingerprints",
                    return_value={},
                ),
                patch(
                    "tools.capture_networking_fixtures.search",
                    side_effect=RuntimeError("reached capture search"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "reached capture search"):
                    capture("1", "2", raw, Path(directory), initialization)

    def test_topology_requires_both_observed_meraki_ap_uplinks(self):
        serials = ("Q2XX-DEMO-0390", "Q2XX-DEMO-0001", "Q2XX-DEMO-0002")
        devices = [
            {
                "row_type": "device",
                "device_authority": '["org-demo","network-demo"]',
                "native_device_id": serial,
                "device_id": "meraki:" + serial,
                "scope": "meraki-nxos",
                "cluster": "cilium-nxos-west",
            }
            for serial in serials
        ]
        links = [
            {
                "row_type": "link",
                "link_kind": "physical",
                "link_source": "meraki_switch_topology_lldp",
                "a_device": devices[0]["device_id"],
                "b_device": device["device_id"],
                "a_interface": port,
                "scope": "meraki-nxos",
                "cluster": "cilium-nxos-west",
            }
            for device, port in zip(devices[1:], ("10", "11"), strict=True)
        ]
        require_topology(devices + links)
        for bad_rows in (
            devices,
            devices + links[:1],
            devices + [{**link, "b_device": "incorrect"} for link in links],
            devices + [{**link, "scope": "another-scope"} for link in links],
        ):
            with self.subTest(rows=bad_rows), self.assertRaises(RuntimeError):
                require_topology(bad_rows)

    def test_capture_binds_effective_writer_and_indexed_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "splunk_app/splunk_adm/default"
            config.mkdir(parents=True)
            (config / "macros.conf").write_text(
                "[adm_example]\ndefinition = index=netflow\n"
            )
            (config / "savedsearches.conf").write_text(
                "[ADM - Example]\nsearch = | makeresults\n"
            )
            (root / "tools").mkdir()
            (root / "tools/gen_raw_fixtures.py").write_text("# fixture generator\n")
            raw = root / "raw"
            raw.mkdir()
            for name in ("scenario.json", "source-profiles.json"):
                (raw / name).write_text("{}")
            (raw / "capture-manifest.json").write_text(
                json.dumps({"index_events": {"netflow": 1}})
            )
            writer = {
                "name": "ADM - Example",
                "content": {
                    "search": "| makeresults",
                    "disabled": True,
                    "is_scheduled": False,
                },
            }

            def get(_method, path):
                if "/conf-macros?" in path:
                    return {
                        "paging": {"total": 1},
                        "entry": [
                            {
                                "name": "adm_example",
                                "content": {"definition": "index=netflow"},
                            }
                        ],
                    }
                if "/saved/searches?" in path:
                    return {"paging": {"total": 1}, "entry": [writer]}
                return []

            hashes = "\n".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  /opt/splunk/etc/apps/splunk_adm/default/{path.name}"
                for path in sorted(config.glob("*.conf"))
            )
            lab = SimpleNamespace(_json=get)
            with (
                patch("tools.capture_networking_fixtures.ROOT", root),
                patch("tools.capture_networking_fixtures.require_local_lab"),
                patch(
                    "tools.capture_networking_fixtures.subprocess.run",
                    return_value=SimpleNamespace(stdout=hashes),
                ) as docker_run,
                patch(
                    "tools.capture_networking_fixtures.search",
                    return_value=(
                        [{"index": "netflow", "evidence_id": "a", "count": "1"}],
                        {},
                    ),
                ) as query,
            ):
                before = evidence_fingerprints(lab, raw, require_candidate=True)
                self.assertEqual(
                    docker_run.call_args.args[0][:6],
                    ["docker", "exec", "-u", "splunk", "adm-splunk-lab", "sha256sum"],
                )
                query.return_value = (
                    [{"index": "netflow", "evidence_id": "b", "count": "1"}],
                    {},
                )
                after = evidence_fingerprints(lab, raw, require_candidate=True)
                self.assertNotEqual(
                    before["indexed_content_sha256"], after["indexed_content_sha256"]
                )
                writer["content"]["search"] = "| makeresults | eval altered=1"
                with self.assertRaisesRegex(RuntimeError, "effective saved search"):
                    evidence_fingerprints(lab, raw, require_candidate=True)

    def test_backend_proof_must_match_this_client_and_port(self):
        graph = [
            {
                "row_type": "node",
                "endpoint_kind": "network_client",
                "id": "client-a",
                "attr_scope": "campus-aci",
                "attr_client_mac": "02:61:00:00:00:20",
            },
            {
                "row_type": "node",
                "id": "frontend",
                "addresses": "10.50.0.20",
            },
            {
                "row_type": "edge",
                "relationship": "traffic_observation",
                "source": "client-a",
                "target": "frontend",
                "source_port": "52000",
                "traffic_observations": [
                    {
                        "source_ip": "10.61.0.20",
                        "destination_ip": "10.50.0.20",
                        "source_port": 52000,
                        "destination_port": 8080,
                        "transport": "tcp",
                        "scope": "campus-aci",
                        "first_seen": 100,
                        "last_seen": 102,
                    }
                ],
            },
            {
                "row_type": "edge",
                "relationship": "forwards_to",
                "source": "frontend",
                "target": "backend",
                "confidence": "observed",
            },
        ]
        handoff = {
            "client_ip": "10.61.0.20",
            "scope": "campus-aci",
            "adm_cport": "52000",
            "adm_fe_id": "frontend",
            "adm_targets": "backend",
            "handoff_basis": "hubble_client_tuple",
            "server_port": "8080",
            "transport": "tcp",
            "adm_ct": "100",
            "adm_cend": "101",
        }
        require_handoff(graph, [handoff], "aci")
        for field, value in (
            ("client_ip", "10.61.0.99"),
            ("adm_cport", "52001"),
            ("adm_fe_id", "another-frontend"),
            ("adm_targets", "another-backend"),
            ("scope", "meraki-nxos"),
            ("handoff_basis", "time_inferred"),
            ("transport", "udp"),
            ("server_port", "443"),
            ("adm_ct", "200"),
            ("adm_ct", None),
            ("adm_cend", "99"),
            ("adm_cend", "NaN"),
        ):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                require_handoff(graph, [{**handoff, field: value}], "aci")

    def test_local_lab_validation_rejects_remote_before_any_container_access(self):
        lab = SimpleNamespace(
            MGMT="https://127.0.0.1:8089", HEC="https://127.0.0.1:8088"
        )
        with (
            patch(
                "benchmark_pipeline.local_docker_endpoint",
                side_effect=ValueError("remote"),
            ),
            patch("benchmark_pipeline.command") as command,
        ):
            with self.assertRaises(ValueError):
                require_local_lab(lab)
            command.assert_not_called()
        with (
            patch("benchmark_pipeline.local_docker_endpoint"),
            patch(
                "benchmark_pipeline.command",
                return_value='{"8088/tcp":[{"HostIp":"0.0.0.0","HostPort":"8088"}]}',
            ),
        ):
            with self.assertRaises(ValueError):
                require_local_lab(lab)

    def test_window_rejects_search_text_and_invalid_bounds(self):
        for bounds in (
            ("now", "now+1h"),
            ("0 | collect", "12"),
            ("2", "2"),
            ("3", "2"),
            ("0", "253402300800"),
        ):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                validate_window(*bounds)
        self.assertEqual(validate_window("0", "123"), ("0", "123"))

    def test_search_evidence_must_be_complete(self):
        valid = {
            "dispatchState": "DONE",
            "isDone": True,
            "isFinalized": False,
            "eventIsTruncated": False,
            "dropCount": 0,
            "resultCount": 1,
            "messages": [],
        }
        require_complete(valid, [{}])
        for key, value in (
            ("dispatchState", "FAILED"),
            ("isDone", False),
            ("isFinalized", True),
            ("eventIsTruncated", True),
            ("resultIsTruncated", True),
            ("resultIsTruncated", "true"),
            ("resultIsTruncated", "malformed"),
            ("resultIsTruncated", None),
            ("dropCount", 1),
            ("resultCount", 2),
            ("messages", [{"type": "WARN", "text": "peer unavailable"}]),
            ("messages", None),
            ("messages", "not a list"),
            ("messages", [None]),
            ("messages", [{"type": None}]),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                require_complete({**valid, key: value}, [{}])
        for value in (False, 0, "0"):
            with self.subTest(resultIsTruncated=value):
                require_complete({**valid, "resultIsTruncated": value}, [{}])
        for key in valid:
            with self.subTest(missing=key), self.assertRaises(RuntimeError):
                require_complete({k: v for k, v in valid.items() if k != key}, [{}])

    def test_capture_requires_scoped_client_backend_and_cluster(self):
        rows = [
            {
                "row_type": "node",
                "endpoint_kind": "network_client",
                "id": "client-a",
                "addresses": "10.61.0.20",
                "attr_scope": "campus-aci",
                "attr_client_mac": "02:61:00:00:00:20",
                "attr_attachment_basis": "catalyst_client_snapshot",
                "cluster": "cilium-aci-east",
            },
            {
                "row_type": "node",
                "id": "service-a",
                "endpoint_kind": "k8s_service",
                "cluster": "cilium-aci-east",
            },
            {
                "row_type": "node",
                "id": "pod:cilium-aci-east/pod-a",
                "cluster": "cilium-aci-east",
            },
            {
                "row_type": "edge",
                "relationship": "traffic_observation",
                "source": "client-a",
                "target": "service-a",
            },
            {
                "row_type": "edge",
                "relationship": "forwards_to",
                "source": "service-a",
                "target": "pod:cilium-aci-east/pod-a",
                "confidence": "observed",
                "evidence": "hubble_client_tuple",
            },
        ]
        require_client(rows, "aci")
        for missing in range(5):
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                require_client(rows[:missing] + rows[missing + 1 :], "aci")
        with self.assertRaises(RuntimeError):
            require_client(rows + [rows[0]], "aci")
        with self.assertRaises(RuntimeError):
            require_client(
                rows
                + [{"row_type": "node", "id": "other", "cluster": "cilium-nxos-west"}],
                "aci",
            )
        for key, value in (
            ("confidence", "inferred"),
            ("evidence", "time_inferred"),
            ("source", "unrelated-service"),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                require_client(rows[:-1] + [{**rows[-1], key: value}], "aci")
