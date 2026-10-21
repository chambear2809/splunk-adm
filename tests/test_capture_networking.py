"""Guard the evidence boundary of captured Cisco demo fixtures."""

import unittest
from unittest.mock import patch
from types import SimpleNamespace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import io
import tarfile

from tools import capture_networking_fixtures as networking

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
                patch.dict(os.environ, {}, clear=True),
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


class CapturePackageFingerprintTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.app = self.root / "splunk_app/splunk_adm"
        (self.app / "default").mkdir(parents=True)
        self.source = {
            "app.conf": b"[id]\nname = splunk_adm\nversion = 0.3.0\n",
            "macros.conf": b"[adm_example]\ndefinition = index=netflow\n",
            "savedsearches.conf": b"[ADM - Example]\nsearch = | makeresults\n",
        }
        for name, content in self.source.items():
            (self.app / "default" / name).write_bytes(content)
        (self.root / "tools").mkdir()
        (self.root / "tools/gen_raw_fixtures.py").write_text("# synthetic generator\n")
        self.raw = self.root / "raw"
        self.raw.mkdir()
        for name in ("scenario.json", "source-profiles.json"):
            (self.raw / name).write_text("{}")
        (self.raw / "capture-manifest.json").write_text(
            json.dumps({"index_events": {"netflow": 1}})
        )
        self.packaged = dict(self.source)
        self.packaged["app.conf"] = (
            b"[install]\nbuild = 1792340274\n" + self.source["app.conf"]
        )
        self.archive = self.root / "candidate.tgz"
        self.installed = dict(self.packaged)
        self.macro = "index=netflow"

    def write_archive(self, configs=None, unsafe=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, content in (
                self.packaged if configs is None else configs
            ).items():
                info = tarfile.TarInfo("splunk_adm/default/" + name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            if unsafe:
                info = tarfile.TarInfo("splunk_adm/default/escape.conf")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(f"{self.archive}.sha256").write_text(
            f"{digest}  {self.archive.name}\n", encoding="utf-8"
        )

    def fingerprint(self, *, supplied=True, strict=True):
        def api(_method, path):
            if "/conf-macros?" in path:
                return {
                    "paging": {"total": 1},
                    "entry": [
                        {"name": "adm_example", "content": {"definition": self.macro}}
                    ],
                }
            if "/saved/searches?" in path:
                return {
                    "paging": {"total": 1},
                    "entry": [
                        {
                            "name": "ADM - Example",
                            "content": {
                                "search": "| makeresults",
                                "disabled": True,
                                "is_scheduled": False,
                            },
                        }
                    ],
                }
            return []

        prefix = "/opt/splunk/etc/apps/splunk_adm/default/"
        hashes = "\n".join(
            hashlib.sha256(content).hexdigest() + "  " + prefix + name
            for name, content in sorted(self.installed.items())
        )
        with (
            patch.dict(
                os.environ,
                {"ADM_LAB_PACKAGE": str(self.archive)} if supplied else {},
                clear=True,
            ),
            patch.object(networking, "ROOT", self.root),
            patch.object(networking, "require_local_lab"),
            patch.object(
                networking.subprocess,
                "check_output",
                return_value="".join(
                    prefix + name + "\n" for name in sorted(self.installed)
                ).encode(),
            ),
            patch.object(
                networking.subprocess,
                "run",
                return_value=SimpleNamespace(stdout=hashes),
            ) as docker,
            patch.object(
                networking,
                "search",
                return_value=(
                    [{"index": "netflow", "evidence_id": "synthetic", "count": "1"}],
                    {},
                ),
            ),
        ):
            evidence = networking.evidence_fingerprints(
                SimpleNamespace(_json=api), self.raw, require_candidate=strict
            )
            self.assertEqual(docker.call_count, 1)
            self.assertIn("sha256sum", docker.call_args.args[0])
            return evidence

    def test_exact_archive_and_source_hashes_are_separately_bound(self):
        self.write_archive()
        result = self.fingerprint()
        self.assertEqual(
            result["package_archive_sha256"],
            hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            result["source_default_sha256"],
            {
                name: hashlib.sha256(content).hexdigest()
                for name, content in self.source.items()
            },
        )
        self.assertEqual(
            result["installed_default_sha256"],
            {
                name: hashlib.sha256(content).hexdigest()
                for name, content in self.packaged.items()
            },
        )
        self.assertNotEqual(
            result["source_default_sha256"]["app.conf"],
            result["installed_default_sha256"]["app.conf"],
        )

    def test_archive_source_query_drift_is_rejected(self):
        self.write_archive(
            dict(
                self.packaged,
                **{"macros.conf": b"[adm_example]\ndefinition = index=other\n"},
            )
        )
        with self.assertRaisesRegex(ValueError, "differs from source"):
            self.fingerprint()

    def test_installed_archive_hash_drift_is_rejected_even_without_strict_mode(self):
        self.write_archive()
        self.installed["app.conf"] += b"# installed drift\n"
        with self.assertRaisesRegex(RuntimeError, "differs from the provided package"):
            self.fingerprint(strict=False)

    def test_installed_extra_or_missing_defaults_are_rejected(self):
        self.write_archive()
        for installed in (
            {"app.conf": self.packaged["app.conf"]},
            dict(self.packaged, **{"props.conf": b"[extra]\n"}),
        ):
            with self.subTest(installed=sorted(installed)):
                self.installed = installed
                with self.assertRaisesRegex(
                    RuntimeError, "config set differs from provided package"
                ):
                    self.fingerprint()

    def test_local_effective_override_is_recorded_without_benchmark_override_guard(
        self,
    ):
        self.write_archive()
        before = self.fingerprint(strict=False)
        self.macro = "index=selected-local-source"
        after = self.fingerprint(strict=False)
        self.assertNotEqual(
            before["effective_macros_sha256"], after["effective_macros_sha256"]
        )
        self.assertEqual(
            before["installed_default_sha256"], after["installed_default_sha256"]
        )
        with self.assertRaisesRegex(RuntimeError, "effective macro"):
            self.fingerprint(strict=True)

    def test_unsafe_archive_fails_shared_validation(self):
        self.write_archive(unsafe=True)
        with self.assertRaisesRegex(ValueError, "links or special files"):
            self.fingerprint()

    def test_no_package_behavior_remains_source_based(self):
        self.installed = dict(self.source)
        result = self.fingerprint(supplied=False)
        self.assertNotIn("package_archive_sha256", result)
        self.assertNotIn("source_default_sha256", result)
        self.installed["app.conf"] = self.packaged["app.conf"]
        with self.assertRaisesRegex(RuntimeError, "differs from the candidate source"):
            self.fingerprint(supplied=False)
