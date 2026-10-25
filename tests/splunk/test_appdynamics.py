"""Installed-lab qualification for the AppDynamics import and Atlas reader."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid
from urllib.request import Request
from urllib.parse import urlsplit

import lab

from tools.export_appdynamics import collect_snapshot
from tools.import_appdynamics import convert_snapshot

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "appdynamics"
SEARCH_HELPER = ROOT / "tools" / "appdynamics_search.mjs"
INDEX = "atlas_asset"


class LabClock:
    def __init__(self) -> None:
        self.value = time.time() - 20

    def __call__(self) -> float:
        self.value += 0.1
        return self.value


class Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body)
        part = self.body[self.offset : self.offset + size]
        self.offset += len(part)
        return part


class FixtureController:
    """Serve official-shape synthetic XML without making external requests."""

    def open(self, request: Request, timeout: int) -> Response:
        del timeout
        path = urlsplit(request.full_url).path
        if path == "/controller/api/oauth/access_token":
            return Response(b'{"access_token":"synthetic-lab-token","expires_in":300}')
        fixture = {
            "/controller/rest/applications": "applications.xml",
            "/controller/rest/applications/101/tiers": "application-101-tiers.xml",
            "/controller/rest/applications/101/tiers/7/nodes": "application-101-tier-7-nodes.xml",
            "/controller/rest/applications/101/backends": "application-101-backends.xml",
            "/controller/rest/applications/202/tiers": "application-202-tiers.xml",
            "/controller/rest/applications/202/tiers/8/nodes": "application-202-tier-8-nodes.xml",
            "/controller/rest/applications/202/backends": "application-202-backends.xml",
        }.get(path)
        if fixture is None:
            raise AssertionError(f"Unexpected fixture Controller path: {path}")
        return Response((FIXTURES / fixture).read_bytes())


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "requires the named disposable Splunk lab"
)
class AppDynamicsInstalledLabTest(unittest.TestCase):
    def test_collect_validate_import_index_and_inspect_current_node_ip(self) -> None:
        authority = "appd-lab-" + uuid.uuid4().hex[:10]
        scope = "appd-lab-" + uuid.uuid4().hex[:8]
        selection = {
            "schemaVersion": 1,
            "workflow": "endpoint",
            "selectionId": uuid.uuid4().hex,
            "trafficContract": 1,
            "window": {"start": int(time.time()) - 86400, "end": int(time.time())},
            "scope": scope,
            "addresses": ["10.20.0.17"],
            "contexts": [],
            "identityBasis": "synthetic AppDynamics Controller lab",
            "configurationFingerprint": "a" * 64,
        }
        config = {
            "source": "appdynamics_inventory",
            "state": "active",
            "indexes": [INDEX],
            "authorities": [authority],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "appd_controller",
                    "observer": authority,
                    "scope": scope,
                    "cluster": "",
                    "mapping_status": "verified",
                    "controller_origin": "https://controller.example.test",
                }
            ],
        }

        clock = LabClock()
        bundle, asset_manifest = collect_snapshot(
            controller_origin="https://controller.example.test",
            controller_authority=authority,
            scope=scope,
            api_client="synthetic-reader",
            account_name="synthetic-account",
            client_secret="synthetic-only-test-value",
            now=clock,
            monotonic=time.monotonic,
            sleep=lambda _seconds: None,
            opener=FixtureController(),
        )
        bundle["asset_history_manifest"] = asset_manifest

        with tempfile.TemporaryDirectory(prefix="adm-appd-installed-") as name:
            directory = Path(name)
            snapshot = directory / "snapshot.json"
            snapshot.write_text(json.dumps(bundle), encoding="utf-8")
            outputs, report = convert_snapshot(snapshot)
            self.assertTrue(report["accepted"])
            self.assertEqual(report["asset_history_records"], 3)

            indexed_paths = []
            for key, payload in outputs.items():
                output = directory / key
                rows = [
                    {**json.loads(line), "index": INDEX}
                    for line in payload.decode("utf-8").splitlines()
                ]
                output.write_text(
                    "".join(
                        json.dumps(row, separators=(",", ":")) + "\n" for row in rows
                    ),
                    encoding="utf-8",
                )
                indexed_paths.append(output)
            self.assertEqual(lab.load(indexed_paths), 13)

            built = subprocess.run(
                ["node", str(SEARCH_HELPER)],
                cwd=ROOT,
                input=json.dumps({"config": config, "selection": selection}),
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            contract = json.loads(built.stdout)
            deadline = time.monotonic() + 45
            rows: list[dict] = []
            while time.monotonic() < deadline:
                rows = lab.search(
                    contract["search"],
                    earliest=str(contract["window"]["start"]),
                    latest=str(contract["window"]["end"]),
                )
                if any(row.get("kind") == "supplemental_completion" for row in rows):
                    break
                time.sleep(0.5)
            normalized = subprocess.run(
                ["node", str(SEARCH_HELPER)],
                cwd=ROOT,
                input=json.dumps(
                    {"config": config, "selection": selection, "rows": rows}
                ),
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            inspected = json.loads(normalized.stdout)
            self.assertEqual(inspected["envelope"]["inputCount"], 10)
            self.assertEqual(inspected["envelope"]["sourceScanCapped"], False)
            contexts = inspected["normalized"]["records"]
            self.assertEqual(inspected["normalized"]["rejected"], 0)
            self.assertEqual(len(contexts), 1)
            context = contexts[0]
            self.assertEqual(
                context["indexedRecordCount"], context["expectedRecordCount"]
            )
            self.assertCountEqual(
                [node["nodeId"] for node in context["nodes"]], ["3", "3"]
            )
            self.assertEqual(
                {node["applicationId"] for node in context["nodes"]}, {"101", "202"}
            )
            self.assertTrue(
                any(
                    backend["associatedWithMatchedNode"]
                    for backend in context["backends"]
                )
            )
            self.assertTrue(
                any(
                    backend["associationStatus"] == "application_scope_only"
                    for backend in context["backends"]
                )
            )

            asset_rows = lab.search(
                f'index={INDEX} sourcetype="adm:asset_history" '
                f'asset_authority="{authority}" scope="{scope}" '
                f'snapshot_id="{bundle["snapshot_id"]}" | fields ip asset_id validity_basis valid_to retired_at'
            )
            self.assertEqual(len(asset_rows), 3)
            self.assertTrue(
                all(
                    row.get("validity_basis") == "snapshot_current"
                    for row in asset_rows
                )
            )
            self.assertTrue(all(not row.get("valid_to") for row in asset_rows))
            self.assertTrue(all(not row.get("retired_at") for row in asset_rows))
