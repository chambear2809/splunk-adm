"""Installed-lab acceptance for imported, historical asset-history evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
INDEX = "atlas_asset"
SEARCH_HELPER = ROOT / "tools" / "asset_history_search.mjs"
IMPORTER = ROOT / "tools" / "import_asset_history.py"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class AssetHistoryInstalledLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = "cmdb-lab-" + uuid.uuid4().hex[:12]
        cls.malformed_authority = cls.authority + "-invalid"
        cls.scope = "lab-asset-" + uuid.uuid4().hex[:8]
        cls.now = int(time.time()) - 10
        cls.start = cls.now - 250
        cls.end = cls.now - 50
        cls.ip_reuse = "198.18.10.11"
        cls.ip_conflict = "198.18.10.12"
        cls.ip_snapshot = "198.18.10.13"
        cls.ip_corrected_close = "198.18.10.14"
        cls.ip_corrected_move = "198.18.10.15"
        cls.ip_corrected_scope = "198.18.10.16"
        cls.ip_corrected_start = "198.18.10.17"
        cls.manifest = {
            "schema_version": 1,
            "authority": cls.authority,
            "snapshot_id": "snapshot-" + uuid.uuid4().hex,
            "snapshot_at": cls.now,
            "snapshot_complete": True,
            "records": [
                {
                    "record_id": "assignment-retired",
                    "revision": 1,
                    "asset_id": "asset-old",
                    "asset_name": "old-owner",
                    "owner_id": "team-old",
                    "owner_name": "Old Team",
                    "environment": "production",
                    "network_id": "vpc-lab",
                    "scope": cls.scope,
                    "ip": cls.ip_reuse,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now - 300,
                    "retired_at": cls.now - 300,
                },
                {
                    "record_id": "assignment-current",
                    "revision": 1,
                    "asset_id": "asset-new",
                    "asset_name": "new-owner",
                    "owner_id": "team-new",
                    "service_id": "service-lab",
                    "service_name": "Lab Service",
                    "environment": "production",
                    "network_id": "vpc-lab",
                    "scope": cls.scope,
                    "ip": cls.ip_reuse,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 300,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "overlap-a",
                    "revision": 1,
                    "asset_id": "asset-conflict-a",
                    "scope": cls.scope,
                    "ip": cls.ip_conflict,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 300,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "overlap-b",
                    "revision": 1,
                    "asset_id": "asset-conflict-b",
                    "scope": cls.scope,
                    "ip": cls.ip_conflict,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 200,
                    "valid_to": cls.now + 100,
                    "retired_at": cls.now + 100,
                },
                {
                    "record_id": "current-only",
                    "revision": 1,
                    "asset_id": "asset-snapshot",
                    "scope": cls.scope,
                    "ip": cls.ip_snapshot,
                    "validity_basis": "snapshot_current",
                },
                {
                    "record_id": "correction-close",
                    "revision": 1,
                    "asset_id": "asset-close-corrected",
                    "scope": cls.scope,
                    "ip": cls.ip_corrected_close,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "correction-close",
                    "revision": 2,
                    "asset_id": "asset-close-corrected",
                    "scope": cls.scope,
                    "ip": cls.ip_corrected_close,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now - 300,
                    "retired_at": cls.now - 300,
                },
                {
                    "record_id": "correction-ip",
                    "revision": 1,
                    "asset_id": "asset-ip-corrected",
                    "scope": cls.scope,
                    "ip": cls.ip_corrected_move,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "correction-ip",
                    "revision": 2,
                    "asset_id": "asset-ip-corrected",
                    "scope": cls.scope,
                    "ip": "198.18.10.25",
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "correction-scope",
                    "revision": 1,
                    "asset_id": "asset-scope-corrected",
                    "scope": cls.scope,
                    "ip": cls.ip_corrected_scope,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "correction-scope",
                    "revision": 2,
                    "asset_id": "asset-scope-corrected",
                    "scope": "lab-corrected-scope",
                    "ip": cls.ip_corrected_scope,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "correction-start",
                    "revision": 1,
                    "asset_id": "asset-start-corrected",
                    "scope": cls.scope,
                    "ip": cls.ip_corrected_start,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "same-revision-scope-conflict",
                    "revision": 1,
                    "asset_id": "asset-same-revision",
                    "scope": cls.scope,
                    "ip": "198.18.10.18",
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 700,
                    "valid_to": cls.now + 500,
                },
                {
                    "record_id": "correction-start",
                    "revision": 2,
                    "asset_id": "asset-start-corrected",
                    "scope": cls.scope,
                    "ip": cls.ip_corrected_start,
                    "validity_basis": "source_interval",
                    "valid_from": cls.now - 30,
                    "valid_to": cls.now + 500,
                },
            ],
        }
        cls.temp = tempfile.TemporaryDirectory(prefix="adm-asset-history-")
        root = Path(cls.temp.name)
        source = root / "manifest.json"
        output = root / "history.ndjson"
        source.write_text(json.dumps(cls.manifest), encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(IMPORTER), str(source), "--output", str(output)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(completed.stderr)
        # The importer deliberately stays index-neutral. This test-only copy
        # assigns the dedicated lab index through the HEC envelope itself.
        indexed_output = root / "history.indexed.ndjson"
        envelopes = [
            {**json.loads(line), "index": INDEX}
            for line in output.read_text(encoding="utf-8").splitlines()
        ]
        # A second ingest can surface conflicting same-revision source copies;
        # keep it out of the importer manifest, which correctly rejects such
        # duplicate record_id/revision pairs in a single export.
        sibling = next(
            row
            for row in envelopes
            if row["event"]["record_id"] == "same-revision-scope-conflict"
        )
        sibling = json.loads(json.dumps(sibling))
        sibling["event"]["scope"] = "lab-conflicting-scope"
        sibling["event"]["record_fingerprint"] = "b" * 64
        envelopes.append(sibling)
        malformed = json.loads(json.dumps(sibling))
        malformed["event"]["asset_authority"] = cls.malformed_authority
        malformed["event"]["record_id"] = "malformed-missing-basis"
        malformed["event"]["ip"] = "198.18.10.19"
        malformed["event"]["revision"] = "invalid-revision"
        malformed["event"].pop("validity_basis", None)
        malformed["event"]["record_fingerprint"] = "c" * 64
        envelopes.append(malformed)
        indexed_output.write_text(
            "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in envelopes),
            encoding="utf-8",
        )
        cls.indexed = lab.load([indexed_output])
        cls._wait_for_events()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    @classmethod
    def _wait_for_events(cls) -> None:
        deadline = time.monotonic() + 45
        query = (
            f'index={INDEX} sourcetype="adm:asset_history" '
            f'(asset_authority="{cls.authority}" OR '
            f'asset_authority="{cls.malformed_authority}") | stats count AS count'
        )
        while time.monotonic() < deadline:
            rows = lab.search(query, "0", "+1h")
            if rows and int(rows[0].get("count", 0)) == cls.indexed:
                return
            time.sleep(0.5)
        raise AssertionError("synthetic asset-history HEC events were not indexed")

    @classmethod
    def _selection(cls, address: str, start: int, end: int) -> dict:
        return {
            "schemaVersion": 1,
            "workflow": "endpoint",
            "selectionId": "asset-lab-" + uuid.uuid4().hex,
            "trafficContract": 1,
            "window": {"start": start, "end": end},
            "scope": cls.scope,
            "addresses": [address],
            "contexts": [],
            "identityBasis": "disposable asset-history lab",
            "configurationFingerprint": "a" * 64,
        }

    @classmethod
    def _search(
        cls, address: str, start: int, end: int, authority: str | None = None
    ) -> tuple[dict, dict, list[dict]]:
        authority = authority or cls.authority
        selection = cls._selection(address, start, end)
        configuration = {
            "source": "asset_history",
            "state": "active",
            "indexes": [INDEX],
            "authorities": [authority],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "asset_authority",
                    "observer": authority,
                    "scope": cls.scope,
                    "cluster": "",
                    "mapping_status": "verified",
                }
            ],
        }
        completed = subprocess.run(
            ["node", str(SEARCH_HELPER)],
            cwd=ROOT,
            input=json.dumps({"config": configuration, "selection": selection}),
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(completed.stderr)
        latest = max(end, int(time.time()))
        return selection, configuration, lab.search(completed.stdout, "0", str(latest))

    @classmethod
    def _normalize(cls, selection: dict, configuration: dict, rows: list[dict]) -> dict:
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        completed = subprocess.run(
            ["node", str(SEARCH_HELPER)],
            cwd=ROOT,
            input=json.dumps(
                {
                    "mode": "normalize",
                    "config": configuration,
                    "selection": selection,
                    "rows": records,
                }
            ),
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(completed.stderr)
        return json.loads(completed.stdout)

    def test_imported_reused_address_returns_current_historical_owner_only(
        self,
    ) -> None:
        selection, configuration, rows = self._search(
            self.ip_reuse, self.start, self.end
        )
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        completion = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(len(completion), 1)
        self.assertEqual(int(completion[0]["input_count"]), 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["asset_id"], "asset-new")
        self.assertEqual(records[0]["owner_id"], "team-new")
        self.assertEqual(records[0]["environment"], "production")
        self.assertEqual(records[0]["network_id"], "vpc-lab")
        self.assertNotEqual(records[0]["asset_id"], "asset-old")
        normalized = self._normalize(selection, configuration, rows)
        self.assertEqual(normalized["rejected"], 0)
        self.assertEqual(normalized["records"][0]["assetId"], "asset-new")
        self.assertEqual(normalized["records"][0]["attribution"], "historical_interval")

    def test_overlapping_claims_remain_two_visible_conflicting_candidates(self) -> None:
        selection, configuration, rows = self._search(
            self.ip_conflict, self.now - 150, self.now - 100
        )
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        self.assertEqual(
            {record["asset_id"] for record in records},
            {"asset-conflict-a", "asset-conflict-b"},
        )
        completion = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(len(completion), 1)
        self.assertEqual(int(completion[0]["input_count"]), 2)
        normalized = self._normalize(selection, configuration, rows)
        self.assertEqual(normalized["rejected"], 0)
        self.assertEqual(len(normalized["records"]), 2)
        self.assertTrue(all(record["conflict"] for record in normalized["records"]))
        self.assertTrue(
            all(
                record["attribution"] == "ambiguous" for record in normalized["records"]
            )
        )

    def test_current_snapshot_is_not_returned_for_pre_snapshot_history(self) -> None:
        _, _, rows = self._search(self.ip_snapshot, self.now - 200, self.now - 100)
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        self.assertEqual(records, [])
        completion = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(len(completion), 1)
        self.assertEqual(int(completion[0]["input_count"]), 0)

    def test_current_snapshot_is_visible_at_its_point_and_retirement_is_explicit(
        self,
    ) -> None:
        selection, configuration, rows = self._search(
            self.ip_snapshot, self.now, self.now + 60
        )
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["validity_basis"], "snapshot_current")
        normalized = self._normalize(selection, configuration, rows)
        self.assertEqual(
            normalized["records"][0]["attribution"], "current_snapshot_context"
        )
        retired = lab.search(
            f'index={INDEX} sourcetype="adm:asset_history" '
            f'asset_authority="{self.authority}" record_id="assignment-retired" '
            "| table retired_at valid_to",
            "0",
            "+1h",
        )
        self.assertEqual(len(retired), 1)
        self.assertEqual(retired[0]["retired_at"], retired[0]["valid_to"])

    def test_latest_correction_prevents_false_historical_attribution(self) -> None:
        for address in (
            self.ip_corrected_close,
            self.ip_corrected_move,
            self.ip_corrected_scope,
            self.ip_corrected_start,
        ):
            with self.subTest(address=address):
                _, _, rows = self._search(address, self.start, self.end)
                self.assertEqual(
                    [row for row in rows if row.get("kind") == "supplemental_record"],
                    [],
                )
                completion = [
                    row for row in rows if row.get("kind") == "supplemental_completion"
                ]
                self.assertEqual(len(completion), 1)
                self.assertGreaterEqual(int(completion[0]["source_scan_count"]), 1)
                self.assertEqual(int(completion[0]["source_scan_invalid_count"]), 0)
                self.assertEqual(int(completion[0]["source_scan_capped"]), 0)

    def test_equal_revision_sibling_outside_scope_still_marks_claim_ambiguous(
        self,
    ) -> None:
        selection, configuration, rows = self._search(
            "198.18.10.18", self.start, self.end
        )
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        self.assertEqual(len(records), 1)
        self.assertEqual(int(records[0]["revision_conflict"]), 1)
        normalized = self._normalize(selection, configuration, rows)
        self.assertEqual(len(normalized["records"]), 1)
        self.assertTrue(normalized["records"][0]["conflict"])
        self.assertEqual(normalized["records"][0]["attribution"], "ambiguous")

    def test_completion_marker_survives_when_malformed_rows_are_ineligible(
        self,
    ) -> None:
        _, _, rows = self._search(
            "198.18.10.19",
            self.start,
            self.end,
            authority=self.malformed_authority,
        )
        self.assertEqual(
            [row for row in rows if row.get("kind") == "supplemental_record"],
            [],
        )
        completion = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(len(completion), 1)
        self.assertEqual(int(completion[0]["source_scan_count"]), 1)
        self.assertEqual(int(completion[0]["source_scan_invalid_count"]), 1)
        self.assertEqual(int(completion[0]["input_count"]), 0)


if __name__ == "__main__":
    unittest.main()
