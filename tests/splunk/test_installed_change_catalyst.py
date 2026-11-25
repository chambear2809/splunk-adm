"""Installed Catalyst audit adapter replay; no controller is contacted."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import unittest

import lab

from tools.capture_networking_fixtures import search as capture_search
from tools.change_correlation.adapters.catalyst import adapt_catalyst_audits
from tools.change_correlation.export import render_generation_hec
from tools.change_correlation.history import build_generation
from tools.activate_configuration_generation import verify_readback

INDEX = "atlas_changes"
CHANGE_TYPE = "adm:configuration_change:v1"
FIXTURE_PATH = (
    Path(__file__).parents[2]
    / "fixtures"
    / "change-correlation"
    / "catalyst"
    / "audit_log_documentation_shaped.json"
)


def read_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1"
    and os.environ.get("ADM_LAB_TASK")
    and os.environ.get("ADM_LAB_NAME")
    and os.environ.get("ADM_LAB_WEB_PORT")
    and os.environ.get("ADM_LAB_MGMT_PORT")
    and os.environ.get("ADM_LAB_HEC_PORT"),
    "requires an explicitly allocated Catalyst task lab",
)
class CatalystAuditInstalledTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        task = os.environ.get("ADM_LAB_TASK", "")
        name = os.environ.get("ADM_LAB_NAME", "")
        ports = [
            os.environ.get("ADM_LAB_WEB_PORT"),
            os.environ.get("ADM_LAB_MGMT_PORT"),
            os.environ.get("ADM_LAB_HEC_PORT"),
        ]
        if not task.startswith("catalyst-") or name == "adm-splunk-lab":
            raise RuntimeError(
                "Catalyst qualification requires a uniquely named Catalyst task lab"
            )
        if len(set(ports)) != len(ports):
            raise RuntimeError("Catalyst qualification requires distinct lab ports")
        lab.verify_target()
        cls.evidence_directory = os.environ.get("ADM_LAB_EVIDENCE_DIRECTORY")
        if not cls.evidence_directory:
            raise RuntimeError(
                "Catalyst installed qualification requires private evidence output"
            )

        cls.fixture = read_fixture()
        if cls.fixture.get("fixture_status") != (
            "documentation_shaped_synthetic_not_native_sample"
        ):
            raise AssertionError("Catalyst fixture lost its non-sample qualification.")
        cls.fixture_sha256 = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
        cls.key = secrets.token_hex(8)
        cls.receipt = adapt_catalyst_audits(
            cls.fixture["native_records"],
            {
                **cls.fixture["collection_metadata"],
                "capture_id": f"catalyst-installed-{cls.key}",
                "received_at": int(time.time()),
                "source_reference": f"synthetic-catalyst-audit:{cls.key}",
            },
        )
        cls.generation = build_generation([cls.receipt])
        cls.manifest = cls.generation["manifest"]
        cls.hec = render_generation_hec(cls.generation, index=INDEX).encode()
        evidence = Path(cls.evidence_directory)
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(evidence, 0o700)
        (evidence / f"catalyst-source-input-{cls.key}.json").write_text(
            json.dumps(
                {
                    "qualification": "documentation_shaped_synthetic_not_native_sample",
                    "fixture_sha256": cls.fixture_sha256,
                    "receipt": cls.receipt,
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (evidence / f"catalyst-generation-{cls.key}.hec.ndjson").write_bytes(cls.hec)

        cls.ingest_start = int(time.time())
        lab._hec_post(cls.hec)
        cls.indexed = cls.wait_change_rows(1)
        cls.rows = verify_readback(
            cls.manifest, [json.loads(row["_raw"]) for row in cls.indexed]
        )
        cls.ingest_end = int(time.time()) + 2

    @classmethod
    def wait_change_rows(cls, expected: int) -> list[dict]:
        query = (
            f'index={INDEX} sourcetype="{CHANGE_TYPE}" '
            f'generation_id="{cls.manifest["generation_id"]}" '
            "| eval _time_epoch=tonumber(_time), _indexed_epoch=tonumber(_indextime) "
            "| table _raw _time_epoch _indexed_epoch"
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            rows, _provenance = capture_search(
                lab,
                query,
                str(cls.manifest["source_earliest"]),
                str(cls.manifest["source_latest"] + 0.001),
            )
            if len(rows) >= expected:
                return rows
            time.sleep(1)
        raise AssertionError("Catalyst audit observation did not reach the owned lab")

    def test_audit_row_is_indexed_as_context_with_distinct_source_and_receipt_clocks(
        self,
    ) -> None:
        rows = verify_readback(self.manifest, self.rows)
        observations = [
            row
            for row in rows
            if row["record_type"] == "observation"
            and row["product"] == "catalyst_center"
            and row["family"] == "audit_log"
        ]
        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation["kind"], "audit")
        self.assertEqual(observation["change_type"], "observation")
        self.assertEqual(observation["scope"], "change-b")
        self.assertEqual(observation["object_id"], "audit-instance-synthetic-001")
        self.assertEqual(observation["actor"], "synthetic-admin-01")
        self.assertEqual(observation["event_at"], 1793102400.123)
        self.assertIsNone(observation["effective_at"])
        self.assertTrue(observation["clock_uncertainty_unknown"])

        for indexed in self.indexed:
            raw = json.loads(indexed["_raw"])
            self.assertEqual(float(indexed["_time_epoch"]), raw["event_at"])
            self.assertGreaterEqual(float(indexed["_indexed_epoch"]), self.ingest_start)
            self.assertLess(float(indexed["_indexed_epoch"]), self.ingest_end)
            self.assertNotEqual(float(indexed["_indexed_epoch"]), raw["event_at"])


if __name__ == "__main__":
    unittest.main()
