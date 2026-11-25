"""Installed AppDynamics audit-to-history replay; no Controller is contacted."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import unittest

import lab

from tools.activate_configuration_generation import verify_readback
from tools.change_correlation.adapters.appdynamics import adapt_appdynamics_audits
from tools.change_correlation.export import render_generation_hec
from tools.change_correlation.history import build_generation

INDEX = "atlas_changes"
CHANGE_TYPE = "adm:configuration_change:v1"
FIXTURE_DIR = (
    Path(__file__).parents[2] / "fixtures" / "change-correlation" / "appdynamics"
)


def read_fixture() -> dict:
    return json.loads(
        (FIXTURE_DIR / "audit_history_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires an owned task lab")
class AppDynamicsAuditHistoryInstalledTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        required_environment = (
            "ADM_LAB_TASK",
            "ADM_LAB_NAME",
            "ADM_LAB_WEB_PORT",
            "ADM_LAB_MGMT_PORT",
            "ADM_LAB_HEC_PORT",
            "ADM_LAB_SECRETS",
            "ADM_LAB_EVIDENCE_DIRECTORY",
        )
        missing = [name for name in required_environment if not os.environ.get(name)]
        if missing:
            raise RuntimeError(
                "AppDynamics installed replay requires an allocated task lab and "
                "private evidence directory"
            )
        lab.verify_target()
        cls.key = secrets.token_hex(8)
        cls.evidence_directory = os.environ.get("ADM_LAB_EVIDENCE_DIRECTORY")
        fixture = read_fixture()
        cls.fixture_sha256 = hashlib.sha256(
            (FIXTURE_DIR / "audit_history_documentation_shaped.json").read_bytes()
        ).hexdigest()
        now = int(time.time())
        metadata = copy.deepcopy(fixture["collection_metadata"])
        metadata.update(
            {
                "capture_id": f"appd-{cls.key}-audit",
                "started_at": now - 20,
                "completed_at": now - 19,
                "received_at": now - 18,
                "source_reference": f"synthetic-controller-audit:{cls.key}",
            }
        )
        cls.receipt = adapt_appdynamics_audits(fixture["native_records"], metadata)
        cls.generation = build_generation([cls.receipt])
        cls.manifest = cls.generation["manifest"]
        cls.hec = render_generation_hec(cls.generation, index=INDEX).encode()

        evidence = Path(cls.evidence_directory)
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(evidence, 0o700)
        (evidence / f"appdynamics-source-input-{cls.key}.json").write_text(
            json.dumps(
                {
                    "qualification": "documentation_shaped_synthetic",
                    "fixture_sha256": cls.fixture_sha256,
                    "collections": [cls.receipt],
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (evidence / f"appdynamics-generation-{cls.key}.hec.ndjson").write_bytes(cls.hec)

        cls.ingest_start = int(time.time())
        lab._hec_post(cls.hec)
        cls.indexed = cls.wait_change_rows(len(cls.generation["rows"]))
        cls.rows = verify_readback(
            cls.manifest, [json.loads(row["_raw"]) for row in cls.indexed]
        )

    @classmethod
    def wait_change_rows(cls, expected: int) -> list[dict]:
        deadline = time.monotonic() + 60
        query = (
            f'index={INDEX} sourcetype="{CHANGE_TYPE}" '
            f'generation_id="{cls.manifest["generation_id"]}" | table _raw'
        )
        while time.monotonic() < deadline:
            rows = lab.search(
                query,
                cls.manifest["source_earliest"],
                cls.manifest["source_latest"] + 0.001,
            )
            if len(rows) >= expected:
                return rows
            time.sleep(1)
        raise AssertionError("AppDynamics generation did not reach indexed row count")

    def test_audit_records_are_replayed_as_reported_observations(self) -> None:
        rows = verify_readback(self.manifest, self.rows)

        observations = [
            row
            for row in rows
            if row["record_type"] == "observation"
            and row["product"] == "appdynamics"
            and row["family"] == "audit_log"
        ]
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(row["kind"] == "audit" for row in observations))
        self.assertTrue(all(row["event_at"] is not None for row in observations))
        self.assertTrue(all(row["effective_at"] is None for row in observations))
        self.assertTrue(
            all(
                row["time_qualification"] == "source_event_time_reported"
                for row in observations
            )
        )

    def test_fixture_secrets_and_unprojected_diffs_are_not_indexed(self) -> None:
        search = (
            f'index={INDEX} sourcetype="{CHANGE_TYPE}" '
            f'generation_id="{self.manifest["generation_id"]}" | table _raw'
        )
        rows = lab.search(
            search,
            self.manifest["source_earliest"],
            self.manifest["source_latest"] + 0.001,
        )
        serialized = "\n".join(row["_raw"] for row in rows)
        self.assertNotIn("objectChanges", serialized)
        self.assertNotIn("controller_url", serialized)
        self.assertNotIn("SYNTHETIC_SECRET", serialized)
