"""Installed ThousandEyes activity-to-history replay; no TE API is contacted."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import unittest

import lab

from tools.activate_configuration_generation import verify_readback
from tools.change_correlation.adapters.thousandeyes import (
    adapt_thousandeyes_activity_events,
)
from tools.change_correlation.export import render_generation_hec
from tools.change_correlation.history import build_generation

INDEX = "atlas_changes"
CHANGE_TYPE = "adm:configuration_change:v1"
FIXTURE_PATH = (
    Path(__file__).parents[2]
    / "fixtures"
    / "change-correlation"
    / "thousandeyes"
    / "activity_api_documentation_shaped.json"
)


def read_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires an owned task lab")
class ThousandEyesActivityHistoryInstalledTest(unittest.TestCase):
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
                "ThousandEyes installed replay requires an allocated task lab and "
                "private evidence directory"
            )
        lab.verify_target()
        cls.key = secrets.token_hex(8)
        cls.evidence_directory = os.environ["ADM_LAB_EVIDENCE_DIRECTORY"]
        fixture = read_fixture()
        cls.fixture_sha256 = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
        now = int(time.time())
        metadata = dict(fixture["collection_metadata"])
        metadata.update(
            {
                "capture_id": f"te-{cls.key}-activity",
                "started_at": now - 20,
                "completed_at": now - 19,
                "received_at": now - 18,
                "source_reference": f"thousandeyes:api:v7:audit-user-events;synthetic:{cls.key}",
            }
        )
        cls.receipt = adapt_thousandeyes_activity_events(
            fixture["native_records"], metadata
        )
        cls.generation = build_generation([cls.receipt])
        cls.manifest = cls.generation["manifest"]
        cls.hec = render_generation_hec(cls.generation, index=INDEX).encode("utf-8")

        evidence = Path(cls.evidence_directory)
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(evidence, 0o700)
        (evidence / f"thousandeyes-source-input-{cls.key}.json").write_text(
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
        (evidence / f"thousandeyes-generation-{cls.key}.hec.ndjson").write_bytes(
            cls.hec
        )

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
        raise AssertionError(
            "ThousandEyes activity generation did not reach indexed row count"
        )

    def test_activity_is_replayed_as_context_only_audit(self) -> None:
        rows = verify_readback(self.manifest, self.rows)

        observations = [
            row
            for row in rows
            if row["record_type"] == "observation"
            and row["product"] == "thousandeyes"
            and row["family"] == "activity_log"
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["kind"], "audit")
        self.assertEqual(observations[0]["event_at"], 1793102400.125)
        self.assertIsNone(observations[0]["effective_at"])
        self.assertTrue(observations[0]["context_only"])
        self.assertEqual(observations[0]["attributes"]["resource_type"], "testName")

    def test_user_email_ip_and_unprojected_values_are_not_indexed(self) -> None:
        query = (
            f'index={INDEX} sourcetype="{CHANGE_TYPE}" '
            f'generation_id="{self.manifest["generation_id"]}" | table _raw'
        )
        rows = lab.search(
            query,
            self.manifest["source_earliest"],
            self.manifest["source_latest"] + 0.001,
        )
        serialized = "\n".join(row["_raw"] for row in rows)
        for omitted in (
            "synthetic@example.invalid",
            "192.0.2.20",
            "Synthetic Account Group",
            "accountGroupName",
            "ipAddress",
        ):
            self.assertNotIn(omitted, serialized)


if __name__ == "__main__":
    unittest.main()
