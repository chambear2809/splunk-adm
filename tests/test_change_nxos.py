"""Fail-closed tests for the unqualified NX-OS/Nexus Dashboard source path."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.change_correlation.adapters.nxos import adapt_nxos_device_snapshots
from tools.change_correlation.contracts import ContractError
from tools.change_correlation.projections import projection_definition

FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "change-correlation"
    / "nxos"
    / "qualification_gate_v1.json"
)


class NxosQualificationGateTests(unittest.TestCase):
    def test_fixture_is_only_a_synthetic_gate_control(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

        self.assertEqual(fixture["fixture_type"], "qualification_gate")
        self.assertIn("not NX-OS", fixture["provenance"])
        self.assertFalse(fixture["native_records_included"])
        self.assertEqual(
            fixture["projection"]["qualification"],
            "normalized_export_only",
        )
        self.assertTrue(fixture["projection"]["native_sample_unqualified"])
        self.assertEqual(
            fixture["projection"]["adapter_disposition"],
            "native_adapter_blocked_pending_versioned_command_sample",
        )

    def test_normalized_export_projection_remains_registered(self) -> None:
        projection = projection_definition("nxos", "device_snapshot")
        self.assertIsNotNone(projection)
        assert projection is not None
        self.assertEqual(projection.qualification, "normalized_export_only")
        self.assertTrue(projection.native_sample_unqualified)

    def test_empty_collection_cannot_become_a_baseline(self) -> None:
        with self.assertRaises(ContractError) as caught:
            adapt_nxos_device_snapshots([], {})

        self.assertEqual(caught.exception.code, "source_projection_blocked")

    def test_untrusted_raw_or_normalized_looking_records_are_not_read_or_echoed(
        self,
    ) -> None:
        canary = "SYNTHETIC_SECRET_CANARY"
        native_records = [{"fields": {"hostname": canary, "password": canary}}]
        metadata = {"source_version": canary, "authority": canary}

        with self.assertRaises(ContractError) as caught:
            adapt_nxos_device_snapshots(native_records, metadata)

        self.assertEqual(caught.exception.code, "source_projection_blocked")
        self.assertNotIn(canary, str(caught.exception))

    def test_generic_ndo_audit_objects_are_not_mapped_as_nxos_snapshots(self) -> None:
        record = {"auditRecords": [{"id": "synthetic-only"}]}

        with self.assertRaises(ContractError) as caught:
            adapt_nxos_device_snapshots([record], {"family": "ndo_audit"})

        self.assertEqual(caught.exception.code, "source_projection_blocked")


if __name__ == "__main__":
    unittest.main()
