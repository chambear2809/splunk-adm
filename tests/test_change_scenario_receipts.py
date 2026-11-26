from __future__ import annotations

import unittest

from tools.change_scenario_receipts import (
    ReceiptContractError,
    build_expected_receipt_manifest,
    verify_physical_readback,
)
from tools.change_scenario_receipts import _sha
from tools.change_scenarios_v2 import load_scenario
from tools.raw_fixtures.change_scenarios_v2 import prepare_source_inputs


class ReceiptManifestTests(unittest.TestCase):
    def test_both_tracks_build_offline_manifest_without_index_claim(self):
        for scenario_id in ("track-a-firewall", "track-b-fabric"):
            manifest = build_expected_receipt_manifest(
                scenario_id,
                execution_id="00000000-0000-4000-8000-000000000071",
                anchor_epoch=1_900_000_200,
            )
            self.assertTrue(manifest["entries"])
            self.assertFalse(manifest["indexed"])

    def test_physical_readback_requires_identity_fields_and_exact_selector(self):
        manifest = build_expected_receipt_manifest(
            "track-b-fabric",
            variant_id="b-aci-attachment",
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        entry = manifest["entries"][0]
        row = {
            **entry,
            "event": next(
                event["event"]
                for event in __import__(
                    "tools.raw_fixtures.change_scenarios_v2",
                    fromlist=["prepare_source_inputs"],
                ).prepare_source_inputs(
                    __import__(
                        "tools.change_scenarios_v2", fromlist=["load_scenario"]
                    ).load_scenario("track-b-fabric", "b-aci-attachment"),
                    execution_id=manifest["execution_id"],
                    anchor_epoch=manifest["anchor_epoch"],
                )["events"]
                if event["id"] == entry["event_id"]
                for event in event["raw_events"]
            ),
            "_bkt": "bucket",
            "_cd": "ctx",
            "_indextime": 1900000201,
        }
        with self.assertRaises(ReceiptContractError):
            verify_physical_readback(
                manifest, [row], expected_manifest_sha256=_sha(manifest)
            )

    def test_full_readback_binds_source_identity_and_timestamp(self):
        scenario = load_scenario("track-b-fabric", "b-aci-attachment")
        inputs = prepare_source_inputs(
            scenario,
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        manifest = build_expected_receipt_manifest(
            "track-b-fabric",
            variant_id="b-aci-attachment",
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        raw = [
            event for item in inputs["events"] for event in item.get("raw_events", [])
        ]
        rows = []
        for index, (entry, event) in enumerate(
            zip(manifest["entries"], raw, strict=True)
        ):
            rows.append(
                {
                    **event,
                    "_bkt": f"bucket-{index}",
                    "_cd": f"context-{index}",
                    "_indextime": 1900000201 + index,
                    "_time": entry["source_time"],
                }
            )
        result = verify_physical_readback(
            manifest, rows, expected_manifest_sha256=_sha(manifest)
        )
        self.assertTrue(result["complete"])
        self.assertTrue(result["indexed"])
        rows[0]["time"] = rows[0]["_time"]
        rows[0]["_time"] = rows[0]["_time"] + 1
        with self.assertRaises(ReceiptContractError):
            verify_physical_readback(
                manifest, rows, expected_manifest_sha256=_sha(manifest)
            )
        rows[0]["_time"] = manifest["entries"][0]["source_time"]
        rows[1]["_bkt"] = rows[0]["_bkt"]
        rows[1]["_cd"] = rows[0]["_cd"]
        with self.assertRaises(ReceiptContractError):
            verify_physical_readback(
                manifest, rows, expected_manifest_sha256=_sha(manifest)
            )

    def test_nonfinite_index_time_is_rejected(self):
        manifest = build_expected_receipt_manifest(
            "track-b-fabric",
            variant_id="b-aci-attachment",
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        scenario = load_scenario("track-b-fabric", "b-aci-attachment")
        inputs = prepare_source_inputs(
            scenario,
            execution_id=manifest["execution_id"],
            anchor_epoch=manifest["anchor_epoch"],
        )
        raw = [
            event for item in inputs["events"] for event in item.get("raw_events", [])
        ]
        rows = []
        for index, (entry, event) in enumerate(
            zip(manifest["entries"], raw, strict=True)
        ):
            rows.append(
                {
                    **event,
                    "_bkt": f"bucket-{index}",
                    "_cd": f"context-{index}",
                    "_indextime": 1900000201 + index,
                    "_time": entry["source_time"],
                }
            )
        rows[0]["_indextime"] = float("inf")
        with self.assertRaises(ReceiptContractError):
            verify_physical_readback(
                manifest, rows, expected_manifest_sha256=_sha(manifest)
            )
