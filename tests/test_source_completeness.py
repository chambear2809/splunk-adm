import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import qualify_source_completeness as source  # noqa: E402


class CompletenessEvidenceTests(unittest.TestCase):
    def setUp(self):
        digest = "a" * 64
        rows = []
        for start, end in source.WINDOWS:
            rows.append(
                {
                    "start": start,
                    "end": end,
                    "expected_population": 10,
                    "indexed_population": 8,
                    "accounted_exclusions": 2,
                    "expected_population_sha256": digest,
                    "observed_population_sha256": digest,
                    "exclusion_evidence_sha256": digest,
                    "producer_dropped": 0,
                    "sampled_out": 0,
                    "indexed_watermark": end + 5,
                    "continuous_receipts": [
                        {"start": start, "end": end, "sha256": digest}
                    ],
                }
            )
        family = {
            "population_method_sha256": digest,
            "producer_receipts_sha256": digest,
            "loss_measurement_sha256": digest,
            "sampling_measurement_sha256": digest,
            "lateness_measurement_sha256": digest,
            "max_lateness_seconds": 5,
            "windows": rows,
        }
        self.doc = {
            "scope": source.SCOPE,
            "producer_id": "uktme-atlas-identity",
            "producer_config_revision": "0b0d18412ba0d8c424ca1d0abe7603612edd66a48a9501eb82d6a288208266fc",
            "catalog_evidence_sha256": digest,
            "families": {
                "identity": copy.deepcopy(family),
                "spans": copy.deepcopy(family),
            },
        }

    def test_consistent_claims_need_independent_review(self):
        result = source.assess(self.doc)
        self.assertEqual(result["status"], "eligible_for_independent_review")
        self.assertFalse(result["qualified"])

    def test_missing_source_or_receipt_gap_remains_incomplete(self):
        self.doc["families"]["identity"]["windows"][0]["continuous_receipts"][0][
            "start"
        ] += 1
        del self.doc["families"]["spans"]["loss_measurement_sha256"]
        gaps = source.assess(self.doc)["gaps"]
        self.assertIn("identity.window_0.continuous_receipts", gaps)
        self.assertIn("spans.loss_measurement", gaps)

    def test_population_exclusions_or_watermark_cannot_be_guessed(self):
        row = self.doc["families"]["spans"]["windows"][0]
        row["accounted_exclusions"] = 1
        row["indexed_watermark"] = row["end"]
        row["sampled_out"] = True
        gaps = source.assess(self.doc)["gaps"]
        self.assertIn("spans.window_0.population", gaps)
        self.assertIn("spans.window_0.watermark", gaps)
        self.assertIn("spans.window_0.loss_sampling", gaps)

    def test_profile_or_scope_mismatch_refused(self):
        self.doc["scope"] = dict(source.SCOPE, namespace="other")
        self.doc["producer_config_revision"] = "0" * 64
        result = source.assess(self.doc)
        self.assertEqual(result["status"], "evidence_insufficient")
        self.assertIn("producer_revision", result["gaps"])
        self.assertIn("scope", result["gaps"])

    def test_no_claim_from_empty_data(self):
        self.assertFalse(source.assess({})["qualified"])
        self.assertEqual(source.assess({})["status"], "evidence_insufficient")
