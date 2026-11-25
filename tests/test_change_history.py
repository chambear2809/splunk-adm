"""Normalized configuration evidence and deterministic history tests."""

from __future__ import annotations

import hashlib
import copy
import math
import unittest

from tools.change_correlation.contracts import (
    ContractError,
    canonical_json,
    normalize_collection,
    sha256_hex,
)
from tools.change_correlation.history import build_generation, row_record_id


def service_object(
    object_id: str = "service:payments",
    *,
    fields: dict | None = None,
    revision: str | None = None,
    observed_at: int = 1_010,
) -> dict:
    return {
        "object_id": object_id,
        "revision": revision,
        "observed_at": observed_at,
        "event_at": None,
        "effective_at": None,
        "kind": "configuration",
        "actor": None,
        "fields": fields
        if fields is not None
        else {
            "service_type": "ClusterIP",
            "selector_keys": ["app", "tier"],
            "port_numbers": [80, 443],
            "target_ports": ["http", "https"],
            "protocols": ["TCP", "TCP"],
            "external_traffic_policy": "Cluster",
            "internal_traffic_policy": "Cluster",
        },
    }


def collection(
    capture_id: str,
    start: int,
    *,
    completed: int | None = None,
    received: int | None = None,
    objects: list[dict] | None = None,
    permissions: str | None = "perm-a",
    status: str = "complete",
    pages_expected: int = 1,
    pages_received: int | None = None,
    enumeration: str = "full",
    deletions_authoritative: bool = True,
    source_version: str = "1.0",
    family: str = "service_snapshot",
    product: str = "kubernetes",
) -> dict:
    if completed is None and status == "complete":
        completed = start + 10
    if received is None:
        received = (completed if completed is not None else start) + 1
    if pages_received is None:
        pages_received = (
            pages_expected if status == "complete" else max(0, pages_expected - 1)
        )
    return {
        "schema_version": 1,
        "capture_id": capture_id,
        "product": product,
        "authority": "cluster:prod-east",
        "source_version": source_version,
        "family": family,
        "partition": "cluster-prod-east",
        "scope": "prod-east",
        "started_at": start,
        "completed_at": completed,
        "received_at": received,
        "status": status,
        "permissions_fingerprint": permissions,
        "pages_expected": pages_expected,
        "pages_received": pages_received,
        "source_reference": f"snapshot:{capture_id}",
        "enumeration": enumeration,
        "deletions_authoritative": deletions_authoritative,
        "objects": objects or [],
    }


class CanonicalJsonTests(unittest.TestCase):
    def test_bounded_decimal_unicode_and_hash_golden_vector(self) -> None:
        value = {
            "z": "é🛰",
            "fraction": 1.25,
            "whole_float": 1.0,
            "negative_zero": -0.0,
        }
        self.assertEqual(
            canonical_json(value),
            '{"fraction":1.25,"negative_zero":0,"whole_float":1,"z":"é🛰"}'.encode(),
        )
        self.assertEqual(
            sha256_hex(value),
            "f2ce3379e3cf28b6820ff6ddcb277b746b48e2342a67bbe7daa7f768c29650f5",
        )
        self.assertEqual(canonical_json(1.001), b"1.001")
        self.assertEqual(canonical_json(1_792_400_000.001), b"1792400000.001")

    def test_rejects_unsupported_precision_nonfinite_and_non_ascii_keys(self) -> None:
        for value in (
            1e-6,
            1.0000000001,
            0.0000000001,
            math.nan,
            math.inf,
            {"é": "not a contract key"},
        ):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ContractError):
                    canonical_json(value)


class CollectionContractTests(unittest.TestCase):
    def test_complete_receipt_requires_pages_partition_and_permissions(self) -> None:
        raw = collection("cap", 1, objects=[])
        raw["permissions_fingerprint"] = None
        with self.assertRaisesRegex(ContractError, "permission fingerprint"):
            normalize_collection(raw)
        raw = collection("cap", 1, objects=[])
        raw["pages_received"] = 0
        with self.assertRaisesRegex(ContractError, "every page"):
            normalize_collection(raw)

    def test_unknown_projection_fields_and_nested_payloads_are_rejected(self) -> None:
        raw = collection("cap", 1, objects=[service_object(fields={"details": "raw"})])
        with self.assertRaisesRegex(ContractError, "unreviewed field"):
            normalize_collection(raw)
        raw = collection(
            "cap",
            1,
            objects=[service_object(fields={"service_type": {"raw": "data"}})],
        )
        with self.assertRaisesRegex(ContractError, "must be text"):
            normalize_collection(raw)

    def test_normalized_text_rejects_urls_and_secret_markers(self) -> None:
        raw = collection(
            "cap",
            1,
            objects=[service_object(fields={"service_type": "https://vendor.invalid"})],
        )
        with self.assertRaisesRegex(ContractError, "disallowed value"):
            normalize_collection(raw)

    def test_authority_accepts_only_canonical_https_origins_as_urls(self) -> None:
        raw = collection("cap", 1, objects=[])
        raw["authority"] = "https://cc-a-fmc.example.invalid"
        self.assertEqual(
            normalize_collection(raw)["authority"],
            "https://cc-a-fmc.example.invalid",
        )
        for authority in (
            "https://user:password@cc-a-fmc.example.invalid",
            "https://cc-a-fmc.example.invalid/admin",
            "https://cc-a-fmc.example.invalid?token=x",
            "http://cc-a-fmc.example.invalid",
            "https://cc-a-fmc.example.invalid/",
        ):
            with self.subTest(authority=authority):
                invalid = collection("cap", 1, objects=[])
                invalid["authority"] = authority
                with self.assertRaises(ContractError):
                    normalize_collection(invalid)

        invalid = collection("cap", 1, objects=[])
        invalid["source_reference"] = "https://vendor.invalid/record/1"
        with self.assertRaisesRegex(ContractError, "disallowed value"):
            normalize_collection(invalid)
        invalid["source_reference"] = "vendor.invalid/record/1"
        with self.assertRaisesRegex(ContractError, "must not contain a URL"):
            normalize_collection(invalid)

    def test_source_family_restricts_semantic_kind(self) -> None:
        raw = collection(
            "cap",
            1,
            family="device_snapshot",
            product="nxos",
            objects=[
                {
                    "object_id": "switch-1",
                    "observed_at": 1_010,
                    "kind": "configuration",
                    "fields": {"hostname": "switch-1"},
                }
            ],
        )
        with self.assertRaisesRegex(
            ContractError, "not allowed for this reviewed projection"
        ):
            normalize_collection(raw)

    def test_partial_duplicate_page_objects_are_deduplicated(self) -> None:
        obj = service_object(observed_at=1_005)
        raw = collection(
            "cap",
            1_000,
            completed=1_010,
            status="partial",
            pages_expected=2,
            pages_received=1,
            objects=[obj, obj],
        )
        normalized = normalize_collection(raw)
        self.assertEqual(len(normalized["objects"]), 1)


class ProjectionSetSemanticsTests(unittest.TestCase):
    def test_reviewed_backend_uid_sets_are_sorted_and_deduplicated(self):
        obj = service_object(fields={"ready_backend_uids": ["pod-b", "pod-a", "pod-a"]})
        obj["kind"] = "operational"
        raw = collection("cap", 1, family="endpointslice_snapshot", objects=[obj])
        normalized = normalize_collection(raw)
        self.assertEqual(
            normalized["objects"][0]["fields"]["ready_backend_uids"],
            ["pod-a", "pod-b"],
        )

    def test_ordered_parallel_port_arrays_keep_their_order(self):
        obj = service_object(fields={"port_numbers": [443, 80]})
        normalized = normalize_collection(collection("cap", 1, objects=[obj]))
        self.assertEqual(normalized["objects"][0]["fields"]["port_numbers"], [443, 80])


class HistoryGenerationTests(unittest.TestCase):
    def test_capture_ids_are_qualified_by_authority_and_scope(self):
        first = collection("shared-capture", 1000, objects=[service_object()])
        for field in ("authority", "scope", "partition"):
            with self.subTest(field=field):
                second = copy.deepcopy(first)
                second[field] = "independent-domain"
                result = build_generation([first, second])
                self.assertEqual(len(result["receipts"]), 2)
                self.assertEqual(len(result["rows"]), 2)
                self.assertEqual(len(result["manifest"]["source_receipt_hashes"]), 2)

    def test_public_builder_stops_at_collection_limit(self) -> None:
        calls = 0

        def unbounded():
            nonlocal calls
            while True:
                calls += 1
                yield collection(f"capture-{calls}", calls * 10, objects=[])

        with self.assertRaisesRegex(ContractError, "10,000-collection limit"):
            build_generation(unbounded())
        self.assertEqual(calls, 10_001)

    def test_unchanged_polls_preserve_receipts_without_inflating_rows(self) -> None:
        first = collection("cap-1", 1_000, objects=[service_object(observed_at=1_010)])
        second = collection("cap-2", 1_020, objects=[service_object(observed_at=1_030)])
        generation = build_generation([second, first])
        self.assertEqual(len(generation["receipts"]), 2)
        self.assertEqual(generation["manifest"]["row_count"], 1)
        self.assertEqual(generation["rows"][0]["record_type"], "baseline")

    def test_changed_snapshot_has_conservative_interval_and_allowlisted_diff(
        self,
    ) -> None:
        before = service_object(observed_at=1_010)
        after_fields = dict(before["fields"])
        after_fields["service_type"] = "LoadBalancer"
        after = service_object(fields=after_fields, observed_at=1_030)
        generation = build_generation(
            [
                collection("cap-1", 1_000, objects=[before]),
                collection("cap-2", 1_020, objects=[after]),
            ]
        )
        modified = [
            row for row in generation["rows"] if row["change_type"] == "modified"
        ]
        self.assertEqual(len(modified), 1)
        row = modified[0]
        self.assertEqual((row["earliest_at"], row["latest_at"]), (1_000, 1_030))
        self.assertEqual(row["event_at"], None)
        self.assertEqual(row["effective_at"], None)
        self.assertEqual(row["field_diffs"][0]["field"], "service_type")
        self.assertEqual(row["field_diffs"][0]["before"], "ClusterIP")
        self.assertEqual(row["field_diffs"][0]["after"], "LoadBalancer")
        self.assertEqual(row["field_diffs"][0]["before_present"], True)
        self.assertEqual(
            row["record_id"],
            row_record_id(
                {
                    k: v
                    for k, v in row.items()
                    if k not in {"record_id", "generation_id"}
                }
            ),
        )

    def test_reordered_allowlisted_array_is_a_semantic_change(self) -> None:
        before = service_object(fields={"port_numbers": [80, 443]})
        after = service_object(fields={"port_numbers": [443, 80]}, observed_at=1_030)
        generation = build_generation(
            [
                collection("cap-1", 1_000, objects=[before]),
                collection("cap-2", 1_020, objects=[after]),
            ]
        )
        changed = next(
            row for row in generation["rows"] if row["change_type"] == "modified"
        )
        self.assertEqual(changed["field_diffs"][0]["before"], [80, 443])
        self.assertEqual(changed["field_diffs"][0]["after"], [443, 80])

    def test_permission_a_to_b_to_a_never_compares_old_a_state(self) -> None:
        base = service_object()
        changed = service_object(fields={"service_type": "LoadBalancer"})
        rows = build_generation(
            [
                collection("a1", 1_000, objects=[base], permissions="perm-a"),
                collection("b1", 1_020, objects=[changed], permissions="perm-b"),
                collection("a2", 1_040, objects=[base], permissions="perm-a"),
            ]
        )["rows"]
        self.assertFalse(any(row["record_type"] == "change" for row in rows))
        self.assertEqual(sum(row["record_type"] == "baseline" for row in rows), 3)
        self.assertEqual(
            sum(row["change_type"] == "permissions_changed" for row in rows), 2
        )

    def test_partial_and_overlapping_receipts_block_ordered_diffs(self) -> None:
        before = service_object()
        after = service_object(
            fields={"service_type": "LoadBalancer"}, observed_at=1_035
        )
        partial = collection(
            "partial",
            1_020,
            completed=1_030,
            status="partial",
            pages_expected=2,
            pages_received=1,
            objects=[after],
        )
        after_collection = collection("cap-2", 1_040, objects=[after])
        rows = build_generation(
            [collection("cap-1", 1_000, objects=[before]), partial, after_collection]
        )["rows"]
        self.assertFalse(any(row["record_type"] == "change" for row in rows))
        self.assertTrue(any(row["change_type"] == "partial_collection" for row in rows))

        overlapping = collection("overlap", 1_005, completed=1_015, objects=[after])
        rows = build_generation(
            [collection("first", 1_000, completed=1_010, objects=[before]), overlapping]
        )["rows"]
        self.assertFalse(any(row["record_type"] == "change" for row in rows))
        self.assertTrue(
            any(row["change_type"] == "overlapping_collection" for row in rows)
        )

    def test_long_interval_resets_baseline(self) -> None:
        before = service_object()
        after = service_object(
            fields={"service_type": "LoadBalancer"}, observed_at=87_410
        )
        rows = build_generation(
            [
                collection("cap-1", 1_000, completed=1_010, objects=[before]),
                collection("cap-2", 87_400, completed=87_410, objects=[after]),
            ]
        )["rows"]
        self.assertFalse(any(row["record_type"] == "change" for row in rows))
        gap = next(row for row in rows if row["change_type"] == "comparison_gap")
        self.assertEqual((gap["earliest_at"], gap["latest_at"]), (1_000, 87_410))

    def test_removal_requires_successive_full_authoritative_enumerations(self) -> None:
        before = collection("cap-1", 1_000, objects=[service_object()])
        incremental = collection("cap-2", 1_020, objects=[], enumeration="incremental")
        full = collection("cap-3", 1_040, objects=[])
        no_removal = build_generation([before, incremental])["rows"]
        self.assertFalse(any(row["change_type"] == "removed" for row in no_removal))
        removal = build_generation([before, full])["rows"]
        removed = next(row for row in removal if row["change_type"] == "removed")
        self.assertEqual(
            removed["qualification"], "authoritative_full_enumeration_interval"
        )

    def test_exact_capture_replay_is_idempotent_and_conflict_fails_closed(self) -> None:
        receipt = collection("same", 1_000, objects=[service_object()])
        first = build_generation([receipt])
        replay = build_generation([receipt, receipt])
        self.assertEqual(
            first["manifest"]["generation_id"], replay["manifest"]["generation_id"]
        )
        conflict = collection("same", 1_000, received=1_012, objects=[service_object()])
        with self.assertRaisesRegex(ContractError, "conflicting receipt content"):
            build_generation([receipt, conflict])

    def test_conflicting_native_revision_is_rejected(self) -> None:
        before = service_object(revision="rv1")
        after_fields = dict(before["fields"])
        after_fields["service_type"] = "LoadBalancer"
        after = service_object(revision="rv1", fields=after_fields, observed_at=1_030)
        with self.assertRaisesRegex(ContractError, "same native revision"):
            build_generation(
                [
                    collection("cap-1", 1_000, objects=[before]),
                    collection("cap-2", 1_020, objects=[after]),
                ]
            )

    def test_audit_observation_replay_deduplicates_without_losing_unknown_times(
        self,
    ) -> None:
        def audit(capture_id: str, start: int, observed_at: int) -> dict:
            return collection(
                capture_id,
                start,
                family="aaa_mod_lr",
                product="aci",
                objects=[
                    {
                        "object_id": "audit:tx-1",
                        "observed_at": observed_at,
                        "event_at": None,
                        "effective_at": None,
                        "kind": "audit",
                        "actor": "user-7",
                        "fields": {
                            "affected_dn": "uni/tn-demo",
                            "event_code": "APIC_MOD",
                        },
                    }
                ],
            )

        generation = build_generation(
            [audit("cap-1", 1_000, 1_010), audit("cap-2", 1_020, 1_030)]
        )
        observations = [
            row for row in generation["rows"] if row["record_type"] == "observation"
        ]
        self.assertEqual(len(observations), 1)
        self.assertIsNone(observations[0]["event_at"])
        self.assertIsNone(observations[0]["effective_at"])
        self.assertEqual(observations[0]["observed_at"], 1_010)
        self.assertEqual(
            observations[0]["projection_qualification"], "normalized_export_only"
        )

    def test_context_only_source_is_static_and_nxos_cannot_claim_configuration(
        self,
    ) -> None:
        te = collection(
            "te",
            1_000,
            family="activity_log",
            product="thousandeyes",
            objects=[
                {
                    "object_id": "event-1",
                    "observed_at": 1_010,
                    "kind": "audit",
                    "fields": {"event_name": "Alert", "account_id": "acct-1"},
                }
            ],
        )
        row = build_generation([te])["rows"][0]
        self.assertTrue(row["native_sample_unqualified"])
        self.assertTrue(row["context_only"])

    def test_row_and_manifest_hashes_are_independently_verifiable(self) -> None:
        generation = build_generation(
            [collection("cap", 1_000, objects=[service_object()])]
        )
        manifest = generation["manifest"]
        self.assertEqual(
            manifest["rows_sha256"],
            hashlib.sha256(
                canonical_json(
                    {
                        k: v
                        for k, v in generation["rows"][0].items()
                        if k != "generation_id"
                    }
                )
            ).hexdigest(),
        )
        manifest_body = {
            key: value for key, value in manifest.items() if key != "generation_id"
        }
        self.assertEqual(manifest["generation_id"], sha256_hex(manifest_body))


if __name__ == "__main__":
    unittest.main()
