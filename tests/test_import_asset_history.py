"""Historical asset import validation and deterministic HEC envelope tests."""

from __future__ import annotations

import json
from pathlib import Path
import os
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.import_asset_history import (
    BatchImportError,
    find_conflicts,
    main,
    normalize_record,
    prepare,
    render_ndjson,
    _atomic_write,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/inventory"


class AssetHistoryImportTests(unittest.TestCase):
    def test_historical_fixture_renders_sorted_deterministic_hec_events(self) -> None:
        records, manifest, input_count, duplicates = prepare(FIXTURES / "history.json")
        self.assertEqual(manifest["authority"], "cmdb-prod")
        self.assertEqual(input_count, 3)
        self.assertEqual(duplicates, 0)
        output = render_ndjson(records)
        self.assertEqual(output, render_ndjson(records))
        lines = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(len(lines), 3)
        self.assertTrue(
            all(line["sourcetype"] == "adm:asset_history" for line in lines)
        )
        self.assertTrue(all(line["source"] == "asset_history" for line in lines))
        web_a = next(
            line["event"]
            for line in lines
            if line["event"]["asset_id"] == "asset-web-a"
        )
        self.assertEqual(web_a["valid_from"], 1792483200)
        self.assertEqual(web_a["valid_to"], 1792569600)
        self.assertEqual(web_a["validity_basis"], "source_interval")
        self.assertEqual(web_a["environment"], "production")
        self.assertEqual(web_a["owner_id"], "team-commerce")
        self.assertEqual(web_a["owner_name"], "Commerce Platform")
        self.assertEqual(web_a["network_id"], "vpc-prod-east")
        self.assertEqual(
            web_a["record_fingerprint"],
            __import__("hashlib")
            .sha256(
                json.dumps(
                    {
                        key: value
                        for key, value in web_a.items()
                        if key != "record_fingerprint"
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            .hexdigest(),
        )

    def test_address_reuse_and_scope_separation_are_not_conflicts(self) -> None:
        rows, _, _, _ = prepare(FIXTURES / "history.json")
        conflicts, count = find_conflicts(rows)
        self.assertEqual(conflicts, [])
        self.assertEqual(count, 0)

    def test_overlapping_distinct_assets_report_conflict_but_other_scope_isolated(
        self,
    ) -> None:
        rows, _, _, _ = prepare(FIXTURES / "owner-conflict.json")
        conflicts, count = find_conflicts(rows)
        self.assertEqual(count, 1)
        self.assertEqual(conflicts[0]["scope"], "prod-east")
        self.assertEqual(conflicts[0]["ip"], "10.20.0.40")
        self.assertEqual(conflicts[0]["asset_ids"], ["asset-a", "asset-b"])
        self.assertEqual(conflicts[0]["from"], 1792627200)
        self.assertEqual(conflicts[0]["to"], 1792713600)

    def test_same_asset_with_overlapping_owner_or_service_disagreement_conflicts(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "context-conflict.json"
            base = {
                "record_id": "a",
                "revision": 1,
                "asset_id": "same-asset",
                "scope": "prod",
                "ip": "10.0.0.9",
                "validity_basis": "source_interval",
                "valid_from": 10,
                "valid_to": 30,
                "owner_id": "team-a",
                "service_id": "service-a",
            }
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": 40,
                        "snapshot_complete": True,
                        "records": [
                            base,
                            {
                                **base,
                                "record_id": "b",
                                "owner_id": "team-b",
                                "service_id": "service-b",
                            },
                        ],
                    }
                )
            )
            rows, _, _, _ = prepare(path)
            conflicts, count = find_conflicts(rows)
            self.assertEqual(count, 1)
            self.assertEqual(conflicts[0]["asset_ids"], ["same-asset"])
            self.assertEqual(
                {
                    (entry["asset_id"], entry["field"])
                    for entry in conflicts[0]["context_conflicts"]
                },
                {("same-asset", "owner_id"), ("same-asset", "service_id")},
            )

    def test_half_open_adjacent_intervals_do_not_conflict(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "adjacent.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": "2026-10-23T12:00:00Z",
                        "snapshot_complete": True,
                        "records": [
                            {
                                "record_id": "a",
                                "asset_id": "a",
                                "scope": "prod",
                                "ip": "10.0.0.1",
                                "validity_basis": "source_interval",
                                "valid_from": 10,
                                "valid_to": 20,
                            },
                            {
                                "record_id": "b",
                                "asset_id": "b",
                                "scope": "prod",
                                "ip": "10.0.0.1",
                                "validity_basis": "source_interval",
                                "valid_from": 20,
                                "valid_to": 30,
                            },
                        ],
                    }
                )
            )
            rows, _, _, _ = prepare(path)
            self.assertEqual(find_conflicts(rows), ([], 0))

    def test_conflicts_use_latest_revision_but_keep_all_revisions_exportable(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "revisions.json"
            common = {
                "asset_id": "asset-a",
                "scope": "prod",
                "ip": "10.0.0.1",
                "validity_basis": "source_interval",
                "valid_from": 10,
            }
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": 100,
                        "snapshot_complete": True,
                        "records": [
                            {
                                **common,
                                "record_id": "assignment-a",
                                "revision": 1,
                            },
                            {
                                **common,
                                "record_id": "assignment-a",
                                "revision": 2,
                                "valid_to": 20,
                            },
                            {
                                "record_id": "assignment-b",
                                "revision": 1,
                                "asset_id": "asset-b",
                                "scope": "prod",
                                "ip": "10.0.0.1",
                                "validity_basis": "source_interval",
                                "valid_from": 30,
                                "valid_to": 40,
                            },
                        ],
                    }
                )
            )
            rows, _, input_count, _ = prepare(path)
            self.assertEqual(input_count, 3)
            self.assertEqual(len(rows), 3)
            self.assertEqual(find_conflicts(rows), ([], 0))

    def test_equal_latest_revision_disagreement_is_reported(self) -> None:
        manifest = {
            "authority": "cmdb-prod",
            "snapshot_id": "s1",
            "snapshot_at": 100,
            "snapshot_complete": True,
        }
        base = {
            "record_id": "same-revision",
            "revision": 3,
            "asset_id": "asset-a",
            "scope": "prod",
            "ip": "10.0.0.1",
            "validity_basis": "source_interval",
            "valid_from": 10,
            "valid_to": 90,
        }
        first = normalize_record(base, manifest, 1)
        sibling = normalize_record({**base, "scope": "prod-west"}, manifest, 2)
        conflicts, count = find_conflicts([first, sibling])
        self.assertEqual(count, 1)
        self.assertEqual(conflicts[0]["kind"], "same_revision_disagreement")
        self.assertEqual(conflicts[0]["record_id"], "same-revision")
        self.assertEqual(conflicts[0]["candidate_count"], 2)

    def test_open_interval_conflicts_stop_at_snapshot_time(self) -> None:
        first = normalize_record(
            {
                "record_id": "observed-open",
                "revision": 1,
                "asset_id": "asset-a",
                "scope": "prod",
                "ip": "10.0.0.1",
                "validity_basis": "source_interval",
                "valid_from": 10,
            },
            {
                "authority": "cmdb-prod",
                "snapshot_id": "s1",
                "snapshot_at": 20,
                "snapshot_complete": True,
            },
            1,
        )
        later = normalize_record(
            {
                "record_id": "future-claim",
                "revision": 1,
                "asset_id": "asset-b",
                "scope": "prod",
                "ip": "10.0.0.1",
                "validity_basis": "source_interval",
                "valid_from": 30,
                "valid_to": 40,
            },
            {
                "authority": "cmdb-prod",
                "snapshot_id": "s2",
                "snapshot_at": 40,
                "snapshot_complete": True,
            },
            2,
        )
        self.assertEqual(find_conflicts([first, later]), ([], 0))

    def test_observed_interval_cannot_begin_after_its_snapshot(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "future-valid-from.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": 20,
                        "snapshot_complete": True,
                        "records": [
                            {
                                "record_id": "future",
                                "asset_id": "asset-future",
                                "scope": "prod",
                                "ip": "10.0.0.1",
                                "validity_basis": "source_interval",
                                "valid_from": 30,
                            }
                        ],
                    }
                )
            )
            with self.assertRaises(BatchImportError) as error:
                prepare(path)
            self.assertEqual(error.exception.errors[0]["code"], "future_valid_from")

    def test_snapshot_only_record_is_point_context_not_a_history_interval(self) -> None:
        rows, _, _, _ = prepare(FIXTURES / "current-snapshot.csv")
        event = rows[0]["event"]
        self.assertEqual(event["validity_basis"], "snapshot_current")
        self.assertEqual(event["valid_from"], event["snapshot_at"])
        self.assertNotIn("valid_to", event)
        self.assertNotIn("retired_at", event)
        self.assertEqual(event["owner_id"], "team-commerce")
        self.assertEqual(event["network_id"], "vpc-prod-east")

    def test_owner_display_name_requires_a_stable_owner_id(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unstable-owner.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": 100,
                        "snapshot_complete": True,
                        "records": [
                            {
                                "record_id": "r1",
                                "asset_id": "asset-1",
                                "owner_name": "Commerce Platform",
                                "scope": "prod",
                                "ip": "10.0.0.1",
                                "validity_basis": "source_interval",
                                "valid_from": 10,
                            }
                        ],
                    }
                )
            )
            with self.assertRaises(BatchImportError) as error:
                prepare(path)
            self.assertEqual(error.exception.errors[0]["code"], "owner_identity")

    def test_explicit_retirement_must_equal_exclusive_valid_to(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "retired.json"
            data = {
                "schema_version": 1,
                "authority": "cmdb-prod",
                "snapshot_id": "s1",
                "snapshot_at": "2026-10-23T12:00:00Z",
                "snapshot_complete": True,
                "records": [
                    {
                        "record_id": "retired-1",
                        "asset_id": "asset-1",
                        "scope": "prod",
                        "ip": "10.0.0.1",
                        "validity_basis": "source_interval",
                        "valid_from": "2026-10-20T00:00:00Z",
                        "valid_to": "2026-10-22T00:00:00Z",
                        "retired_at": "2026-10-22T00:00:00Z",
                    }
                ],
            }
            path.write_text(json.dumps(data))
            rows, _, _, _ = prepare(path)
            self.assertEqual(
                rows[0]["event"]["retired_at"], rows[0]["event"]["valid_to"]
            )
            data["records"][0]["retired_at"] = "2026-10-21T00:00:00Z"
            path.write_text(json.dumps(data))
            with self.assertRaises(BatchImportError):
                prepare(path)

    def test_invalid_records_fail_closed_and_report_the_row(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": "2026-10-23T12:00:00Z",
                        "snapshot_complete": False,
                        "records": [
                            {
                                "record_id": "bad-ip",
                                "asset_id": "asset-1",
                                "scope": "prod",
                                "ip": "example.test",
                                "validity_basis": "source_interval",
                                "valid_from": "2026-10-20T00:00:00Z",
                            }
                        ],
                    }
                )
            )
            with self.assertRaises(BatchImportError) as error:
                prepare(path)
            self.assertEqual(error.exception.errors[0]["code"], "invalid_ip")
            self.assertEqual(error.exception.errors[0]["row"], 1)

    def test_zone_qualified_ipv6_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "zone-ip.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": 100,
                        "snapshot_complete": True,
                        "records": [
                            {
                                "record_id": "link-local",
                                "asset_id": "asset-1",
                                "scope": "prod",
                                "ip": "fe80::1%eth0",
                                "validity_basis": "source_interval",
                                "valid_from": 10,
                            }
                        ],
                    }
                )
            )
            with self.assertRaises(BatchImportError) as error:
                prepare(path)
            self.assertEqual(error.exception.errors[0]["code"], "invalid_ip")

    def test_duplicate_record_revision_conflict_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            record = {
                "record_id": "same",
                "revision": 1,
                "asset_id": "asset-1",
                "scope": "prod",
                "ip": "10.0.0.1",
                "validity_basis": "source_interval",
                "valid_from": 10,
            }
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "authority": "cmdb-prod",
                        "snapshot_id": "s1",
                        "snapshot_at": 100,
                        "snapshot_complete": False,
                        "records": [record, {**record, "ip": "10.0.0.2"}],
                    }
                )
            )
            with self.assertRaises(BatchImportError):
                prepare(path)

    def test_cli_writes_ndjson_and_validation_report_without_overwriting(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "assets.ndjson"
            report = Path(directory) / "assets.report.json"
            result = main(
                [
                    str(FIXTURES / "history.json"),
                    "--output",
                    str(output),
                    "--report",
                    str(report),
                ]
            )
            self.assertEqual(result, 0)
            self.assertEqual(len(output.read_text().splitlines()), 3)
            report_value = json.loads(report.read_text())
            self.assertEqual(report_value["accepted_records"], 3)
            self.assertFalse(report_value["conflicts"])
            output.write_text("keep-me")
            result = main(
                [
                    str(FIXTURES / "history.json"),
                    "--output",
                    str(output),
                    "--report",
                    str(Path(directory) / "second-report.json"),
                ]
            )
            self.assertEqual(result, 1)
            self.assertEqual(output.read_text(), "keep-me")

    def test_fail_on_conflict_writes_report_without_ndjson(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "assets.ndjson"
            report = Path(directory) / "assets.report.json"
            result = main(
                [
                    str(FIXTURES / "owner-conflict.json"),
                    "--output",
                    str(output),
                    "--report",
                    str(report),
                    "--fail-on-conflict",
                ]
            )
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(report.read_text())["conflict_count"], 1)

    def test_non_overwrite_publication_is_exclusive_under_a_race(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "assets.ndjson"
            link = os.link

            def competing_writer(source: str, destination: Path) -> None:
                Path(destination).write_text("winner", encoding="utf-8")
                link(source, destination)

            with patch(
                "tools.import_asset_history.os.link",
                side_effect=competing_writer,
            ):
                with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite"):
                    _atomic_write(output, "loser", overwrite=False)
            self.assertEqual(output.read_text(encoding="utf-8"), "winner")


if __name__ == "__main__":
    unittest.main()
