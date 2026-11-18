"""Offline tests for the bounded case recovery snapshot helper."""

import os
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import case_recovery_snapshot as snapshots  # noqa: E402
from case_recovery_snapshot import (  # noqa: E402
    SnapshotError,
    create_snapshot,
    prepare_restore,
    schema_identity,
    validate_snapshot,
)

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.store import CaseStore  # noqa: E402
from adm_cases_lib.job_ledger import JobLedger  # noqa: E402


PROVENANCE = {"app": "splunk_adm", "app_version": "test", "image": "splunk:test"}
OWNER = "a" * 32
HASH = "c" * 64


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        cases = CaseStore(self.source / "cases.sqlite", lambda *_: True)
        data = {
            "schema_version": 1,
            "title": "Case",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        }
        case_id = cases.create("alice", "create", data)["id"]
        cases.append(
            "alice", "note", case_id, 1, "entry", {"type": "note", "text": "kept"}
        )
        cases.share("alice", "share", case_id, 2, "bob", True)
        os.chmod(self.source / "cases.sqlite", 0o600)
        jobs = JobLedger(self.source / "capture_jobs.sqlite", clock=lambda: 100)
        jobs.reserve(
            "alice", "adm-capture-" + "1" * 32, HASH, 1, 2, OWNER, transport_hash=HASH
        )
        jobs.transition(
            "alice",
            "adm-capture-" + "1" * 32,
            OWNER,
            "creation_unknown",
            expected_revision=1,
        )
        self.schemas = {
            name: schema_identity(self.source / name)
            for name in ("cases.sqlite", "capture_jobs.sqlite")
        }
        self.bundle = self.root / "bundle"
        self.digest = create_snapshot(
            self.source,
            self.bundle,
            expected_schemas=self.schemas,
            provenance=PROVENANCE,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_round_trip_keeps_case_audit_acl_and_unresolved_ledger(self):
        source_db = sqlite3.connect(self.source / "cases.sqlite")
        audit_before = source_db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        source_db.close()
        summary = prepare_restore(
            self.bundle,
            self.root / "restore",
            expected_manifest_sha256=self.digest,
            expected_schemas=self.schemas,
            expected_provenance=PROVENANCE,
        )
        self.assertEqual(summary["absent"], [])
        restored = self.root / "restore"
        with sqlite3.connect(restored / "cases.sqlite") as db:
            self.assertEqual(
                db.execute("SELECT principal FROM acl ORDER BY principal").fetchall(),
                [("alice",), ("bob",)],
            )
            self.assertEqual(
                db.execute("SELECT * FROM audit ORDER BY seq").fetchall(), audit_before
            )
            self.assertIn(
                "kept", db.execute("SELECT document FROM cases").fetchone()[0]
            )
        jobs = JobLedger(restored / "capture_jobs.sqlite", clock=lambda: 10**8)
        self.assertEqual(jobs.outstanding("alice")[0]["state"], "creation_unknown")
        self.assertEqual((restored / "cases.sqlite").stat().st_mode & 0o777, 0o600)

    def test_snapshot_is_independent_of_removed_source_and_cannot_be_overwritten(self):
        for path in self.source.iterdir():
            path.unlink()
        self.assertEqual(
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256=self.digest,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )["manifest_sha256"],
            self.digest,
        )
        with self.assertRaises(SnapshotError):
            create_snapshot(
                self.source,
                self.bundle,
                expected_schemas=self.schemas,
                provenance=PROVENANCE,
            )

    def test_optional_ledger_absence_is_explicit(self):
        source = self.root / "source-without-ledger"
        source.mkdir(mode=0o700)
        source.joinpath("cases.sqlite").write_bytes(
            (self.source / "cases.sqlite").read_bytes()
        )
        os.chmod(source / "cases.sqlite", 0o600)
        schemas = {"cases.sqlite": self.schemas["cases.sqlite"]}
        bundle = self.root / "without-ledger"
        digest = create_snapshot(
            source, bundle, expected_schemas=schemas, provenance=PROVENANCE
        )
        summary = validate_snapshot(
            bundle,
            expected_manifest_sha256=digest,
            expected_schemas=schemas,
            expected_provenance=PROVENANCE,
        )
        self.assertEqual(summary["absent"], ["capture_jobs.sqlite"])

    def test_corrupt_bytes_are_rejected(self):
        with (self.bundle / "cases.sqlite").open("r+b") as stream:
            stream.seek(100)
            byte = stream.read(1)
            stream.seek(100)
            stream.write(bytes([byte[0] ^ 0x40]))
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256=self.digest,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )

    def test_future_case_schema_is_rejected_even_with_resealed_manifest(self):
        cases = self.bundle / "cases.sqlite"
        with sqlite3.connect(cases) as db:
            db.execute("CREATE TABLE future_table (value TEXT)")
            db.execute("INSERT INTO future_table VALUES ('unexpected')")
            db.execute("PRAGMA user_version=0")
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["cases.sqlite"]["size"] = cases.stat().st_size
        manifest["files"]["cases.sqlite"]["sha256"] = snapshots._file_digest(cases)
        manifest["files"]["cases.sqlite"]["schema"] = snapshots.schema_descriptor(cases)
        manifest["files"]["cases.sqlite"]["tables"] = snapshots.inspect_database(
            cases, snapshots.schema_descriptor(cases)
        )["tables"]
        manifest_path.write_bytes(snapshots._canonical(manifest))
        os.chmod(manifest_path, 0o600)
        resealed = snapshots._sha(manifest_path.read_bytes())
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256=resealed,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )

    def test_future_user_version_is_rejected_even_with_resealed_manifest(self):
        ledger = self.bundle / "capture_jobs.sqlite"
        with sqlite3.connect(ledger) as db:
            db.execute("PRAGMA user_version=999")
        manifest_path = self.bundle / "manifest.json"
        manifest = __import__("json").loads(manifest_path.read_text())
        from case_recovery_snapshot import _file_digest, _canonical, _sha

        manifest["files"]["capture_jobs.sqlite"]["size"] = ledger.stat().st_size
        manifest["files"]["capture_jobs.sqlite"]["sha256"] = _file_digest(ledger)
        manifest["files"]["capture_jobs.sqlite"]["schema"] = schema_identity(ledger)
        manifest_path.write_bytes(_canonical(manifest))
        os.chmod(manifest_path, 0o600)
        resealed = _sha(manifest_path.read_bytes())
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256=resealed,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )

    def test_manifest_digest_and_provenance_are_required(self):
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256="0" * 64,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256=self.digest,
                expected_schemas=self.schemas,
                expected_provenance={"app": "other"},
            )

    def test_existing_destination_and_unexpected_files_are_rejected(self):
        occupied = self.root / "occupied"
        occupied.mkdir(mode=0o700)
        with self.assertRaises(SnapshotError):
            prepare_restore(
                self.bundle,
                occupied,
                expected_manifest_sha256=self.digest,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )
        (self.source / "unexpected").write_text("no")
        with self.assertRaises(SnapshotError):
            create_snapshot(
                self.source,
                self.root / "other",
                expected_schemas=self.schemas,
                provenance=PROVENANCE,
            )

    def test_unsafe_source_file_and_hot_journal_are_rejected(self):
        cases = self.source / "cases.sqlite"
        cases.chmod(0o644)
        with self.assertRaises(SnapshotError):
            create_snapshot(
                self.source,
                self.root / "unsafe-mode",
                expected_schemas=self.schemas,
                provenance=PROVENANCE,
            )
        cases.chmod(0o600)
        journal = Path(str(cases) + "-journal")
        journal.write_bytes(b"hot")
        journal.chmod(0o600)
        with self.assertRaises(SnapshotError):
            create_snapshot(
                self.source,
                self.root / "hot-journal",
                expected_schemas=self.schemas,
                provenance=PROVENANCE,
            )

    def test_committed_wal_rows_are_included(self):
        dbpath = self.source / "cases.sqlite"
        with sqlite3.connect(dbpath) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE wal_probe (value TEXT)")
            db.execute("INSERT INTO wal_probe VALUES ('committed')")
        # SQLite may retain a WAL after the final connection closes.
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(dbpath) + suffix)
            if sidecar.exists():
                os.chmod(sidecar, 0o600)
        schemas = {name: schema_identity(self.source / name) for name in self.schemas}
        bundle = self.root / "wal-bundle"
        digest = create_snapshot(
            self.source, bundle, expected_schemas=schemas, provenance=PROVENANCE
        )
        with sqlite3.connect(bundle / "cases.sqlite") as db:
            self.assertEqual(
                db.execute("SELECT value FROM wal_probe").fetchone(), ("committed",)
            )
        self.assertEqual(
            validate_snapshot(
                bundle,
                expected_manifest_sha256=digest,
                expected_schemas=schemas,
                expected_provenance=PROVENANCE,
            )["absent"],
            [],
        )
        self.assertEqual(
            {path.name for path in bundle.iterdir()},
            {"cases.sqlite", "capture_jobs.sqlite", "manifest.json"},
        )
        orphan = bundle / "cases.sqlite-wal"
        orphan.write_bytes(b"unsealed")
        orphan.chmod(0o600)
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                bundle,
                expected_manifest_sha256=digest,
                expected_schemas=schemas,
                expected_provenance=PROVENANCE,
            )

    def test_physical_wal_bound_is_checked_before_sqlite(self):
        wal = Path(str(self.source / "cases.sqlite") + "-wal")
        with wal.open("wb") as stream:
            stream.truncate(snapshots.MAX_TOTAL_BYTES + 1)
        wal.chmod(0o600)
        with patch.object(snapshots, "schema_identity", side_effect=AssertionError):
            with self.assertRaises(SnapshotError):
                create_snapshot(
                    self.source,
                    self.root / "oversized-source",
                    expected_schemas=self.schemas,
                    provenance=PROVENANCE,
                )

    def test_oversized_manifest_is_rejected_before_unbounded_read(self):
        manifest = self.bundle / "manifest.json"
        with manifest.open("wb") as stream:
            stream.truncate(snapshots.MAX_TOTAL_BYTES + 1)
        manifest.chmod(0o600)
        with self.assertRaises(SnapshotError):
            validate_snapshot(
                self.bundle,
                expected_manifest_sha256=self.digest,
                expected_schemas=self.schemas,
                expected_provenance=PROVENANCE,
            )


if __name__ == "__main__":
    unittest.main()
