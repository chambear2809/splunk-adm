import hashlib
import tempfile
import unittest
from pathlib import Path

from tools import qualify_platform_recovery as recovery


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        for name in recovery.COMPONENTS:
            file = self.source / (name + ".snapshot")
            file.write_bytes((name + " fixture").encode())
            file.chmod(0o600)
        self.package = hashlib.sha256(b"package fixture").hexdigest()
        self.manifest, self.digest = recovery.build_inventory(
            self.source,
            source_id="synthetic_source",
            package_sha256=self.package,
            unresolved_operations=0,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_sealed_inventory_and_fresh_staging(self):
        self.assertEqual(
            recovery.verify_inventory(self.source, self.manifest, self.digest)[
                "status"
            ],
            "inventory_verified",
        )
        target = self.root / "target"
        result = recovery.stage_fresh_inventory(
            self.source, self.manifest, self.digest, target
        )
        self.assertFalse(result["operational_restore_qualified"])
        self.assertEqual(
            recovery.verify_inventory(target, self.manifest, self.digest)["components"],
            len(recovery.COMPONENTS),
        )
        self.assertIn(
            '"state":"staging_verified"', (target / "staging.jsonl").read_text()
        )
        with self.assertRaises(FileExistsError):
            recovery.stage_fresh_inventory(
                self.source, self.manifest, self.digest, target
            )

    def test_unresolved_and_missing_components_refused(self):
        with self.assertRaises(recovery.InventoryError):
            recovery.build_inventory(
                self.source,
                source_id="source",
                package_sha256=self.package,
                unresolved_operations=1,
            )
        (self.source / "watch_runs.snapshot").unlink()
        with self.assertRaises(OSError):
            recovery.verify_inventory(self.source, self.manifest, self.digest)

    def test_corruption_and_untrusted_manifest_fail_before_target(self):
        (self.source / "cases.snapshot").write_bytes(b"changed")
        target = self.root / "target"
        with self.assertRaises(recovery.InventoryError):
            recovery.stage_fresh_inventory(
                self.source, self.manifest, self.digest, target
            )
        self.assertFalse(target.exists())
        with self.assertRaises(recovery.InventoryError):
            recovery.verify_inventory(self.source, self.manifest, "0" * 64)

    def test_symlink_hardlink_and_wide_permissions_rejected(self):
        file = self.source / "cases.snapshot"
        file.unlink()
        file.symlink_to(self.source / "case_ledger.snapshot")
        with self.assertRaises(OSError):
            recovery.verify_inventory(self.source, self.manifest, self.digest)
        file.unlink()
        file.hardlink_to(self.source / "case_ledger.snapshot")
        with self.assertRaises(recovery.InventoryError):
            recovery.verify_inventory(self.source, self.manifest, self.digest)
        file.unlink()
        file.write_bytes(b"cases fixture")
        file.chmod(0o600)
        (self.source / "case_ledger.snapshot").chmod(0o644)
        with self.assertRaises(recovery.InventoryError):
            recovery.verify_inventory(self.source, self.manifest, self.digest)

    def test_partial_staging_retained_and_refuses_retry(self):
        original = recovery._read
        calls = 0

        def failing(path, limit):
            nonlocal calls
            calls += 1
            if calls == len(recovery.COMPONENTS) + 2:
                raise OSError("simulated input failure")
            return original(path, limit)

        from unittest.mock import patch

        target = self.root / "partial"
        with patch.object(recovery, "_read", side_effect=failing):
            with self.assertRaises(OSError):
                recovery.stage_fresh_inventory(
                    self.source, self.manifest, self.digest, target
                )
        self.assertTrue((target / "staging.jsonl").exists())
        self.assertNotIn(
            '"state":"staging_verified"', (target / "staging.jsonl").read_text()
        )
        with self.assertRaises(FileExistsError):
            recovery.stage_fresh_inventory(
                self.source, self.manifest, self.digest, target
            )

    def test_nested_and_alias_targets_are_rejected_without_source_writes(self):
        nested = self.source / "nested"
        nested.mkdir(mode=0o700)
        before = sorted(path.name for path in nested.iterdir())
        for target in (nested / "copy", nested / ".." / "copy"):
            with self.assertRaises(recovery.InventoryError):
                recovery.stage_fresh_inventory(
                    self.source, self.manifest, self.digest, target
                )
        self.assertEqual(sorted(path.name for path in nested.iterdir()), before)
        other = self.root / "other"
        other.mkdir(mode=0o700)
        aliased_source = other / ".." / "source"
        with self.assertRaises(recovery.InventoryError):
            recovery.stage_fresh_inventory(
                aliased_source, self.manifest, self.digest, nested / "copy"
            )
        with self.assertRaises(recovery.InventoryError):
            recovery.snapshot_cold_databases(aliased_source, nested / "copy", {})
        self.assertEqual(sorted(path.name for path in nested.iterdir()), before)

    def test_journal_short_writes_complete_and_zero_write_fails(self):
        from unittest.mock import patch

        original = recovery.os.write

        def short(fd, data):
            return original(fd, data[: max(1, len(data) // 2)])

        with patch.object(recovery.os, "write", side_effect=short):
            result = recovery.stage_fresh_inventory(
                self.source, self.manifest, self.digest, self.root / "short"
            )
        self.assertEqual(result["status"], "staged_and_verified")
        with patch.object(recovery.os, "write", return_value=0):
            with self.assertRaises(recovery.InventoryError):
                recovery.stage_fresh_inventory(
                    self.source, self.manifest, self.digest, self.root / "zero"
                )
        self.assertTrue((self.root / "zero" / "staging.jsonl").exists())
        self.assertEqual((self.root / "zero" / "staging.jsonl").read_bytes(), b"")

    def test_duplicate_manifest_key_rejected(self):
        with self.assertRaises(recovery.InventoryError):
            recovery._unique_object([("schema", 1), ("schema", 1)])


class ColdDatabaseTests(unittest.TestCase):
    def test_four_real_sqlite_backups_and_reject_sidecars(self):
        import sqlite3
        from contextlib import closing

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            root.chmod(0o700)
            source = root / "source"
            source.mkdir(mode=0o700)
            for folder in ("baselines", "investigations"):
                (source / folder).mkdir(mode=0o700)
            schemas = {}
            for name, folder in recovery.COLD_DATABASES.items():
                path = source / folder / name
                with closing(sqlite3.connect(path)) as db:
                    db.execute(
                        "CREATE TABLE marker (id INTEGER PRIMARY KEY, payload TEXT)"
                    )
                    db.execute("INSERT INTO marker VALUES (1, ?)", (name,))
                    db.commit()
                path.chmod(0o600)
                schemas[name] = recovery.case_snapshot.schema_descriptor(path)
            results = recovery.snapshot_cold_databases(source, root / "copy", schemas)
            self.assertEqual(set(results), set(recovery.COLD_DATABASES))
            with self.assertRaises(FileExistsError):
                recovery.snapshot_cold_databases(source, root / "copy", schemas)
            from unittest.mock import patch

            original_inspect = recovery.case_snapshot.inspect_database
            calls = 0

            def fail_after_copy(path, schema):
                nonlocal calls
                calls += 1
                if calls == len(recovery.COLD_DATABASES) + 1:
                    raise OSError("simulated verification failure")
                return original_inspect(path, schema)

            with patch.object(
                recovery.case_snapshot, "inspect_database", side_effect=fail_after_copy
            ):
                with self.assertRaises(OSError):
                    recovery.snapshot_cold_databases(source, root / "partial", schemas)
            self.assertTrue((root / "partial").exists())
            with self.assertRaises(FileExistsError):
                recovery.snapshot_cold_databases(source, root / "partial", schemas)
            with closing(sqlite3.connect(root / "copy" / "watch_runs.sqlite")) as db:
                self.assertEqual(
                    db.execute("SELECT payload FROM marker").fetchone()[0],
                    "watch_runs.sqlite",
                )
            (source / "baselines" / "baselines.sqlite-wal").touch(mode=0o600)
            with self.assertRaises(recovery.InventoryError):
                recovery.snapshot_cold_databases(source, root / "refused", schemas)
            self.assertFalse((root / "refused").exists())


class NativeUnitTests(unittest.TestCase):
    def test_render_requires_pinned_inputs_and_fixed_limits(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp).resolve()
            stage.chmod(0o700)
            for name, content in (
                ("package-manifest.json", b"manifest"),
                ("splunk.tgz", b"binary"),
                ("atlas.tgz", b"app"),
                ("driver.py", b"driver"),
            ):
                (stage / name).write_bytes(content)
                (stage / name).chmod(0o444)
            binary = hashlib.sha256(b"binary").hexdigest()
            app = hashlib.sha256(b"app").hexdigest()
            driver = hashlib.sha256(b"driver").hexdigest()
            with (
                patch.object(recovery, "NATIVE_STAGE", stage),
                patch.object(recovery, "INPUT_OWNER_UID", __import__("os").getuid()),
                patch.object(
                    recovery,
                    "NATIVE_MANIFEST_SHA256",
                    hashlib.sha256(b"manifest").hexdigest(),
                ),
                patch.object(recovery, "NATIVE_PACKAGE_SHA256", binary),
                patch.object(recovery, "NATIVE_APP_SHA256", app),
            ):
                result = recovery.render_native_launch(driver)
                self.assertIn("--property=RuntimeMaxSec=2700", result["argv"])
                retry = recovery.render_native_launch(driver, runtime_minutes=44)
                self.assertIn("--property=RuntimeMaxSec=2640", retry["argv"])
                for invalid in (0, 46, True, 44.0, "44"):
                    with (
                        self.subTest(runtime_minutes=invalid),
                        self.assertRaises(recovery.InventoryError),
                    ):
                        recovery.render_native_launch(driver, runtime_minutes=invalid)
                self.assertFalse(result["execution_authorized"])
                self.assertFalse(result["operational_restore_qualified"])
                for prop in (
                    "DynamicUser=yes",
                    "StateDirectoryMode=0700",
                    "RuntimeDirectoryMode=0700",
                    "PrivateNetwork=yes",
                    "ProtectProc=invisible",
                    "CapabilityBoundingSet=",
                    "ProtectSystem=strict",
                    "MemoryMax=8G",
                    "MemorySwapMax=0",
                    "CPUQuota=400%",
                    "TasksMax=1024",
                    "KillMode=control-group",
                    "TimeoutStopSec=15s",
                    "SendSIGKILL=yes",
                    "OOMPolicy=kill",
                ):
                    self.assertIn("--property=" + prop, result["argv"])
                self.assertIn(
                    "--property=InaccessiblePaths=/opt/splunk -/run/dbus/system_bus_socket -/run/docker.sock -/run/containerd",
                    result["argv"],
                )
                with self.assertRaises(recovery.InventoryError):
                    recovery.render_native_launch("0" * 64)
                (stage / "atlas.tgz").chmod(0o600)
                (stage / "atlas.tgz").write_bytes(b"wrong")
                (stage / "atlas.tgz").chmod(0o444)
                with self.assertRaises(recovery.InventoryError):
                    recovery.render_native_launch(driver)


if __name__ == "__main__":
    unittest.main()
