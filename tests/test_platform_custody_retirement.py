import hashlib
import json
import os
import threading
import unittest

from tests import test_platform_custody_archive_verifier as fixtures
from tools.platform_custody_retirement import RetirementError, retire_tree


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.IndependentArchiveTests(
            methodName="test_full_independent_comparison_and_original_unchanged"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        f = self.fixture
        archive, manifest, ar, mr = f.build()
        self.af = os.open(archive, os.O_RDONLY)
        self.mf = os.open(manifest, os.O_RDONLY)
        self.addCleanup(os.close, self.af)
        self.addCleanup(os.close, self.mf)
        self.journal = f.root / "journal"
        self.jf = os.open(self.journal, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, self.jf)
        source, dest = os.fstat(f.sourcefd), os.fstat(f.destfd)
        self.args = dict(
            source_fd=f.sourcefd,
            source_parent_fd=f.parent,
            source_name="state",
            archive_fd=self.af,
            manifest_fd=self.mf,
            archive_parent_fd=f.destfd,
            archive_receipt=ar,
            manifest_receipt=mr,
            independent_receipt={
                "status": "verified",
                "archive_sha256": ar["sha256"],
                "manifest_sha256": mr["sha256"],
                "source_device": source.st_dev,
                "source_inode": source.st_ino,
            },
            expected_source=(
                source.st_dev,
                source.st_ino,
                source.st_uid,
                source.st_mode & 0o7777,
            ),
            expected_source_parent=(
                os.fstat(f.parent).st_dev,
                os.fstat(f.parent).st_ino,
            ),
            expected_archive_parent=(dest.st_dev, dest.st_ino),
            expected_journal_parent=(
                os.fstat(f.parent).st_dev,
                os.fstat(f.parent).st_ino,
            ),
            trusted_archive_sha256=ar["sha256"],
            trusted_manifest_sha256=mr["sha256"],
            journal_fd=self.jf,
            journal_parent_fd=f.parent,
            journal_name="journal",
            run_nonce="a" * 32,
            journal_limit=64 * 1024 * 1024,
            guard=lambda: True,
        )

    def test_exact_tree_retired_with_durable_ordered_records(self):
        result = retire_tree(**self.args)
        self.assertEqual(result["status"], "retired")
        self.assertFalse(self.fixture.source.exists())
        records = [json.loads(line) for line in self.journal.read_text().splitlines()]
        self.assertEqual(records[0]["state"], "retirement_intent")
        self.assertEqual(records[-1]["state"], "root_remove_complete")
        self.assertEqual(result["journal_bytes"], self.journal.stat().st_size)
        self.assertTrue((self.fixture.dest / "archive.tar.gz").exists())

    def test_locked_root_transition_callback_once(self):
        lock = threading.RLock()
        calls = []

        def removed():
            self.assertFalse(self.fixture.source.exists())
            calls.append("removed")

        result = retire_tree(**self.args, transition_lock=lock, on_root_removed=removed)
        self.assertEqual(result["status"], "retired")
        self.assertEqual(calls, ["removed"])

    def test_unpaired_callback_refused_without_action(self):
        calls = []
        with self.assertRaises(RetirementError):
            retire_tree(**self.args, on_root_removed=lambda: calls.append("removed"))
        self.assertEqual(calls, [])
        self.assertEqual(self.journal.stat().st_size, 0)
        self.assertTrue(self.fixture.source.exists())

    def test_replaced_inode_after_intent_is_retained(self):
        f = self.fixture
        replaced = False

        def guard():
            nonlocal replaced
            if not replaced and "entry_remove_intent" in self.journal.read_text():
                path = f.source / "dir/data"
                path.rename(f.root / "preserved")
                path.write_bytes(b"replacement")
                replaced = True
            return True

        self.args["guard"] = guard
        with self.assertRaises((RetirementError, ValueError)):
            retire_tree(**self.args)
        self.assertTrue(replaced)
        self.assertEqual((f.source / "dir/data").read_bytes(), b"replacement")
        self.assertEqual((f.root / "preserved").read_bytes(), b"synthetic")
        self.assertNotIn("entry_remove_complete", self.journal.read_text())

    def test_partial_failure_is_retained_and_journaled(self):
        def guard():
            return "entry_remove_complete" not in self.journal.read_text()

        self.args["guard"] = guard
        with self.assertRaises(RetirementError):
            retire_tree(**self.args)
        self.assertFalse((self.fixture.source / "dir/data").exists())
        self.assertTrue(self.fixture.source.exists())
        self.assertTrue((self.fixture.source / "link").is_symlink())
        self.assertIn("entry_remove_complete", self.journal.read_text())

    def test_receipt_pin_and_journal_capacity_refuse_before_mutation(self):
        for change in (
            {"trusted_archive_sha256": "0" * 64},
            {"journal_limit": 1},
            {"independent_receipt": {}},
        ):
            with self.subTest(change=change):
                with self.assertRaises((RetirementError, ValueError)):
                    retire_tree(**(self.args | change))
                self.assertEqual(self.journal.stat().st_size, 0)
                self.assertTrue((self.fixture.source / "dir/data").exists())

    def test_hostile_manifest_refused_before_mutation(self):
        manifest_path = self.fixture.dest / "manifest.json"
        data = json.loads(manifest_path.read_text())
        data["../escape"] = data.pop("dir/data")
        raw = (
            json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode()
        manifest_path.write_bytes(raw)
        receipt = {
            "name": "manifest.json",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        self.args["manifest_receipt"] = receipt
        self.args["trusted_manifest_sha256"] = receipt["sha256"]
        self.args["independent_receipt"]["manifest_sha256"] = receipt["sha256"]
        with self.assertRaises(ValueError):
            retire_tree(**self.args)
        self.assertEqual(self.journal.stat().st_size, 0)
        self.assertTrue((self.fixture.source / "dir/data").exists())


if __name__ == "__main__":
    unittest.main()
