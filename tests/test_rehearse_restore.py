"""Backup integrity and complete pagination guards, without a Splunk server."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import rehearse_restore as restore


class RestoreTest(unittest.TestCase):
    def backup(self):
        payload = {
            "schema": 2,
            "defaults": {"macros.conf": "abc"},
            "files": dict.fromkeys(restore.FILES),
            "collections": {
                name: [
                    {"_key": "old", "valid_to": 100},
                    {"_key": "new", "valid_from": 100},
                ]
                for name in restore.COLLECTIONS
            },
        }
        return {"payload": payload, "sha256": restore.digest(payload)}

    def test_csv_only_old_backup_is_rejected_before_any_restore_write(self):
        backup = self.backup()
        backup["payload"]["schema"] = 1
        backup["sha256"] = restore.digest(backup["payload"])
        with self.assertRaisesRegex(ValueError, "unsupported backup schema"):
            restore.validate_backup(backup)

    def test_damaged_backup_refuses_restore_before_preflight_or_write(self):
        backup = self.backup()
        backup["payload"]["collections"]["adm_ip_identity"].pop()
        with (
            patch.object(restore, "preflight") as preflight,
            patch.object(restore, "write_file") as write,
        ):
            with self.assertRaisesRegex(ValueError, "checksum"):
                restore.restore(backup)
            preflight.assert_not_called()
            write.assert_not_called()

    def test_checksum_is_not_authorization_for_unknown_paths_or_collections(self):
        for section, name in [
            ("files", "../../inputs.conf"),
            ("collections", "unrelated"),
        ]:
            with self.subTest(section=section):
                backup = self.backup()
                backup["payload"][section][name] = None if section == "files" else []
                backup["sha256"] = restore.digest(backup["payload"])
                with self.assertRaisesRegex(ValueError, "allowlist"):
                    restore.validate_backup(backup)

    def test_duplicate_keys_and_bad_file_encoding_are_rejected(self):
        original = self.backup()
        for variant in ("duplicate", "encoding"):
            backup = copy.deepcopy(original)
            if variant == "duplicate":
                backup["payload"]["collections"]["adm_ip_identity"].append(
                    {"_key": "old"}
                )
            else:
                backup["payload"]["files"]["local/macros.conf"] = "not base64!"
            backup["sha256"] = restore.digest(backup["payload"])
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                restore.validate_backup(backup)

    def test_short_pages_do_not_silently_truncate_a_collection(self):
        pages = iter(
            [
                [{"_key": "a", "_user": "nobody", "valid_to": 100}],
                [{"_key": "b", "valid_from": 100}],
                [],
            ]
        )
        queries = []

        def fetch(method, collection, *, query):
            queries.append(query["query"])
            return next(pages)

        rows = restore.read_collection("adm_ip_identity", fetch=fetch)
        self.assertEqual(
            rows, [{"_key": "a", "valid_to": 100}, {"_key": "b", "valid_from": 100}]
        )
        self.assertEqual(len(queries), 3)
        self.assertIn('"b"', queries[-1])

    def test_repeated_page_fails_instead_of_looping_or_accepting_duplicates(self):
        def fetch(*args, **kwargs):
            return [{"_key": "a"}]

        with self.assertRaisesRegex(ValueError, "advance"):
            restore.read_collection("adm_ip_identity", fetch=fetch)

    def test_missing_reset_authorization_prevents_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "lab.lock"
            # Keep the real decorator while isolating its default lock path.
            with (
                patch("lab_lock.default_lock_path", return_value=lock_path),
                patch.object(restore, "preflight") as preflight,
            ):
                with self.assertRaises(SystemExit):
                    restore.main([])
                preflight.assert_not_called()
            self.assertTrue(lock_path.is_file())
            self.assertEqual(lock_path.read_text(), "")


if __name__ == "__main__":
    unittest.main()
