"""Archive safety and byte preservation for exact-package lab installation."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from tools.stage_lab_package import _read_archive, stage_package

# The staging tool imports check_release as a sibling module; patch that copy.
LIMITS = _read_archive.__module__


def write_checksum(path, digest=None):
    digest = digest or hashlib.sha256(path.read_bytes()).hexdigest()
    Path(f"{path}.sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")


class StageLabPackageTest(unittest.TestCase):
    def archive(self, root, extra=None, *, checksum=True):
        path = root / "candidate.tgz"
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo("splunk_adm/default/app.conf")
            value = b"[launcher]\nversion = 0.3.0\n"
            entry.size = len(value)
            archive.addfile(entry, io.BytesIO(value))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b""))
        if checksum:
            write_checksum(path)
        return path, value

    def test_exact_bytes_and_existing_destination_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, value = self.archive(root)
            stage_package(archive, root)
            self.assertEqual((root / "splunk_adm/default/app.conf").read_bytes(), value)
            with self.assertRaisesRegex(ValueError, "already contains"):
                stage_package(archive, root)

    def test_unsafe_members_rejected_before_any_extraction(self):
        for name, kind, message in (
            ("../escape", tarfile.REGTYPE, "unsafe archive member path"),
            ("/escape", tarfile.REGTYPE, "unsafe archive member path"),
            ("other_app/file", tarfile.REGTYPE, "outside app root"),
            ("splunk_adm/link", tarfile.SYMTYPE, "links or special files"),
            ("splunk_adm/hardlink", tarfile.LNKTYPE, "links or special files"),
            ("splunk_adm/default/app.conf", tarfile.REGTYPE, "duplicate"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/tmp/escape"
                archive, _ = self.archive(root, entry)
                with self.assertRaisesRegex(ValueError, message):
                    stage_package(archive, root)
                self.assertFalse((root / "splunk_adm").exists())

    def test_missing_or_mismatched_checksum_rejected_before_extraction(self):
        for digest in (None, "0" * 64):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive, _ = self.archive(root, checksum=False)
                if digest is None:
                    message = "missing checksum file"
                else:
                    write_checksum(archive, digest)
                    message = "checksum mismatch"
                with self.assertRaisesRegex(ValueError, message):
                    stage_package(archive, root)
                self.assertFalse((root / "splunk_adm").exists())

    def test_release_member_limits_apply(self):
        for limit, value, message in (
            ("MAX_MEMBERS", 1, "too many members"),
            ("MAX_MEMBER_BYTES", 4, "member is too large"),
        ):
            with (
                self.subTest(limit=limit),
                tempfile.TemporaryDirectory() as temp,
                mock.patch(f"{LIMITS}.{limit}", value),
            ):
                root = Path(temp)
                extra = tarfile.TarInfo("splunk_adm/default/extra.conf")
                archive, _ = self.archive(root, extra)
                with self.assertRaisesRegex(ValueError, message):
                    stage_package(archive, root)
                self.assertFalse((root / "splunk_adm").exists())


if __name__ == "__main__":
    unittest.main()
