"""Archive safety and byte preservation for exact-package lab installation."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from tools.stage_lab_package import stage_package


class StageLabPackageTest(unittest.TestCase):
    def archive(self, root, extra=None):
        path = root / "candidate.tgz"
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo("splunk_adm/default/app.conf")
            value = b"[launcher]\nversion = 0.3.0\n"
            entry.size = len(value)
            archive.addfile(entry, io.BytesIO(value))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b""))
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
        for name, kind in (
            ("../escape", tarfile.REGTYPE),
            ("/escape", tarfile.REGTYPE),
            ("splunk_adm/link", tarfile.SYMTYPE),
            ("splunk_adm/hardlink", tarfile.LNKTYPE),
            ("splunk_adm/default/app.conf", tarfile.REGTYPE),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/tmp/escape"
                archive, _ = self.archive(root, entry)
                with self.assertRaisesRegex(ValueError, "unsafe or duplicate"):
                    stage_package(archive, root)
                self.assertFalse((root / "splunk_adm").exists())
