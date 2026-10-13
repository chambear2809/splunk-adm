from __future__ import annotations

import tarfile
import unittest
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.prepare_ci_tas import REQUIRED, _safe_extract, prepare


class PrepareCiTasTests(unittest.TestCase):
    def test_prepare_creates_lab_layout_and_checksums(self) -> None:
        with TemporaryDirectory() as root:
            root_path = Path(root)
            packages = root_path / "packages"
            packages.mkdir()
            entries = []
            roots = {
                "Stream Wire Data": "Splunk_TA_stream_wire_data",
                "Cisco Security Cloud": "CiscoSecurityCloud",
                "Cisco DC Networking": "cisco_dc_networking_app_for_splunk",
            }
            for title, (archive_name, wrapper) in REQUIRED.items():
                archive = packages / archive_name
                with tarfile.open(archive, "w") as tar:
                    info = tarfile.TarInfo(f"{roots[title]}/default/app.conf")
                    info.size = 3
                    import io

                    tar.addfile(info, io.BytesIO(b"app"))
                entries.append(
                    {
                        "title": title,
                        "archive_path": f"research/packages/{archive_name}",
                        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    }
                )
            manifest = root_path / "manifest.json"
            manifest.write_text(json.dumps({"packages": entries}))
            output = root_path / "extracted"
            prepare(manifest, packages, output)
            for title, (_, wrapper) in REQUIRED.items():
                self.assertTrue(
                    (output / wrapper / roots[title] / "default/app.conf").is_file()
                )

    def test_prepare_rejects_bad_checksum(self) -> None:
        with TemporaryDirectory() as root:
            root_path = Path(root)
            packages = root_path / "packages"
            packages.mkdir()
            entries = []
            for title, (archive_name, _) in REQUIRED.items():
                archive = packages / archive_name
                archive.write_bytes(b"not a tar")
                entries.append(
                    {
                        "title": title,
                        "archive_path": f"research/packages/{archive_name}",
                        "sha256": "0" * 64,
                    }
                )
            manifest = root_path / "manifest.json"
            manifest.write_text(json.dumps({"packages": entries}))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                prepare(manifest, packages, root_path / "extracted")

    def test_safe_extract_rejects_path_traversal(self) -> None:
        import io
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            tmp_path = Path(root)
            archive = tmp_path / "unsafe.tar"
            with tarfile.open(archive, "w") as tar:
                info = tarfile.TarInfo("../outside.txt")
                info.size = 4
                tar.addfile(info, io.BytesIO(b"oops"))

            destination = tmp_path / "out"
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                _safe_extract(archive, destination)
            self.assertFalse((tmp_path / "outside.txt").exists())
