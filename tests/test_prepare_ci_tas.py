from __future__ import annotations

import tarfile
import unittest
import hashlib
import json
import io
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
                "Cisco Enterprise Networking App for Splunk": "cisco-catalyst-app",
                "Cisco Enterprise Networking Add-on for Splunk": "TA_cisco_catalyst",
                "Cisco Enterprise Networking NetFlow Add-on for Splunk": "splunk_app_stream_ipfix_cisco_hsl",
                "Cisco Meraki Add-on for Splunk": "Splunk_TA_cisco_meraki",
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

    def test_extract_strips_executable_mode(self) -> None:
        with TemporaryDirectory() as root:
            path = Path(root)
            archive = path / "test.tar"
            with tarfile.open(archive, "w") as tar:
                info = tarfile.TarInfo("app/bin/input.py")
                info.mode = 0o4755
                info.size = 4
                tar.addfile(info, io.BytesIO(b"data"))
            _safe_extract(archive, path / "out")
            self.assertEqual(
                (path / "out/app/bin/input.py").stat().st_mode & 0o7777, 0o600
            )

    def test_extract_refuses_duplicate_link_special_and_windows_paths(self) -> None:
        for kind in ("duplicate", "symlink", "fifo", "windows", "backslash"):
            with self.subTest(kind=kind), TemporaryDirectory() as root:
                path = Path(root)
                archive = path / "test.tar"
                with tarfile.open(archive, "w") as tar:
                    name = {"windows": "C:/app/file", "backslash": "app\\file"}.get(
                        kind, "app/file"
                    )
                    info = tarfile.TarInfo(name)
                    if kind == "symlink":
                        info.type, info.linkname = tarfile.SYMTYPE, "../outside"
                    elif kind == "fifo":
                        info.type = tarfile.FIFOTYPE
                    tar.addfile(info)
                    if kind == "duplicate":
                        tar.addfile(info)
                with self.assertRaises(ValueError):
                    _safe_extract(archive, path / "out")
                self.assertFalse((path / "out").exists())
