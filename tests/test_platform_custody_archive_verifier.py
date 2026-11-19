import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from tools import platform_custody_archive_verifier as verifier


class IndependentArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / "state"
        self.source.mkdir(mode=0o700)
        (self.source / "dir").mkdir()
        (self.source / "dir" / "data").write_bytes(b"synthetic")
        (self.source / "link").symlink_to("dir/data")
        self.parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.sourcefd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.dest = self.root / "custody"
        self.dest.mkdir(mode=0o700)
        self.destfd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        self.manifest = {}
        for path in ("", "dir", "dir/data", "link"):
            target = self.source / path
            st = target.lstat()
            item = verifier._meta(st)
            item["kind"] = (
                "symlink"
                if target.is_symlink()
                else "directory"
                if target.is_dir()
                else "file"
            )
            if item["kind"] == "file":
                item["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            if item["kind"] == "symlink":
                item["target"] = os.readlink(target)
            self.manifest[path] = item
        self.patch = patch.object(verifier, "NOATIME", 0)
        self.patch.start()
        self.xattr = patch.object(verifier, "_no_xattrs", return_value=None)
        self.xattr.start()
        self.mount = patch.object(verifier, "_mount_id", return_value=17)
        self.mount.start()
        self.linkmount = patch.object(verifier, "_check_symlink_mount")
        self.linkmount.start()

    def tearDown(self):
        self.linkmount.stop()
        self.mount.stop()
        self.xattr.stop()
        self.patch.stop()
        os.close(self.sourcefd)
        os.close(self.destfd)
        os.close(self.parent)
        self.tmp.cleanup()

    def build(self, *, omit=None, alter_root=False, corrupt=False, text_owner=False):
        archive = self.dest / "archive.tar.gz"
        manifestfile = self.dest / "manifest.json"
        manifest = dict(self.manifest)
        if alter_root:
            manifest[""] = dict(manifest[""], mode=0o755)
        manifestfile.write_text(
            json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            + "\n"
        )
        manifestfile.chmod(0o600)
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            for path, item in sorted(manifest.items()):
                if path == omit:
                    continue
                info = tarfile.TarInfo("state/" + path if path else "state")
                info.uname = "unexpected" if text_owner else ""
                info.uid = item["uid"]
                info.gid = item["gid"]
                info.mode = item["mode"]
                info.mtime = item["mtime_ns"] // 1000000000
                info.pax_headers = {
                    "ATLAS." + k: str(item[k])
                    for k in ("mtime_ns", "atime_ns", "ctime_ns", "birthtime_ns")
                }
                if item["kind"] == "directory":
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                elif item["kind"] == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = item["target"]
                    tar.addfile(info)
                else:
                    data = (
                        b"corrupted" if corrupt else (self.source / path).read_bytes()
                    )
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        archive.chmod(0o600)

        def receipt(path):
            return {
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        return archive, manifestfile, receipt(archive), receipt(manifestfile)

    def verify(self, archive, manifestfile, ar, mr):
        af = os.open(archive, os.O_RDONLY)
        mf = os.open(manifestfile, os.O_RDONLY)
        try:
            return verifier.verify_contents(
                source_fd=self.sourcefd,
                source_parent_fd=self.parent,
                source_name="state",
                archive_fd=af,
                manifest_fd=mf,
                archive_parent_fd=self.destfd,
                archive_receipt=ar,
                manifest_receipt=mr,
            )
        finally:
            os.close(af)
            os.close(mf)

    def test_full_independent_comparison_and_original_unchanged(self):
        args = self.build()
        result = self.verify(*args)
        self.assertEqual(result["status"], "verified")
        self.assertEqual((self.source / "dir/data").read_bytes(), b"synthetic")
        self.assertEqual(os.readlink(self.source / "link"), "dir/data")

    def test_missing_member_corrupt_content_and_root_metadata_refused(self):
        for kwargs in ({"omit": "link"}, {"corrupt": True}, {"alter_root": True}):
            with self.subTest(kwargs=kwargs):
                args = self.build(**kwargs)
                with self.assertRaises(ValueError):
                    self.verify(*args)

    def test_oversized_pax_and_concatenated_nonpadding_refused(self):
        archive, manifest, ar, mr = self.build()
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = 65537
        archive.write_bytes(
            gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT) + b"x" * 65537)
        )
        ar = {
            "name": archive.name,
            "size": archive.stat().st_size,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
        with self.assertRaises(ValueError):
            self.verify(archive, manifest, ar, mr)
        archive, manifest, ar, mr = self.build()
        archive.write_bytes(archive.read_bytes() + gzip.compress(b"not zero padding"))
        ar = {
            "name": archive.name,
            "size": archive.stat().st_size,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
        with self.assertRaises(ValueError):
            self.verify(archive, manifest, ar, mr)

    def test_long_and_non_ascii_directory_paths_from_standard_pax_writer(self):
        for name in ("a" * 101, "é" * 60):
            path = self.source / name
            path.mkdir()
            item = verifier._meta(path.stat())
            item["kind"] = "directory"
            self.manifest[name] = item
        root = verifier._meta(self.source.stat())
        root["kind"] = "directory"
        self.manifest[""] = root
        self.assertEqual(self.verify(*self.build())["status"], "verified")

    def test_directory_aliases_and_non_directory_slash_rejected(self):
        def info(path, alternate, kind="directory"):
            item = self.manifest[path]
            member = tarfile.TarInfo("state/" + path if path else "state")
            member.uid, member.gid = item["uid"], item["gid"]
            member.mode = item["mode"]
            member.mtime = item["mtime_ns"] // 1000000000
            member.pax_headers = {
                "ATLAS." + key: str(item[key])
                for key in ("mtime_ns", "atime_ns", "ctime_ns", "birthtime_ns")
            }
            member.pax_headers["path"] = alternate
            member.type = tarfile.DIRTYPE if kind == "directory" else tarfile.REGTYPE
            if kind == "file":
                member.size = item["size"]
            return member

        target = self.dest / "alias.tar.gz"
        for bad in ("state/dir//", "state/./dir/", "state/dir/../dir/", "state//dir/"):
            with self.subTest(path=bad):
                with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as tar:
                    tar.addfile(info("", "state"))
                    tar.addfile(info("dir", bad))
                fd = os.open(target, os.O_RDONLY)
                try:
                    with self.assertRaises(ValueError):
                        verifier._compare_archive(fd, self.manifest)
                finally:
                    os.close(fd)
        for scenario in ("duplicate", "file_slash"):
            with self.subTest(scenario=scenario):
                with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as tar:
                    tar.addfile(info("", "state"))
                    if scenario == "duplicate":
                        tar.addfile(info("dir", "state/dir"))
                        tar.addfile(info("dir", "state/dir/"))
                    else:
                        tar.addfile(
                            info("dir/data", "state/dir/data/", "file"),
                            io.BytesIO(b"synthetic"),
                        )
                fd = os.open(target, os.O_RDONLY)
                try:
                    with self.assertRaises(ValueError):
                        verifier._compare_archive(fd, self.manifest)
                finally:
                    os.close(fd)

    @unittest.skipUnless(
        hasattr(os, "O_NOATIME")
        and hasattr(os, "O_PATH")
        and Path("/proc/self/fdinfo").is_dir(),
        "native Linux no-follow mount identity and O_NOATIME required",
    )
    def test_full_native_linux_fd_and_mount_comparison(self):
        args = self.build()
        self.linkmount.stop()
        self.mount.stop()
        self.xattr.stop()
        self.patch.stop()
        original_fd = self.sourcefd
        try:
            self.sourcefd = os.open(
                self.source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME
            )
            self.assertEqual(self.verify(*args)["status"], "verified")
        finally:
            if self.sourcefd != original_fd:
                os.close(self.sourcefd)
            self.sourcefd = original_fd
            self.patch.start()
            self.xattr.start()
            self.mount.start()
            self.linkmount.start()

    def test_conflicting_textual_owner_is_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(*self.build(text_owner=True))

    def test_same_device_different_mount_id_is_rejected(self):
        args = self.build()
        file_inode = (self.source / "dir/data").stat().st_ino
        with patch.object(
            verifier,
            "_mount_id",
            side_effect=lambda fd: 18 if os.fstat(fd).st_ino == file_inode else 17,
        ):
            with self.assertRaises(ValueError):
                self.verify(*args)

    def test_same_inode_mount_replacement_during_scan_is_rejected(self):
        args = self.build()
        file_inode = (self.source / "dir/data").stat().st_ino
        seen = [0]

        def mount_id(fd):
            if os.fstat(fd).st_ino == file_inode:
                seen[0] += 1
                return 17 if seen[0] == 1 else 18
            return 17

        with patch.object(verifier, "_mount_id", side_effect=mount_id):
            with self.assertRaises(ValueError):
                self.verify(*args)
        self.assertGreaterEqual(seen[0], 2)

    def test_fdinfo_mount_id_requires_one_positive_numeric_value(self):
        from unittest.mock import mock_open

        self.mount.stop()
        try:
            with patch("builtins.open", mock_open(read_data=b"pos:\t0\nmnt_id:\t42\n")):
                self.assertEqual(verifier._mount_id(7), 42)
            for data in (b"pos: 0\n", b"mnt_id: nope\n", b"mnt_id: 1\nmnt_id: 2\n"):
                with patch("builtins.open", mock_open(read_data=data)):
                    with self.assertRaises(ValueError):
                        verifier._mount_id(7)
        finally:
            self.mount.start()

    def test_source_path_replacement_during_archive_read_refused(self):
        args = self.build()
        original = verifier._compare_archive

        def replace(fd, manifest):
            original(fd, manifest)
            self.source.rename(self.root / "detached")
            self.source.mkdir()

        with patch.object(verifier, "_compare_archive", side_effect=replace):
            with self.assertRaises(ValueError):
                self.verify(*args)
        self.assertTrue((self.root / "detached/dir/data").exists())

    def test_unsupported_xattr_check_fails_closed(self):
        self.xattr.stop()
        try:
            with patch.object(
                verifier.os, "listxattr", create=True, return_value=["user.private"]
            ):
                with self.assertRaises(ValueError):
                    verifier._no_xattrs(self.sourcefd)
        finally:
            self.xattr.start()


if __name__ == "__main__":
    unittest.main()
