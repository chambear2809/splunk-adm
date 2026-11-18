"""Local transaction tests for preserving platform sitecustomize files."""

import hashlib
import importlib.util
import os
from pathlib import Path
import py_compile
import tempfile
import unittest
from unittest.mock import patch

FIXTURE = Path(__file__).parent / "splunk/case_request_native.py"
spec = importlib.util.spec_from_file_location("case_request_native_test", FIXTURE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class CaseRequestHookTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sdk = self.root / "site-packages"
        self.sdk.mkdir()
        self.source = self.sdk / "sitecustomize.py"
        self.bytecode = self.sdk / "__pycache__" / "sitecustomize.cpython-313.pyc"
        self.bytecode.parent.mkdir()
        self.staged = self.root / "staged"
        self.staged.mkdir(mode=0o700)
        self.hook = self.staged / "case_request_fault_hook.py"
        self.hook.write_bytes(b"# fixture hook payload\n")
        os.chmod(self.hook, 0o600)
        self.backup = self.root / "hook-backup"
        self.transaction = self.backup / "transaction.json"
        self.old = {
            "STAGED": native.STAGED,
            "HOOK_SOURCE": native.HOOK_SOURCE,
            "HOOK_BACKUP": native.HOOK_BACKUP,
            "HOOK_TRANSACTION": native.HOOK_TRANSACTION,
            "ROOT_UID": native.ROOT_UID,
            "ROOT_GID": native.ROOT_GID,
            "paths": native._sitecustomize_paths,
        }
        native.STAGED = self.staged
        native.HOOK_SOURCE = self.hook
        native.HOOK_BACKUP = self.backup
        native.HOOK_TRANSACTION = self.transaction
        native.ROOT_UID = os.getuid()
        native.ROOT_GID = os.getgid()
        native._sitecustomize_paths = lambda: (
            self.sdk,
            "splunk/__init__.py",
            self.source,
            self.bytecode,
        )
        self.pw_patch = patch.object(
            native.pwd,
            "getpwnam",
            return_value=type("User", (), {"pw_uid": os.getuid()})(),
        )
        self.pw_patch.start()
        self.addCleanup(self.pw_patch.stop)
        self.addCleanup(self.restore_globals)

    def restore_globals(self):
        native.STAGED = self.old["STAGED"]
        native.HOOK_SOURCE = self.old["HOOK_SOURCE"]
        native.HOOK_BACKUP = self.old["HOOK_BACKUP"]
        native.HOOK_TRANSACTION = self.old["HOOK_TRANSACTION"]
        native.ROOT_UID = self.old["ROOT_UID"]
        native.ROOT_GID = self.old["ROOT_GID"]
        native._sitecustomize_paths = self.old["paths"]

    def install_and_remove(self):
        digest = hashlib.sha256(self.hook.read_bytes()).hexdigest()
        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            installed = native.hook_install(digest)
            removed = native.hook_remove(digest)
        return installed, removed

    def test_existing_source_and_cache_are_restored_exactly(self):
        original_source = (
            b"# platform behavior\nimport math\nPLATFORM_VALUE = math.pi\n"
        )
        original_cache = b"platform bytecode cache fixture\n"
        self.source.write_bytes(original_source)
        source_times = (1_700_000_000_123_456_789, 1_700_000_000_234_567_890)
        os.utime(self.source, ns=source_times)
        py_compile.compile(str(self.source), cfile=str(self.bytecode), doraise=True)
        os.chmod(self.source, 0o640)
        original_cache = self.bytecode.read_bytes()
        os.chmod(self.bytecode, 0o600)
        cache_times = (1_700_000_100_123_456_789, 1_700_000_100_234_567_890)
        os.utime(self.bytecode, ns=cache_times)
        source_stat = self.source.stat()
        cache_stat = self.bytecode.stat()

        installed, removed = self.install_and_remove()

        self.assertTrue(installed["fixture_hook_active"])
        self.assertEqual(self.source.read_bytes(), original_source)
        self.assertEqual(self.bytecode.read_bytes(), original_cache)
        self.assertEqual(
            (self.source.stat().st_uid, self.source.stat().st_gid),
            (source_stat.st_uid, source_stat.st_gid),
        )
        self.assertEqual((self.source.stat().st_mode & 0o777), 0o640)
        self.assertEqual(self.source.stat().st_mtime_ns, source_stat.st_mtime_ns)
        self.assertEqual(
            (self.bytecode.stat().st_uid, self.bytecode.stat().st_gid),
            (cache_stat.st_uid, cache_stat.st_gid),
        )
        self.assertEqual((self.bytecode.stat().st_mode & 0o777), 0o600)
        self.assertEqual(self.bytecode.stat().st_mtime_ns, cache_stat.st_mtime_ns)
        native._validate_pyc(
            self.bytecode, original_source, self.source.stat().st_mtime
        )
        self.assertTrue(removed["hook_restored"])
        self.assertTrue(removed["cache_restored"])
        self.assertFalse(removed["fixture_hook_active"])
        self.assertFalse(self.backup.exists())

    def test_absent_source_and_cache_are_removed_after_fixture(self):
        _, removed = self.install_and_remove()
        self.assertFalse(self.source.exists())
        self.assertFalse(self.bytecode.exists())
        self.assertTrue(removed["hook_restored"])
        self.assertTrue(removed["cache_restored"])

    def test_cache_created_under_umask_027_is_restored_with_0640_mode(self):
        original_source = b"# platform behavior\nPLATFORM_VALUE = 'kept'\n"
        self.source.write_bytes(original_source)
        os.chmod(self.source, 0o640)
        previous_umask = os.umask(0o027)
        try:
            py_compile.compile(str(self.source), cfile=str(self.bytecode), doraise=True)
        finally:
            os.umask(previous_umask)
        os.chmod(self.source, 0o640)
        original_cache_bytes = self.bytecode.read_bytes()
        self.assertEqual(self.bytecode.stat().st_mode & 0o777, 0o640)
        digest = hashlib.sha256(self.hook.read_bytes()).hexdigest()
        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            installed = native.hook_install(digest)

        previous_umask = os.umask(0o027)
        try:
            py_compile.compile(str(self.source), cfile=str(self.bytecode), doraise=True)
        finally:
            os.umask(previous_umask)
        self.assertEqual(self.bytecode.stat().st_mode & 0o777, 0o640)

        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            removed = native.hook_remove(digest)

        self.assertTrue(installed["fixture_hook_active"])
        self.assertTrue(removed["cache_restored"])
        self.assertEqual(self.bytecode.read_bytes(), original_cache_bytes)
        self.assertEqual(self.bytecode.stat().st_mode & 0o777, 0o640)

    def test_read_only_platform_source_mode_is_restored_exactly(self):
        original_source = b"# read-only platform startup\nPLATFORM_VALUE = 'kept'\n"
        self.source.write_bytes(original_source)
        os.chmod(self.source, 0o444)
        source_mtime = 1_700_000_000_234_567_890
        os.utime(self.source, ns=(source_mtime, source_mtime))
        py_compile.compile(str(self.source), cfile=str(self.bytecode), doraise=True)
        original_cache = self.bytecode.read_bytes()
        os.chmod(self.bytecode, 0o600)
        cache_mtime = 1_700_000_100_234_567_890
        os.utime(self.bytecode, ns=(cache_mtime, cache_mtime))

        _, removed = self.install_and_remove()

        self.assertTrue(removed["hook_restored"])
        self.assertEqual(self.source.read_bytes(), original_source)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o444)
        self.assertEqual(self.source.stat().st_mtime_ns, source_mtime)
        self.assertEqual(self.bytecode.read_bytes(), original_cache)
        self.assertEqual(self.bytecode.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.bytecode.stat().st_mtime_ns, cache_mtime)

    def test_payload_runs_in_separate_namespace_from_original_platform_source(self):
        platform_source = b"PLATFORM_VALUE = 'kept'\n"
        payload = b"PLATFORM_VALUE = 'fixture'\n"
        combined = platform_source + native._fixture_appendage(payload)
        namespace = {"__name__": "sitecustomize", "__file__": str(self.source)}
        exec(compile(combined, str(self.source), "exec"), namespace)
        self.assertEqual(namespace["PLATFORM_VALUE"], "kept")

    def test_remove_refuses_changed_source_and_preserves_transaction_for_recovery(self):
        digest = hashlib.sha256(self.hook.read_bytes()).hexdigest()
        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            native.hook_install(digest)
            self.source.write_bytes(b"administrator changed source")
            with self.assertRaises(RuntimeError):
                native.hook_remove(digest)
        self.assertTrue(self.transaction.exists())

    def test_install_rename_interruption_is_recovered_by_remove(self):
        original = b"# original platform source\nPLATFORM_VALUE = 'kept'\n"
        self.source.write_bytes(original)
        os.chmod(self.source, 0o640)
        digest = hashlib.sha256(self.hook.read_bytes()).hexdigest()
        replace = native.os.replace

        def interrupt_install(source, destination):
            if Path(source).name.endswith(".adm-cases-install"):
                raise OSError("simulated interruption before install rename")
            return replace(source, destination)

        with (
            patch.object(native.os, "chown"),
            patch.object(native.os, "fchown"),
            patch.object(native.os, "replace", side_effect=interrupt_install),
        ):
            with self.assertRaises(OSError):
                native.hook_install(digest)
        self.assertTrue(self.transaction.exists())
        self.assertTrue(
            self.source.with_name(".sitecustomize.py.adm-cases-install").exists()
        )

        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            removed = native.hook_remove(digest)

        self.assertTrue(removed["hook_restored"])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse(self.backup.exists())

    def test_restore_rename_interruption_is_recovered_on_retry(self):
        original = b"# original platform source\nPLATFORM_VALUE = 'kept'\n"
        self.source.write_bytes(original)
        os.chmod(self.source, 0o640)
        digest = hashlib.sha256(self.hook.read_bytes()).hexdigest()
        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            native.hook_install(digest)

        replace = native.os.replace

        def interrupt_restore(source, destination):
            if Path(source).name.endswith(".adm-cases-restore"):
                raise OSError("simulated interruption before restore rename")
            return replace(source, destination)

        with (
            patch.object(native.os, "chown"),
            patch.object(native.os, "fchown"),
            patch.object(native.os, "replace", side_effect=interrupt_restore),
        ):
            with self.assertRaises(OSError):
                native.hook_remove(digest)
        self.assertTrue(self.transaction.exists())
        self.assertTrue(
            self.source.with_name(".sitecustomize.py.adm-cases-restore").exists()
        )

        with patch.object(native.os, "chown"), patch.object(native.os, "fchown"):
            removed = native.hook_remove(digest)

        self.assertTrue(removed["hook_restored"])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse(self.backup.exists())


if __name__ == "__main__":
    unittest.main()
