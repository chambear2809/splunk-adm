import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.platform_recovery_admission import (
    AdmissionError,
    Capacity,
    Lease,
    admit_packet,
    charge_tree,
)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.close, self.fd)

    def test_packet_exact_inventory_and_changed_bytes(self):
        path = self.root / "worker.py"
        path.write_bytes(b"approved")
        path.chmod(0o444)
        expected = {"worker.py": hashlib.sha256(b"approved").hexdigest()}
        self.assertEqual(
            set(admit_packet(self.fd, expected, owner_uid=os.getuid())), {"worker.py"}
        )
        path.chmod(0o644)
        path.write_bytes(b"changed")
        path.chmod(0o444)
        with self.assertRaises(AdmissionError):
            admit_packet(self.fd, expected, owner_uid=os.getuid())
        (self.root / "extra.py").write_bytes(b"extra")
        with self.assertRaises(AdmissionError):
            admit_packet(self.fd, expected, owner_uid=os.getuid())

    def test_packet_rejects_symlink(self):
        (self.root / "worker.py").symlink_to("/dev/null")
        with self.assertRaises((AdmissionError, OSError)):
            admit_packet(self.fd, {"worker.py": "0" * 64}, owner_uid=os.getuid())

    def test_tree_counts_wal_and_stale_files_and_preserves_high_water(self):
        for name in (
            "observer.db",
            "observer.db-wal",
            "observer.db-shm",
            "observer.stale",
        ):
            (self.root / name).write_bytes(b"x" * 1000)
        charge = charge_tree(self.fd, require_mount_identity=False)
        self.assertGreaterEqual(charge, 4000)
        capacity = Capacity(charge + 100)
        self.assertEqual(capacity.observe(charge, 100, 200, 100), charge)
        self.assertEqual(capacity.observe(1, 100, 200, 100), charge)
        with self.assertRaises(AdmissionError):
            capacity.observe(1, 101, 201, 100)
        (self.root / "alias").symlink_to("observer.db")
        with self.assertRaises(AdmissionError):
            charge_tree(self.fd, require_mount_identity=False)

    def test_packet_growth_is_bounded(self):
        path = self.root / "worker.py"
        path.write_bytes(b"abc")
        path.chmod(0o444)
        calls = []

        def grow(_fd, size):
            calls.append(size)
            return b"x" * size

        with patch("tools.platform_recovery_admission.os.read", side_effect=grow):
            with self.assertRaisesRegex(AdmissionError, "grew"):
                admit_packet(self.fd, {"worker.py": "0" * 64}, owner_uid=os.getuid())
        self.assertEqual(calls, [4])

    def test_packet_rejects_nul_and_unexpected_entry(self):
        with self.assertRaises(AdmissionError):
            admit_packet(self.fd, {"bad\0name": "0" * 64}, owner_uid=os.getuid())
        (self.root / "extra").write_bytes(b"x")
        with self.assertRaisesRegex(AdmissionError, "inventory"):
            admit_packet(self.fd, {"missing": "0" * 64}, owner_uid=os.getuid())

    def test_tree_refuses_hardlink_and_fifo(self):
        first = self.root / "data"
        first.write_bytes(b"data")
        os.link(first, self.root / "alias")
        with self.assertRaisesRegex(AdmissionError, "hard link"):
            charge_tree(self.fd, require_mount_identity=False)
        (self.root / "alias").unlink()
        os.mkfifo(self.root / "pipe")
        with self.assertRaisesRegex(AdmissionError, "unsupported"):
            charge_tree(self.fd, require_mount_identity=False)

    def test_tree_refuses_mismatched_or_missing_mount_identity(self):
        (self.root / "data").write_bytes(b"x")
        with patch("tools.platform_recovery_admission._mount_id", side_effect=[1, 2]):
            with self.assertRaisesRegex(AdmissionError, "mount boundary"):
                charge_tree(self.fd)
        with patch(
            "tools.platform_recovery_admission._mount_id",
            side_effect=OSError("missing procfs"),
        ):
            with self.assertRaises(OSError):
                charge_tree(self.fd)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs required")
    def test_native_linux_mount_identity(self):
        (self.root / "data").write_bytes(b"x")
        self.assertGreater(charge_tree(self.fd), 0)

    def test_lease_order_expiry_and_reuse(self):
        lease = Lease("a" * 32, 10)
        with self.assertRaises(AdmissionError):
            lease.transition("new", "active", 1)
        lease.transition("new", "admitted", 1)
        lease.transition("admitted", "active", 2)
        with self.assertRaises(AdmissionError):
            lease.transition("active", "retired", 10)
        lease.transition("active", "retired", 9)
        with self.assertRaises(AdmissionError):
            lease.transition("new", "admitted", 9)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs required")
    def test_parent_inherited_flock_and_release(self):
        # A child tests the actual direct-parent identity and inherited lock.
        script = """import fcntl, os, sys\nfrom tools.platform_recovery_admission import verify_inherited_lock\np=sys.argv[1]; f=os.open(p, os.O_CREAT|os.O_RDWR, 0o600); fcntl.flock(f, fcntl.LOCK_EX)\nr=open('/proc/self/stat').read(); tick=int(r[r.rfind(')')+2:].split()[19])\nc="from tools.platform_recovery_admission import verify_inherited_lock; import os,sys; verify_inherited_lock(int(sys.argv[1]),int(sys.argv[1]),os.getppid(),int(sys.argv[2]),sys.argv[3])"\nimport subprocess\nsubprocess.run([sys.executable,'-c',c,str(f),str(tick),p],pass_fds=(f,),check=True,timeout=5)\nfcntl.flock(f,fcntl.LOCK_UN)\nr=subprocess.run([sys.executable,'-c',c,str(f),str(tick),p],pass_fds=(f,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)\nassert r.returncode != 0\n"""
        subprocess.run(
            [sys.executable, "-c", script, str(self.root / "lock")],
            check=True,
            timeout=15,
        )


if __name__ == "__main__":
    unittest.main()
