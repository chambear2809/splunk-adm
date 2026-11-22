import contextlib
import importlib.util
import io
import os
import json
import subprocess
import sys
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "tools/validation_udp_spool.py"
spec = importlib.util.spec_from_file_location("validation_udp_spool", PATH)
spool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spool)


class Sender:
    def __init__(self, fail=False):
        self.fail = fail
        self.sent = []
        self.options = []
        self.bound = None

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, addr):
        self.bound = addr

    def sendto(self, payload, addr):
        if self.fail:
            raise OSError("synthetic send failure")
        self.sent.append((payload, addr))
        return len(payload)

    def close(self):
        pass


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_umask = os.umask(0o077)
        self.db = spool.Spool(self.root, 8 * 1024 * 1024, 100, 2)

    def tearDown(self):
        if self.db:
            self.db.close()
        os.umask(self.old_umask)
        self.tmp.cleanup()

    def test_fidelity_restart_and_send_not_indexed(self):
        source, dest = ("192.0.2.2", 1234), ("198.51.100.5", 9995)
        data = b"\x00\xff\x00netflow"
        self.assertTrue(self.db.record(data, source, dest, 123456789))
        self.db.close()
        self.db = spool.Spool(self.root, 8 * 1024 * 1024, 100, 2)
        row = self.db.db.execute(
            "SELECT observed_ns,source_ip,source_port,observed_destination_ip,observed_destination_port,payload FROM packets"
        ).fetchone()
        self.assertEqual(row, (123456789, *source, *dest, data))
        self.db.record(b"second", source, dest, 123456790)
        sender = Sender()
        self.assertEqual(
            spool.replay(self.db, dest, socket_factory=lambda *_: sender), 2
        )
        self.assertEqual(sender.sent, [(data, dest), (b"second", dest)])
        self.assertEqual(self.db.report()["indexed_delivery"], "unknown")
        self.assertEqual(self.db.report()["queued"], 0)
        self.assertEqual(
            spool.replay(self.db, dest, socket_factory=lambda *_: sender), 0
        )

    def test_failure_keeps_queue_and_transparent_source_binding(self):
        self.db.record(b"x", ("192.0.2.1", 1111), ("192.0.2.3", 2222), 5)
        with self.assertRaises(OSError):
            spool.replay(
                self.db, ("192.0.2.3", 2222), socket_factory=lambda *_: Sender(True)
            )
        self.assertEqual(self.db.report()["queued"], 1)
        sender = Sender()
        spool.replay(self.db, ("192.0.2.3", 2222), True, lambda *_: sender)
        self.assertEqual(sender.bound, ("192.0.2.1", 1111))
        self.assertIn((socket.SOL_IP, spool.IP_TRANSPARENT, 1), sender.options)

    def test_bounds_and_permissions(self):
        addr = ("127.0.0.1", 12)
        self.assertTrue(self.db.record(b"a" * 60, addr, addr, 1))
        self.assertFalse(self.db.record(b"b" * 41, addr, addr, 2))
        self.assertEqual(self.db.report()["counters"]["queue_overflow"], 1)
        self.assertEqual(self.db.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "udp-spool.lock").stat().st_mode & 0o777, 0o600)
        self.db.close()
        self.db = None
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            spool.Spool(self.root, 8 * 1024 * 1024, 100, 2)
        self.root.chmod(0o700)

    def test_capture_truncated_not_saved_and_destination_fidelity(self):
        class Receiver(Sender):
            def __init__(self):
                super().__init__()
                self.messages = iter(
                    [
                        (b"cut", [], socket.MSG_TRUNC, ("192.0.2.1", 222)),
                        (
                            b"whole",
                            [
                                (
                                    socket.SOL_IP,
                                    spool.IP_PKTINFO,
                                    struct.pack(
                                        "=I4s4s",
                                        1,
                                        b"\0" * 4,
                                        socket.inet_aton("127.0.0.1"),
                                    ),
                                )
                            ],
                            0,
                            ("192.0.2.1", 222),
                        ),
                    ]
                )

            def recvmsg(self, *_):
                try:
                    return next(self.messages)
                except StopIteration:
                    raise KeyboardInterrupt

        with (
            mock.patch.object(spool.socket, "socket", return_value=Receiver()),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(spool.CaptureLoss),
        ):
            spool.capture(self.db, ("0.0.0.0", 9995), 10)
        self.assertEqual(self.db.report()["queued"], 0)
        self.assertEqual(
            self.db.report()["counters"]["truncated_or_missing_destination"], 1
        )

    def test_readonly_status_with_active_writer_and_process_lock(self):
        addr = ("127.0.0.1", 12)
        self.db.record(b"abc", addr, addr, 1)
        before = {p.name for p in self.root.iterdir()}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(spool.main(["status", "--spool-dir", str(self.root)]), 0)
        self.assertEqual(json.loads(output.getvalue())["queued"], 1)
        self.assertEqual(before, {p.name for p in self.root.iterdir()})
        status = subprocess.run(
            [sys.executable, str(PATH), "status", "--spool-dir", str(self.root)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["queued"], 1)
        self.assertEqual(before, {p.name for p in self.root.iterdir()})
        cmd = [
            sys.executable,
            str(PATH),
            "capture",
            "--spool-dir",
            str(self.root),
            "--listen",
            "127.0.0.1:1234",
            "--apply",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.db.report()["queued"], 1)

    def test_queue_state_restart_and_index_plan(self):
        addr = ("127.0.0.1", 12)
        self.db.record(b"one", addr, addr, 1)
        self.db.record(b"two", addr, addr, 2)
        plan = self.db.db.execute(
            "EXPLAIN QUERY PLAN SELECT seq,source_ip,source_port,payload FROM packets WHERE sent_ns IS NULL ORDER BY seq LIMIT 1"
        ).fetchall()
        self.assertIn("packets_pending", str(plan))
        sender = Sender()
        spool.replay(self.db, addr, socket_factory=lambda *_: sender)
        self.assertEqual(
            (self.db.report()["queued"], self.db.report()["queued_payload_bytes"]),
            (0, 0),
        )
        self.db.close()
        self.db = spool.Spool(self.root, 8 * 1024 * 1024, 100, 2)
        self.assertEqual(
            (self.db.report()["queued"], self.db.report()["queued_payload_bytes"]),
            (0, 0),
        )

    def test_replay_interrupt_returns_130_preserving_queue(self):
        addr = ("127.0.0.1", 12)
        self.db.record(b"one", addr, addr, 1)
        self.db.close()
        self.db = None
        with (
            mock.patch.object(spool, "replay", side_effect=KeyboardInterrupt),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = spool.main(
                [
                    "replay",
                    "--spool-dir",
                    str(self.root),
                    "--destination",
                    "127.0.0.1:12",
                    "--allow-destination",
                    "127.0.0.1:12",
                    "--ack-duplicate-risk",
                    "--apply",
                ]
            )
        self.assertEqual(result, 130)
        self.db = spool.Spool(self.root, 8 * 1024 * 1024, 100, 2)
        self.assertEqual(self.db.report()["queued"], 1)

    def test_preview_displays_effective_values(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            spool.main(
                [
                    "replay",
                    "--spool-dir",
                    str(self.root),
                    "--destination",
                    "192.0.2.5:9995",
                    "--allow-destination",
                    "192.0.2.5:9995",
                    "--transparent-source",
                ]
            )
        result = json.loads(output.getvalue())
        self.assertEqual(result["destination"], ["192.0.2.5", 9995])
        self.assertEqual(result["spool_dir"], str(self.root))
        self.assertTrue(result["transparent_source"])
        self.assertTrue(result["warnings"])

    def test_new_class_files_private_despite_caller_umask(self):
        self.db.close()
        self.db = None
        with tempfile.TemporaryDirectory() as tmp:
            os.umask(0)
            obj = spool.Spool(tmp, 8 * 1024 * 1024, 100, 2)
            try:
                self.assertEqual(obj.path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    (Path(tmp) / "udp-spool.lock").stat().st_mode & 0o777, 0o600
                )
            finally:
                obj.close()

    def test_capture_packet_identity_and_fail_closed_overflow(self):
        class Receiver(Sender):
            def __init__(self):
                super().__init__()
                self.packet = (
                    b"abc",
                    [
                        (
                            socket.SOL_IP,
                            spool.IP_PKTINFO,
                            struct.pack(
                                "=I4s4s", 1, b"\0" * 4, socket.inet_aton("127.0.0.1")
                            ),
                        )
                    ],
                    0,
                    ("192.0.2.9", 3333),
                )

            def recvmsg(self, *_):
                return self.packet

        self.db.max_records = 1
        with (
            mock.patch.object(spool.socket, "socket", return_value=Receiver()),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(spool.CaptureLoss),
        ):
            spool.capture(self.db, ("0.0.0.0", 9995), 100)
        self.assertEqual(
            self.db.db.execute(
                "SELECT source_ip,source_port,observed_destination_ip,observed_destination_port,payload FROM packets"
            ).fetchone(),
            ("192.0.2.9", 3333, "127.0.0.1", 9995, b"abc"),
        )
        self.assertEqual(self.db.report()["counters"]["queue_overflow"], 1)

    def test_cli_rejects_unsafe_and_dry_run_does_not_write(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            spool.main(
                [
                    "replay",
                    "--spool-dir",
                    str(self.root),
                    "--destination",
                    "127.0.0.1:9",
                    "--allow-destination",
                    "127.0.0.2:9",
                    "--apply",
                    "--ack-duplicate-risk",
                ]
            )
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            spool.main(
                [
                    "replay",
                    "--spool-dir",
                    str(self.root),
                    "--destination",
                    "127.0.0.1:9",
                    "--allow-destination",
                    "127.0.0.1:9",
                    "--apply",
                ]
            )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                spool.main(
                    [
                        "capture",
                        "--spool-dir",
                        str(self.root / "absent"),
                        "--listen",
                        "127.0.0.1:9",
                    ]
                ),
                0,
            )
        self.assertFalse((self.root / "absent").exists())


if __name__ == "__main__":
    unittest.main()
