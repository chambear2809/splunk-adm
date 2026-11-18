import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "tools/qualify_native_interruption.py"
SPEC = importlib.util.spec_from_file_location("native_interruption", PATH)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class NativeInterruptionTests(unittest.TestCase):
    def test_exact_dispatch_is_durable_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            body = b'{ "x": 1 }\n'
            fixture.journal_dispatch(
                Path(directory).resolve(),
                principal="u",
                method="POST",
                path="/p",
                key="k",
                body=body,
            )
            saved = json.loads((Path(directory) / "dispatch.json").read_text())
            self.assertEqual(base64.b64decode(saved["body_base64"]), body)
            with self.assertRaises(FileExistsError):
                fixture.journal_dispatch(
                    Path(directory).resolve(),
                    principal="u",
                    method="POST",
                    path="/p",
                    key="k",
                    body=body,
                )

    def test_unsafe_directory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(RuntimeError):
                fixture.journal_dispatch(
                    Path(directory).resolve(),
                    principal="u",
                    method="POST",
                    path="/p",
                    key="k",
                    body=b"{}",
                )

    def test_signal_only_verified_worker_and_rechecks_identity(self):
        worker = dict(
            pid=101,
            uid=55,
            state="S",
            ppid=100,
            pgid=101,
            session=101,
            start_time=3,
            argv=[b"python3", b"-I", fixture.WORKER],
        )
        parent = dict(
            pid=100,
            uid=55,
            state="S",
            ppid=1,
            pgid=100,
            session=100,
            start_time=2,
            argv=[b"parent"],
        )
        child = dict(
            pid=102,
            uid=55,
            state="S",
            ppid=101,
            pgid=101,
            session=101,
            start_time=4,
            argv=[b"child"],
        )
        processes = {100: parent, 101: worker, 102: child}
        marker = dict(phase="precommit", pid=101, pgid=101, child_pid=102)
        expected = dict(
            uid=55,
            worker_start=3,
            parent_pid=100,
            parent_start=2,
            parent_argv_sha256=fixture.hashlib.sha256(b"parent\0").hexdigest(),
            child_start=4,
        )
        with (
            mock.patch.object(fixture.os, "pidfd_open", return_value=33, create=True),
            mock.patch.object(fixture.signal, "pidfd_send_signal", create=True) as send,
            mock.patch.object(fixture.os, "close"),
        ):
            fixture.interrupt_owned_worker(
                marker, expected, read_identity=processes.get
            )
            send.assert_called_once_with(33, fixture.signal.SIGKILL)
            child["start_time"] = 5
            with self.assertRaises(RuntimeError):
                fixture.interrupt_owned_worker(
                    marker, expected, read_identity=processes.get
                )
            send.assert_called_once()

    def test_pinned_hook_transform_rejects_unreviewed_bytes(self):
        root = PATH.parents[1]
        source = (root / "tests/splunk/case_request_fault_hook.py").read_bytes()
        transformed = fixture.transformed_hook(source)
        self.assertIn(os.fsencode(fixture.NATIVE_ROOT / "control"), transformed)
        self.assertNotIn(fixture._OLD_CONTROL, transformed)
        with self.assertRaises(RuntimeError):
            fixture.transformed_hook(source + b"# modified")
        helper = (root / "tests/splunk/case_request_native.py").read_bytes()
        module = fixture._load_helper(helper)
        self.assertEqual(module.CONTROL, fixture.NATIVE_ROOT / "control")
        with self.assertRaises(RuntimeError):
            fixture._load_helper(helper + b"# modified")

    def test_restore_attempted_after_uncertain_install_and_disable(self):
        calls = []

        def install():
            calls.append("install")
            raise ValueError("uncertain installation")

        def disable():
            calls.append("disable")
            raise OSError("uncertain disable")

        def restore():
            calls.append("restore")
            return {
                "hook_removed": True,
                "hook_restored": True,
                "cache_restored": True,
                "fixture_hook_active": False,
            }

        with self.assertRaises(ValueError) as error:
            with fixture.installed_native_hook(
                install, disable, restore, lambda x: calls.append(x)
            ):
                self.fail("install must fail")
        self.assertEqual(calls[:3], ["install", "disable", "restore"])
        self.assertIn("disable", error.exception.__notes__[0])

    def test_postcommit_phase_preserves_identity_and_retirement(self):
        import threading
        from types import SimpleNamespace

        event = threading.Event()
        marker = {"phase": "postcommit", "pid": 11, "pgid": 11, "child_pid": 12}
        jobs = [
            {"sid": "one", "state": "deleted", "native_absent": True},
            {"sid": "two", "state": "deleted", "native_absent": True},
        ]
        observations = iter(
            [
                {"receipt_count": 0, "capture_count": 2},
                {
                    "receipt_count": 1,
                    "capture_count": 3,
                    "receipt_digest": "d",
                    "capture_id": "c",
                    "new_jobs": jobs,
                },
                {
                    "receipt_count": 1,
                    "capture_count": 3,
                    "receipt_digest": "d",
                    "capture_id": "c",
                    "new_jobs": jobs,
                },
            ]
        )
        access = dict.fromkeys(
            [
                "revoked_read_redacted",
                "revoked_export_redacted",
                "revoked_exact_retry_redacted",
                "changed_config_read_redacted",
                "changed_config_export_redacted",
                "changed_config_exact_retry_redacted",
                "restored_read",
                "restored_exact_retry",
            ],
            True,
        )
        calls = []
        io = SimpleNamespace(
            inspect=lambda op: next(observations),
            arm=lambda mode, op: calls.append("arm"),
            dispatch=lambda op: event.wait(2),
            observe=lambda mode, op: {"marker_present": True, "marker": marker},
            interrupt=lambda m: event.set(),
            wait_retired=lambda m: {
                "worker_absent": True,
                "group_absent": True,
                "child_absent": True,
            },
            disable=lambda op: calls.append("disable"),
            retry=lambda op: calls.append("retry"),
            check_access=lambda op, ident: access,
        )
        operation = {
            "principal": "u",
            "method": "POST",
            "path": "/cases/1/captures",
            "key": "atlas_intr_" + "a" * 32,
            "body": b"{}",
        }
        with tempfile.TemporaryDirectory() as directory:
            result = fixture.run_capture_phase(
                "postcommit", operation, Path(directory).resolve(), io
            )
        self.assertEqual(result["after_retry"]["capture_id"], "c")
        self.assertEqual(calls, ["arm", "disable", "retry"])

    def test_checkpoint_mismatch_disables_without_signaling(self):
        import threading
        from types import SimpleNamespace

        event = threading.Event()
        observations = iter(
            [
                {"receipt_count": 0, "capture_count": 0},
                {"receipt_count": 1, "capture_count": 1},
            ]
        )
        calls = []
        io = SimpleNamespace(
            inspect=lambda op: next(observations),
            arm=lambda mode, op: calls.append("arm"),
            dispatch=lambda op: event.wait(2),
            observe=lambda mode, op: {
                "marker_present": True,
                "marker": {"phase": mode, "pid": 11, "pgid": 11, "child_pid": 12},
            },
            interrupt=lambda marker: calls.append("interrupt"),
            disable=lambda op: (calls.append("disable"), event.set()),
        )
        operation = {
            "principal": "u",
            "method": "POST",
            "path": "/cases/1/captures",
            "key": "atlas_intr_" + "a" * 32,
            "body": b"{}",
        }
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "cardinality"):
                fixture.run_capture_phase(
                    "precommit", operation, Path(directory).resolve(), io
                )
        self.assertEqual(calls, ["arm", "disable"])

    def test_unsafe_job_result_is_rejected(self):
        jobs = [
            {"sid": "one", "state": "deleted", "native_absent": True},
            {"sid": "two", "state": "deleted", "native_absent": False},
        ]
        with self.assertRaises(RuntimeError):
            fixture._check_jobs({"new_jobs": jobs})

    def test_libc_pidfd_fallback_and_errno(self):
        import ctypes
        from types import SimpleNamespace

        open_fn = mock.MagicMock(return_value=41)
        send_fn = mock.MagicMock(return_value=0)
        libc = SimpleNamespace(pidfd_open=open_fn, pidfd_send_signal=send_fn)
        with (
            mock.patch.object(fixture.os, "pidfd_open", None, create=True),
            mock.patch.object(fixture.signal, "pidfd_send_signal", None, create=True),
            mock.patch.object(ctypes, "CDLL", return_value=libc),
        ):
            # Force the fallback regardless of which Python APIs the test host exposes.
            with (
                mock.patch.object(fixture.os, "pidfd_open", create=True),
                mock.patch.object(fixture.signal, "pidfd_send_signal", create=True),
            ):
                pass
            # Remove API attributes temporarily so the feature test follows native behavior.
            with (
                mock.patch.object(fixture.os, "pidfd_open", create=True),
                mock.patch.object(fixture.signal, "pidfd_send_signal", create=True),
            ):
                del fixture.os.pidfd_open
                del fixture.signal.pidfd_send_signal
                opened, sent = fixture._pidfd_functions()
                self.assertEqual(opened(123), 41)
                sent(41, 9)
                open_fn.assert_called_with(123, 0)
                send_fn.assert_called_with(41, 9, None, 0)
                open_fn.return_value = -1
                with mock.patch.object(ctypes, "get_errno", return_value=3):
                    with self.assertRaises(OSError) as caught:
                        opened(123)
                    self.assertEqual(caught.exception.errno, 3)

    def test_pidfd_preflight_fails_closed_on_kernel_error(self):
        opened = mock.Mock(return_value=41)
        sent = mock.Mock(side_effect=OSError(38, "unavailable"))
        with (
            mock.patch.object(fixture, "_pidfd_functions", return_value=(opened, sent)),
            mock.patch.object(fixture.os, "close") as close,
        ):
            with self.assertRaises(OSError):
                fixture.pidfd_preflight()
            sent.assert_called_once_with(41, 0)
            close.assert_called_once_with(41)

    def test_incomplete_evidence_is_never_accepted(self):
        with self.assertRaises(RuntimeError):
            fixture.validate_evidence({"worker_killed": True})


if __name__ == "__main__":
    unittest.main()
