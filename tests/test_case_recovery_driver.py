"""Parent lock lifetime and child retirement without Docker mutations."""

from contextlib import contextmanager
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import rehearse_case_recovery as driver
from lab_lock import LabLock


class RecoveryDriverTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        self.runtime.chmod(0o700)
        handlers = {
            s: signal.getsignal(s)
            for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        }
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in handlers.items()])
        self.subject = driver.Rehearsal(
            SimpleNamespace(
                runtime=self.runtime,
                package=self.runtime / "unused.tar.gz",
                package_sha256="a" * 64,
                extracted=self.runtime,
                socket="unix:///unused.sock",
            )
        )

    def test_each_child_has_own_lock_and_failure_cleanup_keeps_all_locks(self):
        lock_paths = {}
        checked = []

        @contextmanager
        def lock_factory(_root):
            name = os.environ["ADM_LAB_NAME"]
            path = self.runtime / (name + ".lock")
            lock_paths[name] = path
            with LabLock(path=path) as lock:
                yield lock

        def check_all():
            for kind, (_task, name) in driver.TASKS.items():
                with patch.dict(os.environ, self.subject.envs[kind], clear=True):
                    self.assertTrue(LabLock(path=lock_paths[name]).check_owned())

        def exercise():
            check_all()
            self.assertEqual(
                len(
                    {e["SPLUNK_ADM_LAB_LOCK_TOKEN"] for e in self.subject.envs.values()}
                ),
                3,
            )
            self.subject.created.update(driver.TASKS)
            raise RuntimeError("synthetic primary failure")

        def cleanup(kind):
            check_all()
            checked.append(kind)
            self.subject.created.remove(kind)

        before = os.environ.copy()
        with (
            patch.object(driver, "LabLock", lock_factory),
            patch.object(self.subject, "preflight"),
            patch.object(self.subject, "exercise", side_effect=exercise),
            patch.object(self.subject, "purge", side_effect=cleanup),
            patch.object(self.subject, "persist", side_effect=OSError("no storage")),
        ):
            with self.assertRaisesRegex(RuntimeError, "rehearsal failed"):
                self.subject.execute()
        self.assertEqual(os.environ.copy(), before)
        self.assertEqual(set(checked), set(driver.TASKS))
        for path in lock_paths.values():
            self.assertFalse(LabLock(path=path).check_owned())

    def test_timeout_and_completed_leader_retire_descendants(self):
        self.subject.envs["source"] = os.environ.copy()
        for completed in (False, True):
            heartbeat = self.runtime / f"heartbeat-{completed}"
            code = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                f"p=pathlib.Path({str(heartbeat)!r}); "
                "exec('while True:\\n p.write_text(str(time.monotonic()))\\n time.sleep(.02)')"
            )
            leader = (
                "import pathlib,subprocess,sys,time; "
                f"p=subprocess.Popen([sys.executable,'-c',{code!r}]); "
                f"f=pathlib.Path({str(heartbeat)!r}); "
                "exec('while not f.exists(): time.sleep(.01)'); "
                + ("sys.exit(0)" if completed else "p.wait()")
            )

            def action():
                self.subject.run(
                    "retire-" + str(completed),
                    "source",
                    [sys.executable, "-c", leader],
                    timeout=0.5,
                )

            if completed:
                action()
            else:
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    action()
            self.assertTrue(heartbeat.exists())
            time.sleep(0.1)
            previous = heartbeat.read_bytes()
            time.sleep(0.15)
            self.assertEqual(heartbeat.read_bytes(), previous)
        self.subject.cancelled = True
        self.subject.run(
            "cleanup-after-cancel",
            "source",
            [sys.executable, "-c", "pass"],
            cleanup=True,
        )

    def test_cleanup_runs_when_receipts_and_logs_cannot_be_written(self):
        self.subject.envs["source"] = os.environ.copy()
        marker = self.runtime / "cleanup-was-executed"
        original_open = os.open

        def failing_log_open(path, *args, **kwargs):
            if Path(path).suffix == ".log":
                raise OSError("synthetic output storage failure")
            return original_open(path, *args, **kwargs)

        with (
            patch.object(self.subject, "persist", side_effect=OSError("no storage")),
            patch.object(driver.os, "open", side_effect=failing_log_open),
        ):
            self.subject.run(
                "cleanup-without-storage",
                "source",
                [sys.executable, "-c", f"open({str(marker)!r},'w').close()"],
                cleanup=True,
            )
        self.assertTrue(marker.exists())
        self.assertEqual(self.subject.receipt["status"], "failed_or_uncertain")
        self.assertTrue(self.subject.receipt["reporting_errors"])

    def test_signal_cancels_active_child_before_cleanup(self):
        self.subject.envs["source"] = os.environ.copy()
        ready = self.runtime / "signal-child-ready"

        def cancel_when_ready():
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if ready.exists():
                os.kill(os.getpid(), signal.SIGTERM)

        thread = threading.Thread(target=cancel_when_ready)
        thread.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                self.subject.run(
                    "signal-cancel",
                    "source",
                    [
                        sys.executable,
                        "-c",
                        f"import time;open({str(ready)!r},'w').close();time.sleep(30)",
                    ],
                    timeout=5,
                )
        finally:
            thread.join(timeout=4)
        self.assertTrue(self.subject.cancelled)
        self.assertEqual(
            self.subject.receipt["phases"]["signal-cancel"]["state"],
            "uncertain_timeout_or_cancel",
        )
        self.assertLess(
            self.subject.receipt["phases"]["signal-cancel"]["returncode"], 0
        )


if __name__ == "__main__":
    unittest.main()
