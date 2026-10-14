import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.lab_lock import (
    LabLock,
    LabLockError,
    default_lock_path,
    main,
    run_main,
)


class LabLockTest(unittest.TestCase):
    def test_default_path_is_shared_across_clones(self):
        self.assertEqual(
            default_lock_path("/clone-one"), default_lock_path("/clone-two")
        )

    def test_independent_process_is_rejected_and_nested_child_is_allowed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            ready = Path(directory) / "ready"
            script = (
                "import pathlib,time; pathlib.Path(%r).touch(); time.sleep(2)"
                % str(ready)
            )
            with LabLock(path=path):
                child = subprocess.Popen([sys.executable, "-c", script])
                while not ready.exists():
                    time.sleep(0.01)
                unrelated_env = os.environ.copy()
                for key in (
                    "SPLUNK_ADM_LAB_LOCK_TOKEN",
                    "SPLUNK_ADM_LAB_LOCK_PATH",
                    "SPLUNK_ADM_LAB_LOCK_PID",
                    "SPLUNK_ADM_LAB_LOCK_ACTIVE",
                ):
                    unrelated_env.pop(key, None)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "from tools.lab_lock import LabLock; LabLock(path=%r).acquire()"
                        % str(path),
                    ],
                    capture_output=True,
                    text=True,
                    env=unrelated_env,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("already locked", result.stderr)
                nested = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "from tools.lab_lock import LabLock; LabLock(path=%r).acquire(); print('ok')"
                        % str(path),
                    ],
                    capture_output=True,
                    text=True,
                    env=os.environ,
                )
                self.assertEqual(nested.returncode, 0, nested.stderr)
                child.wait()

    def test_release_and_stale_token_are_reusable(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            with LabLock(path=path):
                pass
            with LabLock(path=path):
                self.assertTrue(path.read_text())
            self.assertEqual(path.read_text(), "")

            os.environ.update(
                {
                    "SPLUNK_ADM_LAB_LOCK_TOKEN": "stale",
                    "SPLUNK_ADM_LAB_LOCK_PATH": str(path),
                    "SPLUNK_ADM_LAB_LOCK_PID": "99999999",
                }
            )
            with LabLock(path=path):
                self.assertNotEqual(path.read_text(), "")
            for key in (
                "SPLUNK_ADM_LAB_LOCK_TOKEN",
                "SPLUNK_ADM_LAB_LOCK_PATH",
                "SPLUNK_ADM_LAB_LOCK_PID",
            ):
                os.environ.pop(key, None)

    def test_check_owned_rejects_stale_active_environment(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            os.environ.update(
                {
                    "SPLUNK_ADM_LAB_LOCK_TOKEN": "stale",
                    "SPLUNK_ADM_LAB_LOCK_PATH": str(path),
                    "SPLUNK_ADM_LAB_LOCK_PID": "99999999",
                }
            )
            self.assertEqual(main(["--root", directory, "--check-owned"]), 1)
            for key in (
                "SPLUNK_ADM_LAB_LOCK_TOKEN",
                "SPLUNK_ADM_LAB_LOCK_PATH",
                "SPLUNK_ADM_LAB_LOCK_PID",
            ):
                os.environ.pop(key, None)

    def test_signal_terminates_child_before_lock_release(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            ready = Path(directory) / "ready"
            child_pid = Path(directory) / "child.pid"
            grandchild_pid = Path(directory) / "grandchild.pid"
            grandchild_script = (
                "import os,pathlib,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "pathlib.Path(%r).write_text(str(os.getpid())); time.sleep(30)"
                % str(grandchild_pid)
            )
            child_script = (
                "import os,pathlib,signal,subprocess,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "g=subprocess.Popen(%r); "
                "pathlib.Path(%r).write_text(str(os.getpid())); pathlib.Path(%r).touch(); time.sleep(30)"
                % (
                    [sys.executable, "-c", grandchild_script],
                    str(child_pid),
                    str(ready),
                )
            )
            wrapper_script = (
                "from tools.lab_lock import run_locked; raise SystemExit(run_locked(%r, path=%r))"
                % ([sys.executable, "-c", child_script], str(path))
            )
            wrapper_env = os.environ.copy()
            for key in (
                "SPLUNK_ADM_LAB_LOCK_TOKEN",
                "SPLUNK_ADM_LAB_LOCK_PATH",
                "SPLUNK_ADM_LAB_LOCK_PID",
            ):
                wrapper_env.pop(key, None)
            wrapper = subprocess.Popen(
                [sys.executable, "-c", wrapper_script], env=wrapper_env
            )
            while not ready.exists():
                time.sleep(0.01)
            os.kill(wrapper.pid, signal.SIGTERM)
            wrapper.wait(timeout=10)
            self.assertNotEqual(wrapper.returncode, 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(grandchild_pid.read_text()), 0)
            with LabLock(path=path):
                pass

    def test_symlink_lock_is_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            target = Path(directory) / "victim"
            target.write_text("safe")
            path.symlink_to(target)
            with self.assertRaisesRegex(LabLockError, "unsafe lab lock"):
                LabLock(path=path).acquire()

    def test_hardlink_lock_is_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            target = Path(directory) / "victim"
            target.write_text("safe")
            os.link(target, path)
            with self.assertRaisesRegex(LabLockError, "unsafe lab lock"):
                LabLock(path=path).acquire()

    def test_run_main_calls_owned_main(self):
        with TemporaryDirectory() as directory:
            calls = []
            path = Path(directory) / "lab.lock"
            with LabLock(path=path):
                result = run_main(
                    lambda: calls.append("called") or 7, root=directory, path=path
                )
            self.assertEqual(result, 7)
            self.assertEqual(calls, ["called"])

    def test_nested_run_locked_stays_in_outer_process_group(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lab.lock"
            pgid_file = Path(directory) / "pgid"
            outer_pgid_file = Path(directory) / "outer-pgid"
            nested = (
                "import os,pathlib; pathlib.Path(%r).write_text(str(os.getpgrp())); "
                "from tools.lab_lock import run_locked; "
                "run_locked([%r, '-c', %r], path=%r)"
                % (
                    str(outer_pgid_file),
                    sys.executable,
                    "import os,pathlib; pathlib.Path(%r).write_text(str(os.getpgrp()))"
                    % str(pgid_file),
                    str(path),
                )
            )
            outer = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "from tools.lab_lock import run_locked; run_locked(%r, path=%r)"
                    % ([sys.executable, "-c", nested], str(path)),
                ]
            )
            outer.wait(timeout=10)
            self.assertEqual(outer.returncode, 0)
            self.assertEqual(
                int(pgid_file.read_text()), int(outer_pgid_file.read_text())
            )


if __name__ == "__main__":
    unittest.main()
