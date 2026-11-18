import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "tools/qualify_native_service_restart.py"
SPEC = importlib.util.spec_from_file_location("restart_fixture", PATH)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class NativeServiceRestartTests(unittest.TestCase):
    def setUp(self):
        self.marker = {"phase": "precommit", "pid": 100, "pgid": 100, "child_pid": 101}
        self.old = {
            "unit": "splunk.service",
            "active": True,
            "main_pid": 10,
            "main_start": 1,
            "invocation": "a" * 32,
            "cgroup": "/system.slice/splunk.service",
        }
        self.new = {**self.old, "main_pid": 11, "main_start": 2, "invocation": "b" * 32}
        self.checkpoint = {
            "worker_pid": 100,
            "child_pid": 101,
            "worker_cgroup": self.old["cgroup"],
            "parent_cgroup": self.old["cgroup"],
            "child_cgroup": self.old["cgroup"],
            "identities_verified": True,
        }
        self.io = mock.Mock(unsafe=True)
        self.io.service_identity.return_value = self.old
        self.io.checkpoint_identity.return_value = self.checkpoint
        self.io.assert_checkpoint_live.return_value = True
        self.io.launch_restart.return_value = {
            "command_pid": 200,
            "exit_status": 0,
            "worker_live_on_launch": True,
        }
        self.io.wait_ready.return_value = self.new
        self.io.old_process_absent.return_value = True

    def test_intent_precedes_restart_and_new_service_is_verified(self):
        order = []
        self.io.journal.side_effect = lambda value: order.append(value["state"])
        self.io.launch_restart.side_effect = lambda: (
            order.append("launch")
            or {"command_pid": 200, "exit_status": 0, "worker_live_on_launch": True}
        )
        result = fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.assertEqual(
            order, ["service_restart_intent", "launch", "service_restart_verified"]
        )
        self.assertEqual(result["new_service"], self.new)

    def test_component_descendant_cgroup_is_accepted(self):
        self.io.checkpoint_identity.return_value = {
            **self.checkpoint,
            "worker_cgroup": self.old["cgroup"] + "/worker",
        }
        fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.launch_restart.assert_called_once()

    def test_similar_prefix_is_not_a_service_descendant(self):
        self.io.checkpoint_identity.return_value = {
            **self.checkpoint,
            "worker_cgroup": self.old["cgroup"] + "-other/worker",
        }
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.launch_restart.assert_not_called()

    def test_checkpoint_wrong_service_never_restarts(self):
        self.io.checkpoint_identity.return_value = {
            **self.checkpoint,
            "worker_cgroup": "/other",
        }
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.launch_restart.assert_not_called()

    def test_old_service_or_worker_change_blocks_launch(self):
        self.io.assert_checkpoint_live.return_value = False
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.launch_restart.assert_not_called()

    def test_worker_must_still_be_held_when_command_launches(self):
        self.io.launch_restart.return_value = {
            "command_pid": 200,
            "exit_status": 0,
            "worker_live_on_launch": False,
        }
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.wait_ready.assert_not_called()
        self.assertEqual(self.io.journal.call_count, 1)

    def test_missing_new_invocation_is_not_a_restart(self):
        self.io.wait_ready.return_value = {
            **self.new,
            "invocation": self.old["invocation"],
        }
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.assertEqual(self.io.journal.call_count, 1)

    def test_failed_intent_journal_never_launches_restart(self):
        self.io.journal.side_effect = OSError("journal unavailable")
        with self.assertRaises(OSError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.launch_restart.assert_not_called()

    def test_old_main_must_be_gone_before_restart_passes(self):
        self.io.old_process_absent.return_value = False
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.assertEqual(self.io.journal.call_count, 1)

    def test_service_change_after_intent_fails_before_launch(self):
        self.io.service_identity.side_effect = [self.old, self.new]
        with self.assertRaises(RuntimeError):
            fixture.restart_at_checkpoint(self.io, "precommit", self.marker)
        self.io.launch_restart.assert_not_called()

    def test_command_pid_is_journaled_before_wait(self):
        order = []
        process = mock.Mock(pid=210)
        process.wait.side_effect = lambda **kwargs: order.append("wait") or 0
        fixture.execute_restart(
            popen=mock.Mock(return_value=process),
            on_launch=lambda pid: order.append(("started", pid)),
        )
        self.assertEqual(order, [("started", 210), "wait"])

    def test_timeout_never_kills_restart_command(self):
        process = mock.Mock(pid=210)
        process.wait.side_effect = subprocess.TimeoutExpired(fixture.RESTART_COMMAND, 1)
        factory = mock.Mock(return_value=process)
        with self.assertRaises(RuntimeError):
            fixture.execute_restart(popen=factory, timeout=1)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.assertEqual(factory.call_args.args[0], fixture.RESTART_COMMAND)


if __name__ == "__main__":
    unittest.main()
