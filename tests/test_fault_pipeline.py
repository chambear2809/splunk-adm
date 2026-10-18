"""Safety checks for the process-interruption rehearsal (no Docker required)."""

import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from tools import fault_pipeline as fault
import lab_lock


class FaultPipelineTest(unittest.TestCase):
    def setUp(self):
        self._lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._lock_directory.cleanup)
        lock_path = Path(self._lock_directory.name) / "lab.lock"
        self._lock_path_patch = patch.object(
            lab_lock, "default_lock_path", return_value=lock_path
        )
        self._lock_path_patch.start()
        self.addCleanup(self._lock_path_patch.stop)

    def test_kv_readiness_waits_for_engine_and_data(self):
        def state(value):
            return {"entry": [{"content": {"current": {"status": value}}}]}

        with (
            patch.object(
                fault.lab,
                "_json",
                side_effect=[
                    state("starting"),
                    state("ready"),
                    fault.lab.LabError("initializing"),
                    state("ready"),
                    [],
                ],
            ) as request,
            patch.object(fault.time, "sleep") as sleep,
        ):
            fault.wait_kv_ready(timeout=1)
        self.assertEqual(sleep.call_count, 2)
        self.assertIn("/storage/collections/data/", request.call_args.args[1])

    def test_wait_bootstrap_requires_completion_marker(self):
        with patch.object(
            fault,
            "_docker",
            side_effect=[
                "2026-10-13T00:00:00Z",
                "startup\nAnsible playbook complete\n",
            ],
        ) as docker:
            fault.wait_bootstrap(timeout=1)
        self.assertEqual(
            docker.call_args_list[1].args[:3],
            ("logs", "--since", "2026-10-13T00:00:00Z"),
        )

    def test_wait_bootstrap_times_out_without_completion_marker(self):
        with (
            patch.object(fault, "_docker", side_effect=["started", "still starting"]),
            self.assertRaisesRegex(TimeoutError, "playbook"),
        ):
            fault.wait_bootstrap(timeout=0)

    def test_preflight_failure_does_not_reset_or_restore_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with (
                patch.object(
                    fault, "preflight", side_effect=ValueError("remote Docker")
                ),
                patch.object(fault, "reset_lab") as reset,
                patch.object(fault, "restore_container") as restore,
                patch.object(fault, "_docker") as docker,
            ):
                result = fault.main(["--reset-lab", "--output", str(output)])
            self.assertEqual(result, 1)
            reset.assert_not_called()
            restore.assert_not_called()
            docker.assert_not_called()
            self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def test_cleanup_failure_returns_failed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with (
                patch.object(fault, "preflight", return_value={}),
                patch.object(fault, "reset_lab"),
                patch.object(fault, "load_events", return_value=(1, "digest")),
                patch.object(fault, "wait_count"),
                patch.object(fault, "raw_identity_digest", return_value="identity"),
                patch.object(fault, "dispatch_rollup", return_value="sid"),
                patch.object(fault, "observe_running", return_value={"is_done": False}),
                patch.object(
                    fault, "kill_container", return_value={"after_kill": "exited"}
                ),
                patch.object(
                    fault,
                    "restore_container",
                    side_effect=RuntimeError("restore failed"),
                ),
                patch.object(fault.time, "time", side_effect=[100, 101]),
            ):
                result = fault.main(["--reset-lab", "--output", str(output)])
            report = json.loads(output.read_text())
            self.assertEqual(result, 1)
            self.assertEqual(report["status"], "failed")
            self.assertIn("restore failed", report["restore_error"])

    def test_kill_requires_a_running_container_and_records_sigkill(self):
        with (
            patch.object(fault, "_docker", side_effect=["running", "exited"]),
            patch.object(fault.subprocess, "run") as run,
        ):
            evidence = fault.kill_container()
        self.assertEqual(evidence["signal"], "SIGKILL (docker kill)")
        self.assertEqual(run.call_args.args[0], ["docker", "kill", fault.CONTAINER])

    def test_running_observation_rejects_already_completed_job(self):
        with (
            patch.object(
                fault.lab,
                "_json",
                return_value={"entry": [{"content": {"isDone": True}}]},
            ),
            self.assertRaisesRegex(RuntimeError, "completed"),
        ):
            fault.observe_running("sid", timeout=1)

    def test_running_observation_requires_incomplete_state(self):
        with patch.object(
            fault.lab,
            "_json",
            return_value={
                "entry": [{"content": {"isDone": False, "dispatchState": "RUNNING"}}]
            },
        ):
            self.assertEqual(fault.observe_running("sid")["is_done"], False)

    def test_queued_job_is_not_proof_of_running_processing(self):
        with (
            patch.object(
                fault.lab,
                "_json",
                return_value={
                    "entry": [{"content": {"isDone": False, "dispatchState": "QUEUED"}}]
                },
            ),
            self.assertRaisesRegex(TimeoutError, "running"),
        ):
            fault.observe_running("sid", timeout=0)

    def test_raw_identity_digest_requires_complete_expected_identity_set(self):
        runner = Mock()
        rows = [{"identity": "netflow|b|1"}, {"identity": "netflow|b|2"}]
        runner.search.return_value = (rows, {"status": "complete"})
        digest = fault.raw_identity_digest(runner, "index=netflow", 2)
        self.assertTrue(digest)
        self.assertIn("sort 0 identity", runner.search.call_args.args[1])
        runner.search.return_value = (rows[:1], {"status": "complete"})
        with self.assertRaisesRegex(ValueError, "every event"):
            fault.raw_identity_digest(runner, "index=netflow", 2)

    def test_raw_identity_digest_rejects_incomplete_search(self):
        runner = Mock()
        runner.search.return_value = ([{"identity": "x"}], {"status": "incomplete"})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            fault.raw_identity_digest(runner, "index=netflow", 1)


if __name__ == "__main__":
    unittest.main()
