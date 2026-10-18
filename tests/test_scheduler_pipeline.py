import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import scheduler_pipeline as scheduler
import lab_lock


class SchedulerPipelineTest(unittest.TestCase):
    def setUp(self):
        self._lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._lock_directory.cleanup)
        lock_path = Path(self._lock_directory.name) / "lab.lock"
        self._lock_path_patch = patch.object(
            lab_lock, "default_lock_path", return_value=lock_path
        )
        self._lock_path_patch.start()
        self.addCleanup(self._lock_path_patch.stop)

    def test_scheduler_evidence_excludes_manual_saved_search_dispatches(self):
        scheduled = {"status": "success", "sid": "scheduler__nobody_job"}
        manual = {"status": "success", "sid": "admin__nobody_job"}
        deferred = {"status": "continued", "reason": "KV starting"}
        skipped = {"status": "skipped", "reason": "concurrency limit"}
        with patch.object(
            scheduler,
            "checked_search",
            return_value=[scheduled, manual, {"status": "success"}, deferred, skipped],
        ):
            self.assertEqual(
                scheduler.scheduler_rows(Mock(), 0), [scheduled, deferred, skipped]
            )

    def test_history_snapshot_excludes_other_searches_and_content(self):
        key = f"nobody;splunk_adm;{scheduler.TARGETS[0]}"
        with patch.object(
            scheduler.lab,
            "_json",
            return_value=[
                {"_key": key, "sched_time": 600, "runtimes": [1], "search": "private"},
                {"_key": "nobody;other_app;other_search", "sched_time": 601},
            ],
        ):
            self.assertEqual(
                scheduler.scheduler_history(),
                [{"_key": key, "sched_time": 600, "runtimes": [1]}],
            )

    def test_outage_requires_container_to_remain_stopped(self):
        with patch.object(
            scheduler.subprocess, "check_output", return_value="exited\n"
        ):
            scheduler.verify_stopped()
        for state in ("running", "restarting", "paused"):
            with (
                self.subTest(state=state),
                patch.object(scheduler.subprocess, "check_output", return_value=state),
                self.assertRaises(scheduler.LabInterferenceError),
            ):
                scheduler.verify_stopped()

    def test_unavailable_container_signals_lost_ownership(self):
        with (
            patch.object(
                scheduler.subprocess,
                "check_output",
                side_effect=scheduler.subprocess.CalledProcessError(1, "docker"),
            ),
            self.assertRaises(scheduler.LabInterferenceError),
        ):
            scheduler.verify_stopped()

    def test_fixture_clocks_shift_together_without_changing_counts(self):
        config = scheduler.Workload(pods=2, flow_copies=2)
        old = list(scheduler.fresh_events(config, scheduler.BASE))
        new = list(scheduler.fresh_events(config, scheduler.BASE + 86400))
        self.assertEqual(len(old), len(new))
        for before, after in zip(old, new):
            self.assertEqual(after["time"] - before["time"], 86400)
            if before["sourcetype"] == "otel:traces":
                self.assertEqual(
                    after["event"]["start_time"] - before["event"]["start_time"],
                    86400 * 10**9,
                )
            elif before["sourcetype"] == "stream:netflow":
                self.assertNotEqual(
                    before["event"]["timestamp"], after["event"]["timestamp"]
                )

    def test_catchup_requires_missed_slot_and_dispatch_after_restart(self):
        base = {
            "savedsearch_name": scheduler.TARGETS[-1],
            "status": "success",
            "scheduled_time": 150,
            "dispatch_time": 210,
        }
        rows = [
            base,
            {**base, "scheduled_time": 90},
            {**base, "dispatch_time": 190},
            {**base, "status": "skipped"},
        ]
        self.assertEqual(scheduler.catchup_rows(rows, 100, 200), [base])

    def test_skips_and_missing_timestamps_are_not_success(self):
        for row in (
            {
                "status": "skipped",
                "scheduled_time": 100,
                "reason": "maximum concurrency",
            },
            {"status": "success"},
        ):
            with self.assertRaises(ValueError):
                scheduler.validate_rows(
                    [{"savedsearch_name": scheduler.TARGETS[0], **row}]
                )

    def test_startup_deferral_is_retained_but_cannot_prove_catchup(self):
        row = {
            "savedsearch_name": scheduler.TARGETS[0],
            "status": "continued",
            "scheduled_time": 0,
            "reason": "Could not get next runtime",
        }
        scheduler.validate_rows([row])
        self.assertEqual(scheduler.catchup_rows([row], 100, 200), [])

    def test_shipped_cron_and_closed_slice_are_required(self):
        config = {
            n: {
                "cron_schedule": scheduler.CRONS[n],
                "realtime_schedule": 0,
                "disabled": 0,
                "is_scheduled": 1,
                "dispatch.index_earliest": "-10m@m",
                "dispatch.index_latest": "@m",
                "dispatch.earliest_time": "-24h",
                "dispatch.latest_time": "+15m",
            }
            for n in scheduler.TARGETS
        }
        config[scheduler.TARGETS[-1]].update(
            {"dispatch.index_earliest": "-10m@m", "dispatch.index_latest": "-5m@m"}
        )
        scheduler.verify_settings(config)
        config[scheduler.TARGETS[-1]]["cron_schedule"] = "* * * * *"
        with self.assertRaisesRegex(ValueError, "cron changed"):
            scheduler.verify_settings(config)

    def test_failed_preflight_does_not_mutate_or_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with (
                patch.object(
                    scheduler, "preflight", side_effect=RuntimeError("not local")
                ),
                patch.object(scheduler, "reset_lab") as reset,
                patch.object(scheduler, "restore_container") as restore,
                patch.object(scheduler, "set_schedules") as schedules,
            ):
                self.assertEqual(
                    scheduler.main(["--reset-lab", "--output", str(output)]), 1
                )
            reset.assert_not_called()
            restore.assert_not_called()
            schedules.assert_not_called()
            self.assertEqual(json.loads(output.read_text())["status"], "failed")


class SchedulerFinalEvidenceTest(unittest.TestCase):
    def setUp(self):
        self._lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._lock_directory.cleanup)
        lock_path = Path(self._lock_directory.name) / "lab.lock"
        self._lock_path_patch = patch.object(
            lab_lock, "default_lock_path", return_value=lock_path
        )
        self._lock_path_patch.start()
        self.addCleanup(self._lock_path_patch.stop)

    def test_expired_catchup_deadline_records_new_target(self):
        report = {"observed_flow_records": 6, "expected_flow_records": 6}
        with (
            patch.object(scheduler.time, "monotonic", return_value=2),
            self.assertRaises(TimeoutError),
        ):
            scheduler.wait_converged(None, 0, 12, 1, report, catchup=(100, 200))
        self.assertEqual(report["expected_flow_records"], 12)
        self.assertEqual(report["observed_flow_records"], 6)
        self.assertEqual(report["catchup_rows"], [])

    def test_empty_graph_cannot_complete(self):
        with self.assertRaisesRegex(ValueError, "meta row"):
            scheduler.verify_graph([], {})

    def test_identity_only_catchup_cannot_complete(self):
        row = {
            "savedsearch_name": scheduler.TARGETS[0],
            "status": "success",
            "scheduled_time": 150,
            "dispatch_time": 210,
        }
        report = {}
        with (
            patch.object(scheduler, "scheduler_rows", return_value=[row]),
            patch.object(scheduler, "summary_count", return_value=12),
            patch.object(scheduler.time, "monotonic", side_effect=[0, 2]),
            patch.object(scheduler.time, "sleep"),
            self.assertRaises(TimeoutError),
        ):
            scheduler.wait_converged(None, 0, 12, 1, report, catchup=(100, 200))
        self.assertEqual(report["observed_flow_records"], 12)
        self.assertEqual(report["expected_flow_records"], 12)
        self.assertEqual(report["catchup_rows"], [row])


class RecoveryExecutionTest(unittest.TestCase):
    def setUp(self):
        self._lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._lock_directory.cleanup)
        lock_path = Path(self._lock_directory.name) / "lab.lock"
        self._lock_path_patch = patch.object(
            lab_lock, "default_lock_path", return_value=lock_path
        )
        self._lock_path_patch.start()
        self.addCleanup(self._lock_path_patch.stop)

    def test_only_verified_empty_binding_warning_is_accepted(self):
        note = "WARN: Found no results to write to collection 'internal_collection'."
        record = {
            "status": "incomplete",
            "scan_count": 0,
            "event_count": 0,
            "warnings": [note],
        }
        runner = Mock()
        runner.search.return_value = ([{"rows_written": "0"}], record)
        scheduler.checked_replay_search(runner, "replay", "ADM - Service binding")
        self.assertTrue(record["accepted_empty_window"])
        for query, rows, changes in (
            ("ADM - Identity builder", [{"rows_written": "0"}], {}),
            ("ADM - Service binding", [{"rows_written": "1"}], {}),
            ("ADM - Service binding", [{"rows_written": "0"}], {"scan_count": 1}),
            ("ADM - Service binding", [{"rows_written": "0"}], {"status": "failed"}),
            (
                "ADM - Service binding",
                [{"rows_written": "0"}],
                {"warnings": [note, "Search was finalized early"]},
            ),
            (
                "ADM - Service binding",
                [{"rows_written": "0"}],
                {"warnings": ["WARN: KV Store unavailable"]},
            ),
        ):
            with self.subTest(query=query, changes=changes):
                runner.search.return_value = (rows, {**record, **changes})
                with self.assertRaisesRegex(ValueError, "incomplete search"):
                    scheduler.checked_replay_search(runner, "replay", query)

    def test_empty_rollup_warning_requires_no_scanned_events_or_results(self):
        runner = Mock()
        for rows, scanned, warnings, accepted in (
            ([], 0, ["WARN: No results to summary index."], True),
            ([], 1, ["WARN: No results to summary index."], False),
            ([{"records": "1"}], 0, ["WARN: No results to summary index."], False),
            (
                [],
                0,
                ["WARN: No results to summary index.", "Preview results returned"],
                False,
            ),
        ):
            record = {
                "status": "incomplete",
                "scan_count": scanned,
                "event_count": 0,
                "warnings": warnings,
            }
            runner.search.return_value = (rows, record)
            if accepted:
                scheduler.checked_replay_search(
                    runner, "replay", "ADM - Conversation rollup"
                )
                self.assertTrue(record["accepted_empty_window"])
            else:
                with self.assertRaisesRegex(ValueError, "incomplete search"):
                    scheduler.checked_replay_search(
                        runner, "replay", "ADM - Conversation rollup"
                    )

    def job(self):
        return {
            "name": scheduler.TARGETS[-1],
            "scheduled_time": 900,
            "earliest": -85500,
            "latest": 1800,
            "index_earliest": 300,
            "index_latest": 600,
        }

    def test_replays_absolute_bounds_while_paused_and_retains_evidence(self):
        runner = Mock(jobs=[{"sid": "replay-job"}])
        report = {"pre_outage_scheduler_rows": []}
        with (
            patch.object(scheduler, "set_schedules") as schedules,
            patch.object(scheduler, "drain_jobs"),
            patch.object(scheduler, "scheduler_rows", return_value=[]),
            patch.object(
                scheduler, "build_recovery_plan", side_effect=[[self.job()], []]
            ) as plan,
            patch.object(scheduler, "checked_replay_search") as search,
            patch.object(scheduler.time, "monotonic", return_value=0),
        ):
            scheduler.replay_missed_slots(runner, 0, 601, 1, report)
        schedules.assert_called_once_with(False, dispatchable=True)
        self.assertEqual(
            search.call_args.kwargs,
            {
                "saved": True,
                "earliest": "-85500",
                "latest": "1800",
                "index_window": ("300", "600"),
            },
        )
        self.assertEqual(report["recovery"]["status"], "complete")
        self.assertEqual(report["recovery"]["jobs"][0]["sid"], "replay-job")
        self.assertEqual(plan.call_args.args[0][0]["scheduled_time"], 900)

    def test_failed_replay_retains_pending_plan_and_does_not_resume(self):
        report = {"pre_outage_scheduler_rows": []}
        with (
            patch.object(scheduler, "set_schedules") as schedules,
            patch.object(scheduler, "drain_jobs"),
            patch.object(scheduler, "scheduler_rows", return_value=[]),
            patch.object(scheduler, "build_recovery_plan", return_value=[self.job()]),
            patch.object(
                scheduler,
                "checked_replay_search",
                side_effect=RuntimeError("search failed"),
            ),
            patch.object(scheduler.time, "monotonic", return_value=0),
            self.assertRaisesRegex(RuntimeError, "search failed"),
        ):
            scheduler.replay_missed_slots(Mock(), 0, 601, 1, report)
        schedules.assert_called_once_with(False, dispatchable=True)
        self.assertEqual(report["recovery"]["status"], "incomplete")
        self.assertEqual(report["recovery"]["pending"], [self.job()])
        self.assertEqual(report["recovery"]["jobs"], [])


class ExecutionOrderTest(unittest.TestCase):
    def rows(self):
        return [
            {
                "savedsearch_name": name,
                "status": "success",
                "scheduled_time": 600 + offset * 60,
                "dispatch_time": 600 + offset * 60,
                "_time": 600 + offset * 60 + 1,
            }
            for name, offset in zip(scheduler.TARGETS, (1, 2, 3, 0))
        ]

    def test_normal_order_and_delayed_catchup_are_distinguished(self):
        rows = self.rows()
        evidence = scheduler.execution_cycles(rows, 910)
        self.assertEqual(evidence[0]["dispatch_order"][0], scheduler.TARGETS[-1])
        self.assertTrue(evidence[0]["before_outage"])

    def test_wrong_baseline_order_fails(self):
        rows = self.rows()
        rows[-1]["dispatch_time"] = 850
        with self.assertRaisesRegex(ValueError, "dispatch order"):
            scheduler.execution_cycles(rows, 910)

    def test_iso_completion_times_and_late_completion(self):
        rows = self.rows()
        for row in rows:
            row["_time"] = scheduler.datetime.fromtimestamp(
                row["_time"], scheduler.timezone.utc
            ).isoformat()
        self.assertTrue(scheduler.execution_cycles(rows, 910)[0]["before_outage"])
        rows[0]["_time"] = "1970-01-01T00:16:00Z"
        with self.assertRaisesRegex(ValueError, "pre-outage"):
            scheduler.execution_cycles(rows, 910)

    def test_post_restart_dispatch_cannot_certify_baseline(self):
        rows = self.rows()
        for i, row in enumerate(rows):
            row["dispatch_time"] = 1000 + i
            row["_time"] = 1001 + i
        with self.assertRaisesRegex(ValueError, "pre-outage"):
            scheduler.execution_cycles(rows, 910)
