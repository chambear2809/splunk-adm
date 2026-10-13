import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import scheduler_pipeline as scheduler


class SchedulerPipelineTest(unittest.TestCase):
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
        with (
            patch.object(scheduler, "scheduler_rows", return_value=[row]),
            patch.object(scheduler, "summary_count", return_value=12),
            patch.object(scheduler.time, "monotonic", side_effect=[0, 2]),
            patch.object(scheduler.time, "sleep"),
            self.assertRaises(TimeoutError),
        ):
            scheduler.wait_converged(None, 0, 12, 1, {}, catchup=(100, 200))


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
