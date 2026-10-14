import configparser
import math
from pathlib import Path
import unittest

from tools.scheduler_recovery import TARGET_WINDOWS, build_recovery_plan


TARGETS = tuple(TARGET_WINDOWS)


def success_rows(checkpoint=900, **extra):
    rows = [
        {
            "savedsearch_name": name,
            "status": "success",
            "scheduled_time": checkpoint
            - ((checkpoint - window["offset"]) % window["period"]),
        }
        for name, window in TARGET_WINDOWS.items()
    ]
    rows.extend(extra.get("rows", []))
    return rows


class RecoveryPlannerTest(unittest.TestCase):
    def test_windows_match_shipped_scheduler_configuration(self):
        config = configparser.RawConfigParser()
        config.read(
            Path(__file__).resolve().parents[1]
            / "splunk_app/splunk_adm/default/savedsearches.conf"
        )
        for name, window in TARGET_WINDOWS.items():
            saved = config[name]
            minute = window["offset"] // 60
            cron = "*/5 * * * *" if minute == 0 else f"{minute}-{minute + 55}/5 * * * *"
            self.assertEqual(saved["cron_schedule"], cron)
            self.assertEqual(window["period"], 300)
            for field, key in (
                ("index_earliest", "dispatch.index_earliest"),
                ("index_latest", "dispatch.index_latest"),
            ):
                minutes = window[field] // 60
                expected = "@m" if minutes == 0 else f"{minutes}m@m"
                self.assertEqual(saved[key], expected)
            self.assertEqual(saved["dispatch.earliest_time"], "-24h")
            self.assertEqual(window["event_earliest"], -24 * 3600)
            self.assertEqual(saved["dispatch.latest_time"], "+15m")
            self.assertEqual(window["event_latest"], 15 * 60)

    def test_exact_windows_and_chronological_order(self):
        rows = success_rows(
            rows=[
                {"savedsearch_name": name, "status": "success", "scheduled_time": slot}
                for name, slot in (
                    (name, 1200 - ((1200 - window["offset"]) % 300))
                    for name, window in TARGET_WINDOWS.items()
                )
            ]
        )
        plan = build_recovery_plan(rows, 901, 1800)
        self.assertEqual(
            [(item["name"], item["scheduled_time"]) for item in plan],
            sorted(
                [
                    (name, slot)
                    for name, window in TARGET_WINDOWS.items()
                    for slot in range(
                        1500 - ((1200 - window["offset"]) % 300),
                        1801,
                        300,
                    )
                ],
                key=lambda pair: (pair[1], pair[0]),
            ),
        )
        by_name = {
            TARGETS[0]: next(
                item
                for item in plan
                if item["name"] == TARGETS[0] and item["scheduled_time"] == 1260
            )
        }
        self.assertEqual(
            by_name[TARGETS[0]],
            {
                "name": TARGETS[0],
                "scheduled_time": 1260,
                "earliest": 1260 - 86400,
                "latest": 1260 + 900,
                "index_earliest": 660,
                "index_latest": 1260,
            },
        )
        self.assertEqual(
            next(item for item in plan if item["name"] == TARGETS[3])["index_latest"],
            1200,
        )

    def test_missing_checkpoint_is_rejected(self):
        rows = success_rows()
        rows.pop()
        with self.assertRaisesRegex(ValueError, "pre-outage"):
            build_recovery_plan(rows, 901, 1000)

    def test_stale_checkpoint_is_rejected(self):
        rows = success_rows(checkpoint=300)
        with self.assertRaisesRegex(ValueError, "stale"):
            build_recovery_plan(rows, 1500, 1600)

    def test_future_success_does_not_hide_old_gap(self):
        rows = success_rows(
            checkpoint=600,
            rows=[
                {
                    "savedsearch_name": name,
                    "status": "success",
                    "scheduled_time": 1200
                    - ((1200 - TARGET_WINDOWS[name]["offset"]) % 300),
                }
                for name in TARGETS
            ],
        )
        with self.assertRaisesRegex(ValueError, "stale"):
            build_recovery_plan(rows, 1000, 1300)

    def test_duplicates_skipped_rows_and_other_targets(self):
        rows = success_rows(
            rows=[
                {
                    "savedsearch_name": TARGETS[0],
                    "status": "success",
                    "scheduled_time": 960,
                },
                {
                    "savedsearch_name": TARGETS[0],
                    "status": "success",
                    "scheduled_time": 960,
                },
                {
                    "savedsearch_name": TARGETS[1],
                    "status": "skipped",
                    "scheduled_time": 1020,
                },
                {
                    "savedsearch_name": "other search",
                    "status": "success",
                    "scheduled_time": "bad",
                },
            ]
        )
        plan = build_recovery_plan(rows, 1000, 1300)
        self.assertEqual(
            [item["name"] for item in plan],
            [TARGETS[1], TARGETS[2], TARGETS[3], TARGETS[0]],
        )

    def test_malformed_bounds_and_success_timestamps(self):
        for outage, through in (
            (math.inf, 100),
            (100, math.nan),
            (901, 900),
            (True, 1000),
            (100, "200"),
            (0, 100),
            (901, 901 + 86401),
        ):
            with (
                self.subTest(outage=outage, through=through),
                self.assertRaises(ValueError),
            ):
                build_recovery_plan(success_rows(), outage, through)
        rows = success_rows(
            rows=[
                {
                    "savedsearch_name": TARGETS[0],
                    "status": "success",
                    "scheduled_time": math.inf,
                },
            ]
        )
        with self.assertRaisesRegex(ValueError, "scheduled_time"):
            build_recovery_plan(rows, 1000, 1100)
        rows = success_rows(
            rows=[
                {
                    "savedsearch_name": TARGETS[0],
                    "status": "success",
                    "scheduled_time": 1001,
                },
            ]
        )
        with self.assertRaisesRegex(ValueError, "aligned"):
            build_recovery_plan(rows, 1100, 1200)

    def test_non_success_malformed_timestamp_is_ignored(self):
        rows = success_rows(
            rows=[
                {
                    "savedsearch_name": TARGETS[0],
                    "status": "failed",
                    "scheduled_time": "bad",
                },
            ]
        )
        self.assertEqual(build_recovery_plan(rows, 901, 901), [])

    def test_scheduler_decimal_timestamp_strings_and_fractional_bounds(self):
        rows = success_rows(
            rows=[
                {
                    "savedsearch_name": name,
                    "status": "success",
                    "scheduled_time": str(1200 - ((1200 - window["offset"]) % 300)),
                }
                for name, window in TARGET_WINDOWS.items()
            ]
        )
        self.assertEqual(build_recovery_plan(rows, 1200.5, 1201.9), [])

    def test_fully_recovered_history_returns_empty(self):
        rows = success_rows(
            rows=[
                {"savedsearch_name": name, "status": "success", "scheduled_time": slot}
                for name, window in TARGET_WINDOWS.items()
                for slot in range(1200 - ((1200 - window["offset"]) % 300), 1801, 300)
            ]
        )
        self.assertEqual(build_recovery_plan(rows, 1201, 1800), [])


if __name__ == "__main__":
    unittest.main()
