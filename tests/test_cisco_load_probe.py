"""Pure checks for bounded Cisco load-probe configuration and evidence."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import call, patch

from tools.cisco_load_probe import (
    ProbeConfig,
    TRAFFIC_CONTENT_FIELDS,
    TRAFFIC_IDENTITY_RESULT_FIELDS,
    TRAFFIC_OBSERVATION_SEARCH,
    TRAFFIC_OPTIONAL_EMPTY_FIELDS,
    _history_receipt_baseline,
    _history_retention_mismatches,
    _indexed_sourcetype,
    _job_messages_are_acceptable,
    _known_empty_summary_warning,
    _positive_time_window,
    _require_numeric_single_row,
    _resolved_scheduler_window,
    _resolved_search_window,
    _search_job_metadata_path,
    _traffic_content_value,
    _traffic_cycle_bounds,
    _traffic_expected_rows,
    _traffic_identity_comparison,
    _traffic_retained_search,
    _conversation_identity_comparison,
    _latest_job_cycles,
    _visible_input_watermark,
    _windows_cover_interval,
    assess_samples,
    run_probe,
)
from tools.capture_networking_fixtures import require_complete
from tools.cisco_load_probe import lab as splunk_lab


JOBS = [
    "ADM - Network client history builder",
    "ADM - Conversation rollup v2",
    "ADM - Traffic observation rollup v2",
]


def cycle_rows(offset=0, status="success"):
    result = {}
    for name in JOBS:
        cycles = []
        for i in (0, 1):
            scheduled = offset + i * 300
            close = scheduled // 300 * 300
            lower = close - 600
            upper = close if name == JOBS[0] else close - 300
            cycles.append(
                {
                    "sid": f"{i}-{name}",
                    "scheduled_time": scheduled,
                    "status": status,
                    "input_window": [lower, upper],
                    "search_window": [lower - 86400, upper + 900],
                    "run_duration_seconds": 2,
                    "schedule_latency_seconds": 1,
                }
            )
        result[name] = cycles
    return result


def sample(offset=0, **changes):
    row = {
        "observed_at": offset,
        "required_jobs": JOBS,
        "job_cycles": cycle_rows(offset),
        "raw_count": 100,
        "raw_expected_count": 100,
        "raw_counts_match": True,
        "raw_source_counts_match": True,
        "raw_unique_count": 90,
        "history_expected_unique": 5,
        "history_unique_count": 5,
        "history_content_mismatch": 0,
        "history_receipt_mismatch": 0,
        "traffic_expected_unique": 10,
        "traffic_count": 10,
        "traffic_unique_count": 10,
        "traffic_content_mismatch": 0,
        "traffic_identity_mismatch_count": 0,
        "traffic_duplicate_rollup_ids": 0,
        "conversation_expected_unique": 3,
        "conversation_unique_count": 3,
        "conversation_identity_mismatch_count": 0,
        "conversation_content_mismatch": 0,
        "conversation_duplicate_rollup_ids": 0,
        "conversation_conflicting_rollup_ids": 0,
        "mapped_traffic_expected_unique": 8,
        "mapped_traffic_retained_unique": 8,
        "mapped_client_count": 3,
        "unprocessed_backlog": 0,
    }
    row.update(changes)
    return row


class CiscoLoadProbeTest(unittest.TestCase):
    def test_index_based_traffic_macro_search_has_valid_base_command(self):
        self.assertEqual(
            TRAFFIC_OBSERVATION_SEARCH,
            "search `adm_traffic_observations_v2`",
        )
        self.assertEqual(
            splunk_lab._query(TRAFFIC_OBSERVATION_SEARCH), TRAFFIC_OBSERVATION_SEARCH
        )

    def test_empty_traffic_identity_summary_requires_explicit_numeric_zeroes(self):
        row = _require_numeric_single_row(
            [dict.fromkeys(TRAFFIC_IDENTITY_RESULT_FIELDS, "0")],
            TRAFFIC_IDENTITY_RESULT_FIELDS,
            "traffic retained-identity comparison",
        )
        self.assertEqual(int(row["compared_identities"]), 0)
        self.assertEqual(int(row["expected_unique"]), 0)
        self.assertEqual(int(row["retained_unique"]), 0)

    def test_traffic_identity_summary_rejects_missing_or_nonfinite_metrics(self):
        with self.assertRaisesRegex(RuntimeError, "was incomplete"):
            _require_numeric_single_row(
                [],
                TRAFFIC_IDENTITY_RESULT_FIELDS,
                "traffic retained-identity comparison",
            )
        with self.assertRaisesRegex(RuntimeError, "invalid expected_unique"):
            _require_numeric_single_row(
                [{"compared_identities": "0", "expected_unique": "nan"}],
                TRAFFIC_IDENTITY_RESULT_FIELDS,
                "traffic retained-identity comparison",
            )

    def test_traffic_identity_comparison_counts_symmetric_difference(self):
        expected_only = "a" * 64
        common = "b" * 64
        retained_only = "c" * 64
        result = _traffic_identity_comparison(
            [{"rollup_id": expected_only}, {"rollup_id": common}],
            [{"rollup_id": retained_only}, {"rollup_id": common}],
        )
        self.assertEqual(result["expected_unique"], 2)
        self.assertEqual(result["retained_unique"], 2)
        self.assertEqual(result["identity_mismatch"], 2)

    def test_traffic_content_canonicalizes_only_empty_optional_strings(self):
        raw = {
            "rollup_id": "same",
            "routing_domain": "",
            "adm_scope_observation_domain_id": "",
            "adm_scope_vpn_id": "",
            "adm_scope_routing_domain": "",
            "adm_scope_authority": "",
            "adm_scope_observation_domain_present": 0,
            "metrics_authoritative": 0,
            "source_port": 0,
        }
        retained = {
            **raw,
            "routing_domain": None,
            "adm_scope_observation_domain_id": None,
            "adm_scope_vpn_id": None,
            "adm_scope_routing_domain": None,
            "adm_scope_authority": None,
        }
        self.assertEqual(
            set(TRAFFIC_OPTIONAL_EMPTY_FIELDS),
            {
                "routing_domain",
                "adm_scope_observation_domain_id",
                "adm_scope_vpn_id",
                "adm_scope_routing_domain",
                "adm_scope_authority",
            },
        )
        self.assertEqual(_traffic_content_value(raw), _traffic_content_value(retained))
        self.assertIn("adm_scope_authority", TRAFFIC_OPTIONAL_EMPTY_FIELDS)
        self.assertNotEqual(
            _traffic_content_value(raw),
            _traffic_content_value({**retained, "metrics_authoritative": None}),
        )
        self.assertNotEqual(
            _traffic_content_value(raw),
            _traffic_content_value(
                {**retained, "adm_scope_observation_domain_present": None}
            ),
        )
        self.assertNotEqual(
            _traffic_content_value(raw),
            _traffic_content_value({**retained, "source_port": "invalid"}),
        )

    def test_traffic_content_difference_is_not_hidden_by_matching_identity(self):
        result = _traffic_identity_comparison(
            [{"rollup_id": "d" * 64, "source_port": "invalid"}],
            [{"rollup_id": "d" * 64, "source_port": None}],
        )
        self.assertEqual(result["identity_mismatch"], 0)
        self.assertEqual(result["content_mismatch"], 1)

    def test_traffic_content_normalizes_only_known_multivalue_serialization(self):
        row = {
            "rollup_id": "d" * 64,
            "adm_quality_warnings": ["unknown_sampling", "unmapped_scope"],
            "adm_quality_errors": [],
        }
        retained = {
            **row,
            "adm_quality_warnings": "unknown_sampling\nunmapped_scope",
            "adm_quality_errors": "",
        }
        self.assertEqual(_traffic_content_value(row), _traffic_content_value(retained))
        self.assertNotEqual(
            _traffic_content_value(row),
            _traffic_content_value({**retained, "adm_quality_warnings": "unexpected"}),
        )

    def test_traffic_comparison_accepts_only_expected_physical_multiplicity(self):
        identity = "a" * 64
        expected = [
            {"rollup_id": identity, "records": 1},
            {"rollup_id": identity, "records": 1},
        ]
        exact = _traffic_identity_comparison(expected, expected)
        self.assertEqual(exact["identity_mismatch"], 0)
        self.assertEqual(exact["content_mismatch"], 0)
        self.assertEqual(exact["expected_duplicate_count"], 1)
        self.assertEqual(exact["duplicate_count"], 0)

        extra = _traffic_identity_comparison(expected, expected + [expected[0]])
        self.assertEqual(extra["identity_mismatch"], 0)
        self.assertEqual(extra["content_mismatch"], 1)
        self.assertEqual(extra["duplicate_count"], 1)

    def test_traffic_comparison_rejects_every_malformed_rollup_identity(self):
        malformed_ids = [None, 9, True, "", " " * 64, "g" * 64]
        result = _traffic_identity_comparison(
            [{"rollup_id": "e" * 64}],
            [
                {"rollup_id": "e" * 64},
                *({"rollup_id": value} for value in malformed_ids),
            ],
        )
        self.assertEqual(result["invalid_identity_count"], len(malformed_ids))
        self.assertEqual(result["identity_mismatch"], 0)

    def test_conversation_comparison_uses_python_content_and_exact_multiplicity(self):
        identity = "c" * 64
        expected = [
            {"rollup_id": identity, "records": 3, "acl_permits": 1},
            {"rollup_id": identity, "records": 3, "acl_permits": 1},
        ]
        exact = _conversation_identity_comparison(expected, expected)
        self.assertEqual(exact["identity_mismatch"], 0)
        self.assertEqual(exact["content_mismatch"], 0)
        self.assertEqual(exact["expected_duplicate_count"], 1)
        self.assertEqual(exact["duplicate_count"], 0)
        extra = _conversation_identity_comparison(expected, expected + [expected[0]])
        self.assertEqual(extra["content_mismatch"], 1)
        self.assertEqual(extra["duplicate_count"], 1)
        changed = _conversation_identity_comparison(
            expected, [expected[0], {**expected[1], "records": 999}]
        )
        self.assertEqual(changed["content_mismatch"], 1)
        invalid = _conversation_identity_comparison(
            expected, expected + [{"rollup_id": None}]
        )
        self.assertEqual(invalid["invalid_identity_count"], 1)

    def test_traffic_expected_queries_use_each_actual_event_and_index_window(self):
        cycles = [
            {
                "status": "success",
                "input_window": [900, 1000],
                "search_window": [100, 200],
            },
            {
                "status": "success",
                "input_window": [1000, 1100],
                "search_window": [200, 300],
            },
            {
                "status": "success",
                "input_window": [900, 1000],
                "search_window": [0, 100],
            },
        ]
        with patch(
            "tools.cisco_load_probe._search_complete", return_value=[]
        ) as search:
            self.assertEqual(_traffic_expected_rows(cycles), [])
        self.assertEqual(
            search.call_args_list,
            [
                call(
                    "search `adm_traffic_observations_v2`",
                    "0",
                    "100",
                    index_earliest="900",
                    index_latest="1000",
                ),
                call(
                    "search `adm_traffic_observations_v2`",
                    "100",
                    "200",
                    index_earliest="900",
                    index_latest="1000",
                ),
                call(
                    "search `adm_traffic_observations_v2`",
                    "200",
                    "300",
                    index_earliest="1000",
                    index_latest="1100",
                ),
            ],
        )
        # An event at 250 is in the index slice but cannot be returned by the
        # corresponding source search, which has event bounds [100, 200).
        self.assertIn(
            call(
                "search `adm_traffic_observations_v2`",
                "100",
                "200",
                index_earliest="900",
                index_latest="1000",
            ),
            search.call_args_list,
        )

    def test_successful_traffic_jobs_keep_repeated_identical_window_multiplicity(self):
        cycle = {
            "status": "success",
            "input_window": [900, 1000],
            "search_window": [100, 200],
        }
        with patch(
            "tools.cisco_load_probe._search_complete", return_value=[]
        ) as search:
            self.assertEqual(_traffic_expected_rows([cycle, dict(cycle)]), [])
        self.assertEqual(search.call_count, 2)

    def test_bucketed_traffic_time_is_not_used_to_filter_retained_rows(self):
        expected = {
            "rollup_id": "f" * 64,
            "_time": 0,
            "received_time": 950,
        }
        retained = dict(expected)
        cycle = {
            "status": "success",
            "input_window": [900, 1000],
            "search_window": [100, 200],
        }
        self.assertEqual(_traffic_cycle_bounds([cycle]), [(900, 1000, 100, 200)])
        self.assertEqual(
            _traffic_identity_comparison([expected], [retained])["identity_mismatch"], 0
        )
        query = _traffic_retained_search(1000, 2000, "rollup_id _time received_time")
        self.assertIn("_indextime>=1000 AND _indextime<2000", query)
        self.assertNotIn("_time>=", query)
        self.assertNotIn("received_time>=", query)

    def test_unexpected_retained_row_without_received_time_is_not_filtered_away(self):
        result = _traffic_identity_comparison(
            [{"rollup_id": "1" * 64}],
            [
                {"rollup_id": "1" * 64},
                {"rollup_id": "2" * 64, "_time": 0},
            ],
        )
        self.assertEqual(result["identity_mismatch"], 1)

    def test_local_lab_guard_runs_before_probe_journal_or_mutations(self):
        with TemporaryDirectory() as directory:
            journal = Path(directory) / "probe.json"
            with patch(
                "tools.cisco_load_probe.require_local_lab",
                side_effect=RuntimeError("not a disposable local lab"),
            ) as local_guard:
                with self.assertRaisesRegex(RuntimeError, "disposable local lab"):
                    run_probe(ProbeConfig(), journal)
            local_guard.assert_called_once()
            self.assertFalse(journal.exists())

    def test_sampling_window_waits_until_time_advances(self):
        self.assertFalse(_positive_time_window(1792174456, 1792174456))
        self.assertTrue(_positive_time_window(1792174456, 1792174457))

    def test_configuration_is_bounded_and_uses_fixed_production_cadence(self):
        ProbeConfig().validate()
        self.assertEqual(ProbeConfig().evidence_class, "production-cadence-observation")
        for config in (
            ProbeConfig(duration_seconds=619),
            ProbeConfig(duration_seconds=3601),
            ProbeConfig(events_per_second=0),
            ProbeConfig(events_per_second=251),
        ):
            with self.subTest(config=config), self.assertRaises(ValueError):
                config.validate()

    def test_search_completion_requires_capture_grade_metadata(self):
        complete = {
            "dispatchState": "DONE",
            "isDone": True,
            "isFinalized": False,
            "eventIsTruncated": False,
            "dropCount": "0",
            "resultCount": "1",
            "messages": [],
        }
        require_complete(complete, [{"ok": "1"}])
        for field, value in (
            ("dispatchState", "RUNNING"),
            ("isDone", False),
            ("isFinalized", True),
            ("eventIsTruncated", True),
            ("dropCount", "1"),
            ("resultCount", "2"),
            ("messages", [{"type": "WARN"}]),
        ):
            invalid = {**complete, field: value}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                require_complete(invalid, [{"ok": "1"}])

    def test_missed_cycle_and_work_exceeding_cadence_are_reported(self):
        cycles = cycle_rows()
        for name in JOBS:
            cycles[name] = [
                {
                    "sid": f"a-{name}",
                    "scheduled_time": 0,
                    "status": "success",
                    "run_duration_seconds": 310,
                },
                {
                    "sid": f"b-{name}",
                    "scheduled_time": 600,
                    "status": "success",
                    "run_duration_seconds": 2,
                },
            ]
        report = assess_samples([sample(job_cycles=cycles)])
        self.assertIn("missed_or_late_cycle", report["issues"])
        self.assertIn("work_exceeded_cadence", report["issues"])

    def test_poll_repetition_does_not_weight_cycle_latency_or_runtime_percentiles(self):
        job_cycles = {
            name: [
                {
                    "sid": f"scheduler__{i}__{name}",
                    "scheduled_time": i * 300,
                    "status": "success",
                    "schedule_latency_seconds": i + 1,
                    "run_duration_seconds": i + 11,
                }
                for i in range(3)
            ]
            for name in JOBS
        }
        single = assess_samples([sample(job_cycles=job_cycles)])
        repeated = assess_samples(
            [sample(offset=when, job_cycles=job_cycles) for when in (0, 5, 10, 15)]
        )
        self.assertEqual(single["schedule_latency_seconds"]["samples"], 9)
        self.assertEqual(single["run_duration_seconds"]["samples"], 9)
        self.assertEqual(
            repeated["schedule_latency_seconds"], single["schedule_latency_seconds"]
        )
        self.assertEqual(
            repeated["run_duration_seconds"], single["run_duration_seconds"]
        )

    def test_cycle_measurements_use_latest_complete_metadata_per_job_and_sid(self):
        name = JOBS[0]
        polls = [
            sample(
                observed_at,
                job_cycles={
                    name: [
                        {
                            "sid": "scheduler__same_sid",
                            "status": "success",
                            "schedule_latency_seconds": latency,
                            "run_duration_seconds": runtime,
                        }
                    ]
                },
            )
            for observed_at, latency, runtime in (
                (0, 2, 4),
                (5, None, None),
                (10, 7, 9),
            )
        ]
        latest = _latest_job_cycles(polls)
        self.assertEqual(len(latest[name]), 1)
        self.assertEqual(latest[name][0]["schedule_latency_seconds"], 7)
        self.assertEqual(latest[name][0]["run_duration_seconds"], 9)
        report = assess_samples(polls)
        self.assertEqual(report["schedule_latency_seconds"]["samples"], 1)
        self.assertEqual(report["schedule_latency_seconds"]["max"], 7)
        self.assertEqual(report["run_duration_seconds"]["samples"], 1)
        self.assertEqual(report["run_duration_seconds"]["max"], 9)

    def test_latency_and_runtime_statistics_require_real_sids(self):
        no_sid = {
            name: [
                {
                    "status": "success",
                    "scheduled_time": 0,
                    "schedule_latency_seconds": 1,
                    "run_duration_seconds": 2,
                }
            ]
            for name in JOBS
        }
        report = assess_samples([sample(job_cycles=no_sid)])
        self.assertEqual(report["schedule_latency_seconds"]["samples"], 0)
        self.assertEqual(report["run_duration_seconds"]["samples"], 0)

    def test_cycle_deduplication_is_scoped_to_saved_search_and_sid(self):
        shared_sid = "scheduler__same-id"
        cycles = {
            name: [
                {
                    "sid": shared_sid,
                    "status": "success",
                    "scheduled_time": 0,
                    "schedule_latency_seconds": 3,
                    "run_duration_seconds": 4,
                }
            ]
            for name in JOBS[:2]
        }
        latest = _latest_job_cycles([sample(job_cycles=cycles)])
        self.assertEqual(sum(len(rows) for rows in latest.values()), 2)
        report = assess_samples([sample(job_cycles=cycles)])
        self.assertEqual(report["schedule_latency_seconds"]["samples"], 2)
        self.assertEqual(report["run_duration_seconds"]["samples"], 2)

    def test_unknown_or_non_success_job_state_cannot_complete(self):
        unknown = cycle_rows()
        unknown[JOBS[0]][0]["status"] = "mysterious"
        report = assess_samples([sample(job_cycles=unknown)])
        self.assertEqual(report["unknown_job_states"], ["mysterious"])
        self.assertIn("required_cycle_not_successful", report["issues"])
        self.assertFalse(report["complete"])

        for state in ("skipped", "failed", "delegated"):
            cycles = cycle_rows(status=state)
            with self.subTest(state=state):
                self.assertFalse(
                    assess_samples([sample(job_cycles=cycles)])["complete"]
                )

    def test_missing_scheduled_cycles_and_empty_job_history_fail_closed(self):
        report = assess_samples([sample(job_cycles={})])
        self.assertEqual(set(report["missing_cycles"]), set(JOBS))
        self.assertIn("required_cycles_missing", report["issues"])
        self.assertFalse(report["complete"])

    def test_successful_cycles_and_exact_identity_counts_can_complete(self):
        report = assess_samples([sample()])
        self.assertEqual(report["issues"], [])
        self.assertTrue(report["complete"])

    def test_final_drain_requires_full_scheduled_window_coverage_and_zero_pending(self):
        incomplete = assess_samples(
            [
                sample(
                    final_drain=True,
                    scheduled_input_coverage=False,
                    pending_input_count=5,
                )
            ]
        )
        self.assertIn("scheduled_input_coverage_incomplete", incomplete["issues"])
        self.assertIn("pending_input_records", incomplete["issues"])
        self.assertFalse(incomplete["complete"])

        complete = assess_samples(
            [
                sample(
                    final_drain=True,
                    scheduled_input_coverage=True,
                    pending_input_count=0,
                )
            ]
        )
        self.assertTrue(complete["complete"])

    def test_final_drain_missing_completed_job_timing_stays_unqualified(self):
        cycles = cycle_rows()
        for rows in cycles.values():
            for cycle in rows:
                cycle["scheduled_time"] = None
                cycle["run_duration_seconds"] = None
                cycle["schedule_latency_seconds"] = None

        report = assess_samples(
            [
                sample(
                    final_drain=True,
                    scheduled_input_coverage=True,
                    pending_input_count=0,
                    max_run_duration_seconds=None,
                    job_cycles=cycles,
                )
            ]
        )

        self.assertIn("cycle_timing_metric_unavailable", report["issues"])
        self.assertFalse(report["complete"])
        self.assertIsNone(report["max_run_duration_seconds"])
        self.assertEqual(report["schedule_latency_seconds"]["samples"], 0)
        self.assertIsNone(report["schedule_latency_seconds"]["p50"])
        self.assertEqual(report["run_duration_seconds"]["samples"], 0)
        self.assertIsNone(report["run_duration_seconds"]["max"])

    def test_schedule_windows_must_cover_the_run_contiguously(self):
        self.assertTrue(_windows_cover_interval([(100, 200), (200, 300)], 125, 275))
        self.assertFalse(_windows_cover_interval([(100, 180), (200, 300)], 125, 275))
        self.assertFalse(_windows_cover_interval([(100, 200)], 125, 225))

    def test_scheduler_window_uses_resolved_request_metadata(self):
        anchor = 1_800_000
        entry = {
            "content": {
                "request": {
                    "index_earliest": "-10m@m",
                    "index_latest": "-5m@m",
                },
                "searchEarliestTime": anchor - 86400,
                "searchLatestTime": anchor + 900,
                "dispatchState": "DONE",
                "isDone": True,
                "isFinalized": False,
                "eventIsTruncated": False,
                "dropCount": "0",
                "messages": [],
                # These observed extrema deliberately do not define bounds.
                "indexEarliestTime": anchor - 75,
                "indexLatestTime": anchor - 2,
            }
        }
        self.assertEqual(
            _resolved_scheduler_window(JOBS[1], entry), (anchor - 600, anchor - 300)
        )
        self.assertEqual(
            _resolved_search_window(JOBS[1], entry),
            (anchor - 86400, anchor + 900),
        )

        wrong_request = {
            **entry,
            "content": {
                **entry["content"],
                "request": {"index_earliest": "-10m@m", "index_latest": "@m"},
            },
        }
        self.assertIsNone(_resolved_scheduler_window(JOBS[1], wrong_request))
        warned = {
            **entry,
            "content": {**entry["content"], "messages": [{"type": "WARN"}]},
        }
        self.assertIsNone(_resolved_scheduler_window(JOBS[1], warned))

    def test_history_bounds_resolve_from_actual_absolute_search_metadata(self):
        entry = {
            "content": {
                "request": {
                    "earliest_time": "0",
                    "index_earliest": "-10m@m",
                    "index_latest": "@m",
                },
                "searchEarliestTime": 0,
                "searchLatestTime": 1985,
                "dispatchState": "DONE",
                "isDone": True,
                "isFinalized": False,
                "eventIsTruncated": False,
                "dropCount": "0",
                "messages": [],
            }
        }
        self.assertEqual(_resolved_search_window(JOBS[0], entry), (0, 1985))
        self.assertEqual(_resolved_scheduler_window(JOBS[0], entry), (480, 1080))
        for change in (
            {"searchEarliestTime": 1},
            {"searchLatestTime": None},
        ):
            invalid = {"content": {**entry["content"], **change}}
            self.assertIsNone(_resolved_search_window(JOBS[0], invalid))
            self.assertIsNone(_resolved_scheduler_window(JOBS[0], invalid))

    def test_history_unbounded_earliest_requires_exact_zero_request(self):
        entry = {
            "content": {
                "request": {
                    "earliest_time": "0",
                    "index_earliest": "-10m@m",
                    "index_latest": "@m",
                },
                "searchEarliestTime": None,
                "searchLatestTime": 1985,
                "dispatchState": "DONE",
                "isDone": True,
                "isFinalized": False,
                "eventIsTruncated": False,
                "dropCount": "0",
                "messages": [],
            }
        }
        self.assertEqual(_resolved_search_window(JOBS[0], entry), (0, 1985))
        self.assertEqual(_resolved_scheduler_window(JOBS[0], entry), (480, 1080))
        for request_earliest in (None, "", "-24h", "1"):
            invalid = {
                "content": {
                    **entry["content"],
                    "request": {
                        **entry["content"]["request"],
                        "earliest_time": request_earliest,
                    },
                }
            }
            self.assertIsNone(_resolved_search_window(JOBS[0], invalid))

    def test_v2_summary_jobs_accept_only_exact_complete_empty_summary_warning(self):
        status = {
            "dispatchState": "DONE",
            "isDone": True,
            "isFinalized": False,
            "eventIsTruncated": False,
            "dropCount": "0",
            "resultCount": "0",
            "messages": [{"type": "WARN", "text": "No results to summary index."}],
        }
        self.assertTrue(_known_empty_summary_warning(status, []))
        self.assertTrue(_job_messages_are_acceptable(JOBS[1], status))
        self.assertTrue(_job_messages_are_acceptable(JOBS[2], status))
        entry = {
            "content": {
                "request": {"index_earliest": "-10m@m", "index_latest": "-5m@m"},
                "searchEarliestTime": 1_713_600,
                "searchLatestTime": 1_800_900,
                **status,
            }
        }
        self.assertIsNotNone(_resolved_scheduler_window(JOBS[1], entry))
        self.assertFalse(_job_messages_are_acceptable(JOBS[0], status))
        for change, rows in (
            ({"resultCount": "1"}, []),
            ({"eventIsTruncated": True}, []),
            ({"messages": [{"type": "WARN", "text": "different warning"}]}, []),
            (status, [{"rollup_id": "unexpected"}]),
        ):
            self.assertFalse(_known_empty_summary_warning({**status, **change}, rows))

    def test_search_job_metadata_path_leaves_output_mode_to_lab_json_helper(self):
        path = _search_job_metadata_path("scheduler__fixture")
        self.assertEqual(
            path,
            "/servicesNS/nobody/splunk_adm/search/jobs/scheduler__fixture",
        )
        self.assertNotIn("?", path)

    def test_visible_watermark_requires_all_acknowledged_rows_and_closes_after_max(
        self,
    ):
        expected_by_index = {"cisco_meraki": 2, "netflow": 3}
        expected_by_source = {"meraki:accesspoints": 2, "stream:netflow": 3}
        expected_by_index_source = {
            "cisco_meraki": {"meraki:accesspoints": 2},
            "netflow": {"stream:netflow": 3},
        }
        visible = [
            {
                "index": "cisco_meraki",
                "sourcetype": "meraki:accesspoints",
                "count": 2,
                "max_index_time": "100.25",
            },
            {
                "index": "netflow",
                "sourcetype": "stream:netflow",
                "count": 3,
                "max_index_time": "101.75",
            },
        ]
        self.assertEqual(
            _visible_input_watermark(
                visible,
                expected_by_index,
                expected_by_source,
                expected_by_index_source,
            ),
            102,
        )
        self.assertIsNone(
            _visible_input_watermark(
                visible[:1],
                expected_by_index,
                expected_by_source,
                expected_by_index_source,
            )
        )
        # The marginals still match, but the wrong source landed in each
        # index. Only exact index+sourcetype counts prove the acknowledged set.
        swapped_sources = [
            {**visible[0], "sourcetype": "stream:netflow"},
            {**visible[1], "sourcetype": "meraki:accesspoints"},
        ]
        self.assertIsNone(
            _visible_input_watermark(
                swapped_sources,
                expected_by_index,
                expected_by_source,
                expected_by_index_source,
            )
        )

    def test_traffic_content_projection_includes_quality_contract(self):
        fields = set(TRAFFIC_CONTENT_FIELDS.split())
        self.assertTrue(
            {
                "adm_quality_status",
                "adm_quality_errors",
                "adm_quality_warnings",
                "quality_status",
                "quality_errors",
                "quality_warnings",
            }.issubset(fields)
        )

    def test_indexed_sourcetype_matches_documented_isovalent_ta_route(self):
        envelope = {
            "index": "cisco_isovalent",
            "sourcetype": "cisco:isovalent",
            "event": {"process_connect": {"source_ip": "10.0.0.1"}},
        }
        self.assertEqual(
            _indexed_sourcetype(envelope), "cisco:isovalent:processConnect"
        )
        self.assertEqual(envelope["sourcetype"], "cisco:isovalent")
        self.assertEqual(
            _indexed_sourcetype(
                {**envelope, "event": {"process_exec": {"binary": "/bin/x"}}}
            ),
            "cisco:isovalent",
        )
        self.assertEqual(
            _indexed_sourcetype({**envelope, "index": "other"}),
            "cisco:isovalent",
        )

    def test_history_receipts_match_exact_preexisting_and_current_extrema(self):
        baseline = _history_receipt_baseline(
            [
                {
                    "_key": "client",
                    "received_time": "100",
                    "latest_received_time": "250",
                }
            ]
        )
        correct = {
            "_key": "client",
            "stored_key": "client",
            "expected_content": "same",
            "retained_content": "same",
            "expected_first_received": "200",
            "expected_latest_received": "300",
            "stored_first_received": "100",
            "stored_latest_received": "300",
        }
        self.assertEqual(_history_retention_mismatches([correct], baseline), (0, 0, 1))
        for changes in (
            {"stored_first_received": "0"},
            {"stored_latest_received": "100000"},
            {"stored_first_received": None},
            {"stored_latest_received": "NaN"},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    _history_retention_mismatches([{**correct, **changes}], baseline),
                    (0, 1, 1),
                )
        for invalid_baseline in (
            [{"_key": "client", "received_time": None, "latest_received_time": 250}],
            [{"_key": "client", "received_time": "inf", "latest_received_time": 250}],
            [{"_key": "client", "received_time": 300, "latest_received_time": 250}],
        ):
            with (
                self.subTest(invalid_baseline=invalid_baseline),
                self.assertRaises(RuntimeError),
            ):
                _history_receipt_baseline(invalid_baseline)

    def test_success_without_resolved_window_or_nonzero_retention_fails_closed(self):
        cycles = cycle_rows()
        cycles[JOBS[2]][0]["input_window"] = None
        report = assess_samples([sample(job_cycles=cycles)])
        self.assertIn("scheduled_window_unavailable", report["issues"])
        self.assertFalse(report["complete"])

        empty = assess_samples(
            [
                sample(
                    final_drain=True,
                    traffic_expected_unique=0,
                    mapped_traffic_expected_unique=0,
                    history_expected_unique=0,
                    mapped_client_count=0,
                    conversation_expected_unique=0,
                )
            ]
        )
        self.assertIn("empty_traffic_expectation", empty["issues"])
        self.assertIn("empty_history_expectation", empty["issues"])
        self.assertIn("no_mapped_client_identity", empty["issues"])
        self.assertIn("empty_conversation_expectation", empty["issues"])

    def test_history_or_traffic_identity_mismatch_is_not_hidden_by_row_counts(self):
        report = assess_samples(
            [
                sample(
                    history_expected_unique=6,
                    history_unique_count=5,
                    traffic_expected_unique=11,
                    traffic_unique_count=10,
                )
            ]
        )
        self.assertIn("history_identity_mismatch", report["issues"])
        self.assertIn("traffic_identity_mismatch", report["issues"])
        self.assertFalse(report["complete"])

    def test_traffic_content_and_duplicate_rollup_id_mismatches_are_reported(self):
        report = assess_samples(
            [
                sample(
                    final_drain=True,
                    traffic_content_mismatch=2,
                    traffic_duplicate_rollup_ids=1,
                    traffic_invalid_identity_count=1,
                    conversation_content_mismatch=3,
                    conversation_unique_count=9,
                )
            ]
        )
        self.assertIn("traffic_content_mismatch", report["issues"])
        self.assertIn("duplicate_traffic_rollup_ids", report["issues"])
        self.assertIn("invalid_traffic_rollup_id", report["issues"])
        self.assertIn("conversation_content_mismatch", report["issues"])
        self.assertIn("conversation_identity_mismatch", report["issues"])

    def test_history_content_and_receipt_mismatches_prevent_final_completion(self):
        report = assess_samples(
            [
                sample(
                    final_drain=True,
                    scheduled_input_coverage=True,
                    pending_input_count=0,
                    history_content_mismatch=1,
                    history_receipt_mismatch=1,
                )
            ]
        )
        self.assertIn("history_content_mismatch", report["issues"])
        self.assertIn("history_receipt_mismatch", report["issues"])
        self.assertFalse(report["complete"])

    def test_conversation_duplicates_and_conflicting_variants_fail_final_completion(
        self,
    ):
        report = assess_samples(
            [
                sample(
                    final_drain=True,
                    scheduled_input_coverage=True,
                    pending_input_count=0,
                    conversation_duplicate_rollup_ids=1,
                    conversation_conflicting_rollup_ids=1,
                )
            ]
        )
        self.assertIn("duplicate_conversation_rollup_ids", report["issues"])
        self.assertIn("conflicting_conversation_rollup_ids", report["issues"])
        self.assertFalse(report["complete"])

    def test_equal_cardinality_but_disjoint_rollup_ids_fail_identity_parity(self):
        report = assess_samples(
            [
                sample(
                    final_drain=True,
                    traffic_expected_unique=10,
                    traffic_unique_count=10,
                    traffic_identity_mismatch_count=2,
                    conversation_expected_unique=3,
                    conversation_unique_count=3,
                    conversation_identity_mismatch_count=2,
                )
            ]
        )
        self.assertIn("traffic_identity_mismatch", report["issues"])
        self.assertIn("conversation_identity_mismatch", report["issues"])
        self.assertFalse(report["complete"])

    def test_active_scheduler_job_is_only_an_issue_during_final_drain(self):
        report = assess_samples([sample(active_jobs=[JOBS[-1]])])
        self.assertNotIn("active_jobs_not_drained", report["issues"])
        report = assess_samples([sample(active_jobs=[JOBS[-1]], final_drain=True)])
        self.assertIn("active_jobs_not_drained", report["issues"])
        self.assertFalse(report["complete"])

    def test_exact_raw_counts_retained_identities_and_backlog_are_distinct(self):
        report = assess_samples(
            [
                sample(0, unprocessed_backlog=1),
                sample(300, unprocessed_backlog=2),
                sample(600, unprocessed_backlog=3),
            ]
        )
        self.assertEqual(report["raw_count_first_last"], [100, 100])
        self.assertEqual(report["raw_unique_count_first_last"], [90, 90])
        self.assertEqual(report["retained_unique_history_first_last"], [5, 5])
        self.assertEqual(report["retained_unique_traffic_first_last"], [10, 10])
        self.assertEqual(report["unprocessed_backlog_first_last"], [1, 3])
        self.assertIn("increasing_unprocessed_backlog", report["issues"])

    def test_raw_mismatch_duplicate_traffic_and_unknown_backlog_prevent_completion(
        self,
    ):
        report = assess_samples(
            [
                sample(
                    raw_count=99,
                    raw_counts_match=False,
                    traffic_count=11,
                    unprocessed_backlog=None,
                )
            ]
        )
        self.assertIn("raw_count_mismatch", report["issues"])
        self.assertIn("duplicate_traffic_observations", report["issues"])
        self.assertIn("backlog_metric_unavailable", report["issues"])
        self.assertFalse(report["complete"])


if __name__ == "__main__":
    unittest.main()
