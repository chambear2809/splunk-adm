"""Offline safety and integrity tests for the two change-scenario tracks."""

from __future__ import annotations

import copy
import hashlib

import unittest

from tools.capture_change_scenario import (
    DIRECT_RESULT_KEYS,
    ENDPOINT_RESULT_KEYS,
    MONITORING_RESULT_KEYS,
    RESULT_KEYS,
    _validate_timeline,
    captured_dependency_binding,
    _validate_result,
    verify_capture_bundle,
)
from tools.change_correlation.contracts import canonical_json
from tools.change_scenarios import (
    SCENARIO_IDS,
    ScenarioError,
    build_run_plan,
    load_scenario,
    offline_preflight,
    scenario_template_hash,
    verify_run_plan,
)
from tools.replay_change_scenario import run_phase_clock


HASH = "a" * 64


class _FakeClock:
    def __init__(self, epoch: float) -> None:
        self.epoch = epoch
        self.elapsed = 0.0

    def wall(self) -> float:
        return self.epoch + self.elapsed

    def monotonic(self) -> float:
        return self.elapsed

    def sleep(self, seconds: float) -> None:
        self.elapsed += seconds


def _readiness(scenario_id: str) -> dict:
    return {
        "schema_version": 1,
        "scenario_id": scenario_id,
        "lab_allocation_sha256": "1" * 64,
        "target_identity_sha256": "9" * 64,
        "package_sha256": "2" * 64,
        "execution_inventory_sha256": "3" * 64,
        "source_mapping_sha256": "4" * 64,
        "configuration_sha256": "5" * 64,
        "contract_sha256": "6" * 64,
        "checks": {
            "lab_owned": True,
            "package_ready": True,
            "source_mappings_ready": True,
            "clock_agrees": True,
            "queries_ready": True,
            "lifecycle_authorized": True,
        },
        "clock": {"measured_offset_milliseconds": 0, "tolerance_milliseconds": 100},
        "query_definitions": {"fixture-query": "7" * 64},
        "fixture_sha256": {"fixtures/example.json": "8" * 64},
    }


def _plan(scenario_id: str = "track-a-firewall") -> dict:
    return build_run_plan(
        load_scenario(scenario_id),
        _readiness(scenario_id),
        now_epoch=1_800_000_000,
        anchor_epoch=1_800_000_300,
        execution_id="12345678-1234-5678-1234-567812345678",
    )


class ChangeScenarioTests(unittest.TestCase):
    def test_captured_dependency_requires_matching_query_input_coverage(self) -> None:
        query_hash = "b" * 64
        receipt = "c" * 64
        window = {"earliest": 1_800_000_300, "latest": 1_800_000_600}
        coverage = {
            "schema_version": 1,
            "basis": "query_level_input_coverage",
            "qualification": "eligible_input_superset_not_per_edge_lineage",
            "execution_id": "execution-1",
            "query_sha256": query_hash,
            "scope": "change-a",
            "graph_window": window,
            "summary_readback": {
                "receipt_fingerprints": [receipt],
                "index_window": {"earliest": 1_800_000_301, "latest": 1_800_000_601},
            },
        }
        graph = {
            "rows": [{"row_type": "edge", "id": "edge-1"}],
            "readback": {
                "query_input_coverage": coverage,
                "receipt_fingerprints": [receipt],
                "index_time_bounds": coverage["summary_readback"]["index_window"],
                "query_job": {"sid": "sid-1"},
            },
        }
        identity = captured_dependency_binding(
            scenario_id="track-a-firewall",
            execution_id="execution-1",
            graph_result_key="graph.baseline",
            edge_id="edge-1",
            scope="change-a",
            window=window,
            query_sha256=query_hash,
            active_traffic_contract_sha256="d" * 64,
            receipt_fingerprints=[receipt],
            graph_result=graph,
        )
        self.assertEqual(
            identity["binding"]["receipt_basis"], "query_input_coverage_v1"
        )
        self.assertEqual(
            identity["binding"]["query_input_coverage_sha256"],
            hashlib.sha256(canonical_json(coverage)).hexdigest(),
        )
        del graph["readback"]["query_input_coverage"]
        with self.assertRaisesRegex(ScenarioError, "query-input coverage"):
            captured_dependency_binding(
                scenario_id="track-a-firewall",
                execution_id="execution-1",
                graph_result_key="graph.baseline",
                edge_id="edge-1",
                scope="change-a",
                window=window,
                query_sha256=query_hash,
                active_traffic_contract_sha256="d" * 64,
                receipt_fingerprints=[receipt],
                graph_result=graph,
            )

    def test_timeline_rejects_selected_row_content_tampering(self) -> None:
        plan = _plan()
        record_id = "e" * 64
        row = {
            "record_id": record_id,
            "generation_id": "placeholder",
            "scope": "change-a",
            "value": "original",
        }
        rows_sha = hashlib.sha256(
            canonical_json(
                {key: value for key, value in row.items() if key != "generation_id"}
            )
        ).hexdigest()
        manifest_body = {
            "row_count": 1,
            "rows_sha256": rows_sha,
            "source": "offline-test",
        }
        generation_id = hashlib.sha256(canonical_json(manifest_body)).hexdigest()
        row["generation_id"] = generation_id
        result = {
            "generation_validation": {
                "generation_id": generation_id,
                "manifest": {**manifest_body, "generation_id": generation_id},
                "complete_row_count": 1,
                "rows_sha256": rows_sha,
                "validated_before_filter": True,
                "ingest_bounds": {
                    "earliest": plan["anchor_t_epoch"],
                    "latest": plan["planned_run_end_epoch"],
                },
            },
            "generation_rows": [row],
            "rows": [dict(row, value="tampered")],
            "selection": {
                "scope": "change-a",
                "window": {
                    "start": plan["anchor_t_epoch"],
                    "end": plan["planned_run_end_epoch"],
                },
                "change_ids": [],
            },
        }
        with self.assertRaisesRegex(ScenarioError, "subset"):
            _validate_timeline(result, load_scenario(plan["scenario_id"]), plan)

    def test_only_two_offline_scenarios_are_exposed_without_assigning_t(self) -> None:
        self.assertEqual(SCENARIO_IDS, ("track-a-firewall", "track-b-fabric"))
        for scenario_id in SCENARIO_IDS:
            scenario = load_scenario(scenario_id)
            result = offline_preflight(scenario)
            self.assertEqual(result["scenario_id"], scenario_id)
            self.assertIsNone(result["planned_t_epoch"])
            self.assertFalse(result["services_contacted"])
            self.assertEqual(result["presentation_status"], "blocked")

    def test_track_a_firewall_authority_and_control_scope_are_source_exact(
        self,
    ) -> None:
        scenario = load_scenario("track-a-firewall")
        registry = scenario["identity_registry"]
        self.assertEqual(
            registry["firewall"]["authority"], registry["firewall"]["source_host"]
        )
        self.assertEqual(registry["firewall"]["authority"], "cc-a-fmc.example.invalid")
        schedule = {item["id"]: item for item in scenario["evidence_schedule"]}
        self.assertNotIn("a-independent-control", schedule)
        self.assertEqual(schedule["a-control-flow"]["product"], "stream_ipfix")
        self.assertEqual(schedule["a-control-handoff"]["product"], "cilium")

    def test_readiness_builds_future_plan_with_future_t_minus_120_prelude(self) -> None:
        plan = _plan()
        self.assertEqual(plan["anchor_t_epoch"], 1_800_000_300)
        self.assertEqual(plan["plan_created_epoch"], 1_800_000_000)
        self.assertEqual(
            plan["planned_source_time_bounds"]["earliest_epoch"], 1_800_000_180
        )
        self.assertGreater(
            plan["planned_source_time_bounds"]["earliest_epoch"],
            plan["plan_created_epoch"],
        )
        self.assertFalse(plan["services_contacted"])
        self.assertEqual(verify_run_plan(plan), plan)

    def test_plan_rejects_unready_checks_and_blocked_required_source_fact(self) -> None:
        scenario = load_scenario("track-a-firewall")
        readiness = _readiness(scenario["scenario_id"])
        readiness["checks"]["lifecycle_authorized"] = False
        with self.assertRaisesRegex(ScenarioError, "Readiness checks"):
            build_run_plan(scenario, readiness, now_epoch=1_800_000_000)

        blocked = copy.deepcopy(scenario)
        blocked["evidence_schedule"][0]["status"] = "blocked"
        with self.assertRaisesRegex(ScenarioError, "Required source facts"):
            build_run_plan(
                blocked, _readiness(scenario["scenario_id"]), now_epoch=1_800_000_000
            )

    def test_phase_clock_never_calls_delivery_before_each_planned_source_time(
        self,
    ) -> None:
        plan = _plan()
        clock = _FakeClock(1_800_000_000)
        delivered: list[str] = []

        def deliver(item: dict) -> dict:
            target = (
                item["planned_source_epoch"]
                if "planned_source_epoch" in item
                else item["planned_collection_start_epoch"]
            )
            now = clock.wall()
            self.assertGreaterEqual(now, target)
            delivered.append(item["id"])
            return {
                "actual_emission_epoch": now,
                "transport_acknowledgment_epoch": now + 0.01,
            }

        report = run_phase_clock(
            plan,
            deliver,
            wall_clock=clock.wall,
            monotonic_clock=clock.monotonic,
            sleep=clock.sleep,
        )
        self.assertTrue(delivered)
        self.assertEqual(report["status"], "delivery_complete_readback_pending")
        self.assertEqual(report["readback_status"], "not_performed")
        self.assertTrue(
            all(item["indexed_receipt_epoch"] is None for item in report["events"])
        )
        self.assertTrue(
            all(item["readback_epoch"] is None for item in report["events"])
        )

    def test_phase_clock_rejects_callback_claim_of_preplanned_emission(self) -> None:
        plan = _plan()
        clock = _FakeClock(1_800_000_000)

        def deliver(item: dict) -> dict:
            target = (
                item["planned_source_epoch"]
                if "planned_source_epoch" in item
                else item["planned_collection_start_epoch"]
            )
            return {"actual_emission_epoch": target - 0.001}

        with self.assertRaisesRegex(ScenarioError, "before plan time"):
            run_phase_clock(
                plan,
                deliver,
                wall_clock=clock.wall,
                monotonic_clock=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_timeline_result_must_use_full_incident_window(self) -> None:
        plan = _plan()
        query_literal = "| makeresults"
        query = {
            "literal": query_literal,
            "sha256": hashlib.sha256(query_literal.encode()).hexdigest(),
        }
        readback = {
            "complete": True,
            "source": "splunk_rest",
            "execution_id": plan["execution_id"],
            "plan_sha256": plan["plan_sha256"],
            "result_count": 0,
            "index_time_bounds": {"earliest": 1_800_000_001, "latest": 1_800_000_002},
            "receipt_fingerprints": [],
        }
        result = {
            "status": "complete",
            "query": query,
            "window": {
                "earliest": plan["anchor_t_epoch"],
                "latest": plan["planned_run_end_epoch"],
                "basis": "source_time",
            },
            "rows": [],
            "readback": readback,
        }
        normalized = _validate_result(
            "timeline.selected",
            result,
            scenario=load_scenario(plan["scenario_id"]),
            plan=plan,
            expected_query_hashes={},
        )
        self.assertEqual(normalized["window"]["earliest"], plan["anchor_t_epoch"])
        self.assertEqual(normalized["window"]["latest"], plan["planned_run_end_epoch"])

        result["window"]["earliest"] += 1
        with self.assertRaisesRegex(ScenarioError, "full incident window"):
            _validate_result(
                "timeline.selected",
                result,
                scenario=load_scenario(plan["scenario_id"]),
                plan=plan,
                expected_query_hashes={},
            )

    def test_capture_bundle_hash_domain_excludes_schema_version(self) -> None:
        scenario = load_scenario("track-a-firewall")
        anchor = 1_793_102_000
        windows = {
            phase["id"]: {
                "earliest": anchor + phase["start_offset_seconds"],
                "latest": anchor + phase["end_offset_seconds"],
            }
            for phase in scenario["clock"]["phases"]
        }
        results = {
            key: {"status": "unavailable", "reason": "schema-only test fixture"}
            for key in RESULT_KEYS
        }
        manifest = {
            "execution_inventory_sha256": HASH,
            "capture_sha256": hashlib.sha256(canonical_json(results)).hexdigest(),
            "scenario_id": scenario["scenario_id"],
            "template_revision": scenario["template_revision"],
            "template_sha256": scenario_template_hash(scenario),
            "application": scenario["application"],
            "selection": scenario["selection"],
            "capture_status": "partial",
            "services_contacted": True,
            "anchor_epoch": anchor,
            "anchor_utc": "2026-10-27T11:53:20Z",
            "phase_windows": windows,
            "fixture_file_sha256": {},
            "fixture_sha256": hashlib.sha256(canonical_json({})).hexdigest(),
            "query_sha256": {},
        }
        body = {"manifest": manifest, "results": results}
        bundle = {
            "schema_version": 1,
            **body,
            "bundle_sha256": hashlib.sha256(canonical_json(body)).hexdigest(),
        }
        self.assertEqual(verify_capture_bundle(bundle), bundle)

        wrong_domain = copy.deepcopy(bundle)
        wrong_domain["bundle_sha256"] = hashlib.sha256(
            canonical_json(wrong_domain)
        ).hexdigest()
        with self.assertRaisesRegex(ScenarioError, "bundle_sha256"):
            verify_capture_bundle(wrong_domain)

        falsely_complete = copy.deepcopy(bundle)
        falsely_complete["manifest"]["capture_status"] = "complete"
        falsely_complete["manifest"]["capture_sha256"] = hashlib.sha256(
            canonical_json(falsely_complete["results"])
        ).hexdigest()
        falsely_complete["bundle_sha256"] = hashlib.sha256(
            canonical_json(
                {
                    "manifest": falsely_complete["manifest"],
                    "results": falsely_complete["results"],
                }
            )
        ).hexdigest()
        with self.assertRaisesRegex(ScenarioError, "required results"):
            verify_capture_bundle(falsely_complete)

    def test_result_key_allowlist_contains_only_the_frozen_evidence_surfaces(
        self,
    ) -> None:
        self.assertEqual(len(DIRECT_RESULT_KEYS), 12)
        self.assertEqual(len(ENDPOINT_RESULT_KEYS), 5)
        self.assertEqual(
            MONITORING_RESULT_KEYS,
            {"monitoring.appdynamics", "monitoring.thousandeyes"},
        )
        self.assertEqual(len(RESULT_KEYS), 19)
