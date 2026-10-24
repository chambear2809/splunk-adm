from contextlib import redirect_stdout
import io
import unittest
import subprocess
import sys
import json
import types
from pathlib import Path
from unittest.mock import patch

from tools.pilot_readiness import (
    ALL_JOBS,
    JOB_DEFINITIONS,
    SOURCES,
    NETWORK_CLIENT_SOURCES,
    analyze,
    selected_health_probes,
    _lab_snapshot,
    main,
)


def snapshot():
    return {
        "active_contract": 1,
        "checked_at": 1800000000,
        "macros": {
            "adm_index_netflow": "index=netflow",
            "adm_index_summary": "index=adm_summary",
            "adm_summary_index_name": "adm_summary",
        },
        "source_health": [
            {
                "name": "NetFlow",
                "records": "4",
                "status": "ok",
                "latest_indexed": 1799999900,
                "probe_lookback_seconds": 604800,
            },
            {
                "name": "Summary",
                "records": "4",
                "status": "ok",
                "latest_indexed": 1799999900,
                "probe_lookback_seconds": 604800,
            },
        ],
        "quality": [
            {
                "source": "netflow",
                "status": "accepted",
                "reason": "evaluated",
                "records": 4,
            }
        ],
        "jobs": [
            {
                "name": n,
                "disabled": int(
                    JOB_DEFINITIONS.get(n, {}).get("stage") != "active"
                    or 1 not in JOB_DEFINITIONS.get(n, {}).get("contracts", [])
                ),
                "is_scheduled": int(
                    JOB_DEFINITIONS.get(n, {}).get("stage") == "active"
                    and 1 in JOB_DEFINITIONS.get(n, {}).get("contracts", [])
                ),
                "last_success": 1799999900,
                "last_run": 1799999900,
                "last_status": "success",
            }
            for n in ALL_JOBS
        ],
        "permissions": {
            "app_read_roles": ["*"],
            "app_write_roles": ["admin", "sc_admin"],
            "saved_searches": [
                {
                    "name": n,
                    "read_roles": ["admin", "sc_admin"],
                    "write_roles": ["admin", "sc_admin"],
                    "dispatchAs": "owner",
                }
                for n in ALL_JOBS
            ],
        },
        "app": {"version": "0.4.0"},
    }


class PilotReadinessTest(unittest.TestCase):
    def test_summary_remains_a_valid_cli_source(self):
        report = analyze(snapshot(), selected_sources={"summary"})
        self.assertEqual(report["selected_sources"], ["summary"])
        self.assertFalse(
            any(
                finding["check"] == "source_selection"
                and finding["status"] == "blocked"
                for finding in report["findings"]
            )
        )

    def test_optional_dns_selection_does_not_change_core_readiness_or_exit_findings(
        self,
    ):
        core = analyze(snapshot(), selected_sources={"netflow"})
        observed = snapshot()
        observed["macros"]["adm_index_dns_stream"] = "index=Bad Name"
        observed["source_health"].append(
            {"name": "Splunk Stream DNS", "status": "failed", "records": "0"}
        )
        with_dns = analyze(observed, selected_sources={"netflow", "dns_stream"})
        self.assertEqual(with_dns["summary"], core["summary"])
        self.assertEqual(with_dns["findings"], core["findings"])
        self.assertEqual(with_dns["selected_sources"], core["selected_sources"])
        self.assertEqual(with_dns["optional_evidence"][0]["source"], "dns_stream")

    def test_dns_only_selection_cannot_establish_traffic_readiness(self):
        result = analyze(snapshot(), selected_sources={"dns_hubble"})
        self.assertEqual(result["summary"]["status"], "unknown")
        self.assertEqual(result["selected_sources"], [])
        self.assertEqual(
            result["optional_evidence"][0]["status"], "runtime_diagnostics_not_run"
        )

    def test_cli_accepts_dns_source_without_changing_core_exit_or_status(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--source", "dns_stream", "--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report["summary"]["status"], "unknown")
        self.assertEqual(report["selected_sources"], [])
        self.assertEqual(
            report["optional_evidence"][0]["status"], "runtime_diagnostics_not_run"
        )

        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--source", "dns_hubble"])
        self.assertEqual(code, 2)
        self.assertIn("optional evidence:", output.getvalue())
        self.assertIn("runtime_diagnostics_not_run", output.getvalue())

    def test_wrong_contract_enabled_writer_is_a_configuration_conflict(self):
        for contract, name in (
            (1, "ADM - Conversation rollup v2"),
            (2, "ADM - Conversation rollup"),
        ):
            with self.subTest(contract=contract):
                data = snapshot()
                data["active_contract"] = contract
                for job in data["jobs"]:
                    job["disabled"] = 1
                    job["is_scheduled"] = 0
                writer = next(job for job in data["jobs"] if job["name"] == name)
                # Enabled is the conflict; this does not assert that it is scheduled.
                writer["disabled"] = 0
                findings = analyze(data, ["netflow"])["findings"]
                conflicts = [
                    f for f in findings if f["check"] == "contract_job_conflict"
                ]
                self.assertEqual(len(conflicts), 1)
                self.assertEqual(conflicts[0]["status"], "blocked")
                self.assertEqual(conflicts[0]["evidence"]["name"], name)
                for flag in (1, None):
                    writer["disabled"] = flag
                    self.assertFalse(
                        any(
                            f["check"] == "contract_job_conflict"
                            for f in analyze(data, ["netflow"])["findings"]
                        )
                    )

    def test_unselected_compatible_and_disabled_staged_jobs_are_not_conflicts(self):
        data = snapshot()
        findings = analyze(data, ["netflow"])["findings"]
        self.assertFalse(any(f["check"] == "contract_job_conflict" for f in findings))
        self.assertNotIn(
            "ADM - Identity builder",
            {f.get("evidence") for f in findings if f["check"] == "schedule"},
        )

    def test_lab_snapshot_timestamps_completion_after_new_receipts(self):
        clock = [1800000000]
        searches = []
        selectors = json.loads(
            (
                Path(__file__).parents[1] / "research/cisco-pipeline-interface.json"
            ).read_text()
        )["activation"]["cutover_selectors"]
        definitions = {item["name"]: item["before"] for item in selectors}
        definitions.update(snapshot()["macros"])

        def request(method, path):
            from urllib.parse import unquote

            clock[0] += 1
            name = unquote(path.rsplit("/", 1)[-1])
            if "/conf-macros/" in path:
                return {
                    "entry": [
                        {
                            "content": {
                                "definition": definitions.get(name, "index=unused")
                            }
                        }
                    ]
                }
            if path.endswith("/adm/deployment-settings"):
                return {
                    "state": "configured",
                    "settings": {"schemaVersion": 1, "revision": "test", "sources": {}},
                    "canWrite": False,
                }
            if path.endswith("/saved/searches?count=0"):
                return {"entry": []}
            return {"entry": [{"content": {"version": "0.4.0"}, "acl": {}}]}

        class Runner:
            def __init__(self, timeout):
                pass

            def search(self, *args):
                clock[0] += 1
                searches.append(args[1])
                return [
                    {
                        "name": "NetFlow",
                        "records": "1",
                        "status": "ok",
                        "latest_indexed": clock[0],
                        "probe_lookback_seconds": 604800,
                    }
                ], {"status": "complete"}

        with (
            patch.dict(
                sys.modules,
                {
                    "lab": types.SimpleNamespace(_json=request),
                    "benchmark_pipeline": types.SimpleNamespace(Runner=Runner),
                },
            ),
            patch("tools.pilot_readiness.time.time", side_effect=lambda: clock[0]),
        ):
            data = _lab_snapshot(["netflow"])
        self.assertEqual(data["checked_at"], clock[0])
        receipt = next(
            item
            for item in analyze(data, ["netflow"])["findings"]
            if item.get("source") == "netflow" and item["check"] == "freshness"
        )
        self.assertEqual(receipt["status"], "pass")
        data["source_health"][0]["latest_indexed"] = clock[0] + 1
        receipt = next(
            item
            for item in analyze(data, ["netflow"])["findings"]
            if item.get("source") == "netflow" and item["check"] == "freshness"
        )
        self.assertEqual(receipt["status"], "unknown")
        for macro in ("adm_index_k8s", "adm_index_traces"):
            definitions[macro] = ""
        with (
            patch.dict(
                sys.modules,
                {
                    "lab": types.SimpleNamespace(_json=request),
                    "benchmark_pipeline": types.SimpleNamespace(Runner=Runner),
                },
            ),
            patch("tools.pilot_readiness.time.time", side_effect=lambda: clock[0]),
        ):
            searches.clear()
            guarded = _lab_snapshot(["k8s", "traces"])
        self.assertEqual(guarded["raw_fields"], {})
        self.assertFalse(
            any(
                "kube:object:pods" in query or "adm_index_traces" in query
                for query in searches
            )
        )
        self.assertTrue(
            any(
                item["check"] == "required_fields" and item["status"] == "unknown"
                for item in analyze(guarded, ["k8s", "traces"])["findings"]
            )
        )

    def test_fractional_job_timestamps_are_valid_but_malformed_values_are_unknown(self):
        data = snapshot()
        data["checked_at"] = 1800000000.75
        job = next(
            item for item in data["jobs"] if item["name"] == "ADM - Conversation rollup"
        )

        def state():
            return next(
                item["status"]
                for item in analyze(data, ["netflow"])["findings"]
                if item["check"] == "job_run"
            )

        for value in ("1799999900.250", 1799999900.25, "1800000000.5"):
            job["last_success"] = value
            self.assertEqual(state(), "pass")
        for value in (True, "nan", float("inf"), -1, 253402300800, {}, "1800000001.5"):
            job["last_success"] = value
            self.assertEqual(state(), "unknown")

    def test_client_quality_reasons_remain_visible_in_readiness(self):
        data = snapshot()
        data["active_contract"] = 2
        data["quality"] = [
            {
                "source": "meraki_association",
                "status": "incomplete",
                "reason": "evaluated",
                "records": 1,
            },
            {
                "source": "meraki_association",
                "status": "incomplete",
                "reason": "missing_client_mac",
                "records": 1,
            },
        ]
        reasons = next(
            item
            for item in analyze(data, ["meraki"])["findings"]
            if item.get("source") == "meraki" and item["check"] == "quality_diagnostics"
        )
        self.assertEqual(reasons["status"], "warning")
        self.assertEqual(reasons["evidence"][0]["reason"], "missing_client_mac")

    def test_required_derived_evidence_prevents_false_readiness(self):
        data = snapshot()
        self.assertEqual(analyze(data, ["netflow"])["summary"]["status"], "ready")
        data["source_health"].pop()
        self.assertEqual(analyze(data, ["netflow"])["summary"]["status"], "unknown")
        data = snapshot()
        data["macros"]["adm_summary_index_name"] = "different_summary"
        result = analyze(data, ["netflow"])
        self.assertTrue(
            any(
                item.get("source") == "summary" and item["status"] == "blocked"
                for item in result["findings"]
            )
        )
        data = snapshot()
        data["source_health"][1]["latest_indexed"] -= 86400
        self.assertTrue(
            any(
                item.get("source") == "summary"
                and item["check"] == "freshness"
                and item["status"] == "warning"
                for item in analyze(data, ["netflow"])["findings"]
            )
        )

    def test_v2_requires_selected_profile_and_summary_families(self):
        data = snapshot()
        data["active_contract"] = 2
        data["macros"].update(
            {
                "adm_index_summary_v2": "index=adm_summary_v2",
                "adm_summary_index_v2_name": "adm_summary_v2",
            }
        )
        profile = {
            "name": "Stream source scope profiles",
            "records": "1",
            "status": "visible",
            "mapped_records": "1",
            "unmapped_records": "0",
            "ambiguous_records": "0",
            "unsupported_records": "0",
            "incomplete_records": "0",
        }
        data["source_health"].append(profile)
        findings = analyze(data, ["netflow"])["findings"]
        self.assertTrue(
            any(
                item.get("source") == "profiles_stream"
                and item["status"] == "pass"
                and item["check"] == "source_mapping"
                for item in findings
            )
        )
        for source in ("summary_v2", "traffic_v2"):
            self.assertTrue(
                any(
                    item.get("source") == source
                    and item["check"] == "visibility"
                    and item["status"] == "unknown"
                    for item in findings
                )
            )
        self.assertFalse(
            any(
                item.get("source")
                in {"profiles_meraki", "profiles_catalyst", "summary"}
                and item["status"] not in {"not_selected"}
                for item in findings
            )
        )
        profile["mapped_records"] = "0"
        profile["ambiguous_records"] = "1"
        self.assertTrue(
            any(
                item.get("source") == "profiles_stream"
                and item["check"] == "source_mapping"
                and item["status"] == "warning"
                for item in analyze(data, ["netflow"])["findings"]
            )
        )
        profile["records"] = "0"
        self.assertTrue(
            any(
                item.get("source") == "profiles_stream"
                and item["check"] == "source_mapping"
                and item["status"] == "blocked"
                for item in analyze(data, ["netflow"])["findings"]
            )
        )

    def test_source_probes_are_selected_before_dispatch_and_shared_queries_deduplicate(
        self,
    ):
        data = snapshot()
        probes = selected_health_probes(data, ["netflow"])
        self.assertEqual(
            probes["sources"],
            ["adm_health_source_netflow", "adm_health_source_summary"],
        )
        self.assertEqual(probes["quality"], ["adm_health_quality_netflow"])
        data["source_configuration"] = {
            "netflow": "not_configured",
            "summary": "configured",
        }
        guarded = selected_health_probes(data, ["netflow"])
        self.assertEqual(guarded["sources"], ["adm_health_source_summary"])
        self.assertEqual(guarded["quality"], [])
        data["source_configuration"]["netflow"] = "unavailable"
        self.assertEqual(selected_health_probes(data, ["netflow"]), guarded)
        data.pop("source_configuration")
        self.assertEqual(selected_health_probes(data, ["nxos"])["quality"], [])
        self.assertEqual(selected_health_probes(data, ["catalyst"])["sources"], [])
        data["active_contract"] = 2
        probes = selected_health_probes(data, ["netflow", "sdwan"])
        self.assertEqual(probes["quality"], ["adm_health_quality_stream_v2"])
        self.assertEqual(probes["sources"].count("adm_health_network_profile_rows"), 1)
        data.pop("active_contract")
        self.assertEqual(
            selected_health_probes(data, ["netflow"]), {"sources": [], "quality": []}
        )

    def test_shared_intent_drives_readiness_without_event_inference(self):
        data = snapshot()
        self.assertEqual(analyze(data)["summary"]["status"], "unknown")
        data["deployment_settings"] = {
            "schemaVersion": 1,
            "revision": "verified",
            "sources": {
                "netflow": {
                    "state": "active",
                    "cadenceSeconds": 300,
                    "staleAfterSeconds": 1200,
                }
            },
        }
        report = analyze(data)
        self.assertEqual(report["selected_sources"], ["netflow"])
        self.assertEqual(report["summary"]["status"], "ready")
        names = {
            item["evidence"]
            for item in report["findings"]
            if item["check"] == "schedule"
        }
        self.assertEqual(names, {"ADM - Conversation rollup"})

    def test_cisco_staging_never_requires_disabled_v2_jobs_on_v1(self):
        data = snapshot()
        report = analyze(data, ["catalyst", "meraki"])
        self.assertEqual(report["summary"]["status"], "unknown")
        self.assertFalse(
            any(item["check"] == "schedule" for item in report["findings"])
        )
        self.assertEqual(
            sum(item["status"] == "staged" for item in report["findings"]), 2
        )

    def test_hourly_cadence_and_insufficient_receipt_window(self):
        data = snapshot()
        data["deployment_settings"] = {
            "schemaVersion": 1,
            "revision": "verified",
            "sources": {
                "netflow": {
                    "state": "active",
                    "cadenceSeconds": 3600,
                    "staleAfterSeconds": 10800,
                }
            },
        }
        data["source_health"][0]["latest_indexed"] = data["checked_at"] - 3700

        def finding():
            return next(
                item
                for item in analyze(data)["findings"]
                if item["check"] == "freshness"
            )

        self.assertEqual(finding()["status"], "pass")
        data["source_health"][0]["probe_lookback_seconds"] = 3600
        self.assertEqual(finding()["status"], "unknown")

    def test_malformed_shared_intent_fails_closed(self):
        data = snapshot()
        for state in (["active"], True, None):
            data["deployment_settings"] = {
                "schemaVersion": 1,
                "revision": "invalid",
                "sources": {
                    "netflow": {
                        "state": state,
                        "cadenceSeconds": 300,
                        "staleAfterSeconds": 1200,
                    }
                },
            }
            self.assertEqual(analyze(data)["summary"]["status"], "unknown")

    def test_required_job_overdue_and_unknown_contract_cannot_pass(self):
        data = snapshot()
        next(job for job in data["jobs"] if job["name"] == "ADM - Conversation rollup")[
            "last_success"
        ] -= 3600
        report = analyze(data, ["netflow"])
        self.assertEqual(
            next(item for item in report["findings"] if item["check"] == "job_run")[
                "status"
            ],
            "blocked",
        )
        del data["active_contract"]
        self.assertEqual(analyze(data, ["netflow"])["summary"]["status"], "unknown")

    def test_missing_observer_mapping_is_actionable_warning(self):
        data = snapshot()
        data["quality"].append(
            {
                "source": "netflow",
                "status": "accepted_with_warning",
                "reason": "unmapped_scope",
                "records": 3,
            }
        )
        finding = next(
            f
            for f in analyze(data, ["netflow"])["findings"]
            if f["check"] == "observer_mapping"
        )
        self.assertEqual(finding["status"], "warning")
        self.assertIn("3", finding["message"])

    def test_invalid_quality_fields_are_actionable(self):
        data = snapshot()
        data["quality"] = [
            {
                "source": "netflow",
                "status": "excluded",
                "reason": "evaluated",
                "records": 2,
            },
            {
                "source": "netflow",
                "status": "accepted_with_warning",
                "reason": "evaluated",
                "records": 1,
            },
        ]
        finding = next(
            f for f in analyze(data, ["netflow"])["findings"] if f["check"] == "quality"
        )
        self.assertEqual(finding["status"], "warning")
        self.assertEqual(finding["evidence"], {"excluded": 2, "warnings": 1})

    def test_quality_invalid_field_reason_blocks_selected_source(self):
        data = snapshot()
        data["quality"] = [
            {
                "source": "netflow",
                "status": "excluded",
                "reason": "evaluated",
                "records": 1,
            },
            {
                "source": "netflow",
                "status": "excluded",
                "reason": "invalid_source_ip",
                "records": 1,
            },
        ]
        finding = next(
            f
            for f in analyze(data, ["netflow"])["findings"]
            if f["check"] == "required_fields"
        )
        self.assertEqual(finding["status"], "blocked")
        self.assertEqual(finding["evidence"], ["invalid_source_ip"])

    def test_disabled_builder_blocks_and_disabled_prune_passes(self):
        data = snapshot()
        next(j for j in data["jobs"] if j["name"] == "ADM - Identity builder")[
            "disabled"
        ] = 1
        findings = analyze(data, ["netflow", "k8s"])["findings"]
        builder = next(
            f for f in findings if f.get("evidence") == "ADM - Identity builder"
        )
        prune = next(f for f in findings if f["check"] == "prune_schedule")
        self.assertEqual(builder["status"], "blocked")
        self.assertEqual(prune["status"], "pass")

    def test_enabled_but_unscheduled_builder_blocks(self):
        data = snapshot()
        next(j for j in data["jobs"] if j["name"] == "ADM - Identity builder")[
            "is_scheduled"
        ] = 0
        finding = next(
            f
            for f in analyze(data, ["netflow", "k8s"])["findings"]
            if f.get("evidence") == "ADM - Identity builder"
        )
        self.assertEqual(finding["status"], "blocked")

    def test_saved_search_acl_lookup_requires_all_eleven(self):
        data = snapshot()
        entry = data["permissions"]["saved_searches"][0]
        entry["write_roles"] = []
        finding = next(
            f
            for f in analyze(data, ["netflow"])["findings"]
            if f["check"] == "permissions"
        )
        self.assertEqual(finding["status"], "blocked")
        self.assertIn(f"{entry['name']}:write", finding["evidence"]["missing"])

    def test_quality_unknown_prevents_ready(self):
        data = snapshot()
        data["quality"] = []
        data["source_health"] = []
        result = analyze(data, ["netflow"])
        self.assertEqual(result["summary"]["status"], "unknown")

    def test_malformed_negative_quality_counts_are_unknown(self):
        data = snapshot()
        data["quality"] = [
            {
                "source": "netflow",
                "status": "accepted",
                "reason": "evaluated",
                "records": "-1",
            }
        ]
        finding = next(
            f for f in analyze(data, ["netflow"])["findings"] if f["check"] == "quality"
        )
        self.assertEqual(finding["status"], "unknown")

    def test_partially_valid_raw_probe_blocks(self):
        data = snapshot()
        data["raw_fields"] = {"k8s": {"records": "3", "valid": "1"}}
        finding = next(
            f
            for f in analyze(data, ["k8s"])["findings"]
            if f["check"] == "required_fields"
        )
        self.assertEqual(finding["status"], "blocked")

    def test_absent_raw_probe_is_unknown(self):
        finding = next(
            f
            for f in analyze(snapshot(), ["k8s"])["findings"]
            if f["check"] == "required_fields"
        )
        self.assertEqual(finding["status"], "unknown")

    def test_nonflow_source_does_not_require_flow_quality(self):
        data = snapshot()
        data["raw_fields"] = {"k8s": {"records": "3", "valid": "3"}}
        data["source_health"] = [{"name": "Kubernetes", "records": "3", "status": "ok"}]
        result = analyze(data, ["k8s"])
        self.assertNotIn("quality", {f["check"] for f in result["findings"]})

    def test_missing_prune_schedule_evidence_is_unknown(self):
        data = snapshot()
        data["jobs"] = [j for j in data["jobs"] if not j["name"].endswith("prune")]
        finding = next(
            f
            for f in analyze(data, ["netflow"])["findings"]
            if f["check"] == "prune_schedule"
        )
        self.assertEqual(finding["status"], "unknown")

    def test_cli_unknown_exits_two(self):
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parents[1] / "tools" / "pilot_readiness.py"),
                "--source",
                "k8s",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)

    def test_nonflow_raw_probe_fails_closed_and_summary_replay_is_warning(self):
        data = snapshot()
        data["raw_fields"] = {"k8s": {"records": "3", "valid": "0"}}
        result = analyze(data, ["k8s"])
        self.assertEqual(
            next(f for f in result["findings"] if f["check"] == "required_fields")[
                "status"
            ],
            "blocked",
        )
        data["raw_fields"] = {"summary": {"records": "3", "valid": "3", "replay": "0"}}
        result = analyze(data, ["summary"])
        self.assertEqual(
            next(f for f in result["findings"] if f["check"] == "replay_identity")[
                "status"
            ],
            "warning",
        )

    def test_unknown_source_is_reported_without_key_error(self):
        result = analyze({}, ["future_vendor"])
        self.assertEqual(result["summary"]["status"], "blocked")
        self.assertTrue(
            any("future_vendor" in f["message"] for f in result["findings"])
        )

    def test_visibility_is_unknown_and_unselected_is_explicit(self):
        data = snapshot()
        data["source_health"] = []
        result = analyze(data, ["netflow"])
        self.assertEqual(
            next(f for f in result["findings"] if f["check"] == "visibility")["status"],
            "unknown",
        )
        self.assertEqual(
            sum(f["status"] == "not_selected" for f in result["findings"]),
            len(SOURCES) - len(NETWORK_CLIENT_SOURCES) - 1,
        )

    def test_unselected_cisco_sources_do_not_change_existing_readiness(self):
        baseline = analyze(snapshot(), ["netflow"])
        self.assertEqual(
            baseline["summary"]["not_selected"],
            len(SOURCES) - len(NETWORK_CLIENT_SOURCES) - 1,
        )
        self.assertFalse(
            any(f.get("source") in {"catalyst", "meraki"} for f in baseline["findings"])
        )

    def test_cisco_source_evidence_distinguishes_gates(self):
        data = snapshot()
        data["active_contract"] = 2
        data["macros"] = {"adm_index_catalyst": "index=cisco_catalyst"}
        data["source_health"] = [
            {"name": "Catalyst Center", "records": 2, "status": "ok"}
        ]
        data["source_permissions"] = {
            "catalyst": {"status": "partial", "missing": ["client read"]}
        }
        data["raw_schema"] = {
            "catalyst": {"status": "partial", "records": 2, "valid": 1}
        }
        data["source_scope"] = {
            "catalyst": {"status": "ambiguous", "profiles": ["campus-a", "campus-b"]}
        }
        data["source_history"] = {"catalyst": {"status": "partial", "gaps": 1}}
        data["collection_evidence"] = {
            "catalyst": {"status": "synthetic", "records": 2}
        }
        findings = analyze(data, ["catalyst"])["findings"]
        statuses = {
            f["check"]: f["status"] for f in findings if f.get("source") == "catalyst"
        }
        self.assertEqual(statuses["source_permissions"], "blocked")
        self.assertEqual(statuses["raw_schema"], "blocked")
        self.assertEqual(statuses["source_mapping"], "blocked")
        self.assertEqual(statuses["source_history"], "warning")
        self.assertEqual(statuses["collection_evidence"], "warning")

    def test_meraki_missing_permission_and_history_evidence_stays_unknown(self):
        data = snapshot()
        data["macros"] = {"adm_index_meraki": "index=cisco_meraki"}
        data["source_health"] = [{"name": "Meraki", "records": 4, "status": "ok"}]
        data["active_contract"] = 2
        findings = analyze(data, ["meraki"])["findings"]
        statuses = {
            f["check"]: f["status"] for f in findings if f.get("source") == "meraki"
        }
        self.assertEqual(statuses["visibility"], "pass")
        self.assertEqual(statuses["source_permissions"], "unknown")
        self.assertEqual(statuses["raw_schema"], "unknown")
        self.assertEqual(statuses["source_history"], "unknown")
        self.assertEqual(statuses["collection_evidence"], "unknown")

    def test_meraki_actual_collection_requires_each_evidence_gate(self):
        data = snapshot()
        data["macros"] = {"adm_index_meraki": "index=cisco_meraki"}
        data["source_health"] = [{"name": "Meraki", "records": 4, "status": "ok"}]
        data["source_permissions"] = {"meraki": {"status": "complete"}}
        data["raw_schema"] = {
            "meraki": {"status": "complete", "records": 4, "valid": 4}
        }
        data["source_scope"] = {
            "meraki": {"status": "mapped", "profile": "org-network"}
        }
        data["source_history"] = {"meraki": {"status": "complete", "gaps": 0}}
        data["collection_evidence"] = {"meraki": {"status": "actual", "records": 4}}
        data["active_contract"] = 2
        findings = analyze(data, ["meraki"])["findings"]
        statuses = {
            f["check"]: f["status"] for f in findings if f.get("source") == "meraki"
        }
        self.assertEqual(statuses["source_permissions"], "pass")
        self.assertEqual(statuses["raw_schema"], "pass")
        self.assertEqual(statuses["source_mapping"], "pass")
        self.assertEqual(statuses["source_history"], "pass")
        self.assertEqual(statuses["collection_evidence"], "pass")


if __name__ == "__main__":
    unittest.main()
