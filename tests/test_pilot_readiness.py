import unittest
import subprocess
import sys
from pathlib import Path

from tools.pilot_readiness import ALL_JOBS, analyze


def snapshot():
    return {
        "macros": {"adm_index_netflow": "index=netflow"},
        "source_health": [{"name": "NetFlow", "records": "4", "status": "ok"}],
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
                "disabled": 1 if n.endswith("prune") else 0,
                "is_scheduled": 0 if n.endswith("prune") else 1,
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
        "app": {"version": "0.3.0"},
    }


class PilotReadinessTest(unittest.TestCase):
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
            sum(f["status"] == "not_selected" for f in result["findings"]), 7
        )

    def test_unselected_cisco_sources_do_not_change_existing_readiness(self):
        baseline = analyze(snapshot(), ["netflow"])
        self.assertEqual(baseline["summary"]["not_selected"], 7)
        self.assertFalse(
            any(f.get("source") in {"catalyst", "meraki"} for f in baseline["findings"])
        )

    def test_cisco_source_evidence_distinguishes_gates(self):
        data = snapshot()
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
