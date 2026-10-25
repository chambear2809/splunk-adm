"""Run the exact bounded O11y search and normalizer against the disposable lab."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools" / "o11y_health_search.mjs"
FIXTURE = ROOT / "fixtures" / "o11y" / "complete.json"
INDEX = "atlas_o11y"
SOURCETYPE = "atlas:o11y_health"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class O11yHealthRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.observer = "o11y-lab-" + uuid.uuid4().hex[:12]
        self.scope = "o11y-lab-" + uuid.uuid4().hex[:8]
        self.now = int(time.time())
        self.start = self.now - 900
        self.end = self.now - 60
        self.capture_time = self.now - 3
        self.service = "checkout-" + uuid.uuid4().hex[:8]
        self.environment = "production"
        self.cluster = "eks-lab-east"
        self.namespace = "commerce"
        self.service_namespace = "payments"
        self.organization = "org-lab-01"
        self.realm = "us0"
        self.apm_mms_id = "lab_custom_service_mms_v1"
        self.config = {
            "source": "o11y_health",
            "state": "active",
            "indexes": [INDEX],
            "authorities": [self.observer],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "o11y_export",
                    "observer": self.observer,
                    "scope": self.scope,
                    "cluster": self.cluster,
                    "mapping_status": "verified",
                    "organization_id": self.organization,
                    "realm": self.realm,
                    "apm_mms_id": self.apm_mms_id,
                }
            ],
        }
        self.selection = {
            "schemaVersion": 1,
            "workflow": "service",
            "selectionId": self.observer,
            "scope": self.scope,
            "window": {"start": self.start, "end": self.end},
            "service": {
                "name": self.service,
                "environment": self.environment,
                "cluster": self.cluster,
                "namespace": self.namespace,
            },
            "identityBasis": "disposable O11y health qualification",
            "configurationFingerprint": "a" * 64,
        }
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.template = [copy.deepcopy(item) for item in fixture["events"]]

    def helper(self, payload: dict) -> str | dict:
        completed = subprocess.run(
            ["node", str(HELPER)],
            cwd=ROOT,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return (
            json.loads(completed.stdout)
            if payload.get("mode") == "normalize"
            else completed.stdout
        )

    def capture(
        self, *, suffix: str = "", service_namespace: str | None = None
    ) -> list[dict]:
        events = []
        capture_id = f"{self.observer}{suffix}"
        selected_service_namespace = service_namespace or self.service_namespace
        for item in self.template:
            event = copy.deepcopy(item["event"])
            event.update(
                {
                    "capture_id": capture_id,
                    "captured_at": self.capture_time,
                    "capture_window_start": self.start,
                    "capture_window_end": self.end,
                    "observer_id": self.observer,
                    "organization_id": self.organization,
                    "realm": self.realm,
                    "routing_scope": self.scope,
                    "service_name": self.service,
                    "environment": self.environment,
                    "cluster": self.cluster,
                    "kubernetes_namespace": self.namespace,
                    "service_namespace": selected_service_namespace,
                    "logical_timestamp": self.end - 5,
                }
            )
            if event.get("event_type") == "export_completion" or event.get(
                "signal_label"
            ) in {"request_count", "request_errors", "request_latency_p90"}:
                event.update(
                    {
                        "apm_mms_id": self.apm_mms_id,
                        "sf_dimensionalized": "true",
                        "sf_mms_id": self.apm_mms_id,
                    }
                )
            events.append(
                {
                    "time": self.capture_time,
                    "host": self.observer,
                    "source": "atlas:o11y_health/export",
                    "sourcetype": SOURCETYPE,
                    "index": INDEX,
                    "event": event,
                }
            )
        return events

    def wait_for_indexed(self, expected: int) -> None:
        deadline = time.monotonic() + 30
        query = (
            f'search index={INDEX} sourcetype="{SOURCETYPE}" host="{self.observer}"'
            " | stats count AS count"
        )
        while time.monotonic() < deadline:
            rows = lab.search(query, str(self.capture_time - 3600), str(self.now + 60))
            if rows and int(rows[0].get("count", -1)) == expected:
                return
            time.sleep(0.5)
        self.fail("synthetic Observability Cloud events did not reach the lab index")

    def run_search(self, search: str) -> tuple[list[dict], dict]:
        with lab._mgmt(
            "POST",
            f"/servicesNS/admin/{lab.APP}/search/v2/jobs?output_mode=json",
            {
                "search": search,
                "exec_mode": "normal",
                "earliest_time": str(self.capture_time - 3600),
                "latest_time": str(self.now + 60),
                "max_time": "30",
                "auto_cancel": "30",
                "auto_pause": "0",
                "status_buckets": "0",
            },
            35,
        ) as response:
            sid = json.loads(response.read())["sid"]
        deadline = time.monotonic() + 45
        content = {}
        while time.monotonic() < deadline:
            entry = lab._json("GET", f"/services/search/v2/jobs/{sid}")["entry"][0]
            content = entry["content"]
            if content.get("dispatchState") == "FAILED":
                self.fail("native Splunk O11y search failed before completion")
            if content.get("isDone"):
                break
            time.sleep(0.5)
        else:
            with lab._mgmt(
                "POST", f"/services/search/v2/jobs/{sid}/control", {"action": "cancel"}
            ):
                pass
            self.fail("native Splunk O11y search timed out and was cancelled")
        errors = [
            message
            for message in content.get("messages", [])
            if message.get("type", "").upper() in {"ERROR", "FATAL"}
        ]
        self.assertFalse(errors, "native Splunk O11y search returned an error")
        self.assertFalse(
            content.get("isFinalized"), "search finalized before completion"
        )
        self.assertFalse(
            content.get("resultIsTruncated"), "search results were truncated"
        )
        result = lab._json("GET", f"/services/search/v2/jobs/{sid}/results?count=0")
        result_errors = [
            message
            for message in result.get("messages", [])
            if message.get("type", "").upper() in {"ERROR", "FATAL"}
        ]
        self.assertFalse(
            result_errors, "native Splunk results endpoint returned an error"
        )
        return result.get("results", []), content

    def search_and_normalize(self) -> tuple[list[dict], dict, dict]:
        search = self.helper({"selection": self.selection, "config": self.config})
        self.assertIsInstance(search, str)
        self.assertIn(f'index={INDEX} sourcetype="{SOURCETYPE}"', search)
        self.assertIn(f'"organization_id")="{self.organization}"', search)
        self.assertIn(f'"realm")="{self.realm}"', search)
        self.assertNotRegex(search, r"(?i)`|\|\s*(lookup|join|map)\b")
        rows, content = self.run_search(search)
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        completion = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(len(completion), 1)
        self.assertEqual(int(completion[0]["input_count"]), len(records))
        self.assertEqual(int(completion[0]["returned_count"]), len(records))
        self.assertEqual(int(completion[0]["input_capped"]), 0)
        self.assertEqual(content.get("isDone"), True)
        normalized = self.helper(
            {
                "mode": "normalize",
                "rows": records,
                "selection": self.selection,
                "config": self.config,
            }
        )
        return records, normalized, completion[0]

    def test_indexed_metrics_require_exact_authority_and_source_completion(self):
        events = self.capture()
        wrong_org = copy.deepcopy(events[0])
        wrong_org["event"]["capture_id"] = self.observer + "-wrong-org"
        wrong_org["event"]["organization_id"] = "other-org"
        wrong_mms = copy.deepcopy(events[0])
        wrong_mms["event"]["capture_id"] = self.observer + "-wrong-mms"
        wrong_mms["event"]["apm_mms_id"] = "other_custom_mms"
        wrong_mms["event"]["sf_mms_id"] = "other_custom_mms"
        lab._hec_post(
            b"\n".join(
                json.dumps(event, separators=(",", ":")).encode()
                for event in [*events, wrong_org, wrong_mms]
            )
        )
        self.wait_for_indexed(len(events) + 2)

        records, normalized, search_completion = self.search_and_normalize()
        self.assertEqual(len(records), len(events))
        self.assertEqual(int(search_completion["schema_version"]), 1)
        self.assertEqual(normalized["rejected"], 0)
        self.assertEqual(len(normalized["records"]), 6)
        self.assertEqual(normalized["records"][-1]["kind"], "export_completion")
        self.assertEqual(normalized["records"][-1]["organizationId"], self.organization)
        self.assertEqual(normalized["records"][-1]["apmMmsId"], self.apm_mms_id)
        self.assertEqual(
            {
                record["signalLabel"]
                for record in normalized["records"]
                if record["kind"] == "metric"
            },
            {
                "request_count",
                "request_errors",
                "request_latency_p90",
                "container_cpu_utilization",
                "jvm_memory_used",
            },
        )

    def test_legacy_v1_capture_remains_readable_after_upgrade(self):
        legacy = FIXTURE.with_name("complete-v1-pre-record-id.json")
        self.template = copy.deepcopy(json.loads(legacy.read_text())["events"])
        self.assertTrue(all("record_id" not in row["event"] for row in self.template))
        self.test_indexed_metrics_require_exact_authority_and_source_completion()

    def test_same_graph_identity_with_multiple_otel_namespaces_is_ambiguous(self):
        events = self.capture()
        events.extend(
            self.capture(suffix="-other-namespace", service_namespace="other-payments")
        )
        lab._hec_post(
            b"\n".join(
                json.dumps(event, separators=(",", ":")).encode() for event in events
            )
        )
        self.wait_for_indexed(len(events))

        records, normalized, _ = self.search_and_normalize()
        self.assertEqual(len(records), len(events))
        self.assertEqual(normalized["records"], [])
        self.assertGreater(normalized["rejected"], 0)


if __name__ == "__main__":
    unittest.main()
