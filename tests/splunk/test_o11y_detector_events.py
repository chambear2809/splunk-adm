"""Qualify the exact detector query/normalizer against indexed synthetic events."""

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
import test_o11y_health as health_runtime

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/o11y/detector_events.json"
HELPER = ROOT / "tools/o11y_detector_events_search.mjs"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class DetectorEventsRuntimeTest(unittest.TestCase):
    # Reuse the existing bounded native-job checks, not a second search transport.
    run_search = health_runtime.O11yHealthRuntimeTest.run_search

    def setUp(self):
        self.now = int(time.time())
        self.capture_time = self.now - 3
        self.start, self.end = self.now - 900, self.now - 60
        self.observer = "detector-lab-" + uuid.uuid4().hex[:12]
        self.scope = "detector-lab-" + uuid.uuid4().hex[:8]
        self.events = copy.deepcopy(json.loads(FIXTURE.read_text())["events"])
        for index, envelope in enumerate(self.events):
            event = envelope["event"]
            envelope.update(
                time=self.capture_time, host=self.observer, index="atlas_o11y"
            )
            event.update(
                observer_id=self.observer,
                routing_scope=self.scope,
                captured_at=self.capture_time,
                capture_window_start=self.start,
                capture_window_end=self.end,
            )
            if event["event_type"] == "detector_event":
                event["event_timestamp_ms"] = (self.start + index * 100 + 1) * 1000
                native = json.loads(event["source_event_json"])
                native["timestamp"] = event["event_timestamp_ms"]
                event["source_event_json"] = json.dumps(native, separators=(",", ":"))
        first = self.events[0]["event"]
        self.selection = {
            "schemaVersion": 1,
            "workflow": "service",
            "selectionId": self.observer,
            "scope": self.scope,
            "window": {"start": self.start, "end": self.end},
            "service": {
                "name": "checkout",
                "environment": "prod",
                "cluster": first["cluster"],
                "namespace": "commerce",
            },
            "identityBasis": "synthetic detector qualification",
            "configurationFingerprint": "a" * 64,
        }
        self.config = {
            "source": "o11y_detector_events",
            "state": "active",
            "indexes": ["atlas_o11y"],
            "authorities": [self.observer],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "o11y_detector",
                    "observer": self.observer,
                    "scope": self.scope,
                    "cluster": first["cluster"],
                    "mapping_status": "verified",
                    "organization_id": first["organization_id"],
                    "realm": first["realm"],
                    "detector_ids": json.dumps(first["configured_detector_ids"]),
                }
            ],
        }

    def helper(self, mode="search", rows=None):
        payload = {"selection": self.selection, "config": self.config, "mode": mode}
        if rows is not None:
            payload["rows"] = rows
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
        return json.loads(completed.stdout) if mode == "normalize" else completed.stdout

    def inspect(self, events):
        lab._hec_post(
            b"\n".join(
                json.dumps(row, separators=(",", ":")).encode() for row in events
            )
        )
        deadline = time.monotonic() + 40
        query = f'search index=atlas_o11y sourcetype="atlas:o11y_detector_event" host="{self.observer}" | stats count AS count'
        while time.monotonic() < deadline:
            count = lab.search(query, str(self.capture_time - 60), str(self.now + 60))
            if count and int(count[0].get("count", -1)) == len(events):
                break
            time.sleep(0.5)
        else:
            self.fail(
                "Detector test events were not indexed within the readback deadline"
            )
        rows, content = self.run_search(self.helper())
        self.assertTrue(content["isDone"])
        completion = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(len(completion), 1)
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        self.assertEqual(int(completion[0]["returned_count"]), len(records))
        return self.helper("normalize", records)

    def test_replay_deduplicates_after_indexing_and_preserves_native_event_values(self):
        normalized = self.inspect(self.events + copy.deepcopy(self.events))
        self.assertEqual(normalized["rejected"], 0)
        events = normalized["capture"]["events"]
        self.assertEqual(len(events), 2)
        self.assertEqual({event["type"] for event in events}, {"ALERT", "CLEAR"})
        self.assertEqual(normalized["capture"]["organizationId"], "org-demo-01")
        self.assertNotIn("service", normalized["capture"])

    def test_partial_capture_does_not_establish_event_or_incident_state(self):
        normalized = self.inspect(self.events[:2])
        self.assertNotIn("capture", normalized)
        self.assertGreater(normalized["rejected"], 0)

    def test_conflicting_replayed_record_is_rejected(self):
        conflict = copy.deepcopy(self.events[0])
        conflict["event"]["severity"] = "Warning"
        normalized = self.inspect(self.events + [conflict])
        self.assertNotIn("capture", normalized)
        self.assertGreater(normalized["rejected"], 0)

    def test_empty_completed_interval_keeps_configured_detector_identity(self):
        completion = self.events[-1]
        completion["event"]["expected_record_count"] = 0
        normalized = self.inspect([completion])
        self.assertEqual(normalized["rejected"], 0)
        self.assertEqual(normalized["capture"]["events"], [])
        self.assertEqual(
            normalized["capture"]["detectorIds"], ["detector_checkout_latency"]
        )
