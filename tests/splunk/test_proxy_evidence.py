"""Run the frontend's exact bounded Envoy SPL against the disposable lab."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools" / "proxy_qualification_queries.mjs"
FIXTURE = ROOT / "fixtures" / "proxy" / "envoy-v1.40-http-access.json"
INDEX = "atlas_proxy"
SOURCETYPE = "atlas:proxy:envoy_access"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class ProxyEvidenceRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.token = "proxyqual-" + uuid.uuid4().hex[:16]
        self.now = int(time.time())
        self.start = self.now - 10
        self.end = self.now + 30
        self.event_time = self.now - 3.125
        self.peer = "192.0.2.10"
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.template = json.loads(self.fixture["_raw"])
        self.config = {
            "source": "proxy_envoy",
            "state": "active",
            "indexes": [INDEX],
            "authorities": [self.token],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "envoy_proxy",
                    "observer": self.token,
                    "scope": self.token,
                    "cluster": "",
                    "mapping_status": "verified",
                }
            ],
        }

    def selection(self, addresses: list[str]) -> dict:
        return {
            "schemaVersion": 1,
            "workflow": "endpoint",
            "selectionId": self.token,
            "trafficContract": 1,
            "window": {"start": self.start, "end": self.end},
            "scope": self.token,
            "addresses": addresses,
            "contexts": [],
            "identityBasis": "disposable Envoy proxy qualification",
            "configurationFingerprint": "a" * 64,
        }

    def build_searches(self) -> list[dict]:
        completed = subprocess.run(
            ["node", str(HELPER)],
            cwd=ROOT,
            input=json.dumps(
                {
                    "config": self.config,
                    "selections": [
                        self.selection([self.peer]),
                        self.selection(["192.0.2.99"]),
                    ],
                }
            ),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        searches = json.loads(completed.stdout)["searches"]
        self.assertEqual(len(searches), 2)
        for item in searches:
            self.assertNotRegex(item["search"], r"(?i)`|\|\s*(lookup|join|map)\b")
            self.assertNotRegex(item["search"], r"(?i)x-forwarded-for|\bxff\b")
        return searches

    def event(self, stream_id: str, changes: dict | None = None) -> dict:
        raw = copy.deepcopy(self.template)
        raw.update(
            {
                "routing_authority": self.token,
                "observer_id": self.token,
                "stream_id": stream_id,
                "start_time": f"{self.event_time:.3f}",
            }
        )
        if changes:
            raw.update(changes)
        return {
            "time": self.event_time,
            "index": INDEX,
            "sourcetype": SOURCETYPE,
            "source": self.token,
            "host": self.token,
            "event": raw,
        }

    def _wait_for_indexed_events(self, expected: int) -> None:
        deadline = time.monotonic() + 30
        query = (
            f'search index={INDEX} sourcetype="{SOURCETYPE}" host="{self.token}"'
            " | stats count AS count"
        )
        while time.monotonic() < deadline:
            rows = lab.search(query, str(self.start - 86400), str(self.end))
            if rows and int(rows[0].get("count", -1)) == expected:
                return
            time.sleep(0.5)
        self.fail("synthetic proxy events did not reach the expected indexed count")

    def _run(
        self, search: str, earliest: float, latest: float
    ) -> tuple[list[dict], dict]:
        with lab._mgmt(
            "POST",
            f"/servicesNS/admin/{lab.APP}/search/v2/jobs?output_mode=json",
            {
                "search": search,
                "exec_mode": "normal",
                "earliest_time": str(earliest),
                "latest_time": str(latest),
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
                self.fail("native Splunk Envoy search failed before completion")
            if content.get("isDone"):
                break
            time.sleep(0.5)
        else:
            with lab._mgmt(
                "POST", f"/services/search/v2/jobs/{sid}/control", {"action": "cancel"}
            ):
                pass
            self.fail("native Splunk Envoy search timed out and was cancelled")
        errors = [
            message
            for message in content.get("messages", [])
            if message.get("type", "").upper() in {"ERROR", "FATAL"}
        ]
        self.assertFalse(errors, "native Splunk Envoy search returned an error")
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

    def assert_envelope(self, built: dict, expected_input: int) -> list[dict]:
        rows, content = self._run(built["search"], built["earliest"], built["latest"])
        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        completions = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(
            len(completions), 1, "query needs one completion row, even at zero matches"
        )
        self.assertEqual(len(rows), len(records) + 1)
        completion = completions[0]
        self.assertEqual(int(completion["schema_version"]), 1)
        self.assertEqual(int(completion["input_count"]), expected_input)
        self.assertEqual(int(completion["returned_count"]), min(expected_input, 64))
        self.assertEqual(int(completion["input_capped"]), 0)
        self.assertTrue(content.get("isDone"))
        self.assertEqual(len(records), min(expected_input, 64))
        return records

    def test_bounded_envoy_spl_completion_malformed_and_xff_cases(self):
        matched_id = f"{self.token}-matched"
        xff_only_id = f"{self.token}-xff-only"
        malformed_schema_id = f"{self.token}-bad-schema"
        malformed_time_id = f"{self.token}-bad-time"
        events = [
            self.event(matched_id),
            self.event(
                xff_only_id,
                {
                    "downstream_direct_remote_ip": "192.0.2.11",
                    "upstream_remote_ip": "203.0.113.9",
                    "x_forwarded_for": self.peer,
                },
            ),
            self.event(
                malformed_schema_id,
                {"schema": "application_atlas.envoy_http_access.invalid"},
            ),
            self.event(malformed_time_id, {"start_time": "not-an-epoch"}),
        ]
        body = b"\n".join(
            json.dumps(event, separators=(",", ":")).encode() for event in events
        )
        lab._hec_post(body)
        self._wait_for_indexed_events(len(events))

        matched_query, empty_query = self.build_searches()
        records = self.assert_envelope(matched_query, 1)
        self.assertEqual(len(records), 1)
        projected = records[0]["_raw"]
        if isinstance(projected, str):
            projected = json.loads(projected)
        self.assertEqual(projected["stream_id"], matched_id)
        self.assertEqual(projected["downstream_direct_remote_ip"], self.peer)
        self.assertNotIn("x_forwarded_for", projected)
        self.assertEqual(records[0]["host"], self.token)
        self.assertEqual(records[0]["index"], INDEX)
        self.assertRegex(records[0]["event_fingerprint"], r"^[a-f0-9]{64}$")
        splunk_time = records[0]["_time"]
        try:
            observed_time = float(splunk_time)
        except (TypeError, ValueError):
            parsed_time = datetime.fromisoformat(
                str(splunk_time).replace("Z", "+00:00")
            )
            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
            observed_time = parsed_time.timestamp()
        self.assertLessEqual(
            abs(observed_time - self.event_time),
            1,
            "the HEC event time must match the producer start_time",
        )
        self.assertLessEqual(
            abs(float(records[0]["event_time_epoch"]) - self.event_time),
            1,
            "the SPL numeric projection must match the producer start_time",
        )

        self.assertEqual(self.assert_envelope(empty_query, 0), [])


if __name__ == "__main__":
    unittest.main()
