"""Run the exact frontend AWS VPC Flow Logs search against a disposable lab."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools" / "cloud_flow_qualification_queries.mjs"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CloudFlowEvidenceRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.authority = "vpcflow-" + uuid.uuid4().hex[:12]
        self.scope = "aws-test-" + uuid.uuid4().hex[:8]
        self.now = int(time.time())
        self.start = self.now - 900
        self.end = self.now - 840
        self.flow_start = self.start - 10
        self.flow_end = self.start + 50
        self.address = "10.0.1.25"
        self.account = "123456789012"
        self.region = "us-east-1"
        self.vpc = "vpc-0abc1234"
        self.selection = {
            "schemaVersion": 1,
            "workflow": "endpoint",
            "selectionId": self.authority,
            "trafficContract": 2,
            "window": {"start": self.start, "end": self.end},
            "scope": self.scope,
            "addresses": [self.address],
            "contexts": [],
            "identityBasis": "disposable AWS flow qualification",
            "configurationFingerprint": "a" * 64,
        }
        self.config = {
            "source": "aws_vpc_flow",
            "state": "active",
            "indexes": ["atlas_cloud"],
            "authorities": [self.authority],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "aws_vpc_flow",
                    "observer": self.authority,
                    "scope": self.scope,
                    "cluster": "",
                    "mapping_status": "verified",
                    "account_id": self.account,
                    "region": self.region,
                    "vpc_id": self.vpc,
                }
            ],
        }

    def helper(self, payload: dict) -> dict:
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
        return json.loads(completed.stdout)

    def flow(self, *, vpc: str | None = None) -> str:
        return " ".join(
            [
                "5",
                "203.0.113.25",
                self.address,
                "49152",
                "443",
                "6",
                str(self.flow_start),
                str(self.flow_end),
                "IPv4",
                "4",
                "1500",
                self.account,
                vpc or self.vpc,
                "subnet-0def1234",
                "i-0abc1234",
                "eni-0def1234",
                self.region,
                "use1-az1",
                "-",
                "-",
                "ACCEPT",
                "19",
                "203.0.113.25",
                self.address,
                "-",
                "-",
                "1",
                "ingress",
                "OK",
            ]
        )

    def status(self) -> str:
        return " ".join(
            [
                "5",
                "-",
                "-",
                "-",
                "-",
                "-",
                str(self.flow_start),
                str(self.flow_end),
                "-",
                "-",
                "-",
                self.account,
                self.vpc,
                "subnet-0def1234",
                "-",
                "eni-0def1234",
                self.region,
                "use1-az1",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "SKIPDATA",
            ]
        )

    def post_events(self) -> None:
        events = [
            {"host": self.authority, "event": self.flow()},
            {"host": self.authority, "event": self.status()},
            {
                "host": self.authority,
                "event": self.flow(vpc="vpc-0fffffff"),
            },
            {"host": self.authority + "-other", "event": self.flow()},
        ]
        batch = []
        for event in events:
            batch.append(
                json.dumps(
                    {
                        **event,
                        "index": "atlas_cloud",
                        "source": "vpc-flow-qualification",
                        "sourcetype": "aws:vpcflow:v5",
                    },
                    separators=(",", ":"),
                ).encode()
            )
        lab._hec_post(b"\n".join(batch))

    def test_v5_search_completion_status_time_and_scope(self):
        built = self.helper({"config": self.config, "selection": self.selection})
        self.assertNotRegex(built["search"], r"(?i)`|\|\s*(lookup|join|map)\b")
        self.assertEqual(
            built["window"],
            {"start": self.start - 660, "end": self.end + 60},
        )
        self.post_events()

        rows = []
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            rows = lab.search(
                built["search"],
                earliest=str(built["window"]["start"]),
                latest=str(built["window"]["end"]),
            )
            records = [row for row in rows if row.get("kind") == "supplemental_record"]
            completions = [
                row for row in rows if row.get("kind") == "supplemental_completion"
            ]
            if len(records) == 3 and len(completions) == 1:
                break
            time.sleep(0.5)

        records = [row for row in rows if row.get("kind") == "supplemental_record"]
        completions = [
            row for row in rows if row.get("kind") == "supplemental_completion"
        ]
        self.assertEqual(
            len(completions), 1, "query must return its completion envelope"
        )
        self.assertEqual(
            len(records), 3, "only the configured capture host is searched"
        )
        self.assertEqual(int(completions[0]["input_count"]), 3)
        self.assertEqual(int(completions[0]["returned_count"]), 3)
        self.assertEqual(int(completions[0]["input_capped"]), 0)
        self.assertEqual(int(completions[0]["oversized"]), 0)
        self.assertTrue(
            all(
                abs(float(record["_time"]) - self.flow_start) <= 1 for record in records
            ),
            "the installed aws:vpcflow:v5 props stanza must extract token seven as event time",
        )

        normalized = self.helper(
            {"config": self.config, "selection": self.selection, "rows": records}
        )["normalized"]
        self.assertEqual(normalized["rejected"], 1, "wrong VPC must not be attributed")
        self.assertEqual(len(normalized["records"]), 2)
        self.assertTrue(
            all(
                abs(record["rowTime"] - self.flow_start) <= 1
                for record in normalized["records"]
            ),
            "normalization must retain start-matched Splunk event time",
        )
        self.assertCountEqual(
            [record["recordClass"] for record in normalized["records"]],
            ["flow", "capture_status"],
        )
        status = next(
            record
            for record in normalized["records"]
            if record["recordClass"] == "capture_status"
        )
        self.assertEqual(status["logStatus"], "SKIPDATA")
        self.assertEqual(status["matchedAddressFields"], [])
        self.assertEqual(status["attribution"], "context_only")
