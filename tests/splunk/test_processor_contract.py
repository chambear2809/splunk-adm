"""Compare direct indexed fixtures with golden facts using installed searches.

This verifies the existing TA and Atlas search behavior in a disposable Splunk
lab. It does not execute Edge Processor or Ingest Processor SPL2.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import uuid
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = ROOT / "fixtures" / "processors" / "v1"
sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import LabLock  # noqa: E402

GOLDEN = json.loads((FIXTURES / "golden_outputs.json").read_text(encoding="utf-8"))
HEALTH = json.loads(
    (FIXTURES / "inputs" / "o11y_health_v1.json").read_text(encoding="utf-8")
)


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _number(value):
    value = _first(value)
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = dt.datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).timestamp()
    return int(number) if number.is_integer() else number


def _identity(row):
    return (
        row["metadata"]["host"],
        row["metadata"]["time"],
        row["raw"].get("exporter_ip"),
        row["raw"].get("seqnumber"),
        row["raw"].get("src_ip"),
        row["raw"].get("dest_ip"),
    )


def _health_helper(payload: dict) -> str | dict:
    completed = subprocess.run(
        ["node", str(ROOT / "tools" / "o11y_health_search.mjs")],
        cwd=ROOT,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(f"Atlas health search helper failed: {completed.stderr}")
    return (
        json.loads(completed.stdout)
        if payload.get("mode") == "normalize"
        else completed.stdout
    )


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1",
    "requires ADM_LAB=1 and the configured disposable Splunk lab",
)
class ProcessorInstalledSearchTest(unittest.TestCase):
    """Assert direct fixture records still produce the checked-in Atlas facts."""

    @classmethod
    def setUpClass(cls):
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")

        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        subprocess.run([str(HERE / "lab.sh"), "reset"], check=True, capture_output=True)
        if os.environ.get("ADM_LAB_PROCESSOR_HEALTH_ONLY") != "1":
            cls.netflow_expected = GOLDEN["netflow"]["installed_search_facts"][
                "records"
            ]
            cls.netflow_count = cls.lab.load(
                [
                    FIXTURES / "inputs" / "stream_netflow.ndjson",
                    FIXTURES / "inputs" / "stream_netflow_late.ndjson",
                ]
            )
            cls.wait_for_count(
                'index=netflow sourcetype="stream:netflow" | stats count AS count',
                cls.netflow_count,
            )
            cls.netflow_rows = cls.lab.search(
                "`adm_flows_netflow` | table _time host source sourcetype index exporter_ip seqnumber src_ip src_port dest_ip dest_port protoid bytes packets exporter_sampling_interval timestamp endtime input_snmpidx output_snmpidx adm_observer adm_exporter adm_transport adm_sampling adm_bytes_fwd adm_packets adm_start adm_end adm_in_ifindex adm_out_ifindex",
                "0",
                "2000000000",
            )

        cls.health_config, cls.health_selection, cls.health_capture = cls.health_case()
        cls.lab._hec_post(
            b"\n".join(
                json.dumps(event, separators=(",", ":")).encode()
                for event in cls.health_capture
            )
        )
        cls.health_observer = cls.health_capture[0]["event"]["observer_id"]
        cls.health_capture_id = cls.health_capture[0]["event"]["capture_id"]
        # HEC acceptance is not indexed-readback evidence; poll the exact capture
        # before either bounded query can cache an incomplete result.
        cls.wait_for_exact_count(
            'index=atlas_o11y sourcetype="atlas:o11y_health" '
            f'host="{cls.health_observer}" '
            "| spath input=_raw path=capture_id output=adm_test_capture_id "
            f'| search adm_test_capture_id="{cls.health_capture_id}" '
            "| stats count AS count",
            expected=6,
        )
        cls.health_indexed_rows = cls.lab.search(
            'index=atlas_o11y sourcetype="atlas:o11y_health" '
            f'host="{cls.health_observer}" | table _raw',
            "0",
            "2000000000",
        )
        cls.health_search = _health_helper(
            {"selection": cls.health_selection, "config": cls.health_config}
        )
        cls.health_rows = cls.lab.search(
            cls.health_search, "0", str(int(time.time()) + 3600)
        )
        cls.health_records = [
            row for row in cls.health_rows if row.get("kind") == "supplemental_record"
        ]
        cls.health_completion = [
            row
            for row in cls.health_rows
            if row.get("kind") == "supplemental_completion"
        ]
        cls.health_normalized = _health_helper(
            {
                "mode": "normalize",
                "rows": cls.health_records,
                "selection": cls.health_selection,
                "config": cls.health_config,
            }
        )

    @classmethod
    def wait_for_count(cls, search: str, expected: int, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        count = 0
        while time.monotonic() < deadline:
            rows = cls.lab.search(search, "0", "2000000000")
            count = int(rows[0].get("count", 0)) if rows else 0
            if count >= expected:
                return
            time.sleep(1)
        raise AssertionError(
            f"only {count} of {expected} direct fixture events were indexed"
        )

    @classmethod
    def wait_for_exact_count(
        cls, search: str, expected: int, timeout: float = 60
    ) -> None:
        deadline = time.monotonic() + timeout
        count = 0
        while time.monotonic() < deadline:
            rows = cls.lab.search(search, "0", "2000000000")
            count = int(rows[0].get("count", 0)) if rows else 0
            if count == expected:
                return
            if count > expected:
                raise AssertionError(
                    f"expected exactly {expected} uniquely scoped health events, got {count}"
                )
            time.sleep(1)
        raise AssertionError(
            f"only {count} of {expected} uniquely scoped health events were indexed"
        )

    @classmethod
    def health_case(cls) -> tuple[dict, dict, list[dict]]:
        source = copy.deepcopy(HEALTH["events"])
        now = int(time.time())
        captured_at = now - 3
        window = {"start": captured_at - 1000, "end": captured_at - 10}
        events = []
        for envelope in source:
            envelope["index"] = (
                "atlas_o11y"  # direct-ingestion target, absent from the producer fixture
            )
            envelope["time"] = captured_at
            event = envelope["event"]
            event["captured_at"] = captured_at
            event["capture_window_start"] = window["start"]
            event["capture_window_end"] = window["end"]
            if event.get("event_type") == "metric":
                event["logical_timestamp"] = window["end"] - 5
            events.append(envelope)

        unique_id = uuid.uuid4().hex[:12]
        observer = f"{events[0]['event']['observer_id']}-{unique_id}"
        capture_id = f"{events[0]['event']['capture_id']}-{unique_id}"
        for envelope in events:
            envelope["host"] = observer
            envelope["event"]["observer_id"] = observer
            envelope["event"]["capture_id"] = capture_id

        first_event = events[0]["event"]
        observer = first_event["observer_id"]
        scope = first_event["routing_scope"]
        cluster = first_event["cluster"]
        organization_id = first_event["organization_id"]
        realm = first_event["realm"]
        apm_mms_id = first_event["apm_mms_id"]
        config = {
            "source": "o11y_health",
            "state": "active",
            "indexes": ["atlas_o11y"],
            "authorities": [observer],
            "schemaQualified": True,
            "staleAfterSeconds": 3600,
            "mappings": [
                {
                    "observer_kind": "o11y_export",
                    "observer": observer,
                    "scope": scope,
                    "cluster": cluster,
                    "mapping_status": "verified",
                    "organization_id": organization_id,
                    "realm": realm,
                    "apm_mms_id": apm_mms_id,
                }
            ],
        }
        selection = {
            "schemaVersion": 1,
            "workflow": "service",
            "selectionId": observer,
            "scope": scope,
            "window": window,
            "service": {
                "name": first_event["service_name"],
                "environment": first_event["environment"],
                "cluster": cluster,
                "namespace": first_event["kubernetes_namespace"],
            },
            "identityBasis": "direct fixture installed-search comparison",
            "configurationFingerprint": "a" * 64,
        }
        return config, selection, events

    def test_stream_installed_ta_search_matches_all_direct_golden_facts(self):
        self.assertEqual(self.netflow_count, 42)
        self.assertEqual(len(self.netflow_rows), len(self.netflow_expected))
        actual_rows = []
        numeric_raw = {
            "seqnumber",
            "src_port",
            "dest_port",
            "protoid",
            "bytes",
            "packets",
            "exporter_sampling_interval",
            "input_snmpidx",
            "output_snmpidx",
        }
        for row in self.netflow_rows:
            actual = {
                "metadata": {
                    "time": _number(row.get("_time")),
                    "host": row.get("host"),
                    "source": row.get("source"),
                    "sourcetype": row.get("sourcetype"),
                    "index": row.get("index"),
                },
                "raw": {
                    key: (_number(value) if key in numeric_raw else value)
                    for key in (
                        "exporter_ip",
                        "seqnumber",
                        "src_ip",
                        "src_port",
                        "dest_ip",
                        "dest_port",
                        "protoid",
                        "bytes",
                        "packets",
                        "exporter_sampling_interval",
                        "timestamp",
                        "endtime",
                        "input_snmpidx",
                        "output_snmpidx",
                    )
                    if (value := _first(row.get(key))) not in (None, "")
                },
                "normalized": {
                    "adm_observer": row.get("adm_observer"),
                    "adm_exporter": row.get("adm_exporter"),
                    "adm_transport": row.get("adm_transport"),
                    "adm_sampling": _number(row.get("adm_sampling")),
                    "adm_bytes_fwd": _number(row.get("adm_bytes_fwd")),
                    "adm_packets": _number(row.get("adm_packets")),
                    "adm_start_epoch": _number(row.get("adm_start")),
                    "adm_end_epoch": _number(row.get("adm_end")),
                    "adm_in_ifindex": _number(row.get("adm_in_ifindex")),
                    "adm_out_ifindex": _number(row.get("adm_out_ifindex")),
                },
            }
            actual_rows.append(actual)
        expected_rows = [
            {
                "metadata": {
                    **item["metadata"],
                    "time": _number(item["metadata"]["time"]),
                },
                "raw": item["raw"],
                "normalized": item["normalized"],
            }
            for item in self.netflow_expected
        ]
        actual_rows.sort(key=_identity)
        expected_rows.sort(key=_identity)
        for actual, expected in zip(actual_rows, expected_rows, strict=True):
            self.assertEqual(actual["metadata"], expected["metadata"])
            self.assertEqual(actual["raw"], expected["raw"])
            for key, expected_value in expected["normalized"].items():
                if key in {"adm_start_epoch", "adm_end_epoch"}:
                    self.assertTrue(
                        math.isclose(
                            actual["normalized"][key], expected_value, abs_tol=0.00001
                        ),
                        f"{key}: expected {expected_value}, got {actual['normalized'][key]}",
                    )
                else:
                    self.assertEqual(actual["normalized"][key], expected_value, key)

    def test_health_installed_search_matches_v1_metrics_and_completion(self):
        self.assertEqual(
            len(self.health_capture), GOLDEN["o11y_health_v1"]["expected_record_count"]
        )
        self.assertEqual(
            len(self.health_records), GOLDEN["o11y_health_v1"]["expected_record_count"]
        )
        self.assertEqual(len(self.health_completion), 1)
        self.assertEqual(int(self.health_completion[0]["input_count"]), 6)
        self.assertEqual(int(self.health_completion[0]["returned_count"]), 6)
        self.assertEqual(int(self.health_completion[0]["input_capped"]), 0)
        self.assertEqual(self.health_normalized["rejected"], 0)
        normalized = self.health_normalized["records"]
        self.assertEqual(len(normalized), 6)
        self.assertEqual(normalized[-1]["kind"], "export_completion")
        self.assertEqual(normalized[-1]["expectedRecordCount"], 5)

        indexed_events = [
            json.loads(_first(row["_raw"]))
            if isinstance(_first(row.get("_raw")), str)
            else _first(row.get("_raw"))
            for row in self.health_indexed_rows
        ]
        indexed_metrics = [
            event for event in indexed_events if event.get("event_type") == "metric"
        ]
        required_nulls = GOLDEN["o11y_health_v1"]["required_null_fields"]
        self.assertEqual(len(indexed_metrics), 5)
        for event in indexed_metrics:
            for field in required_nulls:
                with self.subTest(signal=event["signal_label"], field=field):
                    self.assertIn(field, event)
                    self.assertIsNone(event[field])

        expected = {
            event["event"].get("signal_label"): event["event"]
            for event in HEALTH["events"]
            if event["event"].get("event_type") == "metric"
        }
        actual = {
            record["signalLabel"]: record
            for record in normalized
            if record["kind"] == "metric"
        }
        self.assertEqual(
            set(actual), set(GOLDEN["o11y_health_v1"]["expected_signal_labels"])
        )
        for label, event in expected.items():
            with self.subTest(signal=label):
                record = actual[label]
                self.assertEqual(record["metric"], event["metric_name"])
                self.assertEqual(record["unit"], event["unit"])
                self.assertEqual(record["value"], event["value"])
                self.assertEqual(
                    record["resolutionSeconds"], event["resolution_seconds"]
                )
                self.assertEqual(record["aggregation"], event["aggregation"])
                self.assertEqual(
                    record["logicalTimestamp"],
                    self.health_selection["window"]["end"] - 5,
                )
                self.assertEqual(record["organizationId"], event["organization_id"])
                self.assertEqual(record["realm"], event["realm"])


class ProcessorIndexedReadbackWaitTest(unittest.TestCase):
    """The health gate polls indexed counts and rejects duplicate capture rows."""

    def test_health_capture_scope_is_unique_per_run(self):
        first = ProcessorInstalledSearchTest.health_case()[2]
        second = ProcessorInstalledSearchTest.health_case()[2]
        self.assertEqual(len(first), 6)
        self.assertNotEqual(
            first[0]["event"]["observer_id"], second[0]["event"]["observer_id"]
        )
        self.assertNotEqual(
            first[0]["event"]["capture_id"], second[0]["event"]["capture_id"]
        )
        self.assertTrue(
            all(item["host"] == item["event"]["observer_id"] for item in first)
        )

    def test_waits_for_exact_indexed_health_count(self):
        lab = Mock()
        lab.search.side_effect = [[{"count": "4"}], [{"count": "6"}]]
        with (
            patch.object(ProcessorInstalledSearchTest, "lab", lab, create=True),
            patch.object(time, "sleep"),
        ):
            ProcessorInstalledSearchTest.wait_for_exact_count("unique capture query", 6)
        self.assertEqual(lab.search.call_count, 2)
        self.assertEqual(
            lab.search.call_args.args, ("unique capture query", "0", "2000000000")
        )

    def test_does_not_accept_more_than_the_expected_capture_count(self):
        lab = Mock()
        lab.search.return_value = [{"count": "7"}]
        with (
            patch.object(ProcessorInstalledSearchTest, "lab", lab, create=True),
            self.assertRaisesRegex(AssertionError, "expected exactly 6"),
        ):
            ProcessorInstalledSearchTest.wait_for_exact_count("unique capture query", 6)


if __name__ == "__main__":
    unittest.main()
