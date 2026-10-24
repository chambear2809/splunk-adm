"""Unit tests for complete-only bounded SignalFlow export."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import time
import unittest

from tools import export_o11y_health as export


class Batch:
    def __init__(self, logical_timestamp_ms: int, data: dict[str, float]):
        self.logical_timestamp_ms = logical_timestamp_ms
        self.data = data


EndOfChannelMessage = type("EndOfChannelMessage", (), {})
ErrorMessage = type("ErrorMessage", (), {})
ChannelAbortMessage = type("ChannelAbortMessage", (), {})


def request(**changes) -> export.ExportRequest:
    values = {
        "observer": "o11y-observer-prod",
        "organization_id": "org-demo-01",
        "realm": "us0",
        "scope": "prod-east",
        "service_name": "checkout-api",
        "environment": "production",
        "cluster": "eks-prod-east",
        "kubernetes_namespace": "commerce",
        "apm_mms_id": "checkout_service_mms_v1",
        "service_namespace": "payments",
        "start": 1_792_763_000.0,
        "end": 1_792_763_990.0,
        "timeout_seconds": 2,
    }
    values.update(changes)
    return export.ExportRequest(**values)


def point_metadata(label: str, **changes) -> dict:
    spec = export.METRICS[label]
    metadata = {
        # SignalFlow's sf_metric is a generated computation metric identity.
        "sf_metric": "_SF_COMP_8712-PUBLISH_METRIC",
        "sf_streamLabel": label,
        "sf_originatingMetric": spec.metric,
        "sf_dimensionalized": "true" if spec.metric == "service.request" else None,
        "sf_mms_id": "checkout_service_mms_v1"
        if spec.metric == "service.request"
        else None,
        "service.name": "checkout-api",
        "deployment.environment.name": "production",
        "k8s.cluster.name": "eks-prod-east",
        "k8s.namespace.name": "commerce",
        "service.namespace": "payments",
        "sf_service": "checkout-api",
        "sf_environment": "production",
    }
    if label == "request_errors":
        metadata["sf_error"] = "true"
    metadata.update(changes)
    return metadata


class FakeComputation:
    STATE_COMPLETED = 4

    def __init__(
        self, *, complete=True, metadata_changes=None, values=None, stream_delay=0
    ):
        self.id = "computation-123"
        self.state = 0
        self.find_limited_resultset = False
        self.group_by_missing_property = False
        self.num_input_timeseries = 5
        self.resolution = 10_000
        self.closed = False
        self.stream_delay = stream_delay
        self.values = values or {
            "request_count": 18,
            "request_errors": 2,
            "request_latency_p90": 25_000_000,
            "container_cpu_utilization": 0.42,
            "jvm_memory_used": 134_217_728,
        }
        self.metadata = {}
        data = {}
        for label, value in self.values.items():
            tsid = f"tsid-{label}"
            self.metadata[tsid] = point_metadata(
                label, **(metadata_changes or {}).get(label, {})
            )
            data[tsid] = value
        self._stream_messages = [Batch(1_792_763_980_000, data)]
        if complete:
            self._stream_messages.append(EndOfChannelMessage())
        self._stream = iter(self._stream_messages)
        self._execute = lambda: iter(())

    def stream(self):
        if self.stream_delay:
            time.sleep(self.stream_delay)
        for message in self._stream:
            if isinstance(message, EndOfChannelMessage):
                self.state = self.STATE_COMPLETED
                return
            yield message
        # The pinned SDK reconnects with a zero-argument _execute() after a
        # stream ends without EndOfChannelMessage. A still-empty retry must
        # not turn that partial source stream into a completed capture.
        list(self._execute())

    def get_metadata(self, tsid):
        return self.metadata[tsid]

    def close(self):
        self.closed = True
        self.state = self.STATE_COMPLETED


class FakeClient:
    def __init__(self, computation):
        self.computation = computation
        self.closed = False
        self.execute_args = None

    def execute(self, program, **kwargs):
        self.execute_args = (program, kwargs)
        return self.computation

    def close(self):
        self.closed = True


class O11yExporterTest(unittest.TestCase):
    def test_request_program_projects_exact_identity_and_known_metric_contract(self):
        query = export.build_signalflow_program(request(), 10)
        self.assertIn('histogram("service.request"', query)
        self.assertIn(".count(by=apm_service_dimensions)", query)
        self.assertIn('filter("sf_dimensionalized", "true")', query)
        self.assertIn('filter("sf_mms_id", "checkout_service_mms_v1")', query)
        self.assertIn(
            'apm_service_dimensions = ["service.name", '
            '"deployment.environment.name", "k8s.cluster.name", '
            '"k8s.namespace.name", "service.namespace", '
            '"sf_dimensionalized", "sf_mms_id"]',
            query,
        )
        self.assertIn(".mean(by=service_identity_dimensions)", query)
        self.assertIn('filter("sf_error", "true")', query)
        self.assertIn(".percentile(pct=90, by=apm_service_dimensions)", query)
        self.assertIn('data("container.cpu.utilization"', query)
        self.assertIn('data("jvm.memory.used"', query)
        for key, expected in (
            ("service.name", "checkout-api"),
            ("deployment.environment.name", "production"),
            ("k8s.cluster.name", "eks-prod-east"),
            ("k8s.namespace.name", "commerce"),
            ("service.namespace", "payments"),
        ):
            self.assertIn(f'filter("{key}", "{expected}")', query)

    def test_complete_stream_uses_stream_label_and_preserves_measured_contract(self):
        result = export.collect_capture(
            request(),
            FakeComputation(),
            captured_at=1_792_764_000,
            normal_end=lambda: True,
        )
        metrics = [item for item in result if item["event_type"] == "metric"]
        completion = result[-1]
        self.assertEqual(len(metrics), 5)
        self.assertEqual(completion["expected_record_count"], 5)
        self.assertEqual(completion["signals_with_data"], 5)
        by_label = {item["signal_label"]: item for item in metrics}
        self.assertEqual(by_label["request_count"]["value"], 18)
        self.assertEqual(by_label["request_count"]["unit"], "count")
        self.assertEqual(by_label["request_errors"]["sf_error"], "true")
        self.assertEqual(by_label["request_latency_p90"]["unit"], "ns")
        self.assertEqual(by_label["container_cpu_utilization"]["unit"], "1")
        self.assertEqual(by_label["jvm_memory_used"]["unit"], "By")
        for label in ("request_count", "request_errors", "request_latency_p90"):
            self.assertEqual(by_label[label]["apm_mms_id"], request().apm_mms_id)
            self.assertEqual(by_label[label]["sf_mms_id"], request().apm_mms_id)
            self.assertEqual(by_label[label]["sf_dimensionalized"], "true")
        self.assertIsNone(by_label["container_cpu_utilization"]["apm_mms_id"])
        self.assertEqual(completion["apm_mms_id"], request().apm_mms_id)
        self.assertEqual(completion["sf_mms_id"], request().apm_mms_id)
        self.assertEqual(
            by_label["request_count"]["metric_source_basis"], "sf_originatingMetric"
        )

    def test_records_actual_coarsened_resolution_and_rejects_missing_resolution(self):
        coarsened = FakeComputation(values={"request_count": 18})
        coarsened.resolution = 60_000
        result = export.collect_capture(request(), coarsened, normal_end=lambda: True)
        self.assertEqual(result[0]["resolution_seconds"], 60)

        unknown = FakeComputation(values={"request_count": 18})
        unknown.resolution = None
        with self.assertRaisesRegex(ValueError, "actual resolution"):
            export.collect_capture(request(), unknown, normal_end=lambda: True)

    def test_generated_sf_metric_and_missing_originating_metric_are_qualified(self):
        computation = FakeComputation(
            metadata_changes={
                "request_count": {"sf_originatingMetric": None},
            },
            values={"request_count": 18},
        )
        result = export.collect_capture(
            request(), computation, captured_at=1_792_764_000, normal_end=lambda: True
        )
        self.assertEqual(result[0]["signal_label"], "request_count")
        self.assertEqual(result[0]["metric_source_basis"], "fixed_signalflow_program")

    def test_missing_eoc_timeout_bad_identity_and_bad_label_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "normal end-of-channel"):
            export.collect_capture(
                request(), FakeComputation(complete=False), normal_end=lambda: False
            )
        for terminal in (ErrorMessage(), ChannelAbortMessage()):
            computation = FakeComputation()
            computation._stream = iter([terminal, EndOfChannelMessage()])
            with self.assertRaisesRegex(ValueError, type(terminal).__name__):
                export.collect_capture(request(), computation, normal_end=lambda: True)
        with self.assertRaisesRegex(TimeoutError, "timed out"):
            export.collect_capture(
                request(),
                FakeComputation(),
                normal_end=lambda: True,
                on_timeout=lambda: True,
            )
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            export.collect_capture(
                request(),
                FakeComputation(
                    metadata_changes={"request_count": {"k8s.namespace.name": "other"}}
                ),
                normal_end=lambda: True,
            )
        with self.assertRaisesRegex(ValueError, "label or metric is unrecognized"):
            export.collect_capture(
                request(),
                FakeComputation(
                    metadata_changes={"request_count": {"sf_streamLabel": "untrusted"}}
                ),
                normal_end=lambda: True,
            )
        with self.assertRaisesRegex(ValueError, "APM MMS identity"):
            export.collect_capture(
                request(),
                FakeComputation(
                    metadata_changes={"request_count": {"sf_mms_id": "other_mms"}}
                ),
                normal_end=lambda: True,
            )
        with self.assertRaisesRegex(ValueError, "APM MMS identity"):
            export.collect_capture(
                request(),
                FakeComputation(
                    metadata_changes={"request_count": {"sf_dimensionalized": "false"}}
                ),
                normal_end=lambda: True,
            )

    def test_service_namespace_ambiguity_and_dimension_absence_are_not_joined(self):
        computation = FakeComputation(
            metadata_changes={"request_errors": {"service.namespace": "other"}}
        )
        with self.assertRaisesRegex(
            ValueError, "(?i)more than one OTel service.namespace"
        ):
            export.collect_capture(
                request(service_namespace=None), computation, normal_end=lambda: True
            )
        computation = FakeComputation(
            metadata_changes={"request_count": {"service.namespace": None}}
        )
        with self.assertRaisesRegex(ValueError, "lacks required service.namespace"):
            export.collect_capture(
                request(service_namespace=None), computation, normal_end=lambda: True
            )

    def test_completion_rows_and_atomic_publish_require_whole_stream(self):
        fake_computation = FakeComputation()
        client = FakeClient(fake_computation)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "capture.ndjson"
            result = export.run_export(
                request(),
                target,
                token="test-token-only",
                client_factory=lambda token, realm, timeout: client,
                captured_at=1_792_764_000,
            )
            lines = target.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 6)
            self.assertEqual(
                json.loads(lines[-1])["event"]["event_type"], "export_completion"
            )
            self.assertEqual(len(result), 6)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertTrue(client.closed)
            program, kwargs = client.execute_args
            self.assertIn('publish(label="request_count")', program)
            self.assertEqual(kwargs["start"], int(request().start * 1000))
            self.assertEqual(kwargs["stop"], int(request().end * 1000))
            self.assertTrue(kwargs["immediate"])
            with self.assertRaises(FileExistsError):
                export.publish_atomic(target, "replacement\n")
            self.assertEqual(target.read_text(encoding="utf-8").splitlines(), lines)

    def test_real_timeout_closes_stream_and_leaves_no_output(self):
        computation = FakeComputation(stream_delay=1.2)
        client = FakeClient(computation)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "timed-out.ndjson"
            with self.assertRaisesRegex(TimeoutError, "timed out"):
                export.run_export(
                    request(timeout_seconds=1),
                    target,
                    token="test-token-only",
                    client_factory=lambda token, realm, timeout: client,
                )
            self.assertFalse(target.exists())
            self.assertTrue(computation.closed)
            self.assertTrue(client.closed)

        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "incomplete.ndjson"
            client = FakeClient(FakeComputation(complete=False))
            with self.assertRaisesRegex(ValueError, "normal end-of-channel"):
                export.run_export(
                    request(),
                    target,
                    token="test-token-only",
                    client_factory=lambda token, realm, timeout: client,
                    captured_at=1_792_764_000,
                )
            self.assertFalse(target.exists())
            self.assertTrue(client.closed)

        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "timed-out.ndjson"
            computation = FakeComputation(stream_delay=1.2)
            client = FakeClient(computation)
            with self.assertRaisesRegex(TimeoutError, "timed out"):
                export.run_export(
                    request(timeout_seconds=1),
                    target,
                    token="test-token-only",
                    client_factory=lambda token, realm, timeout: client,
                    captured_at=1_792_764_000,
                )
            self.assertFalse(target.exists())
            self.assertTrue(computation.closed)
            self.assertTrue(client.closed)

    def test_request_limits_reject_arbitrary_or_long_windows(self):
        with self.assertRaisesRegex(ValueError, "24h"):
            request(end=1_792_763_000 + 86_401).validate()
        with self.assertRaisesRegex(ValueError, "timeout"):
            request(timeout_seconds=301).validate()


if __name__ == "__main__":
    unittest.main()
