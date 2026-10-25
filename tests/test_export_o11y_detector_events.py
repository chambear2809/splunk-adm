"""Read-only, bounded detector event export contract tests."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools import export_o11y_detector_events as export
from tools import hec_delivery


def request(**changes) -> export.DetectorExportRequest:
    values = {
        "observer": "o11y-detector-prod",
        "organization_id": "org-demo-01",
        "realm": "us0",
        "scope": "prod-east",
        "cluster": "eks-prod-east",
        "detector_ids": ("detector_A", "detector-B"),
        "start": 1_800_000_000.0,
        "end": 1_800_000_900.0,
        "timeout_seconds": 2,
    }
    values.update(changes)
    return export.DetectorExportRequest(**values)


def source_event(
    event_id: str, *, detector_id="detector_A", timestamp=1_800_000_100_000, **changes
):
    event = {
        "id": event_id,
        "detectorId": detector_id,
        "incidentId": "incident-" + event_id,
        "timestamp": timestamp,
        "eventType": "ALERT",
        "anomalyState": "ANOMALOUS",
        "severity": "Critical",
        "detectLabel": "request_errors",
    }
    event.update(changes)
    return event


class DetectorEventExportTest(unittest.TestCase):
    def test_builds_realm_scoped_read_route_with_inclusive_ms_window_and_offset(self):
        url = export.build_events_url(
            "us0", "detector-A", 1_800_000_000.25, 1_800_000_010.5, offset=20, limit=50
        )
        self.assertEqual(
            url,
            "https://api.us0.observability.splunkcloud.com/v2/detector/detector-A/events"
            "?from=1800000000250&to=1800000010500&offset=20&limit=50",
        )

    def test_validates_bounded_detector_list_and_closed_interval(self):
        with self.assertRaisesRegex(ValueError, "one to 16"):
            request(detector_ids=()).validate()
        with self.assertRaisesRegex(ValueError, "unique literal"):
            request(detector_ids=("same", "same")).validate()
        with self.assertRaisesRegex(ValueError, "no longer than 24h"):
            request(end=1_800_100_000.0).validate()
        with self.assertRaises(ValueError):
            export.build_events_url("us0", "../other", 1, 2, offset=0)
        with self.assertRaises(ValueError):
            export.build_events_url("us-east-1", "detector", 1, 2, offset=0)

    def test_api_transport_keeps_verified_tls_and_refuses_redirects(self):
        context = export._context(None)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, export.ssl.CERT_REQUIRED)
        observed = {}

        class Response:
            status = 302

            def getheader(self, name, default=None):
                return default

        class Connection:
            sock = None

            def __init__(self, host, *, port, timeout, context):
                observed.update(host=host, port=port, timeout=timeout, context=context)

            def request(self, method, path, *, headers):
                observed.update(method=method, path=path, headers=headers)

            def getresponse(self):
                return Response()

            def close(self):
                pass

        address = (
            export.socket.AF_INET,
            export.socket.SOCK_STREAM,
            0,
            "",
            ("127.0.0.1", 443),
        )
        with (
            patch.object(export.socket, "getaddrinfo", return_value=[address]),
            patch.object(export.http.client, "HTTPSConnection", Connection),
        ):
            with self.assertRaises(export._HTTPFailure) as error:
                export._get_json(
                    "https://api.us0.observability.splunkcloud.com/v2/detector/detector_A/events?from=1&to=2&offset=0&limit=1000",
                    "test-token",
                    2,
                    context,
                )
        self.assertEqual(error.exception.status, 302)
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(
            observed["path"],
            "/v2/detector/detector_A/events?from=1&to=2&offset=0&limit=1000",
        )
        self.assertEqual(observed["headers"]["X-SF-TOKEN"], "test-token")

    def test_api_dns_timeout_expires_before_sending_token(self):
        entered = threading.Event()
        release = threading.Event()
        connection_created = []

        def slow_dns(*_args, **_kwargs):
            entered.set()
            release.wait(1)
            return []

        class Connection:
            def __init__(self, *args, **kwargs):
                connection_created.append((args, kwargs))

        with (
            patch.object(export.socket, "getaddrinfo", side_effect=slow_dns),
            patch.object(export.http.client, "HTTPSConnection", Connection),
        ):
            try:
                with self.assertRaises(export._HTTPFailure):
                    export._get_json(
                        "https://api.us0.observability.splunkcloud.com/v2/detector/detector_A/events?from=1&to=2&offset=0&limit=1000",
                        "test-token",
                        0.02,
                        export._context(None),
                    )
            finally:
                release.set()
        self.assertTrue(entered.is_set())
        self.assertEqual(connection_created, [])

    def test_paginates_selected_detectors_and_preserves_reported_lifecycle(self):
        events = [
            source_event("event-1"),
            source_event(
                "event-2",
                timestamp=1_800_000_200_000,
                anomalyState="OK",
                eventType="CLEAR",
            ),
        ]
        calls = []

        def get_json(url, token, timeout, context):
            calls.append(url)
            query = url.split("?", 1)[1]
            params = dict(part.split("=", 1) for part in query.split("&"))
            detector = "detector_A" if "/detector/detector_A/" in url else "detector-B"
            offset = int(params["offset"])
            if detector == "detector_A":
                page = events[offset : offset + int(params["limit"])]
            else:
                page = []
            return export._HTTPResponse(200, json.dumps(page).encode())

        with patch.object(export, "PAGE_SIZE", 1):
            records = export.collect_detector_events(
                request(detector_ids=("detector_A", "detector-B")),
                "secret-only-in-process",
                get_json=get_json,
                captured_at=1_800_000_901,
            )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["anomaly_state"], "ANOMALOUS")
        self.assertEqual(records[1]["anomaly_state"], "OK")
        self.assertEqual(records[1]["source_event_type"], "CLEAR")
        self.assertEqual(
            records[0]["scope"]
            if "scope" in records[0]
            else records[0]["routing_scope"],
            "prod-east",
        )
        self.assertEqual(records[0]["cluster"], "eks-prod-east")
        self.assertNotIn("service_name", records[0])
        self.assertNotIn("apm_mms_id", records[0])
        self.assertGreaterEqual(len(calls), 4)

    def test_preserves_stop_manual_resolution_and_unknown_lifecycle_values(self):
        events = [
            source_event("stopped", eventType="CLEAR", anomalyState="STOPPED"),
            source_event(
                "manual",
                eventType="CLEAR",
                anomalyState="MANUALLY_RESOLVED",
            ),
            source_event(
                "future",
                eventType="FUTURE_EVENT_TYPE",
                anomalyState="FUTURE_STATE",
                extensionField={"source": "verbatim"},
            ),
        ]
        records = export.collect_detector_events(
            request(detector_ids=("detector_A",)),
            "token",
            get_json=lambda *args: export._HTTPResponse(
                200, json.dumps(events).encode()
            ),
            captured_at=1_800_000_901,
        )
        by_id = {record["event_id"]: record for record in records}
        self.assertEqual(by_id["stopped"]["anomaly_state"], "STOPPED")
        self.assertEqual(by_id["manual"]["anomaly_state"], "MANUALLY_RESOLVED")
        self.assertEqual(by_id["future"]["anomaly_state"], "FUTURE_STATE")
        self.assertEqual(by_id["future"]["source_event_type"], "FUTURE_EVENT_TYPE")
        self.assertEqual(
            by_id["future"]["source_event_json"],
            export._canonical_json(events[2]),
        )

    def test_selected_interval_boundaries_are_inclusive(self):
        events = [
            source_event("at-start", timestamp=1_800_000_000_000),
            source_event("at-end", timestamp=1_800_000_900_000),
        ]
        records = export.collect_detector_events(
            request(detector_ids=("detector_A",)),
            "token",
            get_json=lambda *args: export._HTTPResponse(
                200, json.dumps(events).encode()
            ),
            captured_at=1_800_000_901,
        )
        self.assertEqual(
            {record["event_id"] for record in records}, {"at-start", "at-end"}
        )

    def test_exact_duplicate_pages_deduplicate_but_conflicting_ids_fail(self):
        repeated = source_event("repeat")
        pages = iter([[repeated], [repeated], []])
        with patch.object(export, "PAGE_SIZE", 1):
            records = export.collect_detector_events(
                request(detector_ids=("detector_A",)),
                "token",
                get_json=lambda *args: export._HTTPResponse(
                    200, json.dumps(next(pages)).encode()
                ),
                captured_at=1_800_000_901,
            )
        self.assertEqual(len(records), 1)

        conflicting = iter([[repeated], [{**repeated, "severity": "Warning"}], []])
        with patch.object(export, "PAGE_SIZE", 1):
            with self.assertRaisesRegex(export.DetectorExportError, "conflicting"):
                export.collect_detector_events(
                    request(detector_ids=("detector_A",)),
                    "token",
                    get_json=lambda *args: export._HTTPResponse(
                        200, json.dumps(next(conflicting)).encode()
                    ),
                    captured_at=1_800_000_901,
                )

    def test_wrong_detector_out_of_window_and_malformed_page_fail_closed(self):
        for event in (
            source_event("outside", timestamp=1_799_999_999_000),
            source_event("after-end", timestamp=1_800_000_900_001),
            source_event("wrong", detector_id="another-detector"),
        ):
            with (
                self.subTest(event=event["id"]),
                self.assertRaises(export.DetectorExportError),
            ):
                export.collect_detector_events(
                    request(detector_ids=("detector_A",)),
                    "token",
                    get_json=lambda *args, event=event: export._HTTPResponse(
                        200, json.dumps([event]).encode()
                    ),
                    captured_at=1_800_000_901,
                )
        with self.assertRaisesRegex(export.DetectorExportError, "event array"):
            export.collect_detector_events(
                request(detector_ids=("detector_A",)),
                "token",
                get_json=lambda *args: export._HTTPResponse(200, b'{"events":[]}'),
            )

    def test_event_larger_than_the_app_truncate_boundary_fails_before_publish(self):
        large = source_event("large", payload="x" * 65_000)
        with self.assertRaisesRegex(export.DetectorExportError, "record size limit"):
            export.collect_detector_events(
                request(detector_ids=("detector_A",)),
                "token",
                get_json=lambda *args: export._HTTPResponse(
                    200, json.dumps([large]).encode()
                ),
                captured_at=1_800_000_901,
            )

    def test_duplicate_keys_and_nonfinite_constants_fail_collection(self):
        malformed_pages = (
            b'[{"timestamp":1800000000000,"id":"original","id":"overwritten"}]',
            b'[{"timestamp":1800000000000,"id":"nested",'
            b'"dimensions":{"cluster":"east","cluster":"west"}}]',
            b'[{"timestamp":NaN,"id":"nan"}]',
            b'[{"timestamp":Infinity,"id":"infinity"}]',
            b'[{"timestamp":-Infinity,"id":"negative-infinity"}]',
        )
        for body in malformed_pages:
            with (
                self.subTest(body=body),
                self.assertRaisesRegex(export.DetectorExportError, "invalid JSON"),
            ):
                export.collect_detector_events(
                    request(detector_ids=("detector_A",)),
                    "token",
                    get_json=lambda *args, body=body: export._HTTPResponse(200, body),
                    captured_at=1_800_000_901,
                )

    def test_malformed_api_json_never_publishes_a_finalized_capture(self):
        duplicate_body = (
            b'[{"timestamp":1799999999000,"id":"original","id":"overwritten"}]'
        )
        original_collect = export.collect_detector_events

        def collect_with_duplicate_response(request_arg, token, *, ca_bundle=None):
            return original_collect(
                request_arg,
                token,
                ca_bundle=ca_bundle,
                get_json=lambda *args: export._HTTPResponse(200, duplicate_body),
            )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.ndjson"
            args = [
                "--observer",
                "o11y-detector-prod",
                "--organization-id",
                "org-demo-01",
                "--realm",
                "us0",
                "--scope",
                "prod-east",
                "--cluster",
                "eks-prod-east",
                "--detector-id",
                "detector_A",
                "--start",
                "2026-10-24T00:00:00Z",
                "--end",
                "2026-10-24T00:15:00Z",
                "--output",
                str(output),
            ]
            with (
                patch.dict(
                    os.environ, {"SPLUNK_OBSERVABILITY_TOKEN": "unit-test-token"}
                ),
                patch.object(
                    export,
                    "collect_detector_events",
                    side_effect=collect_with_duplicate_response,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(export.main(args), 1)
            self.assertFalse(output.exists())

    def test_event_cap_is_detected_without_publishing_a_partial_capture(self):
        with (
            patch.object(export, "MAX_EVENTS_PER_CAPTURE", 1),
            patch.object(export, "PAGE_SIZE", 1),
        ):
            with self.assertRaisesRegex(export.DetectorExportError, "event cap"):
                export.collect_detector_events(
                    request(detector_ids=("detector_A",)),
                    "token",
                    get_json=lambda url, *_: export._HTTPResponse(
                        200,
                        json.dumps(
                            [source_event("one")]
                            if "offset=0" in url
                            else [source_event("two", timestamp=1_800_000_200_000)]
                        ).encode(),
                    ),
                )

    def test_api_detector_ceiling_is_not_mistaken_for_complete_history(self):
        req = request(detector_ids=("detector_A",))
        events = [source_event("one"), source_event("two", timestamp=1_800_000_200_000)]
        with (
            patch.object(export, "MAX_EVENTS_PER_CAPTURE", 10_000),
            patch.object(export, "API_MAX_EVENTS_PER_DETECTOR", 2),
            patch.object(export, "PAGE_SIZE", 2),
            self.assertRaisesRegex(export.DetectorExportError, "complete history"),
        ):
            export.collect_detector_events(
                req,
                "token",
                get_json=lambda *args: export._HTTPResponse(
                    200, json.dumps(events).encode()
                ),
                captured_at=1_800_000_901,
            )

    def test_event_rows_plus_completion_fit_shared_sender_capture_limit(self):
        self.assertEqual(
            export.MAX_EVENTS_PER_CAPTURE + 1, hec_delivery.CAPTURE_MAX_RECORDS
        )
        req = request(detector_ids=("detector_A",))
        source_events = [source_event("one"), source_event("two")]
        with patch.object(export, "MAX_EVENTS_PER_CAPTURE", 2):
            records = export._event_records(
                req,
                {"detector_A": source_events},
                "capture-two-events",
                1_800_000_901,
            )
            content = export.render_hec_ndjson(
                req,
                records,
                captured_at=1_800_000_901,
                capture_id="capture-two-events",
            )
        self.assertEqual(len(content.splitlines()), 3)

    def test_header_unsafe_or_oversized_tokens_are_rejected_before_request(self):
        for token in ("bad\nheader", "bad\theader", "bad-é", "x" * 8193):
            with (
                self.subTest(token_length=len(token)),
                self.assertRaisesRegex(ValueError, "SPLUNK_OBSERVABILITY_TOKEN"),
            ):
                export.collect_detector_events(
                    request(detector_ids=("detector_A",)),
                    token,
                    get_json=lambda *args: self.fail("request must not be made"),
                )

    def test_completion_is_explicit_for_empty_interval_and_retains_capture_window(self):
        req = request(detector_ids=("detector_A",))
        events = export.collect_detector_events(
            req,
            "token",
            get_json=lambda *args: export._HTTPResponse(200, b"[]"),
            captured_at=1_800_000_901,
        )
        capture_id = "capture-empty"
        content = export.render_hec_ndjson(
            req, events, captured_at=1_800_000_901, capture_id=capture_id
        )
        envelope = json.loads(content)
        self.assertEqual(envelope["event"]["event_type"], "export_completion")
        self.assertEqual(envelope["event"]["expected_record_count"], 0)
        self.assertEqual(envelope["event"]["capture_window_start"], req.start)
        self.assertEqual(envelope["event"]["configured_detector_ids"], ["detector_A"])

    def test_atomic_output_is_private_and_never_overwrites(self):
        req = request(detector_ids=("detector_A",))
        events = export.collect_detector_events(
            req,
            "token",
            get_json=lambda *args: export._HTTPResponse(200, b"[]"),
            captured_at=1_800_000_901,
        )
        content = export.render_hec_ndjson(
            req, events, captured_at=1_800_000_901, capture_id="capture-empty"
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "capture.ndjson"
            export._publish_new(path, content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                export._publish_new(path, content)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
