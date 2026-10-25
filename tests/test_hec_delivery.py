"""Bounded durable HEC sender tests, including its replay failure edges."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import hec_delivery as sender


def envelope(event: dict, *, host: str | None = "observer-a", padding: int = 0) -> dict:
    value = {
        "time": 1_800_000_000,
        "source": "source-a",
        "sourcetype": "atlas:test",
        "event": event,
    }
    if host is not None:
        value["host"] = host
    if padding:
        value["event"]["padding"] = "x" * padding
    return value


def capture(path: Path, *events: dict) -> None:
    path.write_text(
        "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events),
        encoding="utf-8",
    )


def response(body: bytes = b'{"text":"Success","code":0}') -> sender._HTTPResponse:
    return sender._HTTPResponse(200, body)


class HecDeliveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.spool = self.root / "private-spool"
        self.input = self.root / "capture.ndjson"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_enqueue_supports_snapshot_ids_without_host_and_namespaces_sources(self):
        capture(
            self.input,
            envelope(
                {"snapshot_id": "snapshot-1", "record_id": "with spaces"}, host=None
            ),
        )
        original = self.input.read_bytes()
        receipt = sender.enqueue_capture(
            self.input, self.spool, source_id="asset_history"
        )
        self.assertEqual(receipt.capture_key, "snapshot-1")
        self.assertEqual(receipt.capture_key_field, "snapshot_id")
        self.assertFalse(receipt.duplicate)
        self.assertEqual(self.input.read_bytes(), original)

        same_source = sender.enqueue_capture(
            self.input, self.spool, source_id="asset_history"
        )
        other_source = sender.enqueue_capture(
            self.input, self.spool, source_id="appdynamics_inventory"
        )
        self.assertTrue(same_source.duplicate)
        self.assertFalse(other_source.duplicate)
        self.assertNotEqual(same_source.queued_path, other_source.queued_path)

    def test_enqueue_rejects_missing_or_conflicting_identity_without_mutating_input(
        self,
    ):
        capture(self.input, envelope({"other_id": "not-a-capture"}))
        original = self.input.read_bytes()
        with self.assertRaises(sender.DeliveryError):
            sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        self.assertEqual(self.input.read_bytes(), original)

        capture(
            self.input,
            envelope({"capture_id": "same", "snapshot_id": "different"}),
        )
        with self.assertRaisesRegex(sender.DeliveryError, "conflicting"):
            sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")

    def test_enqueue_rejects_blank_jsonl_records(self):
        self.input.write_text(
            json.dumps(envelope({"capture_id": "blank"})) + "\n\n", encoding="utf-8"
        )
        original = self.input.read_bytes()
        with self.assertRaisesRegex(sender.DeliveryError, "empty JSONL"):
            sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        self.assertEqual(self.input.read_bytes(), original)

    def test_same_key_different_bytes_are_quarantined_not_sent(self):
        capture(self.input, envelope({"snapshot_id": "stable", "value": 1}, host=None))
        sender.enqueue_capture(self.input, self.spool, source_id="asset_history")
        conflict = self.root / "conflict.ndjson"
        capture(conflict, envelope({"snapshot_id": "stable", "value": 2}, host=None))
        with self.assertRaises(sender.CaptureConflictError):
            sender.enqueue_capture(conflict, self.spool, source_id="asset_history")
        self.assertTrue(conflict.exists())
        with self.assertRaises(sender.CaptureConflictError):
            sender.enqueue_capture(conflict, self.spool, source_id="asset_history")
        status = sender.spool_status(self.spool)
        self.assertEqual(status.pending_captures, 1)
        self.assertEqual(status.quarantined_captures, 1)

    def test_capacity_error_is_typed_and_preserves_the_finalized_input(self):
        capture(self.input, envelope({"capture_id": "one"}))
        with patch.object(sender, "SPOOL_MAX_PENDING_RECORDS", 1):
            sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
            second = self.root / "second.ndjson"
            capture(second, envelope({"capture_id": "two"}))
            original = second.read_bytes()
            with self.assertRaises(sender.SpoolCapacityError) as context:
                sender.enqueue_capture(second, self.spool, source_id="o11y_health")
        self.assertEqual(context.exception.capacity_kind, "pending_records")
        self.assertEqual(second.read_bytes(), original)

    def test_send_resumes_after_partial_acceptance_without_replaying_accepted_batch(
        self,
    ):
        capture(
            self.input,
            envelope({"capture_id": "large", "record_id": "first"}, padding=150_000),
            envelope({"capture_id": "large", "record_id": "second"}, padding=150_000),
        )
        sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        calls: list[bytes] = []

        def flaky(url, body, token, timeout, context, channel=None):
            calls.append(body)
            if b'"second"' in body:
                raise sender._HTTPFailure(503, True)
            return response()

        first = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=flaky,
        )
        self.assertEqual(first.pending_captures, 1)
        self.assertEqual(first.failed_captures, 1)
        self.assertEqual(len(calls), 4)
        self.assertEqual(
            calls.count(next(body for body in calls if b'"first"' in body)), 1
        )

        resumed: list[bytes] = []
        second = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=lambda url, body, token, timeout, context, channel=None: (
                resumed.append(body) or response()
            ),
        )
        self.assertEqual(second.pending_captures, 0)
        self.assertEqual(second.http_accepted_captures, 1)
        self.assertEqual(len(resumed), 1)
        self.assertIn(b'"second"', resumed[0])

    def test_send_capture_cap_leaves_excess_backlog_queued(self):
        capture(self.input, envelope({"capture_id": "first"}))
        sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        second = self.root / "second.ndjson"
        capture(second, envelope({"capture_id": "second"}))
        sender.enqueue_capture(second, self.spool, source_id="o11y_health")
        calls = []

        result = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            max_captures=1,
            post_json=lambda url, body, token, timeout, context, channel=None: (
                calls.append(body) or response()
            ),
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.attempted_captures, 1)
        self.assertEqual(result.pending_captures, 1)

    def test_acknowledgment_is_reported_separately_from_indexed_readback(self):
        capture(self.input, envelope({"capture_id": "ack-me"}))
        sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        requests = []

        def post(url, body, token, timeout, context, channel=None):
            requests.append((url, body, channel))
            if "/ack?channel=" in url:
                return response(b'{"acks":{"9":true}}')
            return response(b'{"text":"Success","code":0,"ackID":9}')

        result = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            ack_mode="enterprise",
            post_json=post,
        )
        self.assertEqual(result.http_accepted_captures, 1)
        self.assertEqual(result.indexer_acknowledged_captures, 1)
        self.assertEqual(result.status, "indexer_acknowledged_not_searchable")
        self.assertEqual(len(requests), 2)
        self.assertTrue(requests[0][2])
        self.assertEqual(
            sender.spool_status(self.spool).indexer_acknowledged_not_searchable, 1
        )

    def test_http_success_with_ack_id_requires_ack_mode_without_replay(self):
        capture(self.input, envelope({"capture_id": "ack-required"}))
        sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        calls = []

        def post(url, body, token, timeout, context, channel=None):
            calls.append(body)
            return response(b'{"text":"Success","code":0,"ackID":4}')

        first = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=post,
        )
        again = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=post,
        )
        self.assertEqual(first.pending_captures, 1)
        self.assertEqual(again.pending_captures, 1)
        self.assertEqual(len(calls), 1)

    def test_endpoint_requires_tls_and_supported_path(self):
        for endpoint in (
            "http://hec.example.test/services/collector/event",
            "https://user:pass@hec.example.test/services/collector/event",
            "https://hec.example.test/services/collector/event?token=bad",
            "https://hec.example.test:bad/services/collector/event",
            "https://hec.example.test/redirect",
        ):
            with (
                self.subTest(endpoint=endpoint),
                self.assertRaises(sender.DeliveryError),
            ):
                sender._parse_endpoint(endpoint)
        self.assertEqual(
            sender._parse_endpoint("https://hec.example.test/services/collector")[0],
            "https://hec.example.test/services/collector/event",
        )

    def test_http_transport_keeps_tls_verification_and_does_not_follow_redirects(self):
        context = sender._context(None)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, sender.ssl.CERT_REQUIRED)
        observed = {}

        class FakeResponse:
            status = 302

            def read(self, size):
                self.asserted_size = size
                return b"redirect response is ignored"

        class FakeConnection:
            sock = None

            def __init__(self, host, *, port, timeout, context):
                observed.update(host=host, port=port, timeout=timeout, context=context)

            def request(self, method, path, *, body, headers):
                observed.update(method=method, path=path, body=body, headers=headers)

            def getresponse(self):
                return FakeResponse()

            def close(self):
                pass

        with patch.object(sender.http.client, "HTTPSConnection", FakeConnection):
            result = sender._post_json(
                "https://hec.example.test:8443/services/collector/event",
                b'{"event":{}}\n',
                "test-token",
                2,
                context,
            )
        self.assertEqual(result.status, 302)
        self.assertEqual(observed["headers"]["Authorization"], "Splunk test-token")
        self.assertEqual(observed["path"], "/services/collector/event")
        self.assertEqual(observed["body"], b'{"event":{}}\n')
        with self.assertRaises(sender._HTTPFailure):
            sender._successful_hec_response(result)

    def test_request_deadline_is_not_rounded_up(self):
        remaining = 0.125
        value = sender._request_timeout(sender.time.monotonic() + remaining, 30)
        self.assertIsNotNone(value)
        self.assertLessEqual(value, remaining)
        self.assertGreater(value, 0)

    def test_spool_rejects_primary_and_sibling_git_checkouts(self):
        for name in ("primary-checkout", "sibling-worktree"):
            with self.subTest(name=name):
                checkout = self.root / name
                checkout.mkdir()
                (checkout / ".git").write_text("gitdir: ../.git/worktrees/demo\n")
                nested_spool = checkout / "var" / "spool"
                with self.assertRaisesRegex(sender.DeliveryError, "every Git checkout"):
                    sender._ensure_spool(nested_spool)
                self.assertFalse(nested_spool.exists())

    def test_spool_busy_fails_promptly_without_touching_finalized_input(self):
        capture(self.input, envelope({"capture_id": "busy"}))
        original = self.input.read_bytes()
        with sender._SpoolLock(sender._ensure_spool(self.spool)):
            with self.assertRaises(sender.SpoolBusyError):
                sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        self.assertEqual(self.input.read_bytes(), original)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
