"""Bounded durable HEC sender tests, including its replay failure edges."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

    def test_enqueue_rejects_duplicate_json_keys(self):
        self.input.write_text(
            '{"time":1,"source":"source-a","sourcetype":"atlas:test",'
            '"event":{"capture_id":"first","capture_id":"second"}}\n',
            encoding="utf-8",
        )
        original = self.input.read_bytes()
        with self.assertRaisesRegex(sender.DeliveryError, "invalid JSON"):
            sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        self.assertEqual(self.input.read_bytes(), original)

    def test_enqueue_rejects_lines_that_cannot_fit_app_truncate_boundary(self):
        self.input.write_text(
            json.dumps(
                envelope({"capture_id": "oversized-line", "padding": "x" * 65_535}),
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        original = self.input.read_bytes()
        with self.assertRaisesRegex(sender.DeliveryError, "oversized record"):
            sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        self.assertEqual(self.input.read_bytes(), original)
        self.assertEqual(sender.spool_status(self.spool).pending_captures, 0)

    def test_capture_file_read_is_bounded_and_uses_open_file_metadata(self):
        capture(self.input, envelope({"capture_id": "bounded"}))
        observed = []
        original_fdopen = sender.os.fdopen

        class RecordingFile:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args):
                return self.wrapped.__exit__(*args)

            def read(self, size=-1):
                observed.append(size)
                return self.wrapped.read(size)

            def fileno(self):
                return self.wrapped.fileno()

        with patch.object(
            sender.os,
            "fdopen",
            side_effect=lambda descriptor, mode: RecordingFile(
                original_fdopen(descriptor, mode)
            ),
        ):
            parsed = sender._load_capture(self.input, "o11y_health")
        self.assertEqual(parsed.capture_key, "bounded")
        self.assertEqual(observed, [sender.CAPTURE_MAX_BYTES + 1])

    def test_checkpoint_reads_are_bounded_before_json_decode(self):
        checkpoint = self.root / "checkpoint.json"
        checkpoint.write_text('{"version":1}\n', encoding="utf-8")
        observed = []
        original_fdopen = sender.os.fdopen

        class RecordingFile:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args):
                return self.wrapped.__exit__(*args)

            def read(self, size=-1):
                observed.append(size)
                return self.wrapped.read(size)

            def fileno(self):
                return self.wrapped.fileno()

        with patch.object(
            sender.os,
            "fdopen",
            side_effect=lambda descriptor, mode: RecordingFile(
                original_fdopen(descriptor, mode)
            ),
        ):
            self.assertIsNone(sender._read_checkpoint(checkpoint))
        self.assertEqual(observed, [65_537])

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

    def test_byte_cap_reserves_capture_and_checkpoint_write_overhead(self):
        capture(self.input, envelope({"capture_id": "space"}))
        original = self.input.read_bytes()
        with patch.object(sender, "SPOOL_MAX_BYTES", 2 * len(original)):
            with self.assertRaises(sender.SpoolCapacityError) as context:
                sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        self.assertEqual(context.exception.capacity_kind, "total_spool_bytes")
        self.assertEqual(self.input.read_bytes(), original)
        self.assertEqual(sender.spool_status(self.spool).pending_captures, 0)

    def test_send_resumes_after_partial_acceptance_without_replaying_accepted_batch(
        self,
    ):
        capture(
            self.input,
            envelope({"capture_id": "large", "record_id": "first"}, padding=53_000),
            envelope({"capture_id": "large", "record_id": "middle-1"}, padding=53_000),
            envelope({"capture_id": "large", "record_id": "middle-2"}, padding=53_000),
            envelope({"capture_id": "large", "record_id": "middle-3"}, padding=53_000),
            envelope({"capture_id": "large", "record_id": "second"}, padding=53_000),
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

    def _enqueue_partial_capture(self, capture_id: str) -> Path:
        rows = [
            envelope({"capture_id": capture_id, "record_id": record_id}, padding=53_000)
            for record_id in ("first", "middle-1", "middle-2", "middle-3", "second")
        ]
        capture(self.input, *rows)
        receipt = sender.enqueue_capture(
            self.input, self.spool, source_id="o11y_health"
        )
        queued = Path(receipt.queued_path)
        loaded = sender._capture_from_path(queued, "o11y_health")
        return sender._checkpoint_path(
            self.spool,
            loaded.source_id,
            loaded.capture_key,
            loaded.digest,
        )

    def test_corrupt_progress_checksum_preserves_checkpoint_and_replays_from_start(
        self,
    ):
        checkpoint = self._enqueue_partial_capture("corrupt-progress")

        def partial(url, body, token, timeout, context, channel=None):
            if b'"second"' in body:
                raise sender._HTTPFailure(503, True)
            return response()

        first = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=partial,
        )
        self.assertEqual(first.pending_captures, 1)
        state = json.loads(checkpoint.read_text(encoding="utf-8"))
        self.assertGreater(state["next_record_index"], 0)
        self.assertLess(state["next_record_index"], state["record_count"])
        state["next_record_index"] = state["record_count"]
        checkpoint.write_text(json.dumps(state) + "\n", encoding="utf-8")
        sent = []

        second = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=lambda url, body, token, timeout, context, channel=None: (
                sent.append(body) or response()
            ),
        )
        self.assertEqual(second.pending_captures, 0)
        self.assertEqual(len(sent), 2)
        self.assertIn(b'"first"', sent[0])
        self.assertTrue(list(checkpoint.parent.glob(checkpoint.name + ".corrupt.*")))

    def test_partial_capture_rejects_endpoint_drift(self):
        self._enqueue_partial_capture("endpoint-drift")

        def partial(url, body, token, timeout, context, channel=None):
            if b'"second"' in body:
                raise sender._HTTPFailure(503, True)
            return response()

        first = sender.deliver_pending(
            self.spool,
            endpoint="https://hec.example.test/services/collector/event",
            token="test-token",
            post_json=partial,
        )
        self.assertEqual(first.pending_captures, 1)
        calls = []
        drifted = sender.deliver_pending(
            self.spool,
            endpoint="https://other.example.test/services/collector/event",
            token="test-token",
            post_json=lambda *args: calls.append(args),
        )
        self.assertEqual(calls, [])
        self.assertEqual(drifted.pending_captures, 1)
        self.assertEqual(drifted.failed_captures, 1)

    def test_retry_does_not_reset_oldest_pending_age(self):
        capture(self.input, envelope({"capture_id": "old-pending"}))
        receipt = sender.enqueue_capture(
            self.input, self.spool, source_id="o11y_health"
        )
        queued_path = Path(receipt.queued_path)
        now = int(queued_path.stat().st_mtime) + 600
        with (
            patch.object(sender.time, "time", return_value=now),
            patch.object(sender.time, "sleep"),
        ):
            before = sender.spool_status(self.spool).oldest_pending_age_seconds
            result = sender.deliver_pending(
                self.spool,
                endpoint="https://hec.example.test/services/collector/event",
                token="test-token",
                post_json=lambda *args: (_ for _ in ()).throw(
                    sender.DeliveryError("temporary transport failure")
                ),
            )
            after = sender.spool_status(self.spool).oldest_pending_age_seconds
        self.assertEqual(result.pending_captures, 1)
        self.assertEqual(before, after)
        self.assertGreaterEqual(after or 0, 600)

    def test_acknowledgment_is_reported_separately_from_indexed_readback(self):
        capture(self.input, envelope({"capture_id": "ack-me"}))
        sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        requests = []

        def post(url, body, token, timeout, context, channel=None):
            requests.append((url, body, channel))
            if "/ack?channel=" in url:
                return response(b'{"acks":{"9":true}}')
            return response(b'{"text":"Success","code":0,"ackId":9}')

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

    def test_acknowledgment_parser_accepts_documented_and_runtime_field_spelling(self):
        self.assertEqual(
            sender._successful_hec_response(
                response(b'{"text":"Success","code":0,"ackID":"9"}')
            ),
            (9, 0),
        )
        self.assertEqual(
            sender._successful_hec_response(
                response(b'{"text":"Success","code":0,"ackId":9}')
            ),
            (9, 0),
        )
        with self.assertRaisesRegex(sender.DeliveryError, "conflicting"):
            sender._successful_hec_response(
                response(b'{"text":"Success","code":0,"ackID":"9","ackId":10}')
            )

    def test_http_success_with_ack_id_requires_ack_mode_without_replay(self):
        capture(self.input, envelope({"capture_id": "ack-required"}))
        sender.enqueue_capture(self.input, self.spool, source_id="o11y_health")
        calls = []

        def post(url, body, token, timeout, context, channel=None):
            calls.append(body)
            return response(b'{"text":"Success","code":0,"ackId":4}')

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
            "https://hec.example.test/services/collector",
        )
        self.assertEqual(
            sender._parse_endpoint("https://HEC.example.test:443/services/collector")[
                0
            ],
            "https://hec.example.test/services/collector",
        )
        self.assertEqual(
            sender._parse_endpoint("https://hec.example.test")[0],
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
            for path in ("/services/collector/event", "/services/collector"):
                result = sender._post_json(
                    f"https://127.0.0.1:8443{path}",
                    b'{"event":{}}\n',
                    "test-token",
                    2,
                    context,
                )
                self.assertEqual(result.status, 302)
                self.assertEqual(
                    observed["headers"]["Authorization"], "Splunk test-token"
                )
                self.assertEqual(observed["path"], path)
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


class HecDeliveryTlsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if not openssl:
            raise unittest.SkipTest("openssl is required for local TLS transport tests")
        cls.temp = tempfile.TemporaryDirectory()
        cls.certificate = Path(cls.temp.name) / "localhost.pem"
        cls.private_key = Path(cls.temp.name) / "localhost-key.pem"
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(cls.private_key),
                "-out",
                str(cls.certificate),
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def make_server(self, mode: str):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body_size = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(body_size)
                self.server.request_count += 1
                if mode == "slow_headers":
                    time.sleep(0.5)
                    self.send_response(200)
                    self.send_header("Content-Length", "25")
                    self.end_headers()
                    self.wfile.write(b'{"text":"Success","code":0}')
                    return
                if mode == "slow_close_body":
                    self.send_response(200)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b'{"text":"')
                    self.wfile.flush()
                    time.sleep(0.5)
                    self.wfile.write(b'Success","code":0}')
                    self.wfile.flush()
                    return
                response_body = b'{"text":"Success","code":0}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, *_args):
                return

        class QuietThreadingHTTPServer(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, *_args):
                return

        server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.request_count = 0
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(self.certificate), str(self.private_key))
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def post(self, server, timeout: float = 0.15):
        context = ssl.create_default_context(cafile=str(self.certificate))
        return sender._post_json(
            f"https://127.0.0.1:{server.server_port}/services/collector/event",
            b'{"event":{}}\n',
            "test-token",
            timeout,
            context,
        )

    def test_verified_tls_post_succeeds_with_task_local_ca(self):
        server = self.make_server("success")
        try:
            response = self.post(server, timeout=2)
            self.assertEqual(response.status, 200)
            self.assertEqual(sender._successful_hec_response(response), (None, 0))
            self.assertEqual(server.request_count, 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_whole_request_deadline_covers_slow_response_headers(self):
        server = self.make_server("slow_headers")
        try:
            started = time.monotonic()
            with self.assertRaises(sender._HTTPFailure):
                self.post(server)
            self.assertLess(time.monotonic() - started, 0.8)
        finally:
            server.shutdown()
            server.server_close()

    def test_whole_request_deadline_covers_close_delimited_slow_body(self):
        server = self.make_server("slow_close_body")
        try:
            started = time.monotonic()
            with self.assertRaises(sender._HTTPFailure):
                self.post(server)
            self.assertLess(time.monotonic() - started, 0.8)
        finally:
            server.shutdown()
            server.server_close()

    def test_dns_resolution_wait_is_bounded_before_any_authenticated_request(self):
        server = self.make_server("success")
        original_getaddrinfo = socket.getaddrinfo

        def delayed_resolution(host, port, **kwargs):
            time.sleep(0.5)
            return original_getaddrinfo(host, port, **kwargs)

        try:
            started = time.monotonic()
            with patch.object(sender.socket, "getaddrinfo", delayed_resolution):
                with self.assertRaises(sender._HTTPFailure):
                    sender._post_json(
                        f"https://delay.example.test:{server.server_port}/services/collector/event",
                        b'{"event":{}}\n',
                        "test-token",
                        0.15,
                        ssl.create_default_context(cafile=str(self.certificate)),
                    )
            self.assertLess(time.monotonic() - started, 0.4)
            time.sleep(0.45)
            self.assertEqual(server.request_count, 0)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
