"""Exercise the real pinned SDK against private local TLS/SSE endpoints."""

from contextlib import contextmanager, redirect_stderr
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from tools import export_o11y_health as exporter
from tools import o11y_transport as transport


HOST = "stream.us0.observability.splunkcloud.com"
END = (
    b'event: control-message\ndata: {"event":"STREAM_START","timestampMs":1000}\n\n'
    b'event: control-message\ndata: {"event":"JOB_START","timestampMs":1000,"handle":"test-computation"}\n\n'
    b'event: control-message\ndata: {"event":"END_OF_CHANNEL","timestampMs":1000}\n\n'
)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # CI installs this already-pinned optional runtime before Python checks.
        from signalfx.signalflow import SignalFlowClient

        cls.sdk_class = SignalFlowClient
        cls.directory = TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.certificates = {}
        executable = shutil.which("openssl")
        if not executable:
            raise AssertionError("OpenSSL is required for local TLS qualification")
        for name, host in (("valid", HOST), ("wrong", "wrong.example.test")):
            key, cert = (
                Path(cls.directory.name) / f"{name}.{extension}"
                for extension in ("key", "pem")
            )
            subprocess.run(
                [
                    executable,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    f"/CN={host}",
                    "-addext",
                    f"subjectAltName=DNS:{host}",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            cls.certificates[name] = (key, cert)

    @contextmanager
    def server(self, behavior="complete", certificate="valid"):
        requests = []
        key, cert = self.certificates[certificate]

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    requests.append((self.path, dict(self.headers), body))
                    if behavior == "redirect":
                        self.send_response(302)
                        self.send_header(
                            "Location", "https://untrusted.example.test/steal"
                        )
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    if behavior == "slow_headers":
                        for byte in b"HTTP/1.1 200 OK\r\n":
                            self.connection.sendall(bytes([byte]))
                            time.sleep(0.15)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    if behavior == "oversized_header":
                        self.send_header(
                            "Content-Length", str(transport.MAX_RESPONSE_BYTES + 1)
                        )
                    elif behavior == "complete":
                        self.send_header("Content-Length", str(len(END)))
                    self.end_headers()
                    if behavior == "slow_body":
                        for _ in range(30):
                            self.wfile.write(b":")
                            self.wfile.flush()
                            time.sleep(0.1)
                    elif behavior == "oversized_body":
                        self.wfile.write(b"x" * 129)
                        self.wfile.flush()
                    elif behavior == "unknown_control":
                        self.wfile.write(
                            b'event: control-message\ndata: {"event":"PRIVATE-SOURCE-PAYLOAD"}\n\n'
                        )
                        self.wfile.flush()
                    elif behavior == "truncated":
                        self.close_connection = True
                    elif behavior == "complete":
                        self.wfile.write(END)
                        self.wfile.flush()
                except (OSError, ssl.SSLError):
                    pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, *_args):
                pass

        server = Server(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
        )
        thread.start()
        original = socket.getaddrinfo
        resolutions = []

        def resolve(host, port, *args, **kwargs):
            resolutions.append(host)
            if host != HOST:
                raise AssertionError("Unexpected request outside configured realm")
            return original("127.0.0.1", server.server_port, *args, **kwargs)

        try:
            with patch.object(socket, "getaddrinfo", resolve):
                yield requests, resolutions, str(cert)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def execute(self, *, ca_bundle, timeout=2):
        client = transport.make_client("test-token", "us0", timeout, ca_bundle)
        self.assertIsInstance(client, self.sdk_class)
        self.addCleanup(client.close)
        computation = client.execute(
            "A=data('test').publish()",
            start=1000,
            stop=2000,
            resolution=1000,
            immediate=True,
        )
        messages = list(computation.stream())
        client.close()
        return messages, computation

    def test_verified_tls_and_actual_sdk_end_of_channel(self):
        with self.server() as (requests, resolutions, ca):
            messages, computation = self.execute(ca_bundle=ca)
        self.assertEqual(
            [type(message).__name__ for message in messages], ["JobStartMessage"]
        )
        self.assertEqual(computation.id, "test-computation")
        self.assertEqual(computation.state, computation.STATE_COMPLETED)
        self.assertEqual(resolutions, [HOST])
        self.assertEqual(len(requests), 1)
        self.assertIn("/v2/signalflow/execute?", requests[0][0])
        self.assertIn("start=1000", requests[0][0])
        self.assertIn("immediate=true", requests[0][0])
        self.assertEqual(requests[0][1]["X-Sf-Token"], "test-token")

    def test_exporter_tracks_one_real_sdk_completion_before_publishing(self):
        request = exporter.ExportRequest(
            observer="transport-test",
            organization_id="org-test",
            realm="us0",
            scope="prod",
            service_name="checkout",
            environment="production",
            cluster="cluster-a",
            kubernetes_namespace="commerce",
            apm_mms_id="custom-mms",
            service_namespace="payments",
            start=1,
            end=2,
            timeout_seconds=2,
        )
        with self.server() as (_, _, ca), TemporaryDirectory() as directory:
            output = Path(directory) / "capture.ndjson"
            result = exporter.run_export(
                request,
                output,
                token="test-token",
                client_factory=lambda token, realm, timeout: transport.make_client(
                    token, realm, timeout, ca
                ),
            )
            self.assertTrue(output.is_file())
            self.assertEqual(result[-1]["event_type"], "export_completion")
            self.assertEqual(result[-1]["expected_record_count"], 0)

    def test_untrusted_certificate_and_hostname_fail_before_http_authentication(self):
        for certificate, trust in (("valid", False), ("wrong", True)):
            with (
                self.subTest(certificate=certificate),
                self.server(certificate=certificate) as (requests, _, ca),
            ):
                with self.assertRaises(transport.TransportError):
                    self.execute(ca_bundle=ca if trust else None)
                self.assertEqual(requests, [])

    def test_redirect_is_rejected_without_forwarding_credentials(self):
        with self.server("redirect") as (requests, resolutions, ca):
            with self.assertRaises(transport.TransportError):
                self.execute(ca_bundle=ca)
        self.assertEqual(len(requests), 1)
        self.assertEqual(resolutions, [HOST])

    def test_deadline_covers_slow_headers_and_slow_trickle_body(self):
        for behavior in ("slow_headers", "slow_body"):
            with self.subTest(behavior=behavior), self.server(behavior) as (_, _, ca):
                start = time.monotonic()
                with self.assertRaises(transport.TransportError):
                    self.execute(ca_bundle=ca, timeout=1)
                self.assertLess(time.monotonic() - start, 2)

    def test_capped_and_truncated_streams_do_not_reconnect(self):
        for behavior in ("oversized_header", "oversized_body", "truncated"):
            with (
                self.subTest(behavior=behavior),
                self.server(behavior) as (requests, _, ca),
                patch.object(transport, "MAX_RESPONSE_BYTES", 128),
            ):
                with self.assertRaises(transport.TransportError):
                    self.execute(ca_bundle=ca)
                self.assertEqual(len(requests), 1)

    def test_unknown_control_fails_without_sdk_payload_warning(self):
        errors = io.StringIO()
        with self.server("unknown_control") as (_, _, ca), redirect_stderr(errors):
            with self.assertRaises(transport.TransportError) as failure:
                self.execute(ca_bundle=ca)
        self.assertNotIn("PRIVATE-SOURCE-PAYLOAD", str(failure.exception))
        self.assertNotIn("PRIVATE-SOURCE-PAYLOAD", errors.getvalue())

    def test_dns_delay_obeys_caller_deadline_without_late_authentication(self):
        original = socket.getaddrinfo
        release = threading.Event()

        def delayed(_host, _port, *args, **kwargs):
            release.wait(timeout=5)
            return original("127.0.0.1", 9, *args, **kwargs)

        client = transport.make_client("test-token", "us0", 1)
        self.addCleanup(client.close)
        try:
            with patch.object(socket, "getaddrinfo", delayed):
                start = time.monotonic()
                with self.assertRaises(transport.TransportError):
                    client.execute("A=data('test').publish()", start=1000, stop=2000)
                self.assertLess(time.monotonic() - start, 2)
                client.close()
                release.set()
                client._transport._streams[0].thread.join(timeout=1)
                self.assertFalse(client._transport._streams[0].thread.is_alive())
        finally:
            release.set()

    def test_unsupported_sdk_and_oversized_program_are_rejected(self):
        with patch.object(transport, "version", return_value="unsupported"):
            with self.assertRaisesRegex(transport.TransportError, "pinned"):
                transport.make_client("test-token", "us0", 1)
        client = transport.make_client("test-token", "us0", 1)
        self.addCleanup(client.close)
        with patch.object(
            socket,
            "getaddrinfo",
            side_effect=AssertionError("No HTTP request should start"),
        ):
            with self.assertRaisesRegex(transport.TransportError, "byte cap"):
                client.execute(
                    "x" * (transport.MAX_PROGRAM_BYTES + 1), start=1000, stop=2000
                )

    def test_invalid_realm_credential_and_timeout_are_rejected_before_network(self):
        for token, realm, timeout in (
            ("test-token", "us0/elsewhere", 1),
            ("test\nvalue", "us0", 1),
            ("test-token", "us0", True),
            ("test-token", "us0", 301),
        ):
            with self.subTest(realm=realm), self.assertRaises(transport.TransportError):
                transport.make_client(token, realm, timeout)


if __name__ == "__main__":
    unittest.main()
