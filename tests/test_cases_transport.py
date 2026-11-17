"""Offline tests for supervised transport and local TLS limits."""

from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.transport import SupervisedTransport, TransportError  # noqa: E402
from adm_cases_lib import transport_worker  # noqa: E402


def memory_limit_supported():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import resource; resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


class LocalTLS:
    def __init__(self, cert, key, responder):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.responder = responder
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            raw, _ = self.socket.accept()
            with raw, self.context.wrap_socket(raw, server_side=True) as conn:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    data += conn.recv(4096)
                self.responder(conn, data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.socket.close()


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.cert = str(Path(cls.directory.name) / "cert.pem")
        cls.key = str(Path(cls.directory.name) / "key.pem")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                cls.key,
                "-out",
                cls.cert,
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        cls.addClassCleanup(cls.directory.cleanup)
        cls.tls_worker = None
        if not memory_limit_supported():
            # The desktop OS cannot apply RLIMIT_AS; exercise the real TLS code
            # with only that OS-specific limit mocked in this test worker.
            original = (
                Path(__file__).resolve().parents[1]
                / "splunk_app/splunk_adm/bin/adm_cases_lib/transport_worker.py"
            )
            wrapper = Path(cls.directory.name) / "tls_test_worker.py"
            wrapper.write_text(
                "import resource,runpy\n"
                "original = resource.setrlimit\n"
                "resource.setrlimit = lambda kind, limits: None if kind == resource.RLIMIT_AS else original(kind, limits)\n"
                f"runpy.run_path({str(original)!r}, run_name='__main__')\n"
            )
            cls.tls_worker = str(wrapper)

    def transport(self, responder, token="private-session"):
        server = LocalTLS(self.cert, self.key, responder)
        return SupervisedTransport(
            token,
            f"https://localhost:{server.port}",
            self.cert,
            _worker_path=self.tls_worker,
        ), server

    @staticmethod
    def response(status, body):
        def respond(conn, request):
            conn.sendall(
                f"HTTP/1.1 {status} test\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )

        return respond

    def test_embedded_linux_libraries_are_fixed_and_parent_env_is_not_inherited(self):
        from adm_cases_lib.transport import _worker_environment

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "lib").mkdir(mode=0o755)
            executable = root / "bin/python3"
            executable.touch()
            with (
                mock.patch("sys.platform", "linux"),
                mock.patch("sys.executable", str(executable)),
                mock.patch.dict(
                    "os.environ",
                    {
                        "SPLUNK_HOME": str(root),
                        "LD_LIBRARY_PATH": "/untrusted",
                        "SECRET": "private",
                    },
                ),
            ):
                self.assertEqual(
                    _worker_environment(),
                    {"LANG": "C.UTF-8", "LD_LIBRARY_PATH": str(root.resolve() / "lib")},
                )
                (root / "lib").chmod(0o777)
                with self.assertRaises(TransportError):
                    _worker_environment()

    def test_preflight_is_token_free_and_requires_limits(self):
        transport = SupervisedTransport(
            "secret-token",
            "https://localhost:8089",
            self.cert,
            _worker_path=self.tls_worker,
        )
        self.assertTrue(transport.preflight())
        with mock.patch.object(
            transport, "_exchange", return_value={"ready": False}
        ) as exchange:
            self.assertFalse(transport.preflight())
            exchange.assert_called_once_with(b"", 3, method="GET", preflight=True)

    def test_valid_tls_token_headers_and_bounded_error(self):
        seen = []

        def serve(conn, request):
            seen.append(request)
            self.response(200, b'{"ok":true}')(conn, request)

        transport, server = self.transport(serve)
        self.assertEqual(
            transport("GET", "/services/server/info", None, 3), {"ok": True}
        )
        server.thread.join(1)
        self.assertIn(b"Authorization: Splunk private-session", seen[0])
        transport, _ = self.transport(
            self.response(403, b"private body"), token="eyJ.abc.sig"
        )
        with self.assertRaises(TransportError) as error:
            transport("GET", "/services/server/info", None, 3)
        self.assertEqual(error.exception.status, 403)
        self.assertFalse(error.exception.uncertain)
        self.assertNotIn("private", str(error.exception))

    def test_wrong_hostname_and_untrusted_ca_fail_closed(self):
        transport, server = self.transport(self.response(200, b"{}"))
        transport.origin = f"https://127.0.0.1:{server.port}"
        with self.assertRaises(TransportError):
            transport("GET", "/services/server/info", None, 3)
        with self.assertRaises(TransportError):
            SupervisedTransport("token", "https://localhost:8089", "/missing/ca.pem")

    def test_body_limit_and_deadlines(self):
        for status in (200, 403):
            transport, _ = self.transport(
                self.response(status, b"x" * (2 * 1024 * 1024 + 1))
            )
            with self.subTest(status=status), self.assertRaises(TransportError):
                transport("GET", "/services/server/info", None, 3)

        def stall(conn, request):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{")
            time.sleep(2)

        transport, _ = self.transport(stall)
        start = time.monotonic()
        with self.assertRaises(TransportError):
            transport("GET", "/services/server/info", None, 0.3)
        self.assertLess(time.monotonic() - start, 1.5)

        def header_stall(conn, request):
            conn.sendall(b"HTTP/1.1 200 OK\r\nX-Hold: ")
            time.sleep(2)

        transport, _ = self.transport(header_stall)
        with self.assertRaises(TransportError):
            transport("GET", "/services/server/info", None, 0.3)

    def test_private_worker_args_env_and_reaping(self):
        worker = Path(self.directory.name) / "worker.py"
        worker.write_text(
            'import json,os,sys,time\nx=json.loads(sys.stdin.buffer.readline())\nassert x["token"] not in " ".join(sys.argv)\nassert x["token"] not in str(dict(os.environ))\nsys.stdout.buffer.write((200).to_bytes(4,"big")+b"{\\"ok\\":true}")\n'
        )
        transport = SupervisedTransport(
            "sensitive-token",
            "https://localhost:8089",
            self.cert,
            _worker_path=str(worker),
        )
        self.assertEqual(
            transport("GET", "/services/server/info", None, 2), {"ok": True}
        )
        worker.write_text("import time\ntime.sleep(30)\n")
        real = subprocess.Popen
        children = []

        def track(*args, **kwargs):
            child = real(*args, **kwargs)
            children.append(child)
            return child

        with mock.patch("adm_cases_lib.transport.subprocess.Popen", side_effect=track):
            with self.assertRaises(TransportError) as error:
                transport(
                    "POST",
                    "/servicesNS/nobody/splunk_adm/search/v2/jobs",
                    {"padding": "x" * 60000},
                    0.2,
                )
        self.assertTrue(error.exception.uncertain)
        self.assertIsNotNone(children[0].returncode)
        worker.write_text("import sys\nsys.exit(4)\n")
        with self.assertRaises(TransportError):
            transport("GET", "/services/server/info", None, 1)

    def test_oversized_ipc_and_input_are_rejected(self):
        worker = Path(self.directory.name) / "oversized_worker.py"
        worker.write_text(
            'import sys\nsys.stdin.buffer.readline()\nsys.stdout.buffer.write((200).to_bytes(4,"big") + b"x" * (2097152 + 1))\nsys.stdout.buffer.flush()\n'
        )
        transport = SupervisedTransport(
            "token", "https://localhost:8089", self.cert, _worker_path=str(worker)
        )
        with self.assertRaises(TransportError):
            transport("GET", "/services/server/info", None, 3)
        with self.assertRaises(TransportError) as error:
            transport(
                "POST",
                "/servicesNS/nobody/splunk_adm/search/v2/jobs",
                {"oversize": "x" * 65536},
                3,
            )
        self.assertFalse(error.exception.uncertain)

    def test_ca_snapshot_rejects_unsafe_files_and_private_material(self):
        directory = Path(self.directory.name)
        cert = Path(self.cert).read_bytes()
        trusted = directory / "trust-copy.pem"
        trusted.write_bytes(cert)
        trusted.chmod(0o644)
        first = SupervisedTransport("one", "https://localhost", str(trusted))
        self.assertEqual(
            first.trust_digest,
            SupervisedTransport(
                "two", "https://localhost:8089/", str(trusted)
            ).trust_digest,
        )
        trusted.write_bytes(cert + b"\n")
        self.assertNotEqual(
            first.trust_digest,
            SupervisedTransport("one", "https://localhost", str(trusted)).trust_digest,
        )
        trusted.chmod(0o666)
        with self.assertRaises(TransportError):
            SupervisedTransport("token", "https://localhost", str(trusted))
        trusted.chmod(0o644)
        link = directory / "link.pem"
        link.symlink_to(trusted)
        with self.assertRaises(TransportError):
            SupervisedTransport("token", "https://localhost", str(link))
        link.unlink()
        hardlink = directory / "hardlink.pem"
        import os

        os.link(trusted, hardlink)
        try:
            with self.assertRaises(TransportError):
                SupervisedTransport("token", "https://localhost", str(trusted))
        finally:
            hardlink.unlink()
        trusted.write_bytes(cert + Path(self.key).read_bytes())
        with self.assertRaises(TransportError):
            SupervisedTransport("token", "https://localhost", str(trusted))
        trusted.write_bytes(cert + b"x" * (128 * 1024))
        with self.assertRaises(TransportError):
            SupervisedTransport("token", "https://localhost", str(trusted))

    def test_large_valid_ca_bundle_uses_separate_bounded_frame(self):
        bundle = Path(self.directory.name) / "bundle.pem"
        cert = Path(self.cert).read_bytes()
        bundle.write_bytes(cert * (65536 // len(cert) + 2))
        bundle.chmod(0o644)
        self.assertGreater(bundle.stat().st_size, 65536)
        server = LocalTLS(self.cert, self.key, self.response(200, b'{"ok":true}'))
        transport = SupervisedTransport(
            "token",
            f"https://localhost:{server.port}",
            str(bundle),
            _worker_path=self.tls_worker,
        )
        self.assertEqual(
            transport("GET", "/services/server/info", None, 3), {"ok": True}
        )

    def test_ca_snapshot_survives_file_change_after_construction(self):
        trusted = Path(self.directory.name) / "snapshot.pem"
        trusted.write_bytes(Path(self.cert).read_bytes())
        trusted.chmod(0o644)
        server = LocalTLS(self.cert, self.key, self.response(200, b'{"ok":true}'))
        transport = SupervisedTransport(
            "token",
            f"https://localhost:{server.port}",
            str(trusted),
            _worker_path=self.tls_worker,
        )
        trusted.write_text("invalid replacement")
        self.assertEqual(
            transport("GET", "/services/server/info", None, 3), {"ok": True}
        )
        with self.assertRaises(TransportError):
            SupervisedTransport(
                "token", f"https://localhost:{server.port}", str(trusted)
            )

    def test_fixed_path_and_search_constraints(self):
        data = {
            "token": "token",
            "origin": "https://localhost:8089",
            "ca_length": len(Path(self.cert).read_bytes()),
            "method": "GET",
            "path": "/services/search/v2/jobs/x/results?count=0&offset=0",
            "data": None,
            "timeout": 1,
        }
        with self.assertRaises(ValueError):
            transport_worker.request(data, Path(self.cert).read_bytes())
        data.update(
            method="POST",
            path="/servicesNS/nobody/splunk_adm/search/v2/jobs",
            data={"search": "| delete"},
        )
        with self.assertRaises(ValueError):
            transport_worker.request(data, Path(self.cert).read_bytes())
        data.update(
            method="GET", path="https://attacker.test/services/server/info", data=None
        )
        with self.assertRaises(ValueError):
            transport_worker.request(data, Path(self.cert).read_bytes())


if __name__ == "__main__":
    unittest.main()
