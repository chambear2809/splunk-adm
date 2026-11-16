import datetime as dt
import os
import socket
import ssl
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "splunk"))
from lab_tls import (  # noqa: E402
    LabTLSError,
    cleanup_tls,
    prepare_tls,
    read_container,
    remember_container,
    server_bundle,
    tls_context,
    tls_directory,
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


class LabTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.first = cls.root / "first-secrets"
        cls.second = cls.root / "second-secrets"
        cls.identity = ("tls-test", "adm-tls-test")
        cls.second_identity = ("tls-other", "adm-tls-other")
        cls.directory = prepare_tls(cls.first, *cls.identity)
        cls.other = prepare_tls(cls.second, *cls.second_identity)
        cls.http = QuietServer(("127.0.0.1", 0), Handler)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(str(cls.directory / "server.pem"))
        cls.http.socket = server.wrap_socket(cls.http.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join(timeout=5)
        cls.tmp.cleanup()

    def test_verified_loopback_and_hostname_and_wrong_ca_fail(self):
        context = tls_context(self.first, self.identity)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        port = self.http.server_port
        for name in ("127.0.0.1", "localhost"):
            with urllib.request.urlopen(
                f"https://{name}:{port}/", context=context, timeout=5
            ) as response:
                self.assertEqual(response.read(), b"ok")
        wrong_ca = tls_context(self.second, self.second_identity)
        with self.assertRaises(urllib.error.URLError) as bad_ca:
            urllib.request.urlopen(
                f"https://127.0.0.1:{port}/", context=wrong_ca, timeout=5
            )
        self.assertIsInstance(bad_ca.exception.reason, ssl.SSLCertVerificationError)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(raw, server_hostname="wrong.example")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with context.wrap_socket(
                raw, server_hostname=self.identity[1]
            ) as connected:
                self.assertIsNotNone(connected.cipher())
                connected.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                connected.recv(1024)

    def test_private_files_identity_san_and_expiration(self):
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(
            {p.name for p in self.directory.iterdir()},
            {"identity.json", "ca.pem", "server.pem"},
        )
        for path in self.directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertGreater(len(server_bundle(self.first, self.identity)), 0)
        cert = ssl._ssl._test_decode_cert(str(self.directory / "server.pem"))
        self.assertIn(("IP Address", "127.0.0.1"), cert["subjectAltName"])
        self.assertIn(("DNS", "localhost"), cert["subjectAltName"])
        self.assertIn(("DNS", self.identity[1]), cert["subjectAltName"])
        start = dt.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        end = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        self.assertEqual(end - start, dt.timedelta(days=2))
        with self.assertRaises(LabTLSError):
            tls_context(self.first, (self.identity[0], "adm-some-other"))
        with self.assertRaises(LabTLSError):
            tls_context(self.first)
        with self.assertRaises(LabTLSError):
            prepare_tls(self.first, *self.identity)

    def test_unsafe_modes_symlinks_and_missing_material_fail_closed(self):
        with self.assertRaises(LabTLSError):
            prepare_tls(
                Path(__file__).resolve().parents[1] / "unwanted", *self.identity
            )
        ca = self.directory / "ca.pem"
        ca.chmod(0o644)
        try:
            with self.assertRaises(LabTLSError):
                tls_context(self.first, self.identity)
        finally:
            ca.chmod(0o600)
        hardlink = self.directory / "other-link"
        os.link(ca, hardlink)
        try:
            with self.assertRaises(LabTLSError):
                tls_context(self.first, self.identity)
        finally:
            hardlink.unlink()
        self.directory.chmod(0o755)
        try:
            with self.assertRaises(LabTLSError):
                tls_context(self.first, self.identity)
        finally:
            self.directory.chmod(0o700)
        missing = self.root / "missing"
        with self.assertRaises(LabTLSError):
            tls_context(missing, self.identity)
        default_context = tls_context(missing)
        self.assertEqual(default_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(default_context.check_hostname)
        symlink = self.root / "symlink.tls"
        symlink.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(LabTLSError):
            tls_context(self.root / "symlink", self.identity)
        with self.assertRaises(LabTLSError):
            prepare_tls(self.root / "symlink", *self.identity)
        symlink.unlink()
        extra = self.directory / "unexpected"
        extra.write_text("leave this data alone")
        try:
            with self.assertRaises(LabTLSError):
                cleanup_tls(self.first, *self.identity)
            self.assertTrue(extra.exists())
        finally:
            extra.unlink()

    def test_cleanup_requires_exact_identity_and_removes_only_task_files(self):
        secrets_path = self.root / "cleanup"
        identity = ("tls-cleanup", "adm-tls-cleanup")
        directory = prepare_tls(secrets_path, *identity)
        with self.assertRaises(LabTLSError):
            cleanup_tls(secrets_path, identity[0], "adm-wrong")
        self.assertTrue(directory.exists())
        cleanup_tls(secrets_path, *identity)
        self.assertFalse(directory.exists())

    def test_container_id_is_bound_once_and_validated(self):
        secrets_path = self.root / "bound"
        identity = ("tls-bound", "adm-tls-bound")
        directory = prepare_tls(secrets_path, *identity)
        with self.assertRaises(LabTLSError):
            read_container(secrets_path, identity)
        with self.assertRaises(LabTLSError):
            remember_container(secrets_path, identity, "123")
        ident = "a" * 64
        remember_container(secrets_path, identity, ident)
        remember_container(secrets_path, identity, ident)
        self.assertEqual(read_container(secrets_path, identity), ident)
        self.assertEqual(
            stat.S_IMODE((directory / "container-id").stat().st_mode), 0o600
        )
        with self.assertRaises(LabTLSError):
            remember_container(secrets_path, identity, "b" * 64)
        (directory / "container-id").chmod(0o644)
        with self.assertRaises(LabTLSError):
            read_container(secrets_path, identity)
        (directory / "container-id").chmod(0o600)
        saved = directory / "container-id"
        saved.unlink()
        saved.symlink_to(self.directory / "identity.json")
        with self.assertRaises(LabTLSError):
            read_container(secrets_path, identity)
        saved.unlink()
        remember_container(secrets_path, identity, ident)
        cleanup_tls(secrets_path, *identity)
        self.assertFalse(directory.exists())

    def test_runtime_parent_requires_private_owned_directory(self):
        parent = self.root / "parent"
        parent.mkdir(mode=0o700)
        secret = parent / "secrets"
        self.assertEqual(tls_directory(secret), parent / "secrets.tls")
        parent.chmod(0o755)
        try:
            with self.assertRaises(LabTLSError):
                tls_directory(secret)
        finally:
            parent.chmod(0o700)
        link = self.root / "parent-link"
        link.symlink_to(parent, target_is_directory=True)
        try:
            with self.assertRaises(LabTLSError):
                tls_directory(link / "secrets")
        finally:
            link.unlink()


if __name__ == "__main__":
    unittest.main()
