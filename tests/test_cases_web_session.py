"""Synthetic transport/receipt guards for the installed Splunk Web test client."""

import http.cookiejar
from io import BytesIO
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent / "splunk"))
import web_session as web  # noqa: E402


class Response(BytesIO):
    def __init__(self, data=b"{}", status=200):
        super().__init__(data)
        self.code = status
        self.headers = {"Set-Cookie": "synthetic-cookie-do-not-retain"}


class WebSessionGuards(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(
            os.environ,
            {
                "ADM_LAB_TASK": "synthetic-web",
                "ADM_LAB_NAME": "adm-synthetic-web",
                "ADM_LAB_WEB_TLS": "1",
                "ADM_LAB_WEB_PORT": "28900",
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.context = mock.patch.object(
            web.lab, "_context", return_value=ssl.create_default_context()
        )
        self.context.start()
        self.addCleanup(self.context.stop)
        self.verify = mock.patch.object(web.lab, "verify_target")
        self.verify.start()
        self.addCleanup(self.verify.stop)

    def session(self, **kwargs):
        result = web.WebSession(**kwargs)
        self.addCleanup(result.close)
        return result

    def test_requires_explicit_owned_https_and_rejects_other_targets_before_io(self):
        with mock.patch.dict(os.environ, ADM_LAB_WEB_TLS="0"):
            with self.assertRaises(web.WebSessionError):
                self.session()
        session = self.session()
        with mock.patch.object(session.opener, "open") as send:
            for path in (
                "http://127.0.0.1:28900/x",
                "//other.invalid/x",
                "/x#fragment",
                "/x\r\nBad: value",
            ):
                with self.subTest(path=path), self.assertRaises(web.WebSessionError):
                    session.request("POST", path, data={}, csrf=False)
            send.assert_not_called()
        self.assertIsNone(
            web.NoFollow().redirect_request(
                None, None, 302, None, {}, "https://other.invalid"
            )
        )
        with mock.patch.object(
            web.urllib.request, "build_opener", wraps=web.urllib.request.build_opener
        ) as builder:
            self.session()
        proxy = next(
            handler
            for handler in builder.call_args.args
            if isinstance(handler, web.urllib.request.ProxyHandler)
        )
        self.assertEqual(proxy.proxies, {})

    def test_cookie_clone_is_independent_and_response_repr_hides_secrets(self):
        session = self.session()
        session.cookies.set_cookie(
            http.cookiejar.Cookie(
                0,
                "splunkweb_csrf_token_8000",
                "synthetic-token",
                None,
                False,
                "127.0.0.1",
                False,
                False,
                "/",
                True,
                True,
                None,
                True,
                None,
                None,
                {},
                False,
            )
        )
        other = session.clone()
        self.addCleanup(other.close)
        self.assertTrue(other.csrf_token() == session.csrf_token())
        session.close()
        self.assertEqual(len(other.cookies), 1)
        response = web.WebResponse(
            200, b"synthetic-body-secret", {"Set-Cookie": "synthetic-cookie-secret"}
        )
        self.assertNotIn("secret", repr(response))

    def test_transport_unknown_retains_exact_case_request_without_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "journal.json"
            journal = web.RequestJournal(path)
            session = self.session(journal=journal)
            with mock.patch.object(
                session.opener,
                "open",
                side_effect=urllib.error.URLError("synthetic timeout"),
            ):
                with self.assertRaises(web.WebSessionError):
                    session.request(
                        "POST",
                        web.CASES + "/cases",
                        data={"title": "synthetic"},
                        key="fixed-key",
                        csrf="synthetic-csrf",
                    )
            record = json.loads(path.read_text())["requests"][0]
            self.assertEqual(
                record,
                {
                    "method": "POST",
                    "path": web.CASES + "/cases",
                    "idempotency_key": "fixed-key",
                    "body": '{"title": "synthetic"}',
                    "state": "transport_unknown",
                },
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("synthetic-csrf", path.read_text())
            with self.assertRaises(web.WebSessionError):
                web.RequestJournal(path)

    def test_journal_failure_precedes_send_and_login_body_is_never_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "journal.json"
            journal = web.RequestJournal(path)
            session = self.session(journal=journal)
            with (
                mock.patch.object(
                    journal,
                    "_persist",
                    side_effect=web.WebSessionError("synthetic disk failure"),
                ),
                mock.patch.object(session.opener, "open") as send,
            ):
                with self.assertRaises(web.WebSessionError):
                    session.request(
                        "POST", web.CASES + "/cases", data={}, key="fixed", csrf=False
                    )
                send.assert_not_called()
            self.assertEqual(json.loads(path.read_text())["requests"], [])
            journal.records = []
            with mock.patch.object(
                session.opener, "open", return_value=Response(status=302)
            ):
                response = session.request(
                    "POST",
                    "/en-US/account/login",
                    data={"password": "synthetic-private"},
                    csrf=False,
                    form=True,
                )
                self.assertEqual(response.status, 302)
            self.assertNotIn("synthetic-private", path.read_text())
            self.assertEqual(json.loads(path.read_text())["requests"], [])

    def test_csrf_denial_receipt_is_response_not_a_commit_and_excludes_cookies(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "journal.json"
            journal = web.RequestJournal(path)
            session = self.session(journal=journal)
            with mock.patch.object(
                session.opener, "open", return_value=Response(b'{"error":"csrf"}', 403)
            ):
                result = session.request(
                    "POST", web.CASES + "/cases", data={}, key="fixed", csrf=False
                )
            self.assertEqual(result.status, 403)
            record = json.loads(path.read_text())["requests"][0]
            self.assertEqual(
                (record["state"], record["status"]), ("response_received", 403)
            )
            self.assertNotIn("synthetic-cookie-do-not-retain", path.read_text())
