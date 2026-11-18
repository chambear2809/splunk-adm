"""Verified, cookie-authenticated HTTP sessions for the owned Splunk Web lab.

This exercises the real Web login/proxy/CSRF path; it is not a rendered-browser
or protected-source test. Credentials and session cookies stay in memory.
"""

import copy
from dataclasses import dataclass, field
from html.parser import HTMLParser
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import stat
import secrets
import urllib.error
import urllib.parse
import urllib.request

import lab


CONTEXT = (
    "/en-US/splunkd/__raw/services/authentication/current-context?output_mode=json"
)
CASES = "/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/adm/investigations"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class WebSessionError(RuntimeError):
    """Safe diagnostics must never contain credentials, cookies or HTML."""


class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Login returns a redirect. Expose its response; never follow it.
        return None


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.nonce = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name") == "cval":
            value = attributes.get("value")
            if (
                self.nonce is not None
                or not isinstance(value, str)
                or len(value) > 1024
            ):
                raise WebSessionError("ambiguous login nonce")
            self.nonce = value


@dataclass
class WebResponse:
    status: int
    body: bytes = field(repr=False)
    headers: object = field(repr=False)

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeError):
            raise WebSessionError("Web response was not JSON") from None


class RequestJournal:
    """Durable synthetic-case requests; never cookies, CSRF tokens or login bodies."""

    def __init__(self, path):
        self.path = Path(path)
        parent = self.path.parent
        info = parent.lstat()
        if (
            not self.path.is_absolute()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or parent.is_symlink()
            or any((part / ".git").exists() for part in (parent, *parent.parents))
            or self.path.exists()
            or self.path.is_symlink()
        ):
            raise WebSessionError("unsafe or existing Web journal")
        self.records = []
        self.fixture = None
        self._persist()

    def _persist(self):
        data = json.dumps(
            {"schema": 1, "requests": self.records, "fixture": self.fixture}, indent=2
        ).encode()
        if len(data) > 2 * 1024 * 1024:
            raise WebSessionError("Web journal limit reached")
        temporary = self.path.with_name(self.path.name + "." + secrets.token_hex(8))
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def begin(self, method, path, key, body):
        if len(self.records) >= 128:
            raise WebSessionError("Web journal request limit reached")
        self.records.append(
            {
                "method": method,
                "path": path,
                "idempotency_key": key,
                "body": body.decode("utf-8") if body is not None else None,
                "state": "intent",
            }
        )
        self._persist()
        return len(self.records) - 1

    def response(self, index, response):
        record = self.records[index]
        record.update(
            state="response_received",
            status=response.status,
            response_sha256=hashlib.sha256(response.body).hexdigest(),
            csrf_error_mentioned=response.status in (401, 403)
            and b"csrf" in response.body.lower(),
        )
        try:
            data = response.json()
        except WebSessionError:
            data = {}
        if isinstance(data, dict):
            for key in ("id", "revision"):
                if key in data:
                    record["response_" + key] = data[key]
        self._persist()

    def unknown(self, index):
        self.records[index]["state"] = "transport_unknown"
        self._persist()


class WebSession:
    def __init__(self, *, cookies=None, journal=None):
        if lab.task_identity() is None or os.environ.get("ADM_LAB_WEB_TLS") != "1":
            raise WebSessionError("requires an owned HTTPS Web lab")
        self.port = int(os.environ["ADM_LAB_WEB_PORT"])
        self.origin = f"https://127.0.0.1:{self.port}"
        self.cookies = http.cookiejar.CookieJar()
        if cookies is not None:
            for cookie in cookies:
                self.cookies.set_cookie(copy.copy(cookie))
        self.journal = journal
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoFollow(),
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=lab._context()),
        )

    def csrf_token(self):
        names = {f"splunkweb_csrf_token_{self.port}", "splunkweb_csrf_token_8000"}
        values = [cookie.value for cookie in self.cookies if cookie.name in names]
        if len(values) != 1 or not 0 < len(values[0]) <= 1024:
            raise WebSessionError("Web CSRF cookie unavailable or ambiguous")
        return values[0]

    def request(self, method, path, *, data=None, key=None, csrf=True, form=False):
        target = urllib.parse.urlsplit(path)
        if (
            method not in {"GET", "POST", "DELETE"}
            or not path.startswith("/")
            or path.startswith("//")
            or target.scheme
            or target.netloc
            or target.fragment
            or any(ord(char) < 32 for char in path)
        ):
            raise WebSessionError("invalid Web request target")
        lab.verify_target()
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        if csrf is not False:
            headers["X-Splunk-Form-Key"] = self.csrf_token() if csrf is True else csrf
        if key is not None:
            headers["Idempotency-Key"] = key
        body = None
        if data is not None:
            if form:
                body = urllib.parse.urlencode(data).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(data).encode()
                headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.origin + path, method=method, headers=headers, data=body
        )
        intent = None
        if (
            self.journal is not None
            and path.startswith(CASES + "/")
            and method in {"POST", "DELETE"}
        ):
            intent = self.journal.begin(method, path, key, body)
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, ValueError):
            if intent is not None:
                self.journal.unknown(intent)
            raise WebSessionError("verified Web transport failed") from None
        with response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise WebSessionError("Web response exceeded limit")
            result = WebResponse(response.code, content, response.headers)
            if intent is not None:
                self.journal.response(intent, result)
            return result

    def login(self, username, password):
        page = self.request("GET", "/en-US/account/login", csrf=False)
        if page.status != 200:
            raise WebSessionError("Web login page unavailable")
        form = LoginForm()
        form.feed(page.body.decode("utf-8", "strict"))
        values = [cookie.value for cookie in self.cookies if cookie.name == "cval"]
        nonce = form.nonce or (values[0] if len(values) == 1 else None)
        if not nonce:
            # Supply a matched form/cookie nonce if the page provides none.
            # Authentication still requires the expected current-context proof.
            nonce = str(secrets.randbelow(2**53))
            self.cookies.set_cookie(
                http.cookiejar.Cookie(
                    0,
                    "cval",
                    nonce,
                    str(self.port),
                    True,
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
        response = self.request(
            "POST",
            "/en-US/account/login",
            csrf=False,
            form=True,
            data={
                "username": username,
                "password": password,
                "cval": nonce,
                "return_to": "/en-US/",
                "set_has_logged_in": "true",
            },
        )
        if response.status not in {200, 302, 303}:
            raise WebSessionError("Web login rejected")
        proof = self.request("GET", CONTEXT)
        if proof.status != 200:
            raise WebSessionError("Web authentication proof unavailable")
        try:
            content = proof.json()["entry"][0]["content"]
        except (KeyError, IndexError, TypeError):
            raise WebSessionError("invalid Web authentication proof") from None
        if content.get("username") != username:
            raise WebSessionError("Web principal did not match")
        return content

    def clone(self):
        return WebSession(cookies=self.cookies, journal=self.journal)

    def close(self):
        self.cookies.clear()
