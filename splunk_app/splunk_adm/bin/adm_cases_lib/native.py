"""Small caller-owned search budget for explicit investigation captures.

The host creates one instance per HTTP request. No token, authorization result,
search job or source payload is cached across requests.
"""

import datetime as dt
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
import secrets
import threading
import time
from urllib.parse import quote

from .source import RULES


class CaptureUnavailable(Exception):
    pass


# Bound concurrent capture/revalidation requests in this persistent process.
_slots = threading.BoundedSemaphore(1)
_QUERY = re.compile(
    r'\| admqualified mode=graph service="([^"\r\n]*)" '
    r'environment="([^"\r\n]*)" cluster="([^"\r\n]*)" '
    r'namespace="([^"\r\n]*)" start=(0|[1-9][0-9]{0,15}) '
    r"as_of=(0|[1-9][0-9]{0,15})\Z"
)


def _absolute(value, expected):
    if not isinstance(value, str):
        return False
    try:
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
            return Decimal(value) == expected
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (
            parsed.tzinfo is not None and Decimal(str(parsed.timestamp())) == expected
        )
    except (ValueError, OverflowError, InvalidOperation):
        return False


class NativeComparisonSearch:
    def __init__(
        self,
        token,
        *,
        request=None,
        ledger=None,
        transport_hash=None,
        clock=time.monotonic,
        sleep=time.sleep,
        sid_factory=None,
    ):
        if (
            not isinstance(token, str)
            or not token
            or not callable(request)
            or ledger is None
            or not isinstance(transport_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", transport_hash)
        ):
            raise CaptureUnavailable()
        self.token, self.request, self.ledger = token, request, ledger
        self.transport_hash = transport_hash
        self.sid_factory = sid_factory or (
            lambda: "adm-capture-" + secrets.token_hex(16)
        )
        self.lease_owner = secrets.token_hex(16)
        self.clock, self.sleep = clock, sleep
        self.deadline = clock() + 25
        self.cleanup_remaining = 3.0
        self.jobs = 0
        self.memo = {}
        self.principal = None
        self.identity_lock = threading.Lock()

    def _call(self, method, path, data=None, *, cleanup=False, retain_job=False):
        remaining = self.cleanup_remaining if cleanup else self.deadline - self.clock()
        if remaining <= 0:
            raise CaptureUnavailable()
        started = self.clock()
        try:
            value = self.request(method, path, data, min(3, remaining))
            if cleanup and self.clock() - started >= remaining:
                raise CaptureUnavailable()
            if not cleanup and not retain_job and self.clock() >= self.deadline:
                raise CaptureUnavailable()
            if not isinstance(value, dict):
                raise CaptureUnavailable()
            return value
        except Exception:
            raise CaptureUnavailable() from None
        finally:
            if cleanup:
                self.cleanup_remaining = max(
                    0, self.cleanup_remaining - max(0, self.clock() - started)
                )

    def _transition(self, principal, record, state):
        return self.ledger.transition(
            principal,
            record["sid"],
            self.lease_owner,
            state,
            expected_revision=record["revision"],
        )

    def _proof(self, principal, record):
        if record.get("transport_hash") != self.transport_hash:
            raise CaptureUnavailable()
        if not record.get("server_sid"):
            raise CaptureUnavailable()
        status = self._call(
            "GET",
            "/services/search/jobs/" + quote(record["server_sid"], safe=""),
            cleanup=True,
        )
        self._verify_metadata(principal, record, status, require_complete=False)

    @staticmethod
    def _verify_metadata(principal, record, status, *, require_complete):
        entries = status.get("entry")
        if (
            not isinstance(entries, list)
            or len(entries) != 1
            or not isinstance(entries[0], dict)
        ):
            raise CaptureUnavailable()
        content = entries[0].get("content")
        if not isinstance(content, dict):
            raise CaptureUnavailable()
        request, acl = content.get("request"), entries[0].get("acl")
        if (
            not isinstance(request, dict)
            or not isinstance(acl, dict)
            or not record.get("server_sid")
            or content.get("sid") != record["server_sid"]
            or request.get("id") not in (None, "")
            or acl.get("owner") != principal
            or acl.get("app") != "splunk_adm"
            or (
                require_complete
                and (
                    content.get("dispatchState") != "DONE"
                    or content.get("isDone") not in (True, 1, "1")
                )
            )
            or not isinstance(request.get("search"), str)
            or content.get("search") != request["search"]
            or hashlib.sha256(request["search"].encode("utf-8")).hexdigest()
            != record["query_hash"]
            or not _absolute(request.get("earliest_time"), record["window_start"])
            or not _absolute(request.get("latest_time"), record["window_end"])
        ):
            raise CaptureUnavailable()

    def _finish(self, principal, record):
        started, budget = self.clock(), self.cleanup_remaining
        try:
            self._proof(principal, record)
            if (
                record["lease_until"] is None
                or self.ledger.clock() >= record["lease_until"]
            ):
                raise CaptureUnavailable()
            record = self.ledger.claim(
                principal,
                record["sid"],
                self.lease_owner,
                expected_revision=record["revision"],
            )
            if record["state"] != "created":
                record = self._transition(principal, record, "created")
            self._call(
                "DELETE",
                "/services/search/jobs/" + quote(record["server_sid"], safe=""),
                cleanup=True,
            )
            self._transition(principal, record, "deleted")
        except Exception:
            try:
                if record["state"] == "creating":
                    self._transition(principal, record, "creation_unknown")
                elif record["state"] == "created":
                    self._transition(principal, record, "cleanup_unknown")
            except Exception:
                pass
            raise CaptureUnavailable() from None
        finally:
            self.cleanup_remaining = min(
                self.cleanup_remaining, max(0, budget - max(0, self.clock() - started))
            )

    def _reconcile(self, principal):
        started, budget = self.clock(), self.cleanup_remaining
        try:
            records = self.ledger.outstanding(principal)
            if any(
                record.get("transport_hash") != self.transport_hash
                or not record.get("server_sid")
                for record in records
            ):
                raise CaptureUnavailable()
            for record in records:
                if self.cleanup_remaining <= 0:
                    raise CaptureUnavailable()
                record = self.ledger.claim(
                    principal,
                    record["sid"],
                    self.lease_owner,
                    expected_revision=record["revision"],
                )
                self._finish(principal, record)
        finally:
            self.cleanup_remaining = min(
                self.cleanup_remaining, max(0, budget - max(0, self.clock() - started))
            )

    def run(self, principal, query, start, end):
        if (
            not isinstance(principal, str)
            or not principal.strip()
            or not isinstance(query, str)
        ):
            raise CaptureUnavailable()
        match = _QUERY.fullmatch(query)
        if (
            match is None
            or type(start) is not int
            or type(end) is not int
            or start < 0
            or not 0 < end - start <= 300
            or int(match.group(5)) != start
            or int(match.group(6)) != end
            or any(
                not RULES[key].fullmatch(value)
                for key, value in zip(
                    ("service", "environment", "cluster", "namespace"),
                    match.groups()[:4],
                )
            )
        ):
            raise CaptureUnavailable()
        with self.identity_lock:
            if self.principal is None:
                self.principal = principal
            elif self.principal != principal:
                raise CaptureUnavailable()
        if self.clock() >= self.deadline:
            raise CaptureUnavailable()
        key = (principal, query, start, end)
        if key in self.memo:
            return json.loads(self.memo[key])
        if self.jobs >= 3 or not _slots.acquire(blocking=False):
            raise CaptureUnavailable()
        record = None
        encoded = None
        try:
            self._reconcile(principal)
            if self.clock() >= self.deadline or self.cleanup_remaining <= 0:
                raise CaptureUnavailable()
            intent = self.sid_factory()
            query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
            record = self.ledger.reserve(
                principal,
                intent,
                query_hash,
                start,
                end,
                self.lease_owner,
                transport_hash=self.transport_hash,
            )
            self.jobs += 1
            try:
                created = self._call(
                    "POST",
                    "/servicesNS/nobody/splunk_adm/search/v2/jobs",
                    {
                        "search": query,
                        "earliest_time": str(start),
                        "latest_time": str(end),
                        "exec_mode": "normal",
                        "max_time": "5",
                        "auto_cancel": "10",
                        "ttl": "30",
                        "status_buckets": "0",
                    },
                    retain_job=True,
                )
                server_sid = created.get("sid")
                if not isinstance(server_sid, str) or not re.fullmatch(
                    r"[A-Za-z0-9_.:-]{1,255}", server_sid
                ):
                    raise CaptureUnavailable()
                record = self.ledger.bind_created(
                    principal,
                    intent,
                    self.lease_owner,
                    server_sid,
                    expected_revision=record["revision"],
                )
                if self.clock() >= self.deadline:
                    raise CaptureUnavailable()
                path = "/services/search/jobs/" + quote(server_sid, safe="")
                while True:
                    status = self._call("GET", path)
                    entries = status.get("entry")
                    if (
                        not isinstance(entries, list)
                        or len(entries) != 1
                        or not isinstance(entries[0], dict)
                    ):
                        raise CaptureUnavailable()
                    info = entries[0].get("content", {})
                    if not isinstance(info, dict) or status.get("messages"):
                        raise CaptureUnavailable()
                    state = info.get("dispatchState")
                    if state in ("FAILED", "CANCELED", "FINALIZED") or info.get(
                        "isFailed"
                    ) in (True, 1, "1"):
                        raise CaptureUnavailable()
                    if info.get("isDone") in (True, 1, "1"):
                        break
                    if self.clock() >= self.deadline:
                        raise CaptureUnavailable()
                    self.sleep(0.1)
                false = (False, 0, "0")
                if (
                    state != "DONE"
                    or info.get("isFinalized") not in false
                    or info.get("eventIsTruncated") not in false
                    or info.get("resultIsTruncated", False) not in false
                    or str(info.get("dropCount")) != "0"
                    or info.get("messages")
                    or not re.fullmatch(r"[0-9]+", str(info.get("resultCount")))
                    or not 1 <= int(info["resultCount"]) <= 2000
                ):
                    raise CaptureUnavailable()
                self._verify_metadata(principal, record, status, require_complete=True)
                result = self._call(
                    "GET",
                    "/services/search/v2/jobs/"
                    + quote(server_sid, safe="")
                    + "/results?count=2000&offset=0",
                )
                rows = result.get("results")
                if (
                    result.get("preview") not in false
                    or result.get("messages")
                    or not isinstance(rows, list)
                    or len(rows) != int(info["resultCount"])
                    or not all(isinstance(row, dict) for row in rows)
                ):
                    raise CaptureUnavailable()
                encoded = json.dumps(rows, allow_nan=False)
                if len(encoded.encode()) > 512 * 1024:
                    raise CaptureUnavailable()
            finally:
                if record.get("server_sid"):
                    self._finish(principal, record)
                elif record["state"] == "creating":
                    self._transition(principal, record, "creation_unknown")
            if self.clock() >= self.deadline or self.cleanup_remaining <= 0:
                raise CaptureUnavailable()
            self.memo[key] = encoded
            return json.loads(encoded)
        except Exception:
            raise CaptureUnavailable() from None
        finally:
            _slots.release()
