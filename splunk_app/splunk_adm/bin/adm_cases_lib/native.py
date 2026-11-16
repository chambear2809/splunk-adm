"""Small caller-owned search budget for explicit investigation captures.

The host creates one instance per HTTP request. No token, authorization result,
search job or source payload is cached across requests.
"""

import json
import re
import threading
import time
from urllib.parse import parse_qsl, quote, urlsplit

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


class NativeComparisonSearch:
    def __init__(self, token, *, request=None, clock=time.monotonic, sleep=time.sleep):
        self.token = token
        self.request = request or self._request
        self.clock, self.sleep = clock, sleep
        self.deadline = clock() + 25
        self.jobs = 0
        self.memo = {}
        self.principal = None
        self.identity_lock = threading.Lock()

    def _request(self, method, path, data, timeout):
        import splunk.rest

        target = urlsplit(path)
        if (
            target.scheme
            or target.netloc
            or not (
                target.path.startswith("/services/")
                or target.path.startswith("/servicesNS/")
            )
        ):
            raise CaptureUnavailable()
        query = dict(parse_qsl(target.query, strict_parsing=True))
        query["output_mode"] = "json"
        response, body = splunk.rest.simpleRequest(
            target.path,
            sessionKey=self.token,
            token=self.token.startswith("eyJ") and self.token.count(".") == 2,
            method=method,
            getargs=query,
            postargs=data,
            rawResult=True,
            raiseAllErrors=True,
            timeout=timeout,
        )
        if (
            not 200 <= int(response.status) < 300
            or not isinstance(body, (str, bytes))
            or len(body.encode("utf-8") if isinstance(body, str) else body)
            > 2 * 1024 * 1024
        ):
            raise CaptureUnavailable()
        return {} if method == "DELETE" else json.loads(body)

    def _call(self, method, path, data=None, *, cleanup=False, retain_job=False):
        remaining = 3 if cleanup else self.deadline - self.clock()
        if remaining <= 0:
            raise CaptureUnavailable()
        try:
            value = self.request(method, path, data, min(3, remaining))
            if not cleanup and not retain_job and self.clock() >= self.deadline:
                raise CaptureUnavailable()
            if not isinstance(value, dict):
                raise CaptureUnavailable()
            return value
        except Exception:
            raise CaptureUnavailable() from None

    def run(self, principal, query, start, end):
        # Only the trusted ComparisonSource constructs queries. This guard also
        # prevents accidentally turning a future caller into an arbitrary runner.
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
            # The same current caller may need the proof for admission and the
            # response in this request. Never reuse another request/owner's proof.
            return json.loads(self.memo[key])
        if self.jobs >= 3 or not _slots.acquire(blocking=False):
            raise CaptureUnavailable()
        sid = None
        try:
            self.jobs += 1
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
            sid = created.get("sid")
            if not isinstance(sid, str) or not re.fullmatch(
                r"[A-Za-z0-9_.:-]{1,255}", sid
            ):
                sid = None
                raise CaptureUnavailable()
            # Retain a successful creation response before checking elapsed
            # time, so a known late job is still deleted by finally below.
            if self.clock() >= self.deadline:
                raise CaptureUnavailable()
            path = "/services/search/v2/jobs/" + quote(sid, safe="")
            while True:
                status = self._call("GET", path)
                entries = status.get("entry")
                if not isinstance(entries, list) or len(entries) != 1:
                    raise CaptureUnavailable()
                if not isinstance(entries[0], dict):
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
            result = self._call("GET", path + "/results?count=2000&offset=0")
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
            # Cache only after native completion and successful cleanup below.
        finally:
            try:
                if sid is not None:
                    self._call(
                        "DELETE",
                        "/services/search/v2/jobs/" + quote(sid, safe=""),
                        cleanup=True,
                    )
            finally:
                _slots.release()
        self.memo[key] = encoded
        return json.loads(encoded)
