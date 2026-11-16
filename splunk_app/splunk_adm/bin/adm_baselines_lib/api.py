"""Transport-neutral baseline API; authentication and source trust belong to host.

The host supplies principal from authenticated server-side context, never request
content, rejects duplicate query/header keys before creating mappings, and enforces
transport security and CSRF protections. References must identify trusted, stable,
non-secret evidence that the store's configured callbacks can independently check.
"""

import json
import math
import re
from collections.abc import Mapping

from .store import Conflict, Forbidden, Invalid, NotFound, QuotaExceeded

_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_WATCH = r"[A-Za-z0-9_.~-]{1,128}"
_PATH = re.compile(
    rf"^/baselines/({_ID})(?:/(versions(?:/([1-9][0-9]{{0,9}}))?|watches(?:/({_WATCH})/(occurrences|evaluate))?|export|share))?$"
)
_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate field")
        result[key] = value
    return result


def _query(query, allowed):
    if not isinstance(query, Mapping) or set(query) - allowed:
        raise Invalid("invalid query")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in query.items()
    ):
        raise Invalid("invalid query")


def _number(value, default, minimum, maximum):
    if value is None:
        return default
    if len(value) > 10 or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise Invalid("invalid number")
    number = int(value)
    if not minimum <= number <= maximum:
        raise Invalid("invalid number")
    return number


def _now(value):
    if (
        not isinstance(value, str)
        or len(value) > 32
        or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value)
    ):
        raise Invalid("invalid time")
    number = float(value)
    if not math.isfinite(number):
        raise Invalid("invalid time")
    return number


def _exact(data, fields):
    if not isinstance(data, dict) or set(data) != set(fields):
        raise Invalid("unexpected or missing fields")


class BaselineAPI:
    """Return (HTTP status, JSON-compatible body or None, response headers).

    Mutations except maintenance require an idempotency key and, for existing
    baselines, an expected_revision. Purge is independently authorized by the
    store, returns 204 on every successful invocation, and requires a key too.
    """

    def __init__(self, store, *, max_body_bytes=128_000):
        if type(max_body_bytes) is not int or max_body_bytes < 1:
            raise ValueError("invalid body limit")
        self.store = store
        self.max_body_bytes = max_body_bytes

    @staticmethod
    def _response(status, body):
        return status, body, dict(_HEADERS)

    def handle(self, method, path, *, principal, query=None, headers=None, body=b""):
        try:
            return self._handle(method, path, principal, query, headers, body)
        except Invalid:
            return self._response(400, {"error": "invalid_request"})
        except Forbidden:
            return self._response(403, {"error": "forbidden"})
        except NotFound:
            return self._response(404, {"error": "not_found"})
        except Conflict:
            return self._response(409, {"error": "conflict"})
        except QuotaExceeded:
            return self._response(429, {"error": "quota_exceeded"})
        except Exception:
            return self._response(500, {"error": "internal_error"})

    def _handle(self, method, path, principal, query, headers, body):
        if (
            not isinstance(principal, str)
            or not principal
            or principal.strip() != principal
            or len(principal) > 256
            or any(0xD800 <= ord(c) <= 0xDFFF for c in principal)
        ):
            return self._response(401, {"error": "unauthenticated"})
        if (
            not isinstance(method, str)
            or not isinstance(path, str)
            or len(path) > 512
            or not isinstance(body, bytes)
        ):
            raise Invalid("invalid request")
        if len(body) > self.max_body_bytes:
            return self._response(413, {"error": "body_too_large"})
        headers = {} if headers is None else headers
        if not isinstance(headers, Mapping) or len(headers) > 100:
            raise Invalid("invalid headers")
        normalized = {}
        for key, value in headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or len(key) > 256
                or len(value) > 8192
                or key.lower() in normalized
            ):
                raise Invalid("invalid headers")
            normalized[key.lower()] = value
        query = {} if query is None else query
        match = _PATH.fullmatch(path)
        ident = resource = version = watch = watch_resource = None
        if path == "/baselines":
            allowed = {"GET", "POST"}
        elif path == "/baselines/purge":
            allowed = {"POST"}
        elif match:
            ident, resource, version, watch, watch_resource = match.groups()
            if resource is None:
                allowed = {"GET", "DELETE"}
            elif resource in ("versions", "watches"):
                allowed = {"GET", "POST"}
            elif resource in ("export",) or version is not None:
                allowed = {"GET"}
            elif watch_resource in ("occurrences", "evaluate"):
                allowed = {"GET", "POST"}
            else:
                allowed = {"POST"}
        else:
            return self._response(404, {"error": "not_found"})
        if method not in allowed:
            return self._response(405, {"error": "method_not_allowed"})

        if method == "GET":
            if body:
                raise Invalid("unexpected body")
            if path == "/baselines":
                _query(query, {"after", "limit"})
                result = self.store.list(
                    principal,
                    after=query.get("after", ""),
                    limit=_number(query.get("limit"), 50, 1, 100),
                )
            elif resource == "versions":
                _query(query, {"after", "limit"})
                result = self.store.list_versions(
                    principal,
                    ident,
                    after=_number(query.get("after"), 0, 0, 2_147_483_647),
                    limit=_number(query.get("limit"), 50, 1, 100),
                )
            elif version is not None:
                _query(query, set())
                result = self.store.get(
                    principal, ident, _number(version, None, 1, 2_147_483_647)
                )
            elif resource == "watches":
                _query(query, {"after", "limit"})
                result = self.store.list_watches(
                    principal,
                    ident,
                    after=query.get("after", ""),
                    limit=_number(query.get("limit"), 50, 1, 100),
                )
            elif watch_resource == "occurrences":
                _query(query, {"after", "limit"})
                result = self.store.occurrences(
                    principal,
                    ident,
                    watch,
                    after=_number(query.get("after"), 0, 0, 2_147_483_647),
                    limit=_number(query.get("limit"), 50, 1, 100),
                )
            elif watch_resource == "evaluate":
                _query(query, {"signature", "now"})
                if set(query) != {"signature", "now"}:
                    raise Invalid("missing query")
                result = self.store.evaluate(
                    principal, ident, watch, query["signature"], _now(query["now"])
                )
            else:
                _query(query, {"version"})
                selected = _number(query.get("version"), None, 1, 2_147_483_647)
                result = (
                    self.store.export(principal, ident, selected)
                    if resource == "export"
                    else self.store.get(principal, ident, selected)
                )
            return self._response(200, result)

        _query(query, set())
        request_id = normalized.get("idempotency-key")
        if (
            not isinstance(request_id, str)
            or not request_id
            or request_id.strip() != request_id
            or len(request_id) > 128
            or any(0xD800 <= ord(c) <= 0xDFFF for c in request_id)
        ):
            raise Invalid("invalid idempotency key")
        if (
            normalized.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            return self._response(415, {"error": "unsupported_media_type"})
        try:
            data = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(Invalid("invalid JSON")),
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise Invalid("invalid JSON") from exc
        if path == "/baselines/purge":
            _exact(data, set())
            self.store.purge_deleted_receipts(principal)
            return self._response(204, None)
        if path == "/baselines":
            _exact(data, {"name", "reference"})
            return self._response(
                201,
                self.store.create(
                    principal, request_id, data["name"], data["reference"]
                ),
            )
        if (
            not isinstance(data, dict)
            or type(data.get("expected_revision")) is not int
            or data["expected_revision"] < 1
        ):
            raise Invalid("invalid revision")
        revision = data["expected_revision"]
        if resource is None:
            _exact(data, {"expected_revision"})
            result = self.store.delete(principal, request_id, ident, revision)
        elif resource == "versions":
            _exact(data, {"expected_revision", "reference"})
            result = self.store.version(
                principal, request_id, ident, revision, data["reference"]
            )
        elif resource == "watches":
            _exact(data, {"expected_revision", "definition"})
            definition = data["definition"]
            if (
                not isinstance(definition, dict)
                or not isinstance(definition.get("id"), str)
                or not re.fullmatch(_WATCH, definition["id"])
            ):
                raise Invalid("invalid watch id")
            result = self.store.set_watch(
                principal, request_id, ident, revision, definition
            )
        elif watch_resource == "evaluate":
            _exact(data, {"expected_revision", "baseline_version", "reference"})
            result = self.store.evaluate_window(
                principal,
                request_id,
                ident,
                revision,
                watch,
                data["baseline_version"],
                data["reference"],
            )
        elif watch_resource == "occurrences":
            _exact(data, {"expected_revision", "signature", "reference"})
            result = self.store.append_occurrence(
                principal,
                request_id,
                ident,
                revision,
                watch,
                data["signature"],
                data["reference"],
            )
        else:
            _exact(data, {"expected_revision", "member", "grant"})
            result = self.store.share(
                principal, request_id, ident, revision, data["member"], data["grant"]
            )
        return self._response(200, result)
