"""Framework-neutral case HTTP adapter.

The host must supply ``principal`` from its authenticated server-side context,
never from request data, and must enforce transport and CSRF protections. It must
also pass the raw request body and query parameters without collapsing duplicates.
For protected evidence the optional source validator must independently verify
that the authenticated principal may access the specific source and that the
submitted evidence is bound to that source; request assertions are not authority.
"""

import json
import re
from collections.abc import Mapping

from .store import Conflict, Forbidden, Invalid, NotFound, QuotaExceeded

_CASE_PATH = re.compile(
    r"^/cases/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/(entries|captures|attachments|share|export|audit))?$"
)
_RESERVED = frozenset(
    (
        "entitlement",
        "entitlements",
        "permission",
        "permissions",
        "authorized",
        "authorization",
    )
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
            raise Invalid("duplicate JSON field")
        result[key] = value
    return result


def _reserved(value):
    if isinstance(value, dict):
        return any(
            key.lower() in _RESERVED or _reserved(child) for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_reserved(child) for child in value)
    return False


def _query(query, allowed):
    if not isinstance(query, Mapping) or set(query) - allowed:
        raise Invalid("invalid query")
    if any(not isinstance(value, str) for value in query.values()):
        raise Invalid("invalid query")
    return query


def _number(value, default, minimum, maximum):
    if value is None:
        return default
    if not re.fullmatch(r"0|[1-9][0-9]*", value) or len(value) > 10:
        raise Invalid("invalid pagination")
    number = int(value)
    if not minimum <= number <= maximum:
        raise Invalid("invalid pagination")
    return number


class CaseAPI:
    """Return ``(status, JSON-compatible body, headers)`` for an HTTP request.

    ``source_validator(principal, case_id, kind, item)`` must return exactly True
    for every capture or attachment. It is called on retries too. All inputs other
    than principal are untrusted. Query and headers must be mappings with single
    string values; hosts must reject duplicate query/header keys before calling.
    """

    def __init__(self, store, *, source_validator=None, max_body_bytes=128_000):
        if source_validator is not None and not callable(source_validator):
            raise ValueError("invalid source validator")
        if type(max_body_bytes) is not int or max_body_bytes < 1:
            raise ValueError("invalid body limit")
        self.store = store
        self.source_validator = source_validator
        self.max_body_bytes = max_body_bytes

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

    @staticmethod
    def _response(status, payload):
        return status, payload, dict(_HEADERS)

    def _handle(self, method, path, principal, query, headers, body):
        if (
            not isinstance(principal, str)
            or not principal.strip()
            or len(principal) > 256
        ):
            return self._response(401, {"error": "unauthenticated"})
        if not isinstance(method, str) or not isinstance(path, str):
            raise Invalid("invalid request")
        if not isinstance(body, bytes):
            raise Invalid("invalid body")
        if len(body) > self.max_body_bytes:
            return self._response(413, {"error": "body_too_large"})
        if headers is None:
            headers = {}
        if not isinstance(headers, Mapping):
            raise Invalid("invalid headers")
        normalized = {}
        for key, value in headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or key.lower() in normalized
            ):
                raise Invalid("invalid headers")
            normalized[key.lower()] = value
        query = {} if query is None else query
        match = _CASE_PATH.fullmatch(path)
        if path == "/cases":
            allowed = {"GET", "POST"}
            case_id, resource = None, None
        elif match:
            case_id, resource = match.groups()
            allowed = (
                {"GET", "DELETE"}
                if resource is None
                else ({"GET"} if resource in ("audit", "export") else {"POST"})
            )
        else:
            return self._response(404, {"error": "not_found"})
        if method not in allowed:
            return self._response(405, {"error": "method_not_allowed"})

        if method == "GET":
            if body:
                raise Invalid("unexpected body")
            if path == "/cases":
                _query(query, {"after", "limit"})
                result = self.store.list_cases(
                    principal,
                    after=query.get("after", ""),
                    limit=_number(query.get("limit"), 50, 1, 100),
                )
            elif resource == "audit":
                _query(query, {"after", "limit"})
                result = self.store.audit(
                    principal,
                    case_id,
                    after=_number(query.get("after"), 0, 0, 2_147_483_647),
                    limit=_number(query.get("limit"), 100, 1, 100),
                )
            else:
                _query(query, set())
                result = (
                    self.store.export(principal, case_id)
                    if resource == "export"
                    else self.store.get(principal, case_id)
                )
            return self._response(200, result)

        _query(query, set())
        request_id = normalized.get("idempotency-key")
        if (
            not isinstance(request_id, str)
            or not request_id.strip()
            or len(request_id) > 128
        ):
            raise Invalid("missing idempotency key")
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
        if not isinstance(data, dict) or _reserved(data):
            raise Invalid("invalid data")
        if path == "/cases":
            return self._response(201, self.store.create(principal, request_id, data))
        if (
            type(data.get("expected_revision")) is not int
            or data["expected_revision"] < 1
        ):
            raise Invalid("invalid revision")
        if resource is None:
            if set(data) != {"expected_revision"}:
                raise Invalid("invalid data")
            return self._response(
                200,
                self.store.delete(
                    principal, request_id, case_id, data["expected_revision"]
                ),
            )
        if resource == "share":
            if set(data) != {"expected_revision", "member", "grant"}:
                raise Invalid("invalid data")
            return self._response(
                200,
                self.store.share(
                    principal,
                    request_id,
                    case_id,
                    data["expected_revision"],
                    data["member"],
                    data["grant"],
                ),
            )
        if set(data) != {"expected_revision", "item"}:
            raise Invalid("invalid data")
        kind = {"entries": "entry", "captures": "capture", "attachments": "attachment"}[
            resource
        ]
        if kind != "entry":
            # Check case access before consulting the trusted evidence validator.
            self.store.get(principal, case_id)
            try:
                valid = (
                    self.source_validator is not None
                    and self.source_validator(principal, case_id, kind, data["item"])
                    is True
                )
            except Exception:
                valid = False
            if not valid:
                raise Forbidden("source not authorized")
        return self._response(
            200,
            self.store.append(
                principal,
                request_id,
                case_id,
                data["expected_revision"],
                kind,
                data["item"],
            ),
        )
