"""Small, source-independent operator control for dependency watches."""

import json

from .store import Invalid

MAX_BODY = 4096
HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Invalid("duplicate field")
        result[key] = value
    return result


def _response(status, body):
    return status, body, dict(HEADERS)


def handle(method, path, *, query, headers, body, host, expected_principal):
    if method != "POST":
        return _response(405, {"error": "method_not_allowed"})
    if path != "/watch-management/disable":
        return _response(404, {"error": "not_found"})
    if query:
        raise Invalid("invalid query")
    if not isinstance(headers, dict):
        raise Invalid("invalid headers")
    if (
        headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        return _response(415, {"error": "unsupported_media_type"})
    if not isinstance(body, bytes):
        raise Invalid("invalid body")
    if len(body) > MAX_BODY:
        return _response(413, {"error": "body_too_large"})
    try:
        data = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid("invalid JSON")),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Invalid("invalid JSON") from exc
    if (
        not isinstance(data, dict)
        or set(data) != {"binding_id", "expected_revision"}
        or not isinstance(data["binding_id"], str)
        or not data["binding_id"]
        or len(data["binding_id"]) > 128
        or type(data["expected_revision"]) is not int
        or data["expected_revision"] < 1
    ):
        raise Invalid("invalid command")
    result = host.watch_manager(expected_principal=expected_principal).set_enabled(
        data["binding_id"], data["expected_revision"], False
    )
    return _response(200, result)
