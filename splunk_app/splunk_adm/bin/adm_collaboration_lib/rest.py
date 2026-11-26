"""Authenticated collaboration REST adapter. Caller identity comes from Splunk."""

import json

from adm_kv_lib.ledger import (
    Forbidden,
    Invalid,
    LedgerError,
    RecordLedger,
    Unavailable,
)
from adm_kv_lib.store import SplunkCollectionStore

from .payload import PayloadError, merge_views, validate

COLLECTIONS = {"views": "adm_saved_views", "ownership": "adm_business_ownership"}
MAX_BODY_BYTES = 32 * 1024


def principal_of(store):
    import splunk.rest

    response, data = splunk.rest.simpleRequest(
        "/services/authentication/current-context?output_mode=json",
        sessionKey=store.session_key,
        method="GET",
        rawResult=True,
        raiseAllErrors=True,
    )
    if int(response.status) >= 300:
        raise Unavailable("Caller identity is unavailable.")
    payload = json.loads(data)
    entries = payload.get("entry") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        raise Unavailable("Caller identity is unavailable.")
    content = entries[0].get("content")
    name = content.get("username") if isinstance(content, dict) else None
    caps = content.get("capabilities") if isinstance(content, dict) else None
    if not isinstance(name, str) or not name or name == "nobody":
        raise Unavailable("Caller identity is unavailable.")
    if not isinstance(caps, list) or "adm_investigate" not in caps:
        raise Forbidden("Investigation permission is required.")
    return name


def handle_request(request, token):
    method = request.get("method", "").upper()
    if method not in ("GET", "POST"):
        raise Invalid("Only GET and POST are supported.")
    query = request.get("query", [])
    kind = None
    if isinstance(query, list):
        for pair in query:
            if isinstance(pair, list) and len(pair) == 2 and pair[0] == "kind":
                if kind is not None:
                    raise Invalid("Duplicate collaboration kind.")
                kind = pair[1]
    if kind not in COLLECTIONS:
        raise Invalid("Unsupported collaboration kind.")
    store = SplunkCollectionStore(token, COLLECTIONS[kind])
    ledger = RecordLedger(store, kind)
    principal = principal_of(store)
    if method == "GET":
        return visible_result(kind, ledger.read(), principal)
    raw = request.get("payload", "")
    if isinstance(raw, dict):
        body = raw
        encoded = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > MAX_BODY_BYTES:
            raise Invalid("Collaboration payload exceeds 32 KiB.")
    else:
        if not isinstance(raw, str) or not raw:
            raise Invalid("Invalid collaboration payload.")
        if len(raw.encode()) > MAX_BODY_BYTES:
            raise Invalid("Collaboration payload exceeds 32 KiB.")
        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise Invalid("Invalid collaboration payload.") from exc
    if not isinstance(body, dict):
        raise Invalid("Invalid collaboration payload.")
    payload = body.get("payload")
    expected = body.get("expectedRevision")
    request_id = body.get("requestId")
    try:
        submitted = validate(kind, payload, principal)
        if kind == "views":
            current = ledger.read().get("payload") or {"views": []}
            document = merge_views(
                current.get("views") or [], submitted["views"], principal
            )
        else:
            document = submitted
    except PayloadError as exc:
        raise Invalid(str(exc)) from exc
    return visible_result(kind, ledger.write(document, expected, request_id), principal)


def visible_result(kind, result, principal):
    payload = result.get("payload")
    if (
        kind != "views"
        or not isinstance(payload, dict)
        or not isinstance(payload.get("views"), list)
    ):
        return result
    return {
        **result,
        "payload": {
            "views": [
                row
                for row in payload["views"]
                if isinstance(row, dict)
                and (row.get("visibility") == "shared" or row.get("owner") == principal)
            ]
        },
    }


def error_body(exc):
    if isinstance(exc, LedgerError):
        return exc.status, {"code": exc.code, "error": str(exc)}
    if isinstance(exc, PayloadError):
        return 400, {"code": "invalid", "error": str(exc)}
    return 503, {
        "code": "unavailable",
        "error": "Collaboration records are unavailable; verify permissions and persistence health.",
    }
