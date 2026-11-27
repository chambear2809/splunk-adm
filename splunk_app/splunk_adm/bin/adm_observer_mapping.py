"""Administrator-only persistent handler for in-app observer mapping."""

from pathlib import Path
import json
import sys
import time

from splunk.persistconn.application import PersistentServerConnectionApplication

APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

from adm_kv_lib.ledger import Invalid, LedgerError, Unavailable  # noqa: E402
from adm_observer_lib.rest import handle_request  # noqa: E402
from adm_log_lib import log_response  # noqa: E402

HANDLER = "adm_observer_mapping"
MAX_ENVELOPE_BYTES = 256 * 1024
RESPONSE_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _response(status, payload):
    return {
        "status": status,
        "payload": payload,
        "headers": dict(RESPONSE_HEADERS),
    }


class ObserverMappingHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        started = time.monotonic()
        request = None
        if not isinstance(in_string, (str, bytes)):
            return log_response(
                HANDLER,
                _response(
                    400,
                    {
                        "code": "invalid",
                        "error": "Invalid observer mapping request envelope.",
                    },
                ),
                started=started,
            )
        if len(in_string) > MAX_ENVELOPE_BYTES:
            return log_response(
                HANDLER,
                _response(
                    413,
                    {
                        "code": "body_too_large",
                        "error": "Observer mapping request exceeds maximum size.",
                    },
                ),
                started=started,
            )
        try:
            if isinstance(in_string, str):
                raw = in_string.encode("utf-8")
            else:
                in_string.decode("utf-8")
                raw = in_string
        except UnicodeError as exc:
            return log_response(
                HANDLER,
                _response(
                    400,
                    {
                        "code": "invalid",
                        "error": "Invalid observer mapping request envelope.",
                    },
                ),
                started=started,
                error=exc,
            )
        if len(raw) > MAX_ENVELOPE_BYTES:
            return log_response(
                HANDLER,
                _response(
                    413,
                    {
                        "code": "body_too_large",
                        "error": "Observer mapping request exceeds maximum size.",
                    },
                ),
                started=started,
            )
        try:
            parsed = json.loads(in_string)
            if not isinstance(parsed, dict):
                return log_response(
                    HANDLER,
                    _response(
                        400,
                        {
                            "code": "invalid",
                            "error": "Invalid observer mapping request envelope.",
                        },
                    ),
                    started=started,
                )
            request = parsed
            session = request.get("session")
            token = session.get("authtoken") if isinstance(session, dict) else None
            if not isinstance(token, str) or not token:
                return log_response(
                    HANDLER,
                    _response(
                        401,
                        {
                            "code": "forbidden",
                            "error": "Authentication is required.",
                        },
                    ),
                    started=started,
                    request=request,
                )
            result = handle_request(request, token)
            return log_response(
                HANDLER,
                _response(200, result),
                started=started,
                request=request,
            )
        except RecursionError as exc:
            return log_response(
                HANDLER,
                _response(
                    400,
                    {
                        "code": "invalid",
                        "error": "Observer mapping request nesting exceeds maximum depth.",
                    },
                ),
                started=started,
                request=request,
                error=exc,
            )
        except (Invalid, Unavailable, LedgerError) as exc:
            status = getattr(exc, "status", 400 if isinstance(exc, Invalid) else 503)
            code = getattr(
                exc, "code", "invalid" if isinstance(exc, Invalid) else "unavailable"
            )
            return log_response(
                HANDLER,
                _response(status, {"code": code, "error": str(exc)}),
                started=started,
                request=request,
                error=exc,
            )
        except Exception as exc:
            return log_response(
                HANDLER,
                _response(
                    503,
                    {
                        "code": "unavailable",
                        "error": "Observer mapping is unavailable; verify administrator permission and KV Store health.",
                    },
                ),
                started=started,
                request=request,
                error=exc,
            )
