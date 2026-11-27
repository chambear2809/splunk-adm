"""Authenticated persistent handler for shared saved views and ownership."""

from pathlib import Path
import json
import sys
import time

from splunk.persistconn.application import PersistentServerConnectionApplication

APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

from adm_collaboration_lib.rest import error_body, handle_request  # noqa: E402
from adm_kv_lib.ledger import LedgerError  # noqa: E402
from adm_log_lib import log_response  # noqa: E402

HANDLER = "adm_collaboration"
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


class CollaborationHandler(PersistentServerConnectionApplication):
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
                        "error": "Invalid collaboration request envelope.",
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
                        "error": "Collaboration request exceeds maximum size.",
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
                        "error": "Invalid collaboration request envelope.",
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
                        "error": "Collaboration request exceeds maximum size.",
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
                            "error": "Invalid collaboration request envelope.",
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
                        "error": "Collaboration request nesting exceeds maximum depth.",
                    },
                ),
                started=started,
                request=request,
                error=exc,
            )
        except LedgerError as exc:
            status, payload = error_body(exc)
            return log_response(
                HANDLER,
                _response(status, payload),
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
                        "error": "Collaboration records are unavailable; verify permissions and persistence health.",
                    },
                ),
                started=started,
                request=request,
                error=exc,
            )
