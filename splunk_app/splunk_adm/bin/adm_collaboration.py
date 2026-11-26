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


class CollaborationHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        started = time.monotonic()
        request = None
        try:
            request = json.loads(in_string)
            token = request.get("session", {}).get("authtoken")
            if not isinstance(token, str) or not token:
                return log_response(
                    HANDLER,
                    {
                        "status": 401,
                        "payload": {
                            "code": "forbidden",
                            "error": "Authentication is required.",
                        },
                        "headers": {"Cache-Control": "no-store"},
                    },
                    started=started,
                    request=request,
                )
            result = handle_request(request, token)
            return log_response(
                HANDLER,
                {
                    "status": 200,
                    "payload": result,
                    "headers": {"Cache-Control": "no-store"},
                },
                started=started,
                request=request,
            )
        except LedgerError as exc:
            status, payload = error_body(exc)
            return log_response(
                HANDLER,
                {
                    "status": status,
                    "payload": payload,
                    "headers": {"Cache-Control": "no-store"},
                },
                started=started,
                request=request,
                error=exc,
            )
        except Exception as exc:
            return log_response(
                HANDLER,
                {
                    "status": 503,
                    "payload": {
                        "code": "unavailable",
                        "error": "Collaboration records are unavailable; verify permissions and persistence health.",
                    },
                    "headers": {"Cache-Control": "no-store"},
                },
                started=started,
                request=request,
                error=exc,
            )
