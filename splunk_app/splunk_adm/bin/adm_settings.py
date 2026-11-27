"""Authenticated Splunk persistent REST handler for deployment expectations."""

import json
from pathlib import Path
import sys
import time

from splunk.persistconn.application import PersistentServerConnectionApplication

# Splunk's persistent loader executes this file through importlib and does not
# add its directory to sys.path. Resolve only the shipped adjacent app library;
# never depend on the process working directory or a user-provided search path.
APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

from adm_log_lib import log_response  # noqa: E402
from adm_settings_lib import SettingsError  # noqa: E402
from adm_settings_lib.rest import SplunkStore, handle_request, source_ids  # noqa: E402


HANDLER = "adm_deployment_settings"
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


class SettingsHandler(PersistentServerConnectionApplication):
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
                        "error": "Invalid deployment settings request envelope.",
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
                        "error": "Deployment settings request exceeds maximum size.",
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
                        "error": "Invalid deployment settings request envelope.",
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
                        "error": "Deployment settings request exceeds maximum size.",
                    },
                ),
                started=started,
            )
        try:
            parsed = json.loads(in_string)
            if not isinstance(parsed, dict):
                raise SettingsError(
                    400, "invalid", "Invalid deployment settings request envelope."
                )
            request = parsed
            session = request.get("session")
            token = session.get("authtoken") if isinstance(session, dict) else None
            if not isinstance(token, str) or not token:
                raise SettingsError(401, "forbidden", "Authentication is required.")
            result = handle_request(request, SplunkStore(token), source_ids())
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
                        "error": "Deployment settings request nesting exceeds maximum depth.",
                    },
                ),
                started=started,
                request=request,
                error=exc,
            )
        except SettingsError as exc:
            return log_response(
                HANDLER,
                _response(exc.status, {"code": exc.code, "error": str(exc)}),
                started=started,
                request=request,
                error=exc,
            )
        except Exception as exc:
            # Never serialize exception details: Splunk exceptions may contain a
            # request, session token, or internal deployment details.
            return log_response(
                HANDLER,
                _response(
                    503,
                    {
                        "code": "unavailable",
                        "error": "Deployment settings are unavailable; verify permissions and persistence health.",
                    },
                ),
                started=started,
                request=request,
                error=exc,
            )
