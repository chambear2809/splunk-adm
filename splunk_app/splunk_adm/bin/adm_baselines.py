"""Authenticated baseline endpoint; persistence and source are disabled by default."""

import json
from pathlib import Path
import sys
import time

from splunk.persistconn.application import PersistentServerConnectionApplication

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adm_baselines_lib.splunk_host import SplunkHost, handle  # noqa: E402
from adm_log_lib import log_response  # noqa: E402

HANDLER = "adm_dependency_monitoring"
MAX_ENVELOPE_BYTES = 1024 * 1024
RESPONSE_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


class BaselinesHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        started = time.monotonic()
        request = error = None
        if not isinstance(in_string, (str, bytes)):
            return log_response(
                HANDLER,
                {
                    "status": 400,
                    "payload": {"error": "invalid_request"},
                    "headers": dict(RESPONSE_HEADERS),
                },
                started=started,
            )
        if len(in_string) > MAX_ENVELOPE_BYTES:
            return log_response(
                HANDLER,
                {
                    "status": 413,
                    "payload": {"error": "body_too_large"},
                    "headers": dict(RESPONSE_HEADERS),
                },
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
                {
                    "status": 400,
                    "payload": {"error": "invalid_request"},
                    "headers": dict(RESPONSE_HEADERS),
                },
                started=started,
                error=exc,
            )
        if len(raw) > MAX_ENVELOPE_BYTES:
            return log_response(
                HANDLER,
                {
                    "status": 413,
                    "payload": {"error": "body_too_large"},
                    "headers": dict(RESPONSE_HEADERS),
                },
                started=started,
            )
        try:
            parsed = json.loads(in_string)
            if not isinstance(parsed, dict):
                status, payload, headers = (
                    400,
                    {"error": "invalid_request"},
                    dict(RESPONSE_HEADERS),
                )
            else:
                request = parsed
                session = request.get("session")
                token = session.get("authtoken") if isinstance(session, dict) else None
                status, payload, raw_headers = handle(request, SplunkHost(token))
                reserved = {key.lower() for key in RESPONSE_HEADERS}
                headers = {}
                if isinstance(raw_headers, dict):
                    for key, value in raw_headers.items():
                        if isinstance(key, str) and key.lower() not in reserved:
                            headers[key] = value
                headers.update(RESPONSE_HEADERS)
        except RecursionError as exc:
            error = exc
            status, payload, headers = (
                400,
                {"error": "invalid_request"},
                dict(RESPONSE_HEADERS),
            )
        except Exception as exc:
            error = exc
            status, payload, headers = (
                503,
                {"error": "unavailable"},
                dict(RESPONSE_HEADERS),
            )
        return log_response(
            HANDLER,
            {"status": status, "payload": payload, "headers": headers},
            started=started,
            request=request,
            error=error,
        )
