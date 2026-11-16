"""Authenticated persistent handler; note storage is disabled by default."""

import json
from pathlib import Path
import sys

from splunk.persistconn.application import PersistentServerConnectionApplication

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adm_cases_lib.splunk_host import SplunkHost, handle  # noqa: E402


class CasesHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
            token = request.get("session", {}).get("authtoken")
            status, payload, headers = handle(request, SplunkHost(token))
        except Exception:
            status, payload, headers = (
                503,
                {
                    "code": "unavailable",
                    "error": "Investigation storage is unavailable.",
                },
                {"Cache-Control": "no-store"},
            )
        return {"status": status, "payload": payload, "headers": headers}
