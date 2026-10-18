"""Authenticated Splunk persistent REST handler for deployment expectations."""

import json
from pathlib import Path
import sys

from splunk.persistconn.application import PersistentServerConnectionApplication

# Splunk's persistent loader executes this file through importlib and does not
# add its directory to sys.path. Resolve only the shipped adjacent app library;
# never depend on the process working directory or a user-provided search path.
APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

from adm_settings_lib import SettingsError  # noqa: E402
from adm_settings_lib.rest import SplunkStore, handle_request, source_ids  # noqa: E402


class SettingsHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
            token = request.get("session", {}).get("authtoken")
            if not isinstance(token, str) or not token:
                raise SettingsError(401, "forbidden", "Authentication is required.")
            result = handle_request(request, SplunkStore(token), source_ids())
            return {
                "status": 200,
                "payload": result,
                "headers": {"Cache-Control": "no-store"},
            }
        except SettingsError as exc:
            return {
                "status": exc.status,
                "payload": {"code": exc.code, "error": str(exc)},
                "headers": {"Cache-Control": "no-store"},
            }
        except Exception:
            # Never serialize exception details: Splunk exceptions may contain a
            # request, session token, or internal deployment details.
            return {
                "status": 503,
                "payload": {
                    "code": "unavailable",
                    "error": "Deployment settings are unavailable; verify permissions and persistence health.",
                },
                "headers": {"Cache-Control": "no-store"},
            }
