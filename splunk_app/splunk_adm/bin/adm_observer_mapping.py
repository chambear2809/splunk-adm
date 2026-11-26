"""Administrator-only persistent handler for in-app observer mapping."""

from pathlib import Path
import json
import sys

from splunk.persistconn.application import PersistentServerConnectionApplication

APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

from adm_kv_lib.ledger import Invalid, LedgerError, Unavailable  # noqa: E402
from adm_observer_lib.rest import handle_request  # noqa: E402


class ObserverMappingHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
            token = request.get("session", {}).get("authtoken")
            if not isinstance(token, str) or not token:
                return {
                    "status": 401,
                    "payload": {
                        "code": "forbidden",
                        "error": "Authentication is required.",
                    },
                    "headers": {"Cache-Control": "no-store"},
                }
            result = handle_request(request, token)
            return {
                "status": 200,
                "payload": result,
                "headers": {"Cache-Control": "no-store"},
            }
        except (Invalid, Unavailable, LedgerError) as exc:
            status = getattr(exc, "status", 400 if isinstance(exc, Invalid) else 503)
            code = getattr(
                exc, "code", "invalid" if isinstance(exc, Invalid) else "unavailable"
            )
            return {
                "status": status,
                "payload": {"code": code, "error": str(exc)},
                "headers": {"Cache-Control": "no-store"},
            }
        except Exception:
            return {
                "status": 503,
                "payload": {
                    "code": "unavailable",
                    "error": "Observer mapping is unavailable; verify administrator permission and KV Store health.",
                },
                "headers": {"Cache-Control": "no-store"},
            }
