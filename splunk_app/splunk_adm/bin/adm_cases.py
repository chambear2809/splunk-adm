"""Authenticated persistent handler; note storage is disabled by default."""

from pathlib import Path
import sys
import time

from splunk.persistconn.application import PersistentServerConnectionApplication

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adm_cases_lib.request_supervisor import supervise  # noqa: E402
from adm_log_lib import log_outcome, log_response  # noqa: E402

HANDLER = "adm_investigations"


class CasesHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        # Log only here, in the parent: the request child's stderr is discarded
        # and the body is not parsed before the child validates it.
        started = time.monotonic()
        try:
            response = supervise(in_string)
        except Exception as exc:
            log_outcome(HANDLER, started=started, status=503, error=exc)
            raise
        return log_response(HANDLER, response, started=started)
