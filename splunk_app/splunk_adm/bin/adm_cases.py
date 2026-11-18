"""Authenticated persistent handler; note storage is disabled by default."""

from pathlib import Path
import sys

from splunk.persistconn.application import PersistentServerConnectionApplication

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adm_cases_lib.request_supervisor import supervise  # noqa: E402


class CasesHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        super().__init__()

    def handle(self, in_string):
        return supervise(in_string)
