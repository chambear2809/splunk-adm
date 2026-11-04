#!/usr/bin/env python3
"""Caller-scoped, opt-in reader for quarantined ACI poll context."""

from __future__ import annotations

import configparser
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lib"))

from adm_identity_lib.search import NativeSearch, SearchError  # noqa: E402
from adm_aci_lib.reader import query, read_rows, read_fabric_snapshot  # noqa: E402
from adm_aci_lib.config import context_rows, load_bindings  # noqa: E402
from adm_aci_lib.context import resolve_context  # noqa: E402
from admqualified import AdmQualified  # noqa: E402
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch  # noqa: E402


@Configuration(type="events", streaming=False)
class AdmAciPoll(GeneratingCommand):
    start = Option(require=False)
    as_of = Option(require=False)
    mode = Option(require=False)

    def generate(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read(
            [
                str(ROOT.parent / "default" / "adm_aci_poll.conf"),
                str(ROOT.parent / "local" / "adm_aci_poll.conf"),
            ]
        )
        profile = dict(config["profile"]) if config.has_section("profile") else {}
        profile["enabled"] = str(profile.get("enabled", "false")).lower() in (
            "true",
            "1",
        )
        mode = (self.mode or "attachment").lower()
        if mode not in ("attachment", "fabric"):
            raise SearchError("Invalid ACI poll mode.")
        bindings = None if mode == "fabric" else load_bindings(ROOT.parent, profile)
        now = time.time()
        as_of = self.as_of if self.as_of is not None else now - 15
        try:
            start = self.start if self.start is not None else float(as_of) - 300
        except (ValueError, TypeError, OverflowError):
            raise SearchError("Invalid ACI poll time bounds.") from None
        search = query(profile, start, as_of, now)
        token = self.metadata.searchinfo.session_key
        if not isinstance(token, str) or not token:
            raise SearchError("Caller session key is unavailable.")
        rows = NativeSearch(
            lambda method, path, data=None: AdmQualified._request(
                self, token, method, path, data
            )
        ).run(search)
        output = (
            read_fabric_snapshot(rows, profile, start, as_of, now)
            if mode == "fabric"
            else (
                list(
                    context_rows(
                        resolve_context(
                            rows, profile, bindings, start=start, as_of=as_of, now=now
                        )
                    )
                )
                if bindings is not None
                else read_rows(rows, profile, start, as_of, now)
            )
        )
        fields = sorted({key for row in output for key in row})
        for row in output:
            yield {key: row.get(key) for key in fields}


if __name__ == "__main__":
    dispatch(AdmAciPoll, sys.argv, sys.stdin, sys.stdout, __name__)
