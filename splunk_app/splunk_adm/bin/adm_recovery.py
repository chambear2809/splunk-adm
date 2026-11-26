#!/usr/bin/env python3
"""Custom alert-action entrypoint. Accept an owner session through STDIN only."""

from __future__ import annotations

import configparser
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import sys
import time

BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(BIN / "lib"))
from adm_recovery_lib.core import Recovery, Settings, TARGET_WINDOWS  # noqa: E402
from adm_recovery_lib.rest import Rest  # noqa: E402
from adm_log_lib import log_outcome  # noqa: E402

HANDLER = "adm_recovery"


def _spl_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# The detector also reports V2 writers, which this action cannot replay.
DETECTOR_QUERY = (
    '| `adm_health_missed_slots` | where reason="missed_slot" '
    "| search name IN ("
    + ", ".join(_spl_string(name) for name in sorted(TARGET_WINDOWS))
    + ") | sort 0 scheduled_time"
)
MAX_DETECTOR_TIMESTAMP = 253402300799


def earliest_replayable(rows):
    """Return the earliest detector row this action can replay, if any."""
    candidates = []
    for row in rows:
        name = row.get("name")
        if name not in TARGET_WINDOWS:
            continue
        try:
            scheduled = Decimal(str(row.get("scheduled_time")))
        except InvalidOperation:
            continue
        if (
            not scheduled.is_finite()
            or scheduled <= 0
            or scheduled > MAX_DETECTOR_TIMESTAMP
            or scheduled != scheduled.to_integral_value()
        ):
            continue
        candidates.append((scheduled, name))
    return min(candidates)[1] if candidates else None


def main(started=None):
    started = time.monotonic() if started is None else started
    parser = configparser.RawConfigParser()
    parser.read(
        [
            BIN.parent / "default/adm_recovery.conf",
            BIN.parent / "local/adm_recovery.conf",
        ]
    )
    config = parser["recovery"]
    if not config.getboolean("enabled", fallback=False):
        print(json.dumps({"status": "refused", "reason": "recovery is not enabled"}))
        log_outcome(
            HANDLER,
            started=started,
            outcome="refused",
            code="recovery_disabled",
            exit_code=1,
        )
        return 1
    # Bounded input, never logged. No password or system-token fallback.
    payload = json.loads(sys.stdin.read(1024 * 1024))
    if payload.get("app") != "splunk_adm":
        raise ValueError("wrong action namespace")
    target = payload.get("result", {}).get("name")
    api = Rest(
        payload.get("session_key"),
        config.get("management_uri", "https://localhost:8089"),
        config.get("ca_file"),
    )
    settings = Settings(
        enabled=True,
        **{key: config.getint(key) for key in vars(Settings()) if key != "enabled"},
    )
    recovery = Recovery(api, settings)
    if target not in TARGET_WINDOWS:
        target = earliest_replayable(recovery.search(DETECTOR_QUERY))
        if target is None:
            print(
                json.dumps({"status": "noop", "reason": "no replayable detector rows"})
            )
            log_outcome(HANDLER, started=started, code="noop", exit_code=0)
            return 0
    result = recovery.run(target)
    print(json.dumps(result, sort_keys=True))
    exit_code = 0 if result["status"] in ("noop", "recovered") else 1
    log_outcome(HANDLER, started=started, code=result["status"], exit_code=exit_code)
    return exit_code


if __name__ == "__main__":
    STARTED = time.monotonic()
    try:
        sys.exit(main(STARTED))
    except Exception as exc:
        # Avoid logging SDK exceptions or payloads containing session credentials.
        print(json.dumps({"status": "uncertain", "error_type": type(exc).__name__}))
        log_outcome(HANDLER, started=STARTED, code="uncertain", error=exc, exit_code=1)
        sys.exit(1)
