#!/usr/bin/env python3
"""Custom alert-action entrypoint. Accept an owner session through STDIN only."""

from __future__ import annotations

import configparser
import json
from pathlib import Path
import sys

BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(BIN / "lib"))
from adm_recovery_lib.core import Recovery, Settings, TARGET_WINDOWS  # noqa: E402
from adm_recovery_lib.rest import Rest  # noqa: E402


def main():
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
        rows = recovery.search(
            '| `adm_health_missed_slots` | where reason="missed_slot" | sort scheduled_time'
        )
        if not rows:
            print(
                json.dumps({"status": "noop", "reason": "no replayable detector rows"})
            )
            return 0
        target = rows[0]["name"]
    result = recovery.run(target)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("noop", "recovered") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # Avoid logging SDK exceptions or payloads containing session credentials.
        print(json.dumps({"status": "uncertain", "error_type": type(exc).__name__}))
        sys.exit(1)
