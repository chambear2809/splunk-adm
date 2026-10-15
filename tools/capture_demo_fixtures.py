#!/usr/bin/env python3
"""Capture demo scope options from the initialized Splunk lab.

This intentionally runs the shipped macro against the lab; it never fabricates
rows. The lab lock/lifecycle is owned by the caller (normally ``lab_lock.py``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import with_lab_lock  # noqa: E402

MACRO = "| `adm_scope_options`"
FIELDS = ["environment", "cluster", "namespace", "service", "last_seen", "pods"]
MACRO_PATH = ROOT / "splunk_app/splunk_adm/default/macros.conf"


def macro_definition() -> str:
    text = MACRO_PATH.read_text(encoding="utf-8")
    match = re.search(r"\[adm_scope_options\]\n(?P<body>.*?)(?=\n\[|\Z)", text, re.S)
    if not match:
        raise RuntimeError("adm_scope_options macro is missing")
    return match.group("body").strip()


def capture(earliest: str, latest: str) -> dict:
    import sys

    sys.path.insert(0, str(ROOT / "tests" / "splunk"))
    import lab

    rows = lab.search(MACRO, earliest, latest)
    if not rows:
        raise RuntimeError("The initialized lab returned no scope options.")
    normalized = []
    for row in rows:
        if set(row) != set(FIELDS):
            raise RuntimeError(f"macro returned unexpected fields: {sorted(row)}")
        normalized.append({field: row[field] for field in FIELDS})
    macro_sha256 = hashlib.sha256(macro_definition().encode()).hexdigest()
    return {
        "search": MACRO,
        "earliest": earliest,
        "latest": latest,
        "provenance": {
            "source": "splunk_app/splunk_adm/default/macros.conf:adm_scope_options",
            "lookup": "adm_service_workload",
            "input_source": "fixtures/raw/scenario.json and initialized adm_service_workload lookup",
            "schema": FIELDS,
            "input_fields": [
                "service",
                "environment",
                "cluster",
                "namespace",
                "pod_uid",
                "last_seen",
            ],
            "macro_sha256": macro_sha256,
            "captured_at": int(time.time()),
            "method": "tests/splunk/lab.py search against initialized lab",
        },
        "rows": normalized,
    }


@with_lab_lock(root=ROOT)
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--earliest", default="0")
    parser.add_argument("--latest", default="now")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = capture(args.earliest, args.latest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
