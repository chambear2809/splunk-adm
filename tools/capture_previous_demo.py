#!/usr/bin/env python3
"""Capture the preceding ACI graph window from an initialized lab.

The optional ``--initialize`` path loads only the generated preceding batch by
temporarily narrowing ``AciDataLayerTest.BATCHES``. It never starts or stops
Splunk; callers own the lab lifecycle and this command only holds the lab lock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREVIOUS_RAW = ROOT / "dist" / "phase8-raw-aci-prev"
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"
ARGS = {
    "service": "frontend",
    "environment": "demo",
    "cluster": "demo-cluster",
    "namespace": "shop",
}

sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import with_lab_lock  # noqa: E402


def macro_definition() -> str:
    text = MACROS.read_text(encoding="utf-8")
    match = re.search(r"\[adm_graph\(4\)\]\n(?P<body>.*?)(?=\n\[|\Z)", text, re.S)
    if not match:
        raise RuntimeError("adm_graph macro is missing")
    return match.group("body").strip()


def source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def initialize_previous_batch() -> None:
    paths = sorted(PREVIOUS_RAW.glob("*.ndjson"))
    if not paths:
        raise RuntimeError("previous raw fixtures are missing; generate aci-prev first")
    sys.path.insert(0, str(ROOT / "tests" / "splunk"))
    import test_aci

    batches = test_aci.BATCHES
    test_aci.BATCHES = [("previous", lambda: paths)]
    try:
        test_aci.AciDataLayerTest.setUpClass()
    finally:
        test_aci.BATCHES = batches


def capture(earliest: str, latest: str, initialize: bool = False) -> dict:
    if not re.fullmatch(r"\d{1,12}", earliest) or not re.fullmatch(r"\d{1,12}", latest):
        raise ValueError("window must be bounded integer epochs")
    if int(earliest) >= int(latest):
        raise ValueError("window start must be before end")
    if initialize:
        initialize_previous_batch()
    sys.path.insert(0, str(ROOT / "tests" / "splunk"))
    import lab

    call = ",".join(
        json.dumps(ARGS[key])
        for key in ("service", "environment", "cluster", "namespace")
    )
    search = f"`adm_graph({call})`"
    rows = lab.search(search, earliest, latest)
    if not rows:
        raise RuntimeError("previous graph capture returned no rows")
    row_types = {row.get("row_type") for row in rows if isinstance(row, dict)}
    if any(
        not isinstance(row, dict) or row.get("row_type") not in {"node", "edge", "meta"}
        for row in rows
    ):
        raise RuntimeError("previous graph capture returned an unexpected row shape")
    if not {"node", "edge"} <= row_types or "meta" not in row_types:
        raise RuntimeError("previous graph capture is missing node, edge, or meta rows")
    fields = sorted({field for row in rows for field in row})
    macro = macro_definition()
    return {
        "description": "Captured ACI graph for the preceding 15-minute demo window.",
        "search": search,
        "earliest": earliest,
        "latest": latest,
        "args": ARGS,
        "provenance": {
            "source": "splunk_app/splunk_adm/default/macros.conf:adm_graph",
            "schema": fields,
            "macro_sha256": hashlib.sha256(macro.encode()).hexdigest(),
            "macro_file_sha256": source_hash(MACROS),
            "generator_sha256": source_hash(ROOT / "tools/gen_raw_fixtures.py"),
            "scenario_sha256": source_hash(ROOT / "fixtures/raw-aci/scenario.json"),
            "raw_scenario": "dist/phase8-raw-aci-prev (derived from fixtures/raw-aci/scenario.json)",
            "method": "tests/splunk/lab.py search against initialized lab",
            "captured_at": int(time.time()),
        },
        "rows": rows,
    }


@with_lab_lock(root=ROOT)
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--earliest", default="1791372600")
    parser.add_argument("--latest", default="1791373500")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "fixtures" / "demo-rows-aci-prev.json"
    )
    parser.add_argument("--initialize", action="store_true")
    args = parser.parse_args()
    payload = capture(args.earliest, args.latest, args.initialize)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
