#!/usr/bin/env python3
"""Capture catalog and find demo fixtures from the initialized Splunk lab."""

from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import with_lab_lock  # noqa: E402

MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"
CATALOG_FIELDS = [
    "_key",
    "service",
    "environment",
    "cluster",
    "namespace",
    "pods",
    "first_seen",
    "last_seen",
    "peers",
    "conversations_1h",
    "blocked_1h",
    "unknown_peers_1h",
    "updated",
    "window_start",
    "window_end",
]
FIND_FIELDS = [
    "_key",
    "service",
    "environment",
    "cluster",
    "namespace",
    "pods",
    "last_seen",
]


def definitions() -> dict[str, str]:
    text = MACROS.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    pending = ["adm_catalog_build", "adm_find"]
    while pending:
        name = pending.pop()
        if name in out:
            continue
        match = re.search(
            rf"\[{re.escape(name)}(?:\([^]]+\))?\]\n(?P<body>.*?)(?=\n\[|\Z)",
            text,
            re.S,
        )
        if not match:
            raise RuntimeError(f"missing macro definition: {name}")
        out[name] = match.group("body").strip()
        pending.extend(re.findall(r"`(adm_[a-z_]+)(?:\(|`)", out[name]))
    return dict(sorted(out.items()))


def provenance(source: str, fields: list[str], earliest: str, latest: str) -> dict:
    defs = definitions()
    return {
        "source": source,
        "schema": fields,
        "input_fields": [
            "service",
            "environment",
            "cluster",
            "namespace",
            "pod_uid",
            "last_seen",
            "client_ip",
            "server_ip",
            "server_port",
            "transport",
        ],
        "collections": ["adm_service_workload", "adm_ip_identity"],
        "summary_index_macro": "adm_index_summary",
        "macro_sha256": hashlib.sha256(
            json.dumps(defs, sort_keys=True).encode()
        ).hexdigest(),
        "macro_definitions": {
            k: hashlib.sha256(v.encode()).hexdigest() for k, v in defs.items()
        },
        "raw_scenario": "fixtures/raw-aci/scenario.json",
        "method": "tests/splunk/lab.py search against initialized lab",
        "earliest": earliest,
        "latest": latest,
        "captured_at": int(time.time()),
    }


def validate_window(value: str) -> str:
    if not re.fullmatch(r"(?:0|[1-9]\d{0,11})", value) or int(value) > 253402300799:
        raise ValueError("window must be a bounded integer epoch")
    return value


def capture(earliest: str, latest: str, queries: list[str]) -> tuple[dict, dict]:
    earliest, latest = validate_window(earliest), validate_window(latest)
    if int(earliest) >= int(latest):
        raise ValueError("window start must be before end")
    if any(
        not re.fullmatch(r"[A-Za-z0-9:.][A-Za-z0-9._:/@-]{0,254}", q) for q in queries
    ):
        raise ValueError("find queries must be exact single-line values")
    sys.path.insert(0, str(ROOT / "tests" / "splunk"))
    import lab

    cat_search = "| `adm_catalog_build`"
    cat_rows = lab.search(cat_search, earliest, latest)
    if not cat_rows:
        raise RuntimeError("catalog capture returned no rows")
    cat = []
    for row in cat_rows:
        if set(row) != set(CATALOG_FIELDS):
            raise RuntimeError(f"catalog unexpected fields: {sorted(row)}")
        cat.append({field: row[field] for field in CATALOG_FIELDS})
    captured_queries = []
    for query in queries:
        search = f'| `adm_find("{query}")`'
        found = lab.search(search, earliest, latest)
        if not found:
            raise RuntimeError(f"find capture returned no rows for query {query!r}")
        rows = []
        for row in found:
            if set(row) != set(FIND_FIELDS):
                raise RuntimeError(f"find unexpected fields: {sorted(row)}")
            rows.append({field: row[field] for field in FIND_FIELDS})
        captured_queries.append({"query": query, "search": search, "rows": rows})
    return (
        {
            "search": cat_search,
            "earliest": earliest,
            "latest": latest,
            "provenance": provenance(
                "adm_catalog_build", CATALOG_FIELDS, earliest, latest
            ),
            "rows": cat,
        },
        {
            "earliest": earliest,
            "latest": latest,
            "provenance": provenance("adm_find", FIND_FIELDS, earliest, latest),
            "queries": captured_queries,
        },
    )


@with_lab_lock(root=ROOT)
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--earliest", required=True)
    parser.add_argument("--latest", required=True)
    parser.add_argument("--query", action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    catalog, found = capture(args.earliest, args.latest, args.query)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "demo-catalog.json").write_text(
        json.dumps(catalog, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "demo-find.json").write_text(
        json.dumps(found, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
