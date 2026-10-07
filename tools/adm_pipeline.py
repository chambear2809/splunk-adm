#!/usr/bin/env python3
"""Generate one bounded ADM graph snapshot and optional local HEC NDJSON."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 20 * 1024 * 1024
sys.path.insert(0, str(ROOT / "src"))
from splunk_adm.projector import ProjectionError, project, parse_time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("spans", "inventory", "flows", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--hec-output", type=Path)
    parser.add_argument("--boundary-id", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    try:
        def load(path):
            if path.stat().st_size > MAX_INPUT_BYTES: raise ProjectionError(f"input exceeds limit {MAX_INPUT_BYTES} bytes: {path}")
            return json.loads(path.read_text())
        snapshot = project(spans_document=load(args.spans), inventory_document=load(args.inventory), flows_document=load(args.flows), boundary_id=args.boundary_id, service=args.service, environment=args.environment, cluster=args.cluster, namespace=args.namespace, start=args.start, end=args.end, demo=args.demo)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
        if args.hec_output:
            epoch = parse_time(args.end).timestamp()
            args.hec_output.parent.mkdir(parents=True, exist_ok=True)
            args.hec_output.write_text(json.dumps({"time": epoch, "sourcetype": "adm:graph", "event": snapshot}, sort_keys=True) + "\n")
    except (OSError, json.JSONDecodeError, ProjectionError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
