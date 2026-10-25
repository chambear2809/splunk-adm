"""Command-line argument handling for the original generator entrypoint."""

from __future__ import annotations

import json
from pathlib import Path
from . import aci, common, networking, nxos


def main(description: str, argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--scenario",
        choices=("nxos", "aci", "aci-prev", "networking"),
        default="nxos",
        help="nxos: fixtures/raw/ (default); aci: the ACI pilot; aci-prev: derived prior window in dist/; networking: combined campus/Meraki scenario",
    )
    parser.add_argument(
        "--base-time",
        help="UTC ISO-8601 anchor for the combined networking scenario's window start",
    )
    parser.add_argument(
        "--output-dir",
        help="write generated files here instead of the scenario's fixtures/ directory (not supported for aci-prev)",
    )
    args = parser.parse_args(argv)
    scenario = args.scenario
    base_time = args.base_time
    out_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else None
    if scenario == "networking":
        return networking.main_networking(base_time, args.output_dir)
    if scenario == "aci":
        return aci.main_aci(out_dir or common.RAW_ACI)
    if scenario == "aci-prev":
        if out_dir:
            parser.error("--output-dir is not supported for aci-prev")
        return aci.main_aci_previous()
    out_dir = out_dir or common.RAW
    s = common.Scenario(json.loads((common.RAW / "scenario.json").read_text()))
    aci_stats, aci_class = nxos.aci(s)
    netflow, netflow_late = nxos.stream_netflow(s)
    (out_dir / "late").mkdir(parents=True, exist_ok=True)
    outputs = {
        "stream_netflow.ndjson": netflow,
        "late/stream_netflow.ndjson": netflow_late,
        "nd_flows.ndjson": nxos.nd_flows(s),
        "nd_endpoints.ndjson": nxos.nd_endpoints(s),
        "aci_stats.ndjson": aci_stats,
        "aci_class.ndjson": aci_class,
        "nexus9k.ndjson": nxos.nexus9k(s),
        "ftd_estreamer.ndjson": nxos.ftd(s),
        "isovalent.ndjson": nxos.isovalent(s),
        "kube_object_pods.ndjson": nxos.kube_pods(s),
        "otel_traces.ndjson": nxos.otel_traces(s),
    }
    for name, events in outputs.items():
        print(f"{name}: {common.write(name, events, out_dir)}")
    return 0
