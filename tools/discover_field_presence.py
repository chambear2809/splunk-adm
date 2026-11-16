#!/usr/bin/env python3
"""Review-only fixed, bounded field-presence probes for two source contracts."""

from __future__ import annotations

import argparse
import json
import re
import signal
import sys
import time
from pathlib import Path
from urllib.parse import quote

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.discover_feature_sources import Client, Refused, cloud_client, indexes

POD_PATHS = {
    "pod_uid": ("object.metadata.uid", "metadata.uid"),
    "owner_kind": (
        "object.metadata.ownerReferences{}.kind",
        "metadata.ownerReferences{}.kind",
    ),
    "owner_name": (
        "object.metadata.ownerReferences{}.name",
        "metadata.ownerReferences{}.name",
    ),
    "owner_uid": (
        "object.metadata.ownerReferences{}.uid",
        "metadata.ownerReferences{}.uid",
    ),
    "ready_condition_type": (
        "object.status.conditions{}.type",
        "status.conditions{}.type",
    ),
    "ready_condition_status": (
        "object.status.conditions{}.status",
        "status.conditions{}.status",
    ),
    "pod_ips": ("object.status.podIPs{}.ip", "status.podIPs{}.ip"),
    "node_name": ("object.spec.nodeName", "spec.nodeName"),
}
HUBBLE_PATHS = {
    "source_pod": ("flow.source.pod_name",),
    "source_namespace": ("flow.source.namespace",),
    "destination_pod": ("flow.destination.pod_name",),
    "destination_namespace": ("flow.destination.namespace",),
    "source_ip": ("flow.IP.source",),
    "destination_ip": ("flow.IP.destination",),
    "source_port": (
        "flow.l4.TCP.source_port",
        "flow.l4.UDP.source_port",
        "flow.l4.SCTP.source_port",
    ),
    "destination_port": (
        "flow.l4.TCP.destination_port",
        "flow.l4.UDP.destination_port",
        "flow.l4.SCTP.destination_port",
    ),
    "source_workload_name": ("flow.source.workloads{}.name",),
    "source_workload_kind": ("flow.source.workloads{}.kind",),
    "destination_workload_name": ("flow.destination.workloads{}.name",),
    "destination_workload_kind": ("flow.destination.workloads{}.kind",),
    "flow_time": ("flow.time",),
    "verdict": ("flow.verdict",),
    "node_name": ("flow.node_name", "node_name"),
}
SPECS = {
    "hubble": ("adm_index_hubble", "cilium:hubble:flow", HUBBLE_PATHS),
    "pods": ("adm_index_k8s", "kube:object:pods", POD_PATHS),
}


def query_for(family: str, index: str) -> str:
    if family not in SPECS or not re.fullmatch(
        r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", index
    ):
        raise Refused("invalid_query_inputs")
    _, sourcetype, paths = SPECS[family]
    expressions = []
    sums = []
    for name, alternatives in paths.items():
        lookups = ",".join(f'spath(_raw,"{path}")' for path in alternatives)
        value = (
            f"mvindex(coalesce({lookups}),0)"
            if len(alternatives) > 1
            else f"mvindex({lookups},0)"
        )
        expressions.extend(
            (
                f"{name}_present=if(isnotnull({value}),1,0)",
                f"{name}_numeric=if(isnum({value}),1,0)",
                f"{name}_string=if(isstr({value}),1,0)",
            )
        )
        sums.extend(
            f"sum({name}_{kind}) AS {name}_{kind}"
            for kind in ("present", "numeric", "string")
        )
    # The condition type itself may contain multiple conditions; do not assume the first is Ready.
    if family == "pods":
        types = 'coalesce(spath(_raw,"object.status.conditions{}.type"),spath(_raw,"status.conditions{}.type"))'
        expressions.append(
            f'ready_type_found=if(isnotnull(mvfind({types},"^Ready$")),1,0)'
        )
        sums.append("sum(ready_type_found) AS ready_type_found")
    return (
        f'search index="{index}" sourcetype="{sourcetype}" | head 16 | eval '
        + ", ".join(expressions)
        + " | stats count AS sample_count "
        + " ".join(sums)
    )


def probe(client: Client, family: str, index: str, end: int) -> dict:
    query = query_for(family, index)
    expected = {
        f"{name}_{kind}"
        for name in SPECS[family][2]
        for kind in ("present", "numeric", "string")
    }
    if family == "pods":
        expected.add("ready_type_found")
    output = {
        "status": "error",
        "cleanup": "unconfirmed",
        "family": family,
        "earliest": end - 900,
        "latest": end,
    }
    sid = None
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise Refused("active_timer")

    def expired(_signum, _frame):
        raise Refused("deadline")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 35)
    deadline = time.monotonic() + 35
    try:
        created = client.call(
            "POST",
            "/services/search/jobs?output_mode=json",
            {
                "search": query,
                "earliest_time": str(end - 900),
                "latest_time": str(end),
                "max_time": "20",
                "ttl": "60",
                "auto_cancel": "30",
                "exec_mode": "normal",
            },
            timeout=max(0.1, deadline - time.monotonic()),
        )
        sid = created.get("sid")
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", sid):
            sid = None
            raise Refused("invalid_job_id")
        path = "/services/search/jobs/" + quote(sid, safe="")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused("deadline")
            result = client.call("GET", path + "?output_mode=json", timeout=remaining)
            entries = result.get("entry", [])
            if len(entries) != 1 or not isinstance(entries[0].get("content"), dict):
                raise Refused("job_metadata_invalid")
            info = entries[0]["content"]
            if result.get("messages") or info.get("messages"):
                raise Refused("job_messages")
            if info.get("dispatchState") in ("FAILED", "CANCELED", "FINALIZED"):
                raise Refused("job_incomplete")
            if info.get("isDone") in (True, 1, "1"):
                if (
                    info.get("dispatchState") != "DONE"
                    or int(info.get("resultCount", 0)) > 1
                ):
                    raise Refused("job_incomplete_or_capped")
                break
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused("deadline")
        result = client.call(
            "GET", path + "/results?output_mode=json&count=100", timeout=remaining
        )
        rows = result.get("results")
        if (
            result.get("preview") not in (False, 0, "0")
            or result.get("messages")
            or not isinstance(rows, list)
            or len(rows) != 1
            or not isinstance(rows[0], dict)
        ):
            raise Refused("results_incomplete")
        row = rows[0]
        if set(row) != expected | {"sample_count"}:
            raise Refused("result_fields_invalid")
        values = {}
        for key in expected | {"sample_count"}:
            value = row[key]
            if not isinstance(value, (str, int)) or not re.fullmatch(
                r"(?:0|[1-9][0-9]?)", str(value)
            ):
                raise Refused("result_values_invalid")
            values[key] = int(value)
        if values["sample_count"] > 16 or any(
            value > values["sample_count"]
            for key, value in values.items()
            if key != "sample_count"
        ):
            raise Refused("result_values_invalid")
        output.update(status="ok", counts=values)
    except (Refused, TypeError, ValueError, OverflowError) as exc:
        output["reason"] = str(exc) if isinstance(exc, Refused) else "invalid_response"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if sid is not None:
            try:
                client.call(
                    "DELETE",
                    "/services/search/jobs/"
                    + quote(sid, safe="")
                    + "?output_mode=json",
                    timeout=5,
                )
                output["cleanup"] = "ok"
            except Refused:
                output["cleanup"] = "failed"
                output["status"] = "error"
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--profile", required=True, choices=["cloud"])
    parser.add_argument("--run", required=True, action="store_true")
    args = parser.parse_args()
    try:
        client = cloud_client(args.credentials, args.profile)
        end = int(time.time())
        results = []
        for family, (macro, _, _) in SPECS.items():
            names = indexes(client, (macro,))
            result = probe(client, family, names[0], end)
            results.append(result)
            if result["status"] != "ok":
                break
        output = {
            "status": "ok"
            if len(results) == len(SPECS) and all(r["status"] == "ok" for r in results)
            else "error",
            "results": results,
        }
    except Refused as exc:
        output = {"status": "error", "reason": str(exc)}
    print(json.dumps(output, sort_keys=True))
    return 0 if output["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
