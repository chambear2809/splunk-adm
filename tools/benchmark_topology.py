#!/usr/bin/env python3
"""Measure the installed topology search at its bounded row-count edge.

The workload clones only the reviewed NX-OS hostname/interface input shapes.
It checks `adm_topology` in the disposable local Splunk lab; it is not a mixed
source qualification or a production capacity estimate.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import platform
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import benchmark_pipeline as bench  # noqa: E402
from benchmark_fixtures import BASE  # noqa: E402
from lab_lock import run_main, with_lab_lock  # noqa: E402

MAX_TOPOLOGY_ROWS = 20_000
MAX_INPUT_EVENTS = 20_000
RESULT_LIMIT = MAX_TOPOLOGY_ROWS
TEMPLATE_PATH = ROOT / "fixtures/raw/nexus9k.ndjson"
FIELDS_PATH = ROOT / "fixtures/raw/FIELDS.md"
CASES = {
    "below": (9_999, 9_999),
    "at": (9_999, 10_000),
    "above": (9_999, 10_001),
}
NO_LINK_WARNING = (
    "No switch-to-switch links (CDP, ACI fabricLink or fabric LLDP) were collected, "
    "so candidate paths between switches cannot be drawn."
)
NO_IFINDEX_WARNING = (
    "SNMP ifIndex is known only for CDP-connected ports. NetFlow interfaces on "
    "other ports are shown by ifIndex unless 'show interface snmp-ifindex' "
    "output is collected."
)
EXPECTED_META_WARNINGS = (NO_LINK_WARNING, NO_IFINDEX_WARNING)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TopologyWorkload:
    name: str
    devices: int
    interfaces: int

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("name must be nonempty text")
        if type(self.devices) is not int or not 1 <= self.devices <= 10_000:
            raise ValueError("devices must be an integer in 1..10000")
        if (
            type(self.interfaces) is not int
            or not self.devices <= self.interfaces <= 2 * self.devices
        ):
            raise ValueError("interfaces must be in devices..2*devices")
        if self.devices + self.interfaces > MAX_INPUT_EVENTS:
            raise ValueError("workload exceeds the 20,000-event lab guardrail")


def device_id(index: int) -> str:
    return f"scale-node-{index + 1:05d}"


def interface_identity(index: int, devices: int) -> str:
    if index < devices:
        device_index = index
        port = 1
    else:
        device_index = (index - devices) % devices
        port = 2 + (index - devices) // devices
    return f"{device_id(device_index)}|Ethernet1/{port}"


def identity_sha256(values):
    digest = hashlib.sha256()
    for value in sorted(values):
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def expected_device_ids(workload: TopologyWorkload):
    return {device_id(index) for index in range(workload.devices)}


def expected_interface_ids(workload: TopologyWorkload):
    return {
        interface_identity(index, workload.devices)
        for index in range(workload.interfaces)
    }


@lru_cache(maxsize=1)
def templates():
    hostname = interface = None
    for line in TEMPLATE_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        envelope = json.loads(line)
        event = json.loads(envelope["event"])
        if event.get("component") == "nxhostname" and hostname is None:
            hostname = (envelope, event)
        elif event.get("component") == "nxinterface" and interface is None:
            interface = (envelope, event)
        if hostname is not None and interface is not None:
            break
    if hostname is None or interface is None:
        raise ValueError("Reviewed NX-OS workload templates are missing")
    if not isinstance(hostname[1].get("Row_info"), list):
        raise ValueError("NX-OS hostname template has an unsupported Row_info shape")
    if not isinstance(interface[1].get("Row_info"), dict):
        raise ValueError("NX-OS interface template has an unsupported Row_info shape")
    return hostname, interface


def _ip(index: int) -> str:
    return str(ipaddress.ip_address("10.64.0.1") + index)


def _event(template, data, *, ip, event_time):
    envelope = copy.deepcopy(template)
    payload = copy.deepcopy(data)
    payload["device"] = f"{ip}:443"
    payload["timestamp"] = datetime.fromtimestamp(event_time, timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    envelope["time"] = event_time
    envelope["event"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return envelope


def iter_events(workload: TopologyWorkload):
    hostname_template, interface_template = templates()
    event_time = BASE + 1
    for index in range(workload.devices):
        envelope, event = hostname_template
        payload = copy.deepcopy(event)
        payload["Row_info"][0]["hostname"] = device_id(index)
        yield _event(
            envelope,
            payload,
            ip=_ip(index),
            event_time=event_time,
        )
    for index in range(workload.interfaces):
        envelope, event = interface_template
        payload = copy.deepcopy(event)
        identity = interface_identity(index, workload.devices)
        _device, interface_name = identity.split("|", 1)
        payload["Row_info"]["interface"] = interface_name
        device_index = (
            index
            if index < workload.devices
            else (index - workload.devices) % workload.devices
        )
        yield _event(
            envelope,
            payload,
            ip=_ip(device_index),
            event_time=event_time,
        )


def manifest(workload: TopologyWorkload):
    template_sha256 = hashlib.sha256(TEMPLATE_PATH.read_bytes()).hexdigest()
    fields_sha256 = hashlib.sha256(FIELDS_PATH.read_bytes()).hexdigest()
    configuration = asdict(workload)
    identity = json.dumps(
        {
            "schema": "adm-topology-nxos-workload-v1",
            "configuration": configuration,
            "template_sha256": template_sha256,
            "fields_sha256": fields_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    device_ids = expected_device_ids(workload)
    interface_ids = expected_interface_ids(workload)
    result_rows = workload.devices + workload.interfaces + 1
    return {
        "workload_id": hashlib.sha256(identity).hexdigest(),
        "generator_schema": "adm-topology-nxos-workload-v1",
        "configuration": configuration,
        "input_events": workload.devices + workload.interfaces,
        "source_mix": {
            "index": "cisco_dc",
            "sourcetype": "cisco:dc:nexus9k",
            "components": {
                "nxhostname": workload.devices,
                "nxinterface": workload.interfaces,
            },
        },
        "event_time_range": {
            "earliest": str(BASE + 1),
            "latest": str(BASE + 1),
            "basis": "synthetic HEC event time; UTC epoch seconds",
        },
        "search_window": {"earliest": str(BASE - 300), "latest": str(BASE + 600)},
        "expected": {
            "device_rows": workload.devices,
            "interface_rows": workload.interfaces,
            "link_rows": 0,
            "meta_rows": 1,
            "result_rows": result_rows,
            "devices": workload.devices,
            "links": 0,
            "interfaces": workload.interfaces,
            "device_id_count": len(device_ids),
            "device_id_sha256": identity_sha256(device_ids),
            "interface_id_count": len(interface_ids),
            "interface_id_sha256": identity_sha256(interface_ids),
            "meta_warnings": list(EXPECTED_META_WARNINGS),
            "application_limit_rows": MAX_TOPOLOGY_ROWS,
            "application_accepts": result_rows <= MAX_TOPOLOGY_ROWS,
        },
        "provenance": {
            "template_file": "fixtures/raw/nexus9k.ndjson",
            "template_sha256": template_sha256,
            "field_contract": "fixtures/raw/FIELDS.md",
            "field_contract_sha256": fields_sha256,
            "source_definition": "NX-OS show hostname and show interface TA-grounded event shapes only",
        },
    }


def _count(value):
    parsed = bench.metric_integer(value)
    return parsed


def _warning_values(value):
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return ["invalid meta warning shape"]


def topology_check(rows, workload: TopologyWorkload):
    expected = manifest(workload)["expected"]
    notes = []
    if not isinstance(rows, list):
        return ["Topology search did not return a row list"]
    counts = Counter(row.get("row_type") for row in rows if isinstance(row, dict))
    for row_type, key in (
        ("device", "device_rows"),
        ("interface", "interface_rows"),
        ("link", "link_rows"),
        ("meta", "meta_rows"),
    ):
        if counts[row_type] != expected[key]:
            notes.append(
                f"{row_type} rows {counts[row_type]} != expected {expected[key]}"
            )
    if len(rows) != expected["result_rows"]:
        notes.append(f"result rows {len(rows)} != expected {expected['result_rows']}")

    devices = [
        row.get("device_id")
        for row in rows
        if isinstance(row, dict) and row.get("row_type") == "device"
    ]
    expected_devices = expected_device_ids(workload)
    if len(devices) != len(set(devices)) or set(devices) != expected_devices:
        notes.append("Device identities differ from the deterministic workload")
    if identity_sha256(devices) != expected["device_id_sha256"]:
        notes.append("Device identity fingerprint differs from the workload")

    interfaces = [
        f"{row.get('device_id')}|{row.get('interface')}"
        for row in rows
        if isinstance(row, dict) and row.get("row_type") == "interface"
    ]
    expected_interfaces = expected_interface_ids(workload)
    if (
        len(interfaces) != len(set(interfaces))
        or set(interfaces) != expected_interfaces
    ):
        notes.append("Interface identities differ from the deterministic workload")
    if identity_sha256(interfaces) != expected["interface_id_sha256"]:
        notes.append("Interface identity fingerprint differs from the workload")

    metas = [
        row for row in rows if isinstance(row, dict) and row.get("row_type") == "meta"
    ]
    if len(metas) == 1:
        meta = metas[0]
        for key in ("devices", "links", "interfaces"):
            actual = _count(meta.get(key))
            if actual != expected[key]:
                notes.append(
                    f"Topology meta {key} {actual} != expected {expected[key]}"
                )
        if _warning_values(meta.get("warnings")) != expected["meta_warnings"]:
            notes.append(
                "Topology warnings differ from the expected NX-OS-only warning set"
            )
    return notes


def search_measurement_complete(job, expected_accepts, expected_rows, result_limit):
    if job.get("status") == "complete":
        return True
    over_limit_warning = (
        f"Final result count exceeds configured limit {result_limit}; "
        f"retrieval is bounded to {result_limit + 1} rows"
    )
    return (
        not expected_accepts
        and job.get("status") == "incomplete"
        and job.get("dispatch_state") == "DONE"
        and job.get("is_done") is True
        and job.get("is_failed") is False
        and job.get("is_finalized") is False
        and job.get("result_limit_exceeded") is True
        and job.get("result_count") == expected_rows
        and job.get("fetched_rows") == result_limit + 1 == expected_rows
        and bool(job.get("result_pages"))
        and job.get("warnings") == [over_limit_warning]
    )


def load_events(workload: TopologyWorkload, progress=None):
    digest = hashlib.sha256()
    batch, size, count = [], 0, 0

    if progress is None:
        progress = {}
    progress.update(
        generated_event_count=0,
        generated_prefix_sha256=None,
        hec_batches_attempted=0,
        hec_events_attempted=0,
        hec_batches_acknowledged=0,
        hec_events_acknowledged=0,
        last_batch_acknowledgement="none",
    )

    def submit_batch():
        events = len(batch)
        body = b"\n".join(batch)
        progress["hec_batches_attempted"] += 1
        progress["hec_events_attempted"] += events
        progress["last_batch_acknowledgement"] = "pending"
        try:
            bench.lab._hec_post(body)
        except Exception:
            # A transport error can happen after Splunk accepted the batch.
            progress["last_batch_acknowledgement"] = "unknown"
            raise
        progress["hec_batches_acknowledged"] += 1
        progress["hec_events_acknowledged"] += events
        progress["last_batch_acknowledgement"] = "acknowledged"

    for event in iter_events(workload):
        line = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest.update(line + b"\n")
        count += 1
        progress["generated_event_count"] = count
        progress["generated_prefix_sha256"] = digest.hexdigest()
        if batch and size + len(line) + 1 > bench.lab.MAX_BATCH_BYTES:
            submit_batch()
            batch, size = [], 0
        batch.append(line)
        size += len(line) + 1
    if batch:
        submit_batch()
    return count, digest.hexdigest()


def run_case(name, workload, timeout, result_limit):
    meta = manifest(workload)
    case_started = time.monotonic()
    result = {
        "name": name,
        "workload": meta,
        "status": "failed",
        "case_started_at": utc_now(),
        "jobs": [],
        "input_progress": {},
        "non_task_docker_activity": {},
    }
    runner = bench.Runner(timeout, result_limit=result_limit)
    memory = None
    try:
        bench.reset_lab([])
        with bench.MemorySampler() as memory:
            started = time.monotonic()
            count, digest = load_events(workload, result["input_progress"])
            result["input_sha256"] = digest
            result["input_event_count"] = count
            result["load_submit_seconds"] = round(time.monotonic() - started, 4)
            bench.require(
                count == meta["input_events"], "Generated event count mismatch"
            )
            query = 'index=cisco_dc sourcetype="cisco:dc:nexus9k"'
            bench.wait_count(runner, query, meta["input_events"], timeout=180)
            result["load_searchable_seconds"] = round(time.monotonic() - started, 4)

            window = meta["search_window"]
            result["non_task_docker_activity"]["before_search"] = (
                bench.non_task_docker_activity()
            )
            search_started = time.monotonic()
            result["search_started_at"] = utc_now()
            try:
                rows, job = runner.search(
                    f"topology-{name}",
                    "`adm_topology`",
                    window["earliest"],
                    window["latest"],
                )
            finally:
                result["search_completed_at"] = utc_now()
                result["search_wall_seconds"] = round(
                    time.monotonic() - search_started, 4
                )
                try:
                    result["non_task_docker_activity"]["after_search"] = (
                        bench.non_task_docker_activity()
                    )
                except Exception as exc:
                    result["non_task_docker_activity"]["after_search_error"] = str(exc)[
                        :1000
                    ]
            job["correctness_warnings"] = topology_check(rows, workload)
            if result["non_task_docker_activity"].get("after_search_error"):
                job["correctness_warnings"].append(
                    "Could not capture non-task Docker activity after the search"
                )
            job["application_row_limit"] = MAX_TOPOLOGY_ROWS
            job["application_accepts_rows"] = len(rows) <= MAX_TOPOLOGY_ROWS
            expected_accepts = meta["expected"]["application_accepts"]
            job["application_limit_check_passed"] = (
                job["application_accepts_rows"] == expected_accepts
            )
            job["measurement_complete"] = search_measurement_complete(
                job,
                expected_accepts,
                meta["expected"]["result_rows"],
                result_limit,
            )
            result["application_row_limit"] = MAX_TOPOLOGY_ROWS
            result["application_accepts_rows"] = job["application_accepts_rows"]
            result["expected_application_accepts_rows"] = expected_accepts
            result["status"] = (
                "complete"
                if job["measurement_complete"]
                and not job["correctness_warnings"]
                and job["application_limit_check_passed"]
                else "incomplete"
            )
        result.update(memory.metrics())
    except Exception as exc:
        result["error"] = str(exc)[:2000]
    finally:
        if memory is not None:
            result.update(memory.metrics())
        result["jobs"] = runner.jobs
        result["case_completed_at"] = utc_now()
        result["case_wall_seconds"] = round(time.monotonic() - case_started, 4)
    return result


def write_report(path: Path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# NX-OS topology search boundary measurements",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "These are local Docker Splunk search measurements for a deterministic NX-OS-only workload. They do not qualify mixed-source topology, a production deployment, or a service-level objective. The 20,001-row case is fetched only as a one-row-over-limit diagnostic sentinel; the application contract rejects it.",
        "",
        "| Case | Input events | Devices | Interfaces | Actual/expected rows | App result | Search wall seconds | Job run seconds | Scan count | Container peak MiB | Status |",
        "| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for case in report["cases"]:
        job = case["jobs"][-1] if case.get("jobs") else {}
        expected = case["workload"]["expected"]
        peak = case.get("sampled_container_peak_bytes")
        lines.append(
            "| {name} | {events} | {devices} | {interfaces} | {rows} | {app_result} | {wall} | {run} | {scans} | {memory} | {status} |".format(
                name=case["name"],
                events=case.get("input_event_count", "—"),
                devices=expected["devices"],
                interfaces=expected["interfaces"],
                rows=f"{job.get('result_count', '—')}/{expected['result_rows']}",
                app_result="accepted"
                if expected["application_accepts"]
                else "rejected",
                wall=job.get("wall_seconds", "—"),
                run=job.get("run_seconds", "—"),
                scans=job.get("scan_count", "—"),
                memory=round(peak / 2**20, 1) if peak else "—",
                status=case["status"],
            )
        )
        if case.get("error"):
            lines.extend(["", f"{case['name']} error: {case['error']}"])
        for job in case.get("jobs", []):
            if job.get("status") != "complete" or job.get("correctness_warnings"):
                lines.extend(
                    [
                        "",
                        f"{case['name']} job {job.get('name')}: {json.dumps(job, sort_keys=True)}",
                    ]
                )
    lines.extend(
        [
            "",
            "The adjacent JSON binds each workload and Splunk job to the source/template hashes, package SHA-256, image ID, container resource limits, correctness identity hashes, warnings, and available metrics. Per-search CPU/RSS and per-indexer I/O were unavailable; sampled memory is whole-container cgroup memory and includes cache. Host collectors and other containers were left running, so host contention was uncontrolled.",
            "",
        ]
    )
    path.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")


def command(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


@with_lab_lock(root=ROOT)
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset-lab",
        action="store_true",
        help="Authorize erasing only the configured disposable lab for every case",
    )
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--result-limit", type=int, default=RESULT_LIMIT)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/benchmarks/topology-boundary.json"
    )
    args = parser.parse_args(argv)
    if not args.reset_lab:
        parser.error(
            "--reset-lab is required; this benchmark resets only the owned lab"
        )
    if not 10 <= args.timeout <= 1800:
        parser.error("timeout must be 10..1800 seconds")
    if not 1 <= args.result_limit <= bench.MAX_RESULT_LIMIT:
        parser.error(f"result-limit must be 1..{bench.MAX_RESULT_LIMIT}")

    environment = bench.preflight()
    environment["preflight_captured_at"] = utc_now()
    environment["phase_note"] = (
        "Task lab startup and package installation completed before this measurement window; setup time is excluded from topology search timings."
    )
    measurement_started_at = utc_now()
    cases = []
    for name in args.cases:
        devices, interfaces = CASES[name]
        case = run_case(
            name,
            TopologyWorkload(f"topology-{name}", devices, interfaces),
            args.timeout,
            args.result_limit,
        )
        cases.append(case)
        report = {
            "generated_at": utc_now(),
            "measurement_window": {
                "started_at": measurement_started_at,
                "last_case_completed_at": case.get("case_completed_at"),
                "startup_and_install_included": False,
                "case_wall_includes_reset_ingestion_and_visibility_wait": True,
                "search_wall_is_recorded_separately_per_case": True,
            },
            "measurement_class": "local-docker-splunk-search",
            "github_revision": command("git", "-C", str(ROOT), "rev-parse", "HEAD"),
            "git_dirty": bool(command("git", "-C", str(ROOT), "status", "--porcelain")),
            "host_architecture": platform.machine(),
            "environment": environment,
            "measurement_conditions": {
                "cache_flush": "not attempted; filesystem/Splunk caches are not isolated",
                "repeat_order": "each case resets lab event data, then runs one boundary search",
                "host_load": "pre-existing host collectors and non-task containers left running; host CPU and I/O contention uncontrolled",
                "result_retrieval": {
                    "configured_limit": args.result_limit,
                    "sentinel_rows_requested": args.result_limit + 1,
                    "page_size": bench.DEFAULT_RESULT_PAGE_SIZE,
                    "pagination": "Splunk results endpoint fetched with count/offset pages, bounded to limit plus one sentinel; final resultCount and returned-row count must agree",
                },
            },
            "parameters": {
                "timeout_seconds": args.timeout,
                "result_limit": args.result_limit,
            },
            "source_sha256": {
                str(path.relative_to(ROOT)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in (
                    Path(__file__),
                    ROOT / "tools/benchmark_pipeline.py",
                    ROOT / "tools/benchmark_fixtures.py",
                    ROOT / "splunk_app/splunk_adm/default/macros.conf",
                    ROOT / "frontend/src/data/searchClient.ts",
                    ROOT / "frontend/src/topology.ts",
                )
            },
            "cases": cases,
        }
        write_report(args.output, report)
        print(f"{name}: {case['status']}", flush=True)
        if case["status"] != "complete":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, root=ROOT))
