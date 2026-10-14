#!/usr/bin/env python3
"""Exercise shipped continuous schedules and catch-up in the disposable local lab."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests/splunk"))
import lab  # noqa: E402
from lab_lock import run_main, with_lab_lock  # noqa: E402
from benchmark_fixtures import BASE, Workload, iter_events, manifest  # noqa: E402
from benchmark_pipeline import (  # noqa: E402
    CONTAINER,
    Runner,
    graph_check,
    preflight,
    require,
    reset_lab,
    wait_count,
    truth,
)  # noqa: E402
from fault_pipeline import restore_container  # noqa: E402
from scheduler_recovery import build_recovery_plan  # noqa: E402
from soak_pipeline import (  # noqa: E402
    checked_search,
    graph_query,
    post_batches,
    summary_count,
    wait_summary,
)

TARGETS = (
    "ADM - Identity builder",
    "ADM - Service binding",
    "ADM - Service backends",
    "ADM - Conversation rollup",
)
CRONS = dict(
    zip(TARGETS, ("1-56/5 * * * *", "2-57/5 * * * *", "3-58/5 * * * *", "*/5 * * * *"))
)
ISO_KEYS = {"timestamp", "endtime", "creationTimestamp", "startTime"}


class LabInterferenceError(RuntimeError):
    """Another process changed the lab during the deliberate outage."""


def verify_stopped():
    try:
        state = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.Status}}", CONTAINER],
            text=True,
            timeout=30,
        ).strip()
    except subprocess.SubprocessError as exc:
        raise LabInterferenceError(
            "Cannot verify stopped lab; ownership is uncertain"
        ) from exc
    if state != "exited":
        raise LabInterferenceError(
            f"Lab changed during planned outage (state={state}); reserve exclusive lab access"
        )


def fresh_events(config, epoch):
    """Shift both envelope and embedded fixture clocks into shipped lateness bounds."""
    delta = epoch - BASE

    def shift(value):
        if isinstance(value, list):
            return [shift(v) for v in value]
        if not isinstance(value, dict):
            return value
        out = {}
        for key, item in value.items():
            if key in ISO_KEYS and isinstance(item, str):
                dt = datetime.fromisoformat(item.replace("Z", "+00:00"))
                item = (
                    datetime.fromtimestamp(dt.timestamp() + delta, timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            elif key in {"start_time", "end_time"} and isinstance(item, (int, float)):
                item += delta * 1_000_000_000
            out[key] = shift(item)
        return out

    for event in iter_events(config):
        event = shift(copy.deepcopy(event))
        event["time"] += delta
        yield event


def settings():
    return {
        e["name"]: e["content"]
        for e in lab._json(
            "GET", "/servicesNS/nobody/splunk_adm/saved/searches?count=0"
        )["entry"]
    }


def scheduler_history():
    """Keep only this rehearsal's scheduling metadata, never other search content."""
    rows = lab._json(
        "GET", "/servicesNS/nobody/system/storage/collections/data/SavedSearchHistory"
    )
    keys = {f"nobody;splunk_adm;{name}" for name in TARGETS}
    return [
        {
            key: row[key]
            for key in ("_key", "sched_time", "durable_cursor", "runtimes")
            if key in row
        }
        for row in rows
        if row.get("_key") in keys
    ]


def set_schedules(enabled, *, dispatchable=False):
    for name in settings():
        if name.startswith("ADM - "):
            active = enabled and name in TARGETS
            lab._json(
                "POST",
                "/servicesNS/nobody/splunk_adm/saved/searches/" + quote(name, safe=""),
                {
                    "disabled": "0"
                    if active or (dispatchable and name in TARGETS)
                    else "1",
                    "is_scheduled": "1" if active else "0",
                },
            )


def verify_settings(config):
    for name in TARGETS:
        row = config[name]
        require(
            row.get("cron_schedule") == CRONS[name], f"{name}: shipped cron changed"
        )
        require(
            not truth(row.get("realtime_schedule")),
            f"{name}: continuous scheduling required",
        )
        require(
            not truth(row.get("disabled")) and truth(row.get("is_scheduled")),
            f"{name}: not scheduled",
        )
        require(
            row.get("dispatch.index_earliest") == "-10m@m"
            and row.get("dispatch.index_latest")
            == ("-5m@m" if name == TARGETS[-1] else "@m")
            and row.get("dispatch.earliest_time") == "-24h"
            and row.get("dispatch.latest_time") == "+15m",
            f"{name}: recovery window changed",
        )


def scheduler_rows(runner, started):
    rows = checked_search(
        runner,
        "scheduler-log",
        'index=_internal source=*scheduler.log* app="splunk_adm" savedsearch_name="ADM -*" status=* '
        f"| where _time>={int(started)} | table _time savedsearch_name scheduled_time dispatch_time status reason sid run_time",
        earliest=str(int(started) - 60),
    )

    # Manual saved-search dispatches also appear in scheduler.log. Retain
    # sid-less deferrals/skips, but never count manual jobs as real schedules.
    return [
        r
        for r in rows
        if str(r.get("sid") or "").startswith("scheduler__")
        or (not r.get("sid") and r.get("status") != "success")
    ]


def validate_rows(rows):
    for row in rows:
        if row.get("savedsearch_name") in TARGETS:
            # Continuous searches can defer while startup restores their history.
            # Retain these records, but only a completed run can satisfy catch-up.
            if row.get("status") == "continued":
                continue
            require(
                row.get("status") == "success",
                f"scheduler outcome: {row.get('savedsearch_name')} {row.get('status')} {row.get('reason', '')}",
            )
            require(
                float(row.get("scheduled_time", 0)) > 0,
                "scheduler timestamp unavailable",
            )


def catchup_rows(rows, outage_start, restarted):
    return [
        r
        for r in rows
        if r.get("savedsearch_name") in TARGETS
        and r.get("status") == "success"
        and outage_start < float(r.get("scheduled_time", 0)) < restarted
        and float(r.get("dispatch_time") or 0) >= restarted
    ]


def wait_converged(runner, started, expected, deadline, report, catchup=None):
    report["expected_flow_records"] = expected
    if catchup:
        report["catchup_rows"] = []
    while time.monotonic() < deadline:
        rows = scheduler_rows(runner, started)
        report["scheduler_rows"] = rows
        validate_rows(rows)
        total = summary_count(runner)
        report["observed_flow_records"] = total
        require(total <= expected, f"scheduled rollup overcount {total}/{expected}")
        names = {
            r.get("savedsearch_name") for r in rows if r.get("status") == "success"
        }
        replayed = catchup_rows(rows, *catchup) if catchup else []
        if catchup:
            report["catchup_rows"] = replayed
        if (
            total == expected
            and set(TARGETS) <= names
            and (
                not catchup
                or set(TARGETS) <= {r.get("savedsearch_name") for r in replayed}
            )
        ):
            return replayed
        print(
            f"Scheduler progress: {total}/{expected} flow records; {len(names & set(TARGETS))}/{len(TARGETS)} jobs observed",
            flush=True,
        )
        time.sleep(15)
    raise TimeoutError("scheduled convergence/catch-up evidence deadline exceeded")


def drain_jobs(timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        active = [
            e
            for e in lab._json("GET", "/services/search/v2/jobs?count=0")["entry"]
            if e.get("acl", {}).get("app") == "splunk_adm"
            and not truth(e["content"].get("isDone"))
        ]
        if not active:
            return
        require(time.monotonic() < deadline, "scheduled jobs did not drain")
        time.sleep(1)


def checkpoint_rows(runner, started, stop_before):
    """Wait for the current pre-outage completions to reach the internal index."""
    offsets = dict(zip(TARGETS, (60, 120, 180, 0)))
    while time.time() < stop_before:
        rows = scheduler_rows(runner, started)
        validate_rows(rows)
        now = int(time.time())
        latest = {
            name: (now - offset) // 300 * 300 + offset
            for name, offset in offsets.items()
        }
        done = {
            (r.get("savedsearch_name"), int(float(r["scheduled_time"])))
            for r in rows
            if r.get("status") == "success"
        }
        if all((name, slot) in done for name, slot in latest.items()):
            return rows
        time.sleep(2)
    raise TimeoutError(
        "current scheduler checkpoint was not indexed before safe outage boundary"
    )


def checked_replay_search(runner, name, query, **kwargs):
    rows, record = runner.search(name, query, **kwargs)
    if record["status"] == "complete":
        return
    # An empty binding slice reaches outputlookup append=true with
    # override_if_empty=false. Splunk warns despite this being a safe no-op.
    # An empty rollup similarly warns when collect has no rows. Accept only
    # these exact outputs with zero scanned/matched events and the sole known
    # warning. Truncation, preview and all other warnings still fail.
    notes = record.get("warnings", [])
    empty_binding = (
        query == "ADM - Service binding"
        and rows == [{"rows_written": "0"}]
        and len(notes) == 1
        and notes[0].startswith("WARN: Found no results to write to collection '")
        and notes[0].endswith("'.")
    )
    empty_rollup = (
        query == "ADM - Conversation rollup"
        and rows == []
        and notes == ["WARN: No results to summary index."]
    )
    require(
        record["status"] == "incomplete"
        and record.get("scan_count") == 0
        and record.get("event_count") == 0
        and (empty_binding or empty_rollup),
        f"{name}: incomplete search",
    )
    record["accepted_empty_window"] = True


def replay_missed_slots(runner, started, outage_started, deadline, report):
    """Assist recovery explicitly; never count manual replay as scheduler catch-up."""
    recovery = report["recovery"] = {
        "mode": "absolute-slice-replay",
        "status": "incomplete",
        "jobs": [],
    }
    set_schedules(False, dispatchable=True)
    drain_jobs()
    replayed = []
    while time.monotonic() < deadline:
        rows = scheduler_rows(runner, started)
        report["scheduler_rows"] = rows
        validate_rows(rows)
        plan = build_recovery_plan(
            report["pre_outage_scheduler_rows"] + rows + replayed,
            outage_started,
            time.time() - 1,
        )
        recovery["pending"] = plan
        if not plan:
            recovery["status"] = "complete"
            return
        for job in plan:
            require(time.monotonic() < deadline, "recovery replay deadline exceeded")
            checked_replay_search(
                runner,
                "recovery: " + job["name"],
                job["name"],
                saved=True,
                earliest=str(job["earliest"]),
                latest=str(job["latest"]),
                index_window=(str(job["index_earliest"]), str(job["index_latest"])),
            )
            recovery["jobs"].append({**job, "sid": runner.jobs[-1]["sid"]})
            replayed.append(
                {
                    "savedsearch_name": job["name"],
                    "scheduled_time": job["scheduled_time"],
                    "status": "success",
                }
            )
    raise TimeoutError("recovery replay deadline exceeded")


def event_epoch(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def execution_cycles(rows, outage_start):
    cycles = {}
    offsets = dict(zip(TARGETS, (1, 2, 3, 0)))
    for row in rows:
        name = row.get("savedsearch_name")
        if name not in TARGETS or row.get("status") != "success":
            continue
        scheduled = int(float(row["scheduled_time"]))
        require(
            scheduled % 60 == 0 and (scheduled // 60) % 5 == offsets[name],
            "observed scheduler slot does not match shipped cron",
        )
        cycles.setdefault(scheduled // 300 * 300, []).append(row)
    evidence = []
    expected = (TARGETS[-1], *TARGETS[:-1])
    for cycle, group in sorted(cycles.items()):
        if len(group) != len(TARGETS) or {r["savedsearch_name"] for r in group} != set(
            TARGETS
        ):
            continue
        order = [
            r["savedsearch_name"]
            for r in sorted(group, key=lambda r: float(r["dispatch_time"]))
        ]
        baseline = cycle + 300 <= outage_start and all(
            float(r["dispatch_time"]) < outage_start
            and event_epoch(r.get("_time") or float("inf")) < outage_start
            for r in group
        )
        if baseline:
            require(
                tuple(order) == expected,
                "baseline dispatch order differs from shipped staggering",
            )
        evidence.append(
            {"cycle": cycle, "dispatch_order": order, "before_outage": baseline}
        )
    require(
        any(c["before_outage"] for c in evidence),
        "no complete pre-outage scheduler cycle observed",
    )
    return evidence


def verify_graph(rows, expected):
    notes = graph_check(rows, expected)
    require(not notes, "; ".join(notes))


@with_lab_lock(root=ROOT)
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset-lab", action="store_true", required=True)
    parser.add_argument("--recovery", choices=("native", "replay"), default="native")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--downtime", type=int, default=330)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/scheduler/latest.json"
    )
    args = parser.parse_args(argv)
    require(900 <= args.timeout <= 3600, "timeout must be 900..3600 seconds")
    require(
        310 <= args.downtime <= 600,
        "downtime must miss at least one five-minute schedule (310..600s)",
    )
    runner = Runner(120)
    config = Workload(pods=3, flow_copies=2)
    report = {
        "status": "failed",
        "mode": "shipped-cron",
        "recovery_mode": args.recovery,
        "targets": TARGETS,
        "downtime_seconds": args.downtime,
    }
    owned = False
    try:
        report["environment"] = preflight()
        owned = True
        reset_lab(manifest(config)["scope_rows"])
        set_schedules(False)
        started = time.time()
        deadline = time.monotonic() + args.timeout
        lines = [
            json.dumps(e, sort_keys=True).encode()
            for e in fresh_events(config, int(started) - 60)
        ]
        report["fixture_sha256"] = hashlib.sha256(b"\n".join(lines)).hexdigest()
        raw_query = "(index=netflow OR index=k8s OR index=otel_traces)"
        post_batches(lines)
        wait_count(runner, raw_query, len(lines), 120)
        set_schedules(True)
        current = settings()
        verify_settings(current)
        report["settings"] = {
            name: {
                k: current[name].get(k)
                for k in (
                    "cron_schedule",
                    "realtime_schedule",
                    "dispatch.index_earliest",
                    "dispatch.index_latest",
                    "dispatch.earliest_time",
                    "dispatch.latest_time",
                )
            }
            for name in TARGETS
        }
        expected = manifest(config)["expected"]["flows"]
        print("Waiting for shipped schedules to process the first batch", flush=True)
        wait_converged(runner, started, expected, deadline, report)
        report["baseline_flow_records"] = expected
        # Independent indexed observations; same payload is intentionally not a retry.
        second_lines = []
        for line in lines:
            event = json.loads(line)
            event["source"] = "adm-scheduler-wave-2"
            second_lines.append(json.dumps(event, sort_keys=True).encode())
        post_batches(second_lines)
        wait_count(runner, raw_query, 2 * len(lines), 120)
        indexed = checked_search(
            runner,
            "second-batch-index-times",
            raw_query
            + ' source="adm-scheduler-wave-2" | stats min(_indextime) AS first max(_indextime) AS last count AS count',
        )
        require(
            len(indexed) == 1 and int(indexed[0]["count"]) == len(lines),
            "second batch evidence incomplete",
        )
        first, last = int(indexed[0]["first"]), int(indexed[0]["last"])
        require(first // 300 == last // 300, "second batch crossed index slices; rerun")
        report["second_batch_index_times"] = {"first": first, "last": last}
        # Stop only after the second batch's five-minute ingestion slice closes.
        # Its lagged rollup slot then falls inside the deliberate outage.
        close_at = (last // 300 + 1) * 300
        report["second_batch_rollup_slot"] = close_at + 300
        print(
            "Waiting for second batch's index slice to close before outage", flush=True
        )
        while time.time() < close_at + 10:
            time.sleep(min(15, close_at + 10 - time.time()))
        require(
            summary_count(runner) == expected,
            "second batch already processed before outage",
        )
        report["history_before_outage"] = scheduler_history()
        report["pre_outage_scheduler_rows"] = checkpoint_rows(
            runner, started, report["second_batch_rollup_slot"] - 90
        )
        require(
            time.time() < report["second_batch_rollup_slot"] - 90,
            "missed safe outage boundary; rerun",
        )
        report["outage_started"] = time.time()
        subprocess.run(
            ["docker", "stop", "--time", "60", CONTAINER],
            check=True,
            timeout=90,
            stdout=subprocess.DEVNULL,
        )
        print(f"Container stopped; holding downtime for {args.downtime}s", flush=True)
        outage_deadline = time.monotonic() + args.downtime
        while time.monotonic() < outage_deadline:
            verify_stopped()
            time.sleep(max(0, min(15, outage_deadline - time.monotonic())))
        verify_stopped()
        report["restart_requested"] = time.time()
        restore_container(240)
        report["ready_after_restart"] = time.time()
        report["history_after_restart"] = scheduler_history()
        verify_settings(settings())
        if args.recovery == "native":
            print(
                "Waiting for continuous scheduler catch-up and complete summary",
                flush=True,
            )
            report["catchup_rows"] = wait_converged(
                runner,
                started,
                2 * expected,
                deadline,
                report,
                catchup=(report["outage_started"], report["restart_requested"]),
            )
        else:
            print("Pausing schedules and replaying missing absolute slices", flush=True)
            replay_missed_slots(
                runner, started, report["outage_started"], deadline, report
            )
            report["catchup_rows"] = catchup_rows(
                report["scheduler_rows"],
                report["outage_started"],
                report["restart_requested"],
            )
            wait_summary(
                runner, 2 * expected, min(120, max(0, deadline - time.monotonic()))
            )
            report["resumed_at"] = time.time()
            set_schedules(True)
            report["resume_evidence"] = {}
            print("Checking fresh scheduled runs after assisted recovery", flush=True)
            wait_converged(
                runner,
                report["resumed_at"],
                2 * expected,
                deadline,
                report["resume_evidence"],
            )
        recovered_slots = [
            (r.get("savedsearch_name"), int(float(r["scheduled_time"])))
            for r in report["catchup_rows"]
        ] + [
            (r["name"], r["scheduled_time"])
            for r in report.get("recovery", {}).get("jobs", [])
        ]
        require(
            (TARGETS[-1], report["second_batch_rollup_slot"]) in recovered_slots,
            "second batch missed rollup slot was not recovered",
        )
        set_schedules(False)
        drain_jobs()
        wait_count(runner, raw_query, 2 * len(lines), 120)
        report["final_flow_records"] = summary_count(runner)
        require(
            report["final_flow_records"] == 2 * expected,
            "summary changed after scheduler drained",
        )
        graph = checked_search(
            runner,
            "scheduled-graph",
            graph_query(config),
            earliest=str(int(started) - 900),
            latest="+15m",
        )
        graph_expected = dict(manifest(config)["expected"])
        graph_expected["graph_bytes"] *= 2
        verify_graph(graph, graph_expected)
        report["graph"] = {
            "nodes": sum(r.get("row_type") == "node" for r in graph),
            "edges": sum(r.get("row_type") == "edge" for r in graph),
        }
        report["health_jobs"] = checked_search(
            runner,
            "scheduler-health",
            "| `adm_health_jobs`",
            earliest=str(int(started) - 60),
        )
        health = {r["name"]: r for r in report["health_jobs"]}
        for name in TARGETS:
            require(
                name in health
                and float(health[name].get("last_success") or 0) >= started,
                f"health missing scheduled success: {name}",
            )
            require(
                int(health[name].get("skips") or 0) == 0
                and int(health[name].get("failures") or 0) == 0,
                f"health reported missed/failed job: {name}",
            )
        report["execution_cycles"] = execution_cycles(
            report["scheduler_rows"], report["outage_started"]
        )
        report["status"] = "complete"
    except Exception as exc:
        report["error"] = str(exc)[:2000]
        if isinstance(exc, LabInterferenceError):
            owned = False
            report["cleanup_skipped"] = (
                "Lab ownership lost; leaving other process's state intact"
            )
    finally:
        if owned:
            try:
                restore_container(240)
                set_schedules(False)
            except Exception as exc:
                report["cleanup_error"] = str(exc)[:1000]
                report["status"] = "failed"
        report["jobs"] = runner.jobs
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(run_main(main, root=ROOT))
