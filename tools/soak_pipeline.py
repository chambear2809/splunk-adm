#!/usr/bin/env python3
"""Bounded local continuous-ingestion correctness soak (no live network)."""

from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "splunk"))
sys.path.insert(0, str(ROOT / "tools"))
import lab  # noqa: E402
from lab_lock import run_main, with_lab_lock  # noqa: E402
from benchmark_fixtures import Workload, iter_events, manifest  # noqa: E402

# ruff: noqa: E402
from benchmark_pipeline import (
    Runner,
    graph_check,
    preflight,
    require,
    reset_lab,
    wait_count,
)  # noqa: E402


def batch_events(config: Workload, token: str) -> tuple[list[bytes], str]:
    lines, digest = [], hashlib.sha256()
    for event in iter_events(config):
        event = json.loads(json.dumps(event))
        event["source"] = f"adm-soak:{token}"
        event.setdefault("fields", {})["adm.soak_token"] = token
        line = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        digest.update(line + b"\n")
        lines.append(line)
    return lines, digest.hexdigest()


def post_batches(lines: list[bytes], workers: int = 2) -> int:
    batches, current, size = [], [], 0
    for line in lines:
        if current and size + len(line) + 1 > lab.MAX_BATCH_BYTES:
            batches.append(b"\n".join(current))
            current, size = [], 0
        current.append(line)
        size += len(line) + 1
    if current:
        batches.append(b"\n".join(current))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(lab._hec_post, batches))
    return len(lines)


SUMMARY = (
    'index=adm_summary source="adm:conversation" | `adm_summary_dedup` '
    "| stats sum(records) AS records count(eval(isnull(rollup_id))) AS unprotected"
)


def checked_search(runner, name, query, **kwargs):
    rows, job = runner.search(name, query, **kwargs)
    require(job["status"] == "complete", f"{name}: incomplete search")
    return rows


def summary_count(runner):
    rows = checked_search(runner, "summary-count", SUMMARY)
    require(int(rows[0].get("unprotected", 0)) == 0, "summary lacks replay identity")
    return int(rows[0].get("records", 0))


def wait_summary(runner, expected, timeout):
    deadline = time.monotonic() + timeout
    while True:
        actual = summary_count(runner)
        require(actual <= expected, f"summary overcount: {actual} > {expected}")
        if actual == expected:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"summary only {actual}/{expected}")
        time.sleep(1)


def closed_boundary():
    # Splunk _indextime has integer-second precision; leave the entire current
    # second on the closed side and begin the next slice at its exclusive end.
    boundary = int(time.time()) + 1
    while time.time() < boundary:
        time.sleep(0.05)
    return boundary


def graph_query(config):
    args = manifest(config)["graph_args"]
    return (
        "`adm_graph("
        + ",".join(
            json.dumps(args[k])
            for k in ("service", "environment", "cluster", "namespace")
        )
        + ")`"
    )


def check_graph(runner, config, copies):
    expected = dict(manifest(config)["expected"])
    expected["graph_bytes"] *= copies
    rows = checked_search(runner, "map-read", graph_query(config))
    require(not graph_check(rows, expected), "; ".join(graph_check(rows, expected)))
    return len(rows)


def rollup(runner, start, end, expected, timeout):
    raw_query = 'index=adm_summary source="adm:conversation"'
    raw_before = checked_search(
        runner, "raw-summary-count", raw_query + " | stats count AS count"
    )
    count_before = int(raw_before[0]["count"])
    rows = checked_search(
        runner,
        "rollup",
        "ADM - Conversation rollup",
        saved=True,
        index_window=(start, end),
    )
    require(bool(rows), "rollup returned no rows")
    wait_count(runner, raw_query, count_before + len(rows), timeout)
    wait_summary(runner, expected, timeout)
    replay = checked_search(
        runner,
        "replay",
        "ADM - Conversation rollup",
        saved=True,
        index_window=(start, end),
    )
    require(len(replay) == len(rows), "replay returned different row count")
    wait_count(runner, raw_query, count_before + len(rows) + len(replay), timeout)
    wait_summary(runner, expected, timeout)


@with_lab_lock(root=ROOT)
def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reset-lab", action="store_true")
    p.add_argument("--batches", "--cycles", dest="batches", type=int, default=3)
    p.add_argument("--interval", type=float, default=1)
    p.add_argument("--flow-copies", type=int, default=2)
    p.add_argument("--pods", type=int, default=3)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument(
        "--pause-cycle", "--fault-cycle", dest="pause_cycle", type=int, default=2
    )
    p.add_argument("--output", type=Path, default=ROOT / "dist/soak/latest.json")
    args = p.parse_args(argv)
    if (
        not args.reset_lab
        or not 3 <= args.batches <= 20
        or not 0 <= args.pause_cycle < args.batches
    ):
        p.error("requires --reset-lab, batches 3..20, and pause-cycle 0..batches-1")
    if (
        not 0.1 <= args.interval <= 10
        or not 10 <= args.timeout <= 1800
        or not 1 <= args.flow_copies <= 100
        or not 2 <= args.pods <= 100
    ):
        p.error("interval .1..10, timeout 10..1800, flow-copies 1..100, pods 2..100")
    config = Workload(pods=args.pods, flow_copies=args.flow_copies)
    expected = manifest(config)["expected"]
    runner = Runner(args.timeout)
    report = {
        "status": "failed",
        "parameters": {**vars(args), "output": str(args.output)},
        "waves": [],
    }
    try:
        report["environment"] = preflight()
        reset_lab(manifest(config)["scope_rows"])
        start = closed_boundary()
        lines, digest = batch_events(config, "seed-" + uuid.uuid4().hex[:12])
        seed_token = json.loads(lines[0])["source"]
        post_batches(lines)
        wait_count(runner, f'index=* source="{seed_token}"', len(lines), args.timeout)
        end = closed_boundary()
        for name in (
            "ADM - Identity builder",
            "ADM - Service binding",
            "ADM - Service backends",
        ):
            checked_search(runner, name, name, saved=True, index_window=(start, end))
        rollup(runner, start, end, expected["flows"], args.timeout)
        check_graph(runner, config, 1)
        report["seed_sha256"] = digest
        processed_copies, submitted_copies = 1, 1
        pending_start = end
        for wave in range(1, args.batches + 1):
            print(
                f"wave {wave}: paced ingestion with concurrent builders and map reads",
                flush=True,
            )
            token = f"wave-{wave}-" + uuid.uuid4().hex[:12]
            lines, digest = batch_events(config, token)
            submissions, errors = [], []
            stop = threading.Event()
            # Three bounded chunks, paced while the coordinator repeatedly reads
            # the map. Control-plane builders replay the previous CLOSED slice.
            chunks = [lines[i::3] for i in range(3)]

            def produce():
                try:
                    for chunk in chunks:
                        if stop.wait(args.interval):
                            return
                        began = time.time()
                        post_batches(chunk)
                        submissions.append((began, time.time()))
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=produce)
            intervals = []
            thread.start()
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    builders = [
                        pool.submit(
                            checked_search,
                            runner,
                            name,
                            name,
                            saved=True,
                            index_window=(start, end),
                        )
                        for name in ("ADM - Identity builder", "ADM - Service binding")
                    ]
                    while thread.is_alive():
                        began = time.time()
                        check_graph(runner, config, processed_copies)
                        intervals.append((began, time.time()))
                    for future in builders:
                        future.result()
            finally:
                stop.set()
                thread.join(timeout=125)
            require(not thread.is_alive(), "producer did not stop")
            require(not errors, "; ".join(errors))
            require(len(submissions) == 3, "producer did not finish all chunks")
            overlaps = sum(
                any(a < d and c < b for c, d in intervals) for a, b in submissions
            )
            require(overlaps > 0, "no measured ingestion/search overlap")
            wait_count(
                runner, f'index=* source="adm-soak:{token}"', len(lines), args.timeout
            )
            new_end = closed_boundary()
            submitted_copies += 1
            item = {
                "wave": wave,
                "submitted": len(lines),
                "searchable": len(lines),
                "sha256": digest,
                "overlapping_submissions": overlaps,
                "index_start": end,
                "index_end": new_end,
            }
            if wave == args.pause_cycle:
                require(
                    summary_count(runner) == processed_copies * expected["flows"],
                    "paused rollup changed summary",
                )
                item["processing"] = "rollup skipped; backlog retained until next wave"
            else:
                rollup(
                    runner,
                    pending_start,
                    new_end,
                    submitted_copies * expected["flows"],
                    args.timeout,
                )
                processed_copies = submitted_copies
                pending_start = new_end
                item["processing"] = "closed slice processed and replayed"
                check_graph(runner, config, processed_copies)
            item["backlog_flow_records"] = (
                submitted_copies - processed_copies
            ) * expected["flows"]
            report["waves"].append(item)
            start, end = end, new_end
        require(processed_copies == submitted_copies, "backlog remains")
        report["summary_flow_records"] = summary_count(runner)
        report["expected_flow_records"] = submitted_copies * expected["flows"]
        report["status"] = "complete"
    except Exception as exc:
        report["error"] = str(exc)[:2000]
    finally:
        report["jobs"] = runner.jobs
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(run_main(main, root=ROOT))
