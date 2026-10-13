#!/usr/bin/env python3
"""Exercise recovery from a real, abrupt Splunk container interruption.

This is deliberately local-only and destructive to the disposable lab.  The
raw source slice is retained while the summary index is rebuilt after the
SIGKILL, so the report never treats a partially written aggregate as safe to
replay in place.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "splunk"))
sys.path.insert(0, str(ROOT / "tools"))
import lab  # noqa: E402
from benchmark_fixtures import Workload, manifest  # noqa: E402
from benchmark_pipeline import (  # noqa: E402
    CONTAINER,
    Runner,
    load_events,
    preflight,
    request,
    reset_lab,
    require,
    wait_count,
)


def _docker(*args: str, timeout: float = 30) -> str:
    return subprocess.check_output(
        ["docker", *args], text=True, timeout=timeout, stderr=subprocess.DEVNULL
    ).strip()


def kill_container() -> dict[str, str]:
    """Kill (never gracefully restart) and return pre/post state evidence."""
    before = _docker("inspect", "--format", "{{.State.Status}}", CONTAINER)
    require(before == "running", f"cannot fault container in state {before}")
    subprocess.run(
        ["docker", "kill", CONTAINER], check=True, timeout=30, stdout=subprocess.DEVNULL
    )
    after = _docker("inspect", "--format", "{{.State.Status}}", CONTAINER)
    require(after == "exited", f"docker kill did not stop container: {after}")
    return {"before": before, "after_kill": after, "signal": "SIGKILL (docker kill)"}


def wait_bootstrap(timeout: float = 180) -> None:
    """Management opens before the image's startup playbook has finished."""
    started = _docker("inspect", "--format", "{{.State.StartedAt}}", CONTAINER)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = _docker("logs", "--since", started, "--tail", "40", CONTAINER)
        if "Ansible playbook complete" in logs:
            return
        time.sleep(1)
    raise TimeoutError("container startup playbook did not finish")


def restore_container(timeout: float = 180) -> None:
    state = _docker("inspect", "--format", "{{.State.Status}}", CONTAINER)
    if state != "running":
        subprocess.run(
            ["docker", "start", CONTAINER],
            check=True,
            timeout=30,
            stdout=subprocess.DEVNULL,
        )
    try:
        lab.wait_ready(timeout=timeout)
        wait_bootstrap(timeout=timeout)
        wait_kv_ready(timeout=timeout)
    except Exception:
        # A failed summary-only maintenance step may leave the container up
        # while splunkd is stopped; recover the application service as well.
        subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "splunk",
                CONTAINER,
                "/opt/splunk/bin/splunk",
                "start",
                "--answer-yes",
                "--no-prompt",
            ],
            check=True,
            timeout=60,
            stdout=subprocess.DEVNULL,
        )
        lab.wait_ready(timeout=timeout)
        wait_bootstrap(timeout=timeout)
        wait_kv_ready(timeout=timeout)


def wait_kv_ready(timeout: float = 180) -> None:
    """Wait for the KV REST surface after splunkd readiness."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            lab._json(
                "GET",
                "/servicesNS/nobody/splunk_adm/storage/collections/config?count=0",
            )
            return
        except Exception:
            time.sleep(1)
    raise TimeoutError("KV store was not ready after Splunk restart")


def reset_summary_only(timeout: float = 180) -> None:
    """Clear only derived summaries, preserving the accepted raw slice."""
    splunk = "/opt/splunk/bin/splunk"
    subprocess.run(
        ["docker", "exec", "-u", "splunk", CONTAINER, splunk, "stop"],
        check=True,
        timeout=60,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "docker",
            "exec",
            "-u",
            "splunk",
            CONTAINER,
            splunk,
            "clean",
            "eventdata",
            "-index",
            "adm_summary",
            "-f",
        ],
        check=True,
        timeout=120,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "docker",
            "exec",
            "-u",
            "splunk",
            CONTAINER,
            splunk,
            "start",
            "--answer-yes",
            "--no-prompt",
        ],
        check=True,
        timeout=60,
        stdout=subprocess.DEVNULL,
    )
    lab.wait_ready(timeout=timeout)
    wait_kv_ready(timeout=timeout)


def dispatch_rollup(runner: Runner, start: int, end: int) -> str:
    path = "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Conversation%20rollup/dispatch"
    value = request(
        "POST",
        path,
        {
            "dispatch.earliest_time": "0",
            "dispatch.latest_time": "now",
            "dispatch.index_earliest": str(start),
            "dispatch.index_latest": str(end),
            "trigger_actions": "1",
        },
        timeout=30,
    )
    sid = value.get("sid")
    require(bool(sid), "rollup dispatch returned no SID")
    runner.jobs.append({"name": "faulted-rollup", "sid": sid, "status": "interrupted"})
    return sid


def observe_running(sid: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        content = lab._json("GET", f"/services/search/v2/jobs/{sid}")["entry"][0][
            "content"
        ]
        if content.get("isDone"):
            raise RuntimeError("rollup completed before a running state was observed")
        if str(content.get("dispatchState", "")).upper() == "RUNNING":
            return {"dispatch_state": content.get("dispatchState"), "is_done": False}
        time.sleep(0.25)
    raise TimeoutError("did not observe rollup running before fault deadline")


def raw_identity_digest(runner: Runner, query: str, expected: int) -> str:
    rows, job = runner.search(
        "raw-identities",
        query
        + ' | eval identity=index."|"._bkt."|"._cd | fields identity | sort 0 identity',
    )
    require(job["status"] == "complete", "raw identity search incomplete")
    require(len(rows) == expected, "raw identity search did not return every event")
    require(all(row.get("identity") for row in rows), "raw event identity missing")
    digest = hashlib.sha256()
    for row in rows:
        digest.update(str(row.get("identity", "")).encode() + b"\n")
    return digest.hexdigest()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reset-lab", action="store_true", required=True)
    p.add_argument("--pods", type=int, default=20)
    p.add_argument("--flow-copies", type=int, default=100)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--output", type=Path, default=ROOT / "dist/fault/latest.json")
    args = p.parse_args(argv)
    require(
        2 <= args.pods <= 100 and 10 <= args.flow_copies <= 1000,
        "pods 2..100 and flow-copies 10..1000",
    )
    config = Workload(pods=args.pods, flow_copies=args.flow_copies)
    expected = manifest(config)["expected"]["flows"]
    runner = Runner(args.timeout)
    report = {
        "status": "failed",
        "parameters": {**vars(args), "output": str(args.output)},
    }
    local_owned = False
    fault_started = None
    try:
        report["environment"] = preflight()
        local_owned = True
        reset_lab(manifest(config)["scope_rows"])
        start = int(time.time()) + 1
        while time.time() < start:
            time.sleep(0.05)
        submitted, digest = load_events(config)
        raw_query = "(index=netflow sourcetype=stream:netflow) OR (index=k8s sourcetype=kube:object:pods) OR (index=otel_traces sourcetype=otel:traces)"
        # load_events returns count; wait for every accepted event to be searchable.
        raw_count = submitted
        wait_count(runner, raw_query, raw_count, args.timeout)
        raw_before_digest = raw_identity_digest(runner, raw_query, raw_count)
        end = int(time.time()) + 1
        while time.time() < end:
            time.sleep(0.05)
        report["submitted"] = report["searchable_before_fault"] = raw_count
        report["source_digest"] = digest
        sid = dispatch_rollup(runner, start, end)
        report["rollup_job"] = {"sid": sid, **observe_running(sid)}
        report["rollup_job"]["pre_kill"] = observe_running(sid, timeout=2)
        fault_started = time.monotonic()
        report["fault"] = kill_container()
        restore_container(args.timeout)
        reset_summary_only(args.timeout)
        report["recovery_seconds_to_summary_reset"] = round(
            time.monotonic() - fault_started, 3
        )
        replay_rows, replay_job = runner.search(
            "recovery-rollup",
            "ADM - Conversation rollup",
            saved=True,
            index_window=(start, end),
        )
        require(replay_job["status"] == "complete", "recovery rollup incomplete")
        require(bool(replay_rows), "recovery rollup produced no rows")
        wait_count(
            runner,
            'index=adm_summary source="adm:conversation"',
            len(replay_rows),
            args.timeout,
        )
        report["replay_job"] = replay_job
        summary_rows, summary_job = runner.search(
            "recovery-summary-count",
            'index=adm_summary source="adm:conversation" | `adm_summary_dedup` | stats sum(records) AS records',
        )
        recovered = int(summary_rows[0].get("records", 0))
        require(summary_job["status"] == "complete", "summary count incomplete")
        require(recovered == expected, f"recovered {recovered}, expected {expected}")
        raw_after_rows, raw_after_job = runner.search(
            "recovery-raw-count", raw_query + " | stats count AS count"
        )
        raw_after = int(raw_after_rows[0].get("count", 0))
        require(raw_after_job["status"] == "complete", "raw count incomplete")
        require(
            raw_after == raw_count,
            f"raw records after restart {raw_after}, expected {raw_count}",
        )
        raw_after_digest = raw_identity_digest(runner, raw_query, raw_count)
        require(raw_after_digest == raw_before_digest, "raw event identity set changed")
        report.update(
            {
                "summary_records_after_rebuild": recovered,
                "raw_records_after_rebuild": raw_after,
                "raw_count_job": raw_after_job,
                "raw_identity_digest_before": raw_before_digest,
                "raw_identity_digest_after": raw_after_digest,
                "recovery_seconds": round(time.monotonic() - fault_started, 3),
                "summary_job": summary_job,
                "status": "complete",
            }
        )
    except Exception as exc:
        report["error"] = str(exc)[:2000]
    finally:
        try:
            if local_owned:
                restore_container(180)
        except Exception as exc:
            report["restore_error"] = str(exc)[:1000]
            report["status"] = "failed"
        report["jobs"] = runner.jobs
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
