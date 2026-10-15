#!/usr/bin/env python3
"""Measure synthetic pipeline workloads in the disposable localhost Splunk lab.

Requires --reset-lab: each case erases this lab's indexes and KV collections.
Never accepts a remote URL or credentials. Raw output is saved incrementally.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import configparser
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "splunk"))
sys.path.insert(0, str(ROOT / "tools"))
import lab  # noqa: E402
from lab_lock import run_main, with_lab_lock  # noqa: E402
from benchmark_fixtures import Workload, iter_events, manifest  # noqa: E402

CONTAINER = "adm-splunk-lab"
COLLECTIONS = (
    "adm_observer_scope",
    "adm_ip_identity",
    "adm_service_workload",
    "adm_interfaces",
    "adm_service_backends",
    "adm_service_routes",
    "adm_aci_policy",
    "adm_app_catalog",
)
# Orthogonal pairs separate record volume, exporter count, graph size, history,
# and observations of the same traffic at multiple network devices.
CASES = {
    "smoke": dict(pods=3, flow_copies=2, history=1, exporters=1),
    "baseline": dict(pods=10, flow_copies=100, history=1, exporters=1),
    "flow-volume": dict(pods=10, flow_copies=10000, history=1, exporters=1),
    "many-devices": dict(pods=100, flow_copies=100, history=1, exporters=100),
    "one-device": dict(pods=100, flow_copies=100, history=1, exporters=1),
    "identity-history": dict(pods=100, flow_copies=100, history=10, exporters=100),
    "shared-observers": dict(
        pods=100, flow_copies=100, history=1, exporters=100, observer_copies=3
    ),
    "wide-graph": dict(pods=400, flow_copies=250, history=10, exporters=100),
    "unique-connections": dict(
        pods=100, flow_copies=100, history=1, exporters=100, connections_per_pair=50
    ),
    "connection-cap": dict(
        pods=10, flow_copies=100, history=1, exporters=10, connections_per_pair=100
    ),
}


def command(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def truth(value):
    return value is True or str(value).lower() in ("1", "true")


def warnings(messages):
    return [
        f"{m.get('type', 'UNKNOWN')}: {m.get('text', '')}"
        for m in messages or []
        if m.get("type", "").upper() != "INFO"
    ]


def validate_ports(ports):
    for port in ("8088/tcp", "8089/tcp"):
        bindings = ports.get(port) or []
        if bindings != [{"HostIp": "127.0.0.1", "HostPort": port.split("/")[0]}]:
            raise ValueError(f"Refusing benchmark: {port} must bind only to localhost")


def local_docker_endpoint():
    context = os.environ.get("DOCKER_CONTEXT")
    endpoint = (
        command(
            "docker",
            "context",
            "inspect",
            context,
            "--format",
            "{{.Endpoints.docker.Host}}",
        )
        if context
        else os.environ.get("DOCKER_HOST")
        or command(
            "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
        )
    )
    if not endpoint.startswith("unix:///"):
        raise ValueError("Refusing benchmark: Docker must use a local Unix socket")
    # Pin all subsequent CLI calls, including lab.sh, to the verified local endpoint.
    os.environ.pop("DOCKER_CONTEXT", None)
    os.environ["DOCKER_HOST"] = endpoint


def validate_saved_overrides(text):
    conf = configparser.RawConfigParser()
    conf.read_string(text)
    for section in conf.sections():
        if not section.startswith("ADM - ") or set(conf[section]) - {
            "disabled",
            "enablesched",
        }:
            raise ValueError(
                "Unexpected saved-search override; reinstall the disposable lab app"
            )


def installed_fingerprints():
    fingerprints = {}
    app = ROOT / "splunk_app/splunk_adm"
    for path in sorted((app / "default").glob("*.conf")):
        installed = subprocess.check_output(
            [
                "docker",
                "exec",
                CONTAINER,
                "cat",
                f"/opt/splunk/etc/apps/splunk_adm/default/{path.name}",
            ],
            timeout=30,
        )
        if installed != path.read_bytes():
            raise ValueError(
                f"Installed {path.name} differs from source; run lab.sh install"
            )
        fingerprints[str(path.relative_to(ROOT))] = hashlib.sha256(
            installed
        ).hexdigest()
    # These overrides change pipeline behavior; this harness only changes schedules.
    for name in (
        "macros.conf",
        "transforms.conf",
        "collections.conf",
        "props.conf",
        "limits.conf",
    ):
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "root",
                CONTAINER,
                "test",
                "-e",
                f"/opt/splunk/etc/apps/splunk_adm/local/{name}",
            ],
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            raise ValueError(
                f"Unexpected local/{name}; reinstall the disposable lab app"
            )
        if result.returncode != 1:
            raise ValueError("Unable to inspect lab overrides")
    saved = "/opt/splunk/etc/apps/splunk_adm/local/savedsearches.conf"
    present = subprocess.run(
        ["docker", "exec", "-u", "root", CONTAINER, "test", "-e", saved],
        capture_output=True,
        timeout=30,
    )
    if present.returncode == 0:
        validate_saved_overrides(
            command("docker", "exec", "-u", "root", CONTAINER, "cat", saved)
        )
    elif present.returncode != 1:
        raise ValueError("Unable to inspect saved-search overrides")
    return fingerprints


def request(method, path, data=None, timeout=120):
    sep = "&" if "?" in path else "?"
    with lab._mgmt(
        method, f"{path}{sep}output_mode=json", data, timeout=timeout
    ) as response:
        return json.load(response)


def preflight():
    local_docker_endpoint()
    if lab.MGMT != "https://127.0.0.1:8089" or lab.HEC != "https://127.0.0.1:8088":
        raise ValueError("Benchmark is restricted to the disposable localhost lab")
    validate_ports(
        json.loads(
            command(
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Ports}}",
                CONTAINER,
            )
        )
    )
    info = json.loads(command("docker", "info", "--format", "{{json .}}"))
    image = command("docker", "inspect", "--format", "{{.Config.Image}}", CONTAINER)
    if image != "splunk/splunk:10.6.0.5":
        raise ValueError("Unexpected lab image; update the benchmark after validation")
    image_id = command("docker", "inspect", "--format", "{{.Image}}", CONTAINER)
    limits = json.loads(
        command("docker", "inspect", "--format", "{{json .HostConfig}}", CONTAINER)
    )
    return {
        "installed_default_sha256": installed_fingerprints(),
        "host_architecture": platform.machine(),
        "python": platform.python_version(),
        "docker_architecture": info.get("Architecture"),
        "docker_cpus": info.get("NCPU"),
        "docker_memory_bytes": info.get("MemTotal"),
        "image": image,
        "image_id": image_id,
        "container_memory_limit_bytes": limits.get("Memory"),
        "container_nano_cpus": limits.get("NanoCpus"),
        "container_platform": "linux/amd64 (lab.sh)",
        "memory_measurement": "Sampled cgroup v2 memory.current; entire container including cache, not per-search RSS",
    }


class MemorySampler:
    def __init__(self):
        self.samples = []
        self.errors = 0
        self.stop = threading.Event()
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:
                value = int(
                    command(
                        "docker",
                        "exec",
                        CONTAINER,
                        "cat",
                        "/sys/fs/cgroup/memory.current",
                    )
                )
                self.samples.append((time.monotonic() - self.started, value))
            except (ValueError, subprocess.SubprocessError):
                self.errors += 1
            self.stop.wait(1)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=35)

    def metrics(self):
        return {
            "sampled_container_peak_bytes": max(
                (s[1] for s in self.samples), default=None
            ),
            "memory_samples": len(self.samples),
            "memory_sample_errors": self.errors,
            "memory_sample_target_interval_seconds": 1,
        }


class Runner:
    def __init__(self, timeout):
        self.timeout = timeout
        self.jobs = []
        self.lock = threading.Lock()

    def search(
        self, name, query, earliest="0", latest="now", *, saved=False, index_window=None
    ):
        started = time.monotonic()

        def api(method, path, data=None):
            nonlocal sid
            remaining = self.timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError(f"Search exceeded {self.timeout}s")
            value = request(method, path, data, timeout=min(120, remaining))
            if method == "POST" and "sid" in value:
                sid = value["sid"]
            if time.monotonic() - started > self.timeout:
                raise TimeoutError(f"Search exceeded {self.timeout}s")
            return value

        sid = None
        record = {"name": name, "status": "failed"}
        rows = []
        try:
            if saved:
                path = f"/servicesNS/nobody/splunk_adm/saved/searches/{quote(query, safe='')}/dispatch"
                data = {
                    "dispatch.earliest_time": earliest,
                    "dispatch.latest_time": latest,
                    "trigger_actions": "1",
                }
                if index_window:
                    data.update(
                        {
                            "dispatch.index_earliest": str(index_window[0]),
                            "dispatch.index_latest": str(index_window[1]),
                        }
                    )
            else:
                path = "/servicesNS/admin/splunk_adm/search/v2/jobs"
                data = {
                    "search": lab._query(query),
                    "exec_mode": "normal",
                    "earliest_time": earliest,
                    "latest_time": latest,
                }
            sid = api("POST", path, data)["sid"]
            record["sid"] = sid
            while True:
                content = api("GET", f"/services/search/v2/jobs/{sid}")["entry"][0][
                    "content"
                ]
                if content.get("dispatchState") == "FAILED" or truth(
                    content.get("isFailed")
                ):
                    raise RuntimeError(
                        "; ".join(warnings(content.get("messages"))) or "Search failed"
                    )
                if truth(content.get("isDone")):
                    break
                if time.monotonic() - started > self.timeout:
                    raise TimeoutError(f"Search exceeded {self.timeout}s")
                time.sleep(0.25)
            result = api("GET", f"/services/search/v2/jobs/{sid}/results?count=0")
            rows = result.get("results", [])
            notes = warnings(content.get("messages")) + warnings(result.get("messages"))
            if truth(content.get("isFinalized")):
                notes.append("Search was finalized early")
            if int(content.get("resultCount", -1)) != len(rows):
                notes.append("Fetched row count differs from final result count")
            if truth(result.get("preview")):
                notes.append("Preview results returned")
            record.update(
                status="complete" if not notes else "incomplete",
                warnings=list(dict.fromkeys(notes)),
                run_seconds=float(content.get("runDuration", 0)),
                result_count=len(rows),
                scan_count=int(content.get("scanCount", 0)),
                event_count=int(content.get("eventCount", 0)),
            )
        except Exception as exc:
            record["error"] = str(exc)[:2000]
            if sid:
                try:
                    request(
                        "POST",
                        f"/services/search/v2/jobs/{sid}/control",
                        {"action": "cancel"},
                        timeout=5,
                    )
                except Exception:
                    pass
            raise
        finally:
            if sid:
                record["sid"] = sid
            record["wall_seconds"] = round(time.monotonic() - started, 4)
            with self.lock:
                self.jobs.append(record)
        return rows, record


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wait_count(runner, query, expected, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        rows, job = runner.search("index-visibility", query + " | stats count AS count")
        require(job["status"] == "complete", "Incomplete ingestion check")
        actual = int(rows[0]["count"])
        if actual == expected:
            return
        require(actual < expected, f"Unexpected extra events: {actual} > {expected}")
        if time.monotonic() > deadline:
            raise TimeoutError(f"Only {actual}/{expected} events became searchable")
        time.sleep(1)


def reset_lab(scope_rows):
    subprocess.run(
        [str(ROOT / "tests/splunk/lab.sh"), "reset"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Benchmarks own this disposable lab. Do not inherit test overrides or enabled schedules.
    subprocess.run(
        [
            "docker",
            "exec",
            "-u",
            "root",
            CONTAINER,
            "rm",
            "-f",
            "/opt/splunk/etc/apps/splunk_adm/local/macros.conf",
        ],
        check=True,
    )
    lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")
    deadline = time.monotonic() + 120
    while True:
        try:
            for collection in COLLECTIONS:
                lab._mgmt(
                    "DELETE",
                    f"/servicesNS/nobody/splunk_adm/storage/collections/data/{collection}",
                ).close()
            break
        except lab.LabError:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)
    configs = lab._json("GET", "/servicesNS/nobody/splunk_adm/saved/searches?count=0")
    for entry in configs["entry"]:
        if entry["name"].startswith("ADM - "):
            lab._json(
                "POST",
                f"/servicesNS/nobody/splunk_adm/saved/searches/{quote(entry['name'], safe='')}",
                {"disabled": "0", "is_scheduled": "0"},
            )
    seed_scope(scope_rows)


def seed_scope(scope_rows):
    # SPL does not decode JSON-escaped CSV newlines into actual CSV records.
    # JSON records avoid that ambiguity; verify the stored lookup, not just the write job.
    runner = Runner(60)
    _, job = runner.search(
        "scope-seed",
        "| makeresults format=json data="
        + json.dumps(json.dumps(scope_rows))
        + " | eval observer_kind=lower(observer_kind), observer=lower(observer), "
        + "_key=sha256(json_array(observer_kind, observer)) "
        + "| fields _key observer_kind observer scope cluster "
        + "| outputlookup adm_observer_scope",
    )
    require(job["status"] == "complete", "scope lookup write incomplete")
    actual, job = runner.search("scope-verify", "| inputlookup adm_observer_scope")
    require(job["status"] == "complete", "scope lookup read incomplete")
    keys = ("observer_kind", "observer", "scope", "cluster")
    expected = sorted(
        tuple(
            row.get(k, "").lower()
            if k in ("observer_kind", "observer")
            else row.get(k, "")
            for k in keys
        )
        for row in scope_rows
    )
    observed = sorted(tuple(row.get(k, "") for k in keys) for row in actual)
    require(observed == expected, "scope lookup did not retain all configured mappings")


def load_events(config):
    digest = hashlib.sha256()
    batch, size, count = [], 0, 0
    for event in iter_events(config):
        line = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        digest.update(line + b"\n")
        if batch and size + len(line) + 1 > lab.MAX_BATCH_BYTES:
            lab._hec_post(b"\n".join(batch))
            batch, size = [], 0
        batch.append(line)
        size += len(line) + 1
        count += 1
    if batch:
        lab._hec_post(b"\n".join(batch))
    return count, digest.hexdigest()


def graph_check(rows, expected):
    metas = [r for r in rows if r.get("row_type") == "meta"]
    notes = []
    if len(metas) != 1:
        return ["Expected exactly one graph meta row"]
    value = metas[0].get("warnings", [])
    notes.extend(value if isinstance(value, list) else [value] if value else [])
    counts = {
        kind: sum(r.get("row_type") == kind for r in rows) for kind in ("node", "edge")
    }
    for kind in counts:
        if counts[kind] != expected[f"graph_{kind}s"]:
            notes.append(
                f"Graph {kind} count {counts[kind]} != expected {expected[f'graph_{kind}s']}"
            )
    traffic = [
        r
        for r in rows
        if r.get("row_type") == "edge" and r.get("relationship") == "communicates_with"
    ]
    actual_bytes = sum(float(r.get("bytes", 0)) for r in traffic)
    if actual_bytes != expected["graph_bytes"]:
        notes.append(
            f"Graph traffic bytes {actual_bytes} != expected {expected['graph_bytes']}"
        )
    actual_connections = sum(float(r.get("count", 0)) for r in traffic)
    if actual_connections != expected["graph_connections"]:
        notes.append(
            f"Graph connections {actual_connections} != expected {expected['graph_connections']}"
        )
    return notes


def run_case(name, config, concurrency, repeats, timeout):
    meta = manifest(config)
    result = {
        "name": name,
        "workload": asdict(config),
        "manifest": meta,
        "status": "failed",
        "jobs": [],
    }
    runner = Runner(timeout)
    print(f"{name}: resetting disposable lab", flush=True)
    memory = None
    try:
        reset_lab(meta["scope_rows"])
        with MemorySampler() as memory:
            started = time.monotonic()
            start = int(time.time()) - 1
            count, digest = load_events(config)
            result.update(
                input_sha256=digest,
                load_submit_seconds=round(time.monotonic() - started, 4),
            )
            require(
                count == meta["expected"]["events"], "Generated event count mismatch"
            )
            wait_count(runner, "index=* NOT index=_* NOT index=adm_summary", count)
            result["load_searchable_seconds"] = round(time.monotonic() - started, 4)
            end = int(time.time()) + 1
            time.sleep(2)
            for saved in (
                "ADM - Identity builder",
                "ADM - Service binding",
                "ADM - Conversation rollup",
            ):
                print(f"{name}: {saved}", flush=True)
                rows, job = runner.search(
                    saved, saved, saved=True, index_window=(start, end)
                )
                require(job["status"] == "complete", f"Incomplete {saved}")
                for row in rows:
                    require(not row.get("warnings"), f"{saved}: {row.get('warnings')}")
                if saved.endswith("rollup"):
                    result["rollup_within_five_minutes"] = job["wall_seconds"] < 300
                    wait_count(
                        runner, 'index=adm_summary source="adm:conversation"', len(rows)
                    )
            rows, _ = runner.search(
                "summary-correctness",
                'index=adm_summary source="adm:conversation" | `adm_summary_dedup` | stats sum(records) AS records sum(bytes_c2s) AS bytes count(eval(isnull(rollup_id))) AS unprotected',
            )
            require(
                int(rows[0]["records"]) == meta["expected"]["flows"],
                f"Rollup records mismatch: {rows}",
            )
            require(
                float(rows[0]["bytes"]) == meta["expected"]["flow_bytes"],
                f"Rollup bytes mismatch: {rows}",
            )
            require(int(rows[0]["unprotected"]) == 0, "Rollup lacks replay identities")
            result["summary_totals"] = rows[0]
            result["collection_rows"] = {}
            for collection, expected_key in (
                ("adm_ip_identity", "identity_rows"),
                ("adm_service_workload", "bindings"),
            ):
                rows, _ = runner.search(
                    "collection-count", f"| inputlookup {collection} | stats count"
                )
                value = int(rows[0]["count"])
                result["collection_rows"][collection] = value
                require(
                    value == meta["expected"][expected_key],
                    f"{collection}: {value} != expected {meta['expected'][expected_key]}",
                )
            args = meta["graph_args"]
            query = (
                "`adm_graph("
                + ",".join(
                    json.dumps(args[k])
                    for k in ("service", "environment", "cluster", "namespace")
                )
                + ")`"
            )
            window = meta["window"]

            def graph(label):
                rows, job = runner.search(
                    label, query, window["earliest"], window["latest"]
                )
                job["quality_warnings"] = graph_check(rows, meta["expected"])
                return job

            graph("graph-first")
            for clients in concurrency:
                print(
                    f"{name}: {clients} simultaneous graph requests, {repeats} waves",
                    flush=True,
                )
                for wave in range(repeats):
                    barrier = threading.Barrier(clients)

                    def request(_):
                        barrier.wait(timeout=30)
                        job = graph(f"graph-c{clients}")
                        job.update(concurrency=clients, wave=wave)
                        return job

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=clients
                    ) as pool:
                        list(pool.map(request, range(clients)))
        result.update(memory.metrics())
        result["status"] = (
            "complete"
            if all(
                j["status"] == "complete" and not j.get("quality_warnings")
                for j in runner.jobs
            )
            else "incomplete"
        )
    except Exception as exc:
        result["error"] = str(exc)[:2000]
    finally:
        if memory is not None:
            result.update(memory.metrics())
        result["jobs"] = runner.jobs
    return result


def summary(values):
    return (
        {
            "samples": len(values),
            "median": round(statistics.median(values), 4),
            "max": max(values),
        }
        if values
        else None
    )


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# Synthetic pipeline benchmark",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "Local synthetic measurements; not a production capacity guarantee. Graph timings include dispatch, polling and result download. Memory is sampled for the whole container, including cache. No frontend rendering or live network collectors are measured.",
        "",
        "| Case | Flow records | Exporters | Rollup seconds | Graph median / max seconds | Sampled memory MiB | Result |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for case in report["cases"]:
        jobs = case["jobs"]
        rollup = next(
            (
                j.get("wall_seconds")
                for j in jobs
                if j["name"] == "ADM - Conversation rollup"
            ),
            None,
        )
        times = [j["wall_seconds"] for j in jobs if j["name"].startswith("graph-c")]
        stats = summary(times)
        peak = case.get("sampled_container_peak_bytes")
        lines.append(
            f"| {case['name']} | {case['manifest']['expected']['flows']} | {case['workload'].get('exporters', 1)} | {rollup} | {str(stats['median']) + ' / ' + str(stats['max']) if stats else '—'} | {round(peak / 2**20, 1) if peak else '—'} | {case['status']} |"
        )
        if case.get("error"):
            lines.extend(["", f"{case['name']} error: {case['error']}", ""])
    lines.extend(
        [
            "",
            "See the adjacent JSON for each concurrency level, search messages, correctness checks, fixture fingerprints, and machine configuration. A complete result requires exact synthetic counts and no graph or search warnings. Results do not establish a maximum supported size.",
            "",
        ]
    )
    path.with_suffix(".md").write_text("\n".join(lines))


@with_lab_lock(root=ROOT)
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset-lab",
        action="store_true",
        help="Authorize erasing the disposable lab for every case",
    )
    parser.add_argument("--cases", nargs="+", choices=CASES, default=["smoke"])
    parser.add_argument(
        "--concurrency", nargs="+", type=int, choices=range(1, 9), default=[1, 2, 4]
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/benchmarks/latest.json"
    )
    args = parser.parse_args(argv)
    if not args.reset_lab:
        parser.error(
            "--reset-lab is required; this benchmark erases only the disposable local lab"
        )
    if not 1 <= args.repeats <= 20 or not 10 <= args.timeout <= 1800:
        parser.error("repeats must be 1..20 and timeout 10..1800")
    environment = preflight()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": environment,
        "git_revision": command("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        "git_dirty": bool(command("git", "-C", str(ROOT), "status", "--porcelain")),
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (
                Path(__file__),
                ROOT / "tools/benchmark_fixtures.py",
                ROOT / "splunk_app/splunk_adm/default/macros.conf",
                ROOT / "splunk_app/splunk_adm/default/savedsearches.conf",
            )
        },
        "parameters": {
            "concurrency": args.concurrency,
            "repeats": args.repeats,
            "timeout": args.timeout,
        },
        "cases": [],
    }
    for name in args.cases:
        case = run_case(
            name, Workload(**CASES[name]), args.concurrency, args.repeats, args.timeout
        )
        report["cases"].append(case)
        write_report(args.output, report)
        print(f"{name}: {case['status']}", flush=True)
        if case["status"] == "failed":
            break
    return (
        0
        if len(report["cases"]) == len(args.cases)
        and all(c["status"] == "complete" for c in report["cases"])
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(run_main(main, root=ROOT))
