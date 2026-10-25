#!/usr/bin/env python3
"""Measure synthetic pipeline workloads in the disposable localhost Splunk lab.

Requires --reset-lab: each case erases this lab's indexes and KV collections.
Never accepts a remote URL or credentials. Raw output is saved incrementally.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import configparser
from collections import Counter
import hashlib
import json
import os
import platform
import re
import signal
import statistics
import subprocess
import sys
import tempfile
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
from stage_lab_package import stage_package  # noqa: E402

CONTAINER = os.environ.get("ADM_LAB_NAME", "adm-splunk-lab")
DEFAULT_RESULT_LIMIT = 20_000
MAX_RESULT_LIMIT = 100_000
DEFAULT_RESULT_PAGE_SIZE = 10_000
MAX_RESULT_PAGE_SIZE = 20_000
LAB_RESET_TIMEOUT_SECONDS = 900
LAB_RESET_DOCKER_TIMEOUT_SECONDS = 30
PROCESS_TERMINATION_GRACE_SECONDS = 5
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


class LabResetTimeout(TimeoutError):
    """A bounded reset subprocess ended without proving the lab's final state."""

    def __init__(self, operation, timeout_seconds, host_process_group_stopped):
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.host_process_group_stopped = host_process_group_stopped
        termination = (
            "host process group stopped"
            if host_process_group_stopped
            else "host process-group termination could not be confirmed"
        )
        super().__init__(
            f"{operation} timed out after {timeout_seconds}s; {termination}; "
            "lab reset state is uncertain"
        )


def _process_group_exists(process_group_id):
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _wait_for_process_group_exit(process_group_id, timeout):
    deadline = time.monotonic() + timeout
    while True:
        exists = _process_group_exists(process_group_id)
        if exists is False:
            return True
        if exists is None or time.monotonic() >= deadline:
            return False
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def _terminate_process_group(process):
    """Stop and confirm only the reset child session, preserving the parent lock."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        # Still make a best effort with SIGKILL below.
        pass
    try:
        process.communicate(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass

    # The group leader may exit on TERM while a descendant ignores it. Check
    # the process group independently of communicate()/the leader's exit.
    exists = _process_group_exists(process.pid)
    if exists is None:
        return False
    if exists:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        if not _wait_for_process_group_exit(
            process.pid, PROCESS_TERMINATION_GRACE_SECONDS
        ):
            return False

    try:
        process.communicate(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        return False
    return (
        process.returncode is not None and _process_group_exists(process.pid) is False
    )


def _run_bounded_subprocess(args, *, timeout, operation, **kwargs):
    """Run reset work in a child process group with a finite deadline."""
    process = subprocess.Popen(args, start_new_session=True, **kwargs)
    try:
        process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stopped = _terminate_process_group(process)
        raise LabResetTimeout(operation, timeout, stopped) from None
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, args)
    return subprocess.CompletedProcess(args, process.returncode)


def truth(value):
    return value is True or str(value).lower() in ("1", "true")


def metric_integer(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        return int(value)
    return None


def metric_number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 and number < float("inf") else None


def metric_flag(value):
    if isinstance(value, bool):
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("0", "1", "false", "true"):
        return value.strip().lower() in ("1", "true")
    return None


def job_metrics(content):
    drop_count = metric_integer(content.get("dropCount"))
    return {
        "run_seconds": metric_number(content.get("runDuration")),
        "scan_count": metric_integer(content.get("scanCount")),
        "event_count": metric_integer(content.get("eventCount")),
        "result_count": metric_integer(content.get("resultCount")),
        "disk_usage_bytes": metric_integer(content.get("diskUsage")),
        "drop_count": drop_count,
        "event_is_truncated": metric_flag(content.get("eventIsTruncated")),
        "result_is_truncated": metric_flag(content.get("resultIsTruncated")),
        "result_is_streaming": metric_flag(content.get("resultIsStreaming")),
        "performance": content.get("performance")
        if isinstance(content.get("performance"), dict)
        else None,
    }


def warnings(messages):
    return [
        f"{m.get('type', 'UNKNOWN')}: {m.get('text', '')}"
        for m in messages or []
        if m.get("type", "").upper() != "INFO"
    ]


def validate_ports(ports):
    for container_port, env_name, default in (
        ("8088/tcp", "ADM_LAB_HEC_PORT", "8088"),
        ("8089/tcp", "ADM_LAB_MGMT_PORT", "8089"),
    ):
        host_port = os.environ.get(env_name, default)
        bindings = ports.get(container_port) or []
        if bindings != [{"HostIp": "127.0.0.1", "HostPort": host_port}]:
            raise ValueError(
                f"Refusing benchmark: {container_port} must bind only to localhost:{host_port}"
            )


def validate_lab_target(lab_client=None):
    client = lab if lab_client is None else lab_client
    if os.environ.get("ADM_LAB_TASK"):
        client.verify_target()
    if not re.fullmatch(r"adm-[a-z0-9-]+", CONTAINER):
        raise ValueError("Refusing benchmark: invalid lab container name")
    for actual, env_name, default in (
        (client.MGMT, "ADM_LAB_MGMT_PORT", "8089"),
        (client.HEC, "ADM_LAB_HEC_PORT", "8088"),
    ):
        port = os.environ.get(env_name, default)
        if not port.isascii() or not port.isdecimal() or not 1024 <= int(port) <= 65535:
            raise ValueError(f"Refusing benchmark: invalid {env_name}")
        if actual != f"https://127.0.0.1:{port}":
            raise ValueError("Benchmark is restricted to the disposable localhost lab")


def non_task_docker_activity():
    running = [
        json.loads(line)
        for line in command("docker", "ps", "--format", "{{json .}}").splitlines()
        if line.strip()
    ]
    return [
        {
            "name": entry.get("Names", "unknown"),
            "image": entry.get("Image", "unknown"),
            "status": entry.get("Status", "unknown"),
        }
        for entry in running
        if entry.get("Names") != CONTAINER
    ]


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


def _package_default_configs(app: Path, archive: Path) -> tuple[dict[str, bytes], str]:
    """Bind safe archive defaults to this source, allowing only generated build."""
    source = {
        path.relative_to(app / "default").as_posix(): path.read_bytes()
        for path in (app / "default").rglob("*.conf")
    }
    with tempfile.TemporaryDirectory(prefix="adm-benchmark-package-") as directory:
        stage = Path(directory)
        archive_sha256 = stage_package(archive, stage)
        packaged = {
            path.relative_to(stage / "splunk_adm/default").as_posix(): path.read_bytes()
            for path in (stage / "splunk_adm/default").rglob("*.conf")
        }
    if source.keys() != packaged.keys():
        raise ValueError("Provided package default config set differs from source")
    for name, content in source.items():
        observed = packaged[name]
        if observed == content:
            continue
        # package-app.mjs prepends exactly this stanza. It does not rewrite
        # source versions, options, whitespace or other configuration bytes.
        build = re.match(rb"\[install\]\nbuild = [1-9][0-9]*\n", observed)
        if name != "app.conf" or build is None or observed[build.end() :] != content:
            raise ValueError(f"Provided package {name} differs from source")
    return packaged, archive_sha256


def installed_fingerprints():
    fingerprints = {}
    app = ROOT / "splunk_app/splunk_adm"
    archive = os.environ.get("ADM_LAB_PACKAGE")
    if archive:
        expected, _ = _package_default_configs(app, Path(archive))
        prefix = "/opt/splunk/etc/apps/splunk_adm/default/"
        listing = (
            subprocess.check_output(
                [
                    "docker",
                    "exec",
                    CONTAINER,
                    "find",
                    prefix.rstrip("/"),
                    "-type",
                    "f",
                    "-name",
                    "*.conf",
                    "-print",
                ],
                timeout=30,
            )
            .decode("utf-8")
            .splitlines()
        )
        if (
            len(listing) != len(set(listing))
            or any(not name.startswith(prefix) for name in listing)
            or {name[len(prefix) :] for name in listing} != expected.keys()
        ):
            raise ValueError(
                "Installed default config set differs from provided package"
            )
    else:
        # Preserve the existing source-only, byte-exact behavior when no
        # archive was explicitly supplied to the owned lab installation.
        expected = {
            path.name: path.read_bytes()
            for path in sorted((app / "default").glob("*.conf"))
        }
    for name, content in sorted(expected.items()):
        installed = subprocess.check_output(
            [
                "docker",
                "exec",
                CONTAINER,
                "cat",
                f"/opt/splunk/etc/apps/splunk_adm/default/{name}",
            ],
            timeout=30,
        )
        if installed != content:
            origin = "provided package" if archive else "source"
            raise ValueError(
                f"Installed {name} differs from {origin}; run lab.sh install"
            )
        fingerprints[str((app / "default" / name).relative_to(ROOT))] = hashlib.sha256(
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
    validate_lab_target()
    port_bindings = json.loads(
        command(
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings.Ports}}",
            CONTAINER,
        )
    )
    validate_ports(port_bindings)
    info = json.loads(command("docker", "info", "--format", "{{json .}}"))
    image = command("docker", "inspect", "--format", "{{.Config.Image}}", CONTAINER)
    if image != "splunk/splunk:10.6.0.5":
        raise ValueError("Unexpected lab image; update the benchmark after validation")
    image_id = command("docker", "inspect", "--format", "{{.Image}}", CONTAINER)
    limits = json.loads(
        command("docker", "inspect", "--format", "{{json .HostConfig}}", CONTAINER)
    )
    labels = (
        json.loads(
            command(
                "docker", "inspect", "--format", "{{json .Config.Labels}}", CONTAINER
            )
        )
        or {}
    )
    mounts = (
        json.loads(
            command("docker", "inspect", "--format", "{{json .Mounts}}", CONTAINER)
        )
        or []
    )
    networks = (
        json.loads(
            command(
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                CONTAINER,
            )
        )
        or {}
    )
    network_mode = command(
        "docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", CONTAINER
    )
    non_task_activity = non_task_docker_activity()
    other_images = Counter(entry["image"] for entry in non_task_activity)
    package = os.environ.get("ADM_LAB_PACKAGE")
    return {
        "container_id": command("docker", "inspect", "--format", "{{.Id}}", CONTAINER),
        "lab_configuration": {
            "task": os.environ.get("ADM_LAB_TASK"),
            "lab_name": CONTAINER,
            "docker_endpoint": os.environ.get("DOCKER_HOST"),
            "ownership_labels": {
                key: labels.get(key)
                for key in ("org.splunk-adm.task", "org.splunk-adm.lab")
            },
            "network_mode": network_mode,
            "networks": sorted(networks),
            "volume_mounts": [
                {
                    "type": mount.get("Type"),
                    "name": mount.get("Name"),
                    "destination": mount.get("Destination"),
                }
                for mount in mounts
                if mount.get("Destination") in ("/opt/splunk/etc", "/opt/splunk/var")
            ],
            "port_bindings": port_bindings,
        },
        "preexisting_running_containers": {
            "count_excluding_this_lab": sum(other_images.values()),
            "images_excluding_this_lab": dict(sorted(other_images.items())),
            "containers_excluding_this_lab": non_task_activity,
            "collection_method": "docker ps before measurement; all non-task containers left running",
            "limits": "Docker activity only; native host-process activity was not attributed by this harness",
        },
        "installed_default_sha256": installed_fingerprints(),
        "package": {
            "archive_name": Path(package).name if package else None,
            "archive_sha256": hashlib.sha256(Path(package).read_bytes()).hexdigest()
            if package
            else None,
            "installed_defaults_basis": "provided_package" if package else "source",
        },
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
        "resource_diagnostics": {
            "per_search_cpu_seconds": None,
            "per_search_rss_bytes": None,
            "per_indexer_cpu_or_io": None,
            "note": "The lab exposes whole-container memory and Splunk job metrics; it does not expose per-search CPU/RSS or production indexer diagnostics in this harness.",
        },
        "cache_conditions": {
            "filesystem_and_search_cache_flushed": False,
            "first_query": "first measured query after ingestion and correctness checks; not a cold-cache measurement",
            "repeated_queries": "subsequent requests share the running Splunk container and host caches",
            "host_load_isolated": False,
        },
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
    def __init__(
        self,
        timeout,
        result_limit=DEFAULT_RESULT_LIMIT,
        page_size=DEFAULT_RESULT_PAGE_SIZE,
    ):
        if type(result_limit) is not int or not 1 <= result_limit <= MAX_RESULT_LIMIT:
            raise ValueError(
                f"result_limit must be an integer in 1..{MAX_RESULT_LIMIT}"
            )
        if type(page_size) is not int or not 1 <= page_size <= MAX_RESULT_PAGE_SIZE:
            raise ValueError(
                f"page_size must be an integer in 1..{MAX_RESULT_PAGE_SIZE}"
            )
        self.timeout = timeout
        self.result_limit = result_limit
        self.page_size = page_size
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
        record = {
            "name": name,
            "status": "failed",
            "result_pages": [],
            "result_page_count": 0,
            "fetched_rows": 0,
            "result_retrieval_seconds": None,
        }
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
                metrics = job_metrics(content)
                record.update(
                    dispatch_state=content.get("dispatchState"),
                    is_done=metric_flag(content.get("isDone")),
                    is_failed=metric_flag(content.get("isFailed")),
                    is_finalized=metric_flag(content.get("isFinalized")),
                    metrics=metrics,
                    metrics_unavailable=[
                        key for key, value in metrics.items() if value is None
                    ],
                    warnings=warnings(content.get("messages")),
                )
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
            result_count = metric_integer(content.get("resultCount"))
            retrieval_limit = self.result_limit + 1
            target_rows = (
                min(result_count, retrieval_limit)
                if result_count is not None
                else min(self.page_size, retrieval_limit)
            )
            retrieval_started = time.monotonic()
            page_notes = []
            page_records = []
            offset = 0
            while offset < target_rows:
                requested = min(self.page_size, target_rows - offset)
                page = api(
                    "GET",
                    f"/services/search/v2/jobs/{sid}/results?count={requested}&offset={offset}",
                )
                page_rows = page.get("results")
                if not isinstance(page_rows, list):
                    raise ValueError("Splunk returned invalid search results")
                page_records.append(
                    {
                        "offset": offset,
                        "requested_count": requested,
                        "returned_count": len(page_rows),
                        "preview": metric_flag(page.get("preview")),
                    }
                )
                page_notes.extend(warnings(page.get("messages")))
                if truth(page.get("preview")):
                    page_notes.append("Preview results returned")
                remaining = retrieval_limit - len(rows)
                rows.extend(page_rows[:remaining])
                if len(page_rows) > requested:
                    page_notes.append("Splunk exceeded a requested result page size")
                if len(page_rows) < requested:
                    page_notes.append(
                        "Result pagination ended before the requested row count"
                    )
                    break
                offset += min(len(page_rows), requested)
                record.update(
                    result_pages=page_records,
                    result_page_count=len(page_records),
                    fetched_rows=len(rows),
                    result_retrieval_seconds=round(
                        time.monotonic() - retrieval_started, 4
                    ),
                )
            notes = warnings(content.get("messages")) + page_notes
            dispatch_state = content.get("dispatchState")
            if not isinstance(dispatch_state, str) or not dispatch_state:
                notes.append("Search dispatch state is unavailable")
            elif dispatch_state.upper() != "DONE":
                notes.append(f"Search dispatch state is {dispatch_state}")
            if not truth(content.get("isDone")):
                notes.append("Search job is not marked done")
            if truth(content.get("isFinalized")):
                notes.append("Search was finalized early")
            if result_count is None:
                notes.append("Final result count is unavailable or invalid")
            elif result_count > self.result_limit:
                notes.append(
                    f"Final result count exceeds configured limit {self.result_limit}; retrieval is bounded to {self.result_limit + 1} rows"
                )
            if result_count is not None and result_count != len(rows):
                if (
                    result_count > self.result_limit
                    and len(rows) == self.result_limit + 1
                ):
                    notes.append("Fetched only the bounded result-limit sentinel rows")
                else:
                    notes.append("Fetched row count differs from final result count")
            if len(rows) > self.result_limit + 1:
                notes.append("Splunk exceeded the requested result retrieval bound")
            drop_count = metrics["drop_count"]
            if content.get("dropCount") is not None and drop_count is None:
                notes.append("Dropped-event count is invalid")
            elif drop_count is not None and drop_count > 0:
                notes.append(f"Search dropped {drop_count} events")
            event_is_truncated = metrics["event_is_truncated"]
            result_is_truncated = metrics["result_is_truncated"]
            if event_is_truncated is True:
                notes.append("Search events were truncated")
            if result_is_truncated is True:
                notes.append("Search results were truncated")
            metrics["result_count"] = result_count
            record.update(
                status="complete" if not notes else "incomplete",
                warnings=list(dict.fromkeys(notes)),
                dispatch_state=dispatch_state,
                is_done=metric_flag(content.get("isDone")),
                is_failed=metric_flag(content.get("isFailed")),
                is_finalized=metric_flag(content.get("isFinalized")),
                result_limit=self.result_limit,
                result_limit_exceeded=result_count is not None
                and result_count > self.result_limit,
                fetched_rows=len(rows),
                result_page_size=self.page_size,
                result_pages=page_records,
                result_page_count=len(page_records),
                result_retrieval_seconds=round(time.monotonic() - retrieval_started, 4),
                metrics=metrics,
                metrics_unavailable=[
                    key for key, value in metrics.items() if value is None
                ],
                run_seconds=metrics["run_seconds"],
                result_count=metrics["result_count"],
                scan_count=metrics["scan_count"],
                event_count=metrics["event_count"],
                disk_usage_bytes=metrics["disk_usage_bytes"],
                scan_events_per_second=(
                    metrics["scan_count"] / metrics["run_seconds"]
                    if metrics["scan_count"] is not None
                    and metrics["run_seconds"] is not None
                    and metrics["run_seconds"] > 0
                    else None
                ),
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
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for {expected} searchable events")
        original_timeout = runner.timeout
        runner.timeout = min(original_timeout, remaining)
        try:
            rows, job = runner.search(
                "index-visibility", query + " | stats count AS count"
            )
        finally:
            runner.timeout = original_timeout
        require(job["status"] == "complete", "Incomplete ingestion check")
        actual = int(rows[0]["count"])
        if actual == expected:
            return
        require(actual < expected, f"Unexpected extra events: {actual} > {expected}")
        if time.monotonic() > deadline:
            raise TimeoutError(f"Only {actual}/{expected} events became searchable")
        time.sleep(1)


def reset_lab(scope_rows):
    _run_bounded_subprocess(
        [str(ROOT / "tests/splunk/lab.sh"), "reset"],
        timeout=LAB_RESET_TIMEOUT_SECONDS,
        operation="lab.sh reset",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Benchmarks own this disposable lab. Do not inherit test overrides or enabled schedules.
    _run_bounded_subprocess(
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
        timeout=LAB_RESET_DOCKER_TIMEOUT_SECONDS,
        operation="remove local macros override",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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
        "lab_reset": {
            "status": "not_started",
            "timeout_seconds": LAB_RESET_TIMEOUT_SECONDS,
            "docker_exec_timeout_seconds": LAB_RESET_DOCKER_TIMEOUT_SECONDS,
        },
    }
    runner = Runner(timeout)
    print(f"{name}: resetting disposable lab", flush=True)
    memory = None
    try:
        try:
            reset_lab(meta["scope_rows"])
        except Exception as exc:
            result["lab_reset"].update(
                status="failed",
                lab_state="uncertain",
                error=str(exc)[:1000],
                host_process_group_stopped=(
                    exc.host_process_group_stopped
                    if isinstance(exc, LabResetTimeout)
                    else None
                ),
            )
            raise
        result["lab_reset"].update(status="complete", lab_state="ready")
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
            "lab_reset_timeout_seconds": LAB_RESET_TIMEOUT_SECONDS,
            "lab_reset_docker_exec_timeout_seconds": LAB_RESET_DOCKER_TIMEOUT_SECONDS,
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
