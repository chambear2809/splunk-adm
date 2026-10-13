#!/usr/bin/env python3
"""Rehearse app-state backup/restore into a recreated disposable localhost lab."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import quote, urlencode
from urllib.request import Request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/splunk"))
sys.path.insert(0, str(ROOT / "tools"))
import lab  # noqa: E402
from benchmark_fixtures import Workload, manifest  # noqa: E402
from benchmark_pipeline import (  # noqa: E402
    COLLECTIONS,
    CONTAINER,
    Runner,
    graph_check,
    load_events,
    preflight,
    require,
    reset_lab,
    truth,
    wait_count,
)
from soak_pipeline import checked_search, closed_boundary, graph_query, rollup  # noqa: E402

FILES = (
    "local/macros.conf",
    "local/transforms.conf",
    "local/collections.conf",
    "local/props.conf",
    "local/limits.conf",
    "local/savedsearches.conf",
    "metadata/local.meta",
    "lookups/adm_observer_scope.csv",
)
MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 100_000


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_backup(backup):
    require(
        isinstance(backup, dict) and set(backup) == {"payload", "sha256"},
        "invalid backup envelope",
    )
    payload = backup["payload"]
    require(digest(payload) == backup["sha256"], "backup checksum mismatch")
    require(
        set(payload) == {"schema", "defaults", "files", "collections"}
        and payload["schema"] == 1,
        "unsupported backup schema",
    )
    require(set(payload["files"]) == set(FILES), "backup file allowlist mismatch")
    require(
        set(payload["collections"]) == set(COLLECTIONS),
        "backup collection allowlist mismatch",
    )
    for content in payload["files"].values():
        if content is not None:
            require(isinstance(content, str), "invalid file encoding")
            require(
                len(base64.b64decode(content, validate=True)) <= MAX_BYTES,
                "file too large",
            )
    for rows in payload["collections"].values():
        require(
            isinstance(rows, list) and len(rows) <= MAX_ROWS, "collection too large"
        )
        keys = [row.get("_key") for row in rows if isinstance(row, dict)]
        require(
            len(keys) == len(rows) and all(isinstance(k, str) and k for k in keys),
            "missing collection keys",
        )
        require(len(set(keys)) == len(keys), "duplicate collection keys")
    require(len(canonical(backup)) <= MAX_BYTES, "backup too large")
    return payload


def docker(*args, data=None):
    result = subprocess.run(
        ["docker", *args], input=data, capture_output=True, timeout=120
    )
    if result.returncode:
        raise RuntimeError(
            f"Docker operation failed ({result.returncode}); inspect the disposable lab"
        )
    return result.stdout


def read_file(relative):
    require(relative in FILES, "file not allowed")
    path = f"/opt/splunk/etc/apps/splunk_adm/{relative}"
    # File names are a fixed allowlist, never caller-provided shell fragments.
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-u",
            "root",
            CONTAINER,
            "sh",
            "-c",
            f"if test -f {path}; then cat {path}; else exit 44; fi",
        ],
        capture_output=True,
        timeout=30,
    )
    if result.returncode == 44:
        return None
    require(result.returncode == 0, f"cannot read {relative}")
    require(len(result.stdout) <= MAX_BYTES, "file exceeds backup bound")
    return base64.b64encode(result.stdout).decode()


def write_file(relative, content):
    require(relative in FILES, "file not allowed")
    path = f"/opt/splunk/etc/apps/splunk_adm/{relative}"
    if content is None:
        docker("exec", "-u", "root", CONTAINER, "rm", "-f", path)
    else:
        parent = path.rsplit("/", 1)[0]
        docker(
            "exec",
            "-u",
            "root",
            "-i",
            CONTAINER,
            "sh",
            "-c",
            f"mkdir -p {parent} && cat > {path} && chown splunk:splunk {path} && chmod 600 {path}",
            data=base64.b64decode(content, validate=True),
        )


def kv(method, collection, *, query=None, rows=None):
    require(collection in COLLECTIONS, "collection not allowed")
    path = f"/servicesNS/nobody/splunk_adm/storage/collections/data/{collection}"
    if rows is None:
        with lab._mgmt(
            method, path + ("?" + urlencode(query) if query else ""), timeout=30
        ) as response:
            return json.load(response)
    auth = base64.b64encode(
        f"admin:{lab.read_secrets()['SPLUNK_PASSWORD']}".encode()
    ).decode()
    request = Request(
        lab.MGMT + path + "/batch_save",
        data=canonical(rows),
        method="POST",
        headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"},
    )
    with lab._open(request, timeout=30) as response:
        return json.load(response)


def read_collection(collection, fetch=kv):
    rows, last = [], ""
    while True:
        page = fetch(
            "GET",
            collection,
            query={
                "limit": "500",
                "sort": "_key:1",
                "query": json.dumps({"_key": {"$gt": last}}),
            },
        )
        require(isinstance(page, list), "KV returned an unexpected response")
        if not page:
            break
        keys = [r.get("_key") for r in page]
        require(
            all(isinstance(k, str) and k > last for k in keys)
            and keys == sorted(set(keys)),
            "KV page did not advance strictly",
        )
        rows.extend({k: v for k, v in r.items() if k != "_user"} for r in page)
        require(len(rows) <= MAX_ROWS, "collection exceeds backup bound")
        last = keys[-1]
    return rows


def wait_kv(timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = lab._json("GET", "/services/kvstore/status")["entry"][0]["content"]
        if status.get("current", {}).get("status") == "ready":
            return
        time.sleep(2)
    raise TimeoutError("KV store not ready")


def assert_idle():
    searches = lab._json("GET", "/servicesNS/nobody/splunk_adm/saved/searches?count=0")[
        "entry"
    ]
    require(len(searches) == 11, "unexpected saved-search inventory")
    require(
        all(
            truth(e["content"].get("disabled"))
            and not truth(e["content"].get("is_scheduled"))
            for e in searches
        ),
        "pause every ADM saved search before backup or restore",
    )
    jobs = lab._json("GET", "/services/search/v2/jobs?count=0")["entry"]
    require(
        not any(
            e.get("acl", {}).get("app") == "splunk_adm"
            and not truth(e["content"].get("isDone"))
            for e in jobs
        ),
        "active app jobs prevent a consistent backup",
    )


def pause_writers():
    searches = lab._json("GET", "/servicesNS/nobody/splunk_adm/saved/searches?count=0")[
        "entry"
    ]
    for entry in searches:
        lab._json(
            "POST",
            "/servicesNS/nobody/splunk_adm/saved/searches/"
            + quote(entry["name"], safe=""),
            {"disabled": "1", "is_scheduled": "0"},
        )
    assert_idle()


def capture(defaults):
    assert_idle()
    first = {name: read_collection(name) for name in COLLECTIONS}
    files = {name: read_file(name) for name in FILES}
    second = {name: read_collection(name) for name in COLLECTIONS}
    require(
        first == second and files == {name: read_file(name) for name in FILES},
        "state changed during backup",
    )
    assert_idle()
    payload = {"schema": 1, "defaults": defaults, "files": files, "collections": first}
    backup = {"payload": payload, "sha256": digest(payload)}
    validate_backup(backup)
    return backup


def restore(backup):
    payload = validate_backup(backup)  # No writes until the entire backup validates.
    environment = preflight()
    require(
        environment["installed_default_sha256"] == payload["defaults"],
        "restore requires the identical app defaults",
    )
    wait_kv()
    pause_writers()
    require(
        all(not read_collection(name) for name in COLLECTIONS),
        "restore requires empty target collections",
    )
    for name, content in payload["files"].items():
        write_file(name, content)
    lab.restart()
    wait_kv()
    assert_idle()
    for name, rows in payload["collections"].items():
        for start in range(0, len(rows), 100):
            batch = rows[start : start + 100]
            keys = kv("POST", name, rows=batch)
            require(
                set(keys) == {row["_key"] for row in batch},
                "KV batch restore was incomplete",
            )
    restored = capture(payload["defaults"])
    require(restored == backup, "restored app state differs from backup")


def graph_snapshot(runner, config):
    rows = checked_search(
        runner,
        "restore-map",
        graph_query(config),
        earliest=manifest(config)["window"]["earliest"],
        latest=manifest(config)["window"]["latest"],
    )
    require(
        not graph_check(rows, manifest(config)["expected"]),
        "restored graph does not match fixture expectations",
    )
    return sorted(
        ({k: v for k, v in row.items() if k != "generated_at"} for row in rows),
        key=canonical,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset-lab",
        action="store_true",
        help="authorize deletion and recreation of the disposable lab",
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/restore/latest.json"
    )
    args = parser.parse_args(argv)
    if not args.reset_lab:
        parser.error(
            "--reset-lab required: this rehearsal recreates the disposable lab"
        )
    runner = Runner(180)
    report = {"status": "failed"}
    try:
        environment = preflight()
        defaults = environment["installed_default_sha256"]
        config = Workload(pods=3, history=2, flow_copies=2)
        expected = manifest(config)["expected"]
        reset_lab(manifest(config)["scope_rows"])
        start = closed_boundary()
        sent, fixture_digest = load_events(config)
        wait_count(runner, "index=* NOT index=_* NOT index=adm_summary", sent)
        end = closed_boundary()
        for name in (
            "ADM - Identity builder",
            "ADM - Service binding",
            "ADM - Service backends",
        ):
            checked_search(runner, name, name, saved=True, index_window=(start, end))
        rollup(runner, start, end, expected["flows"], 120)
        for name in COLLECTIONS:
            if not read_collection(name):
                kv(
                    "POST",
                    name,
                    rows=[
                        {
                            "_key": "restore-old",
                            "scope": "restore-other",
                            "cluster": "restore-other",
                            "valid_from": 100,
                            "valid_to": 200,
                        },
                        {
                            "_key": "restore-new",
                            "scope": "restore-other",
                            "cluster": "restore-other",
                            "valid_from": 200,
                        },
                    ],
                )
        lab._json(
            "POST",
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_netflow",
            {"definition": "index=netflow"},
        )
        before_graph = graph_snapshot(runner, config)
        pause_writers()
        backup = capture(defaults)
        location = ROOT / "dist/restore" / uuid.uuid4().hex
        location.mkdir(parents=True, mode=0o700)
        backup_path = location / "backup.json"
        with open(
            backup_path,
            "x",
            encoding="utf-8",
            opener=lambda path, flags: os.open(path, flags, 0o600),
        ) as stream:
            json.dump(backup, stream, sort_keys=True)
        report.update(
            environment=environment,
            backup_path=str(backup_path.relative_to(ROOT)),
            backup_sha256=backup["sha256"],
            collection_rows={
                name: len(rows)
                for name, rows in backup["payload"]["collections"].items()
            },
            fixture_sha256=fixture_digest,
            graph_sha256_before=digest(before_graph),
        )
        print("Backup verified; recreating the disposable container", flush=True)
        # Keep the image and generated lab credentials; discard all server data.
        for action in ("down", "up", "install"):
            subprocess.run(
                [str(ROOT / "tests/splunk/lab.sh"), action],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        loaded = json.loads(backup_path.read_text())
        restore(loaded)
        print(
            "Collections/configuration restored; rebuilding summary from retained synthetic fixtures",
            flush=True,
        )
        start = closed_boundary()
        restored_sent, restored_digest = load_events(config)
        require(
            restored_digest == fixture_digest and restored_sent == sent,
            "rebuild fixture mismatch",
        )
        wait_count(runner, "index=* NOT index=_* NOT index=adm_summary", sent)
        end = closed_boundary()
        lab._json(
            "POST",
            "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Conversation%20rollup",
            {"disabled": "0", "is_scheduled": "0"},
        )
        rollup(runner, start, end, expected["flows"], 120)
        pause_writers()
        after_graph = graph_snapshot(runner, config)
        require(before_graph == after_graph, "map changed after restore/rebuild")
        require(
            {name: read_collection(name) for name in COLLECTIONS}
            == loaded["payload"]["collections"],
            "restored collections drifted after map verification",
        )
        report.update(
            status="complete",
            graph_sha256_after=digest(after_graph),
            summary_flow_records=expected["flows"],
            raw_events=sent,
        )
    except Exception as exc:
        report["error"] = str(exc)[:2000]
    finally:
        report["jobs"] = runner.jobs
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
