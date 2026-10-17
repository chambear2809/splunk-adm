#!/usr/bin/env python3
"""Initialize the disposable localhost lab with the combined Cisco scenario.

This is a synthetic parsing/pipeline check, not an API collector or IPFIX decoder
qualification. The caller owns the complete lab lifecycle under lab_lock.py.
Only tests/splunk/lab.py's fixed localhost endpoints are used.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from capture_networking_fixtures import (  # noqa: E402
    evidence_fingerprints,
    require_complete,
    require_local_lab,
    search,
)
from lab_lock import with_lab_lock  # noqa: E402

BUILDERS = (
    "ADM - Identity builder",
    "ADM - Service binding",
    "ADM - Interface inventory",
    "ADM - Service backends",
    "ADM - ACI policy",
    "ADM - Network client history builder",
    "ADM - Conversation rollup v2",
    "ADM - Traffic observation rollup v2",
)
COLLECTIONS = (
    "adm_observer_scope",
    "adm_ip_identity",
    "adm_service_workload",
    "adm_interfaces",
    "adm_service_backends",
    "adm_service_routes",
    "adm_aci_policy",
    "adm_app_catalog",
    "adm_app_catalog_v2",
    "adm_network_source_scope",
    "adm_network_client_history",
    "adm_cilium_cluster_settings",
)
PROFILE_KEY = (
    "source",
    "source_authority",
    "domain_kind",
    "observation_domain_present",
    "observation_domain_id",
    "vpn_id",
    "routing_domain",
)


def epoch(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def raw_window(paths: list[Path]) -> tuple[str, str]:
    times = [
        json.loads(line)["time"]
        for path in paths
        for line in path.read_text().splitlines()
        if line.strip()
    ]
    if not times or any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        for value in times
    ):
        raise ValueError("raw events require finite nonnegative HEC timestamps")
    # Baseline inventory and stale negative cases precede the graph window.
    # Splunk's latest bound is exclusive, including exact-second observations.
    return str(math.floor(min(times))), str(math.floor(max(times)) + 1)


def _lookup(lab, collection: str, rows: list[dict], key: tuple[str, ...]) -> None:
    if not rows:
        raise ValueError(f"no configured rows for {collection}")
    if collection == "adm_observer_scope":
        rows = [
            {
                **row,
                "observer_kind": str(row.get("observer_kind", "")).lower(),
                "observer": str(row.get("observer", "")).lower(),
            }
            for row in rows
        ]
    identities = [tuple(str(row.get(field, "")) for field in key) for row in rows]
    if len(set(identities)) != len(identities):
        raise ValueError(f"duplicate configured key in {collection}")
    # Let Splunk encode json_array, so lookup and writer key encodings agree.
    data = json.dumps(json.dumps(rows, separators=(",", ":")))
    fields = sorted({field for row in rows for field in row})
    normalization = ", ".join(
        f'{field}=tostring(coalesce({field}, ""))' for field in key
    )
    # Splunk may retype an eval field containing "0" as a number. Cast inside
    # json_array itself so the persisted mapping key equals the reader's key.
    key_arguments = ",".join(f'tostring(coalesce({field}, ""))' for field in key)
    key_expression = f"sha256(json_array({key_arguments}))"
    if collection == "adm_network_source_scope":
        identity = (
            f"| eval mapping_key={key_expression}, duplicate_count=1 "
            "| eval _key=sha256(json_array(mapping_key, scope, cluster, profile, mapping_status)) "
        )
        fields += ["mapping_key", "duplicate_count"]
    else:
        identity = f"| eval _key={key_expression} "
    query = (
        f"| makeresults format=json data={data} "
        f"| eval {normalization} "
        f"{identity}"
        f"| fields _key {' '.join(fields)} | outputlookup {collection}"
    )
    actual, _ = search(lab, query, "0", str(int(time.time()) + 3600))
    if len(actual) != len(rows):
        raise RuntimeError(f"configuration write count differs for {collection}")


def seed_profiles(lab, profiles: dict) -> None:
    _lookup(
        lab,
        "adm_network_source_scope",
        profiles["network_source_scope"],
        PROFILE_KEY,
    )
    _lookup(
        lab,
        "adm_observer_scope",
        profiles["legacy_observer_scope"],
        ("observer_kind", "observer"),
    )
    settings = []
    for item in profiles["clusters"]:
        cilium = item["cilium"]
        settings.append(
            {
                "cluster": item["name"],
                "lb_mode": cilium["loadBalancerMode"],
                "ingress_mode": cilium["ingressMode"],
                "l2announcements_enabled": int(cilium["l2announcementsEnabled"]),
                "mapping_status": "mapped",
            }
        )
    _lookup(lab, "adm_cilium_cluster_settings", settings, ("cluster",))


def wait_summary_readback(lab, name: str, rows: list[dict]) -> None:
    sources = {
        "ADM - Conversation rollup v2": "adm:conversation",
        "ADM - Traffic observation rollup v2": "adm:traffic_observation",
    }
    if name not in sources or not rows:
        return
    expected = {}
    for row in rows:
        key = row.get("rollup_id", "")
        if not re.fullmatch(r"[0-9a-f]{64}", key) or key in expected:
            raise RuntimeError(
                "summary writer returned missing or duplicate replay identities"
            )
        expected[key] = tuple(
            str(row.get(field))
            for field in ("contract_version", "adm_record", "records")
        )
        if expected[key][0] != "2":
            raise RuntimeError("summary writer returned an unsupported contract")
    ids = ",".join(json.dumps(key) for key in sorted(expected))
    query = (
        f'index=adm_summary_v2 source="{sources[name]}" rollup_id IN ({ids}) '
        "| stats values(contract_version) AS contract_version values(adm_record) AS adm_record "
        "values(records) AS records BY rollup_id"
    )
    deadline = time.monotonic() + 120
    while True:
        persisted, _ = search(lab, query, "0", "+10y")
        actual = {
            row["rollup_id"]: tuple(
                str(row.get(field))
                for field in ("contract_version", "adm_record", "records")
            )
            for row in persisted
        }
        if any(
            key not in expected or value != expected[key]
            for key, value in actual.items()
        ):
            raise RuntimeError("persisted summary differs from the writer result")
        if actual == expected:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "summary job completed but exact expected records are not searchable"
            )
        time.sleep(2)


def dispatch(lab, name: str, bounds: tuple[int, int], window: tuple[str, str]):
    path = "/servicesNS/nobody/splunk_adm/saved/searches/" + quote(name, safe="")
    before = lab._json("GET", path)["entry"][0]["content"]
    if before.get("disabled") is not True and before.get("is_scheduled") is not False:
        raise RuntimeError(
            f"fixture loader refuses an active or unknown schedule: {name}"
        )
    saved = {field: str(before[field]) for field in ("disabled", "is_scheduled")}
    state_file = ROOT / "dist/cisco-lab-dispatch.json"
    state_file.parent.mkdir(exist_ok=True)
    state = {
        "name": name,
        "index_window": list(bounds),
        "window": list(window),
        "state": "pending",
    }

    def record():
        temporary = state_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n")
        temporary.chmod(0o600)
        temporary.replace(state_file)

    record()
    try:
        lab._json("POST", path, {"disabled": "0", "is_scheduled": "0"})
        job = lab._json(
            "POST",
            path + "/dispatch",
            {
                "trigger_actions": "0",
                "dispatch.earliest_time": window[0],
                "dispatch.latest_time": window[1],
                "dispatch.index_earliest": str(bounds[0]),
                "dispatch.index_latest": str(bounds[1]),
            },
        )
        sid = job["sid"]
        state.update(state="running", sid=sid)
        record()
        status = lab._wait_job(sid)
        rows = lab._results(sid)
        require_complete(status, rows)
        wait_summary_readback(lab, name, rows)
        lab._json("POST", path, saved)
        state["state"] = "complete"
        record()
        return {
            "name": name,
            "sid": sid,
            "result_count": len(rows),
            "duration_seconds": status.get("runDuration"),
            "index_window": list(bounds),
            "warnings": [],
        }
    except Exception:
        # Never resume a schedule after an unknown dispatch/configuration result.
        # The journal identifies the operation for the lab owner to reconcile.
        state["state"] = "unresolved"
        record()
        try:
            lab._json("POST", path, {"disabled": "1", "is_scheduled": "0"})
        except Exception:
            state["stop_state"] = "unconfirmed"
            record()
        raise


def initialize(raw_dir: Path, output: Path, regenerate: bool) -> dict:
    sys.path.insert(0, str(ROOT / "tests/splunk"))
    import lab

    require_local_lab(lab)
    subprocess.run([str(ROOT / "tests/splunk/lab.sh"), "reset"], check=True)
    deadline = time.monotonic() + 180
    while True:
        status = lab._json("GET", "/services/kvstore/status")["entry"][0]["content"]
        if status.get("current", {}).get("status") == "ready":
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "KV Store did not become ready after the disposable reset"
            )
        time.sleep(3)
    for collection in COLLECTIONS:
        lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/splunk_adm/storage/collections/data/{collection}",
        ).close()
    if regenerate:
        # Snapshot receipt must precede the reference flow. It must never be
        # backdated with a fabricated collector timestamp in a HEC field.
        base = datetime.fromtimestamp(int(time.time()) - 30, timezone.utc)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/gen_raw_fixtures.py"),
                "--scenario",
                "networking",
                "--base-time",
                base.isoformat(),
                "--output-dir",
                str(raw_dir),
            ],
            check=True,
        )
    manifest = json.loads((raw_dir / "capture-manifest.json").read_text())
    profiles = json.loads((raw_dir / "source-profiles.json").read_text())
    # Summary records use five-minute buckets. Include the containing buckets
    # when the synthetic event anchor is not aligned to a scheduler boundary.
    scenario_start = epoch(manifest["window_start"])
    scenario_end = epoch(manifest["window_end"])
    window = (
        str(scenario_start // 300 * 300),
        str(math.ceil(scenario_end / 300) * 300),
    )
    seed_profiles(lab, profiles)
    start = int(time.time()) - 1
    paths = [raw_dir / name for name in manifest["output_events"]]
    build_window = raw_window(paths)
    sent = lab.load(paths)
    expected = sum(manifest["index_events"].values())
    if sent != expected:
        raise RuntimeError("loaded event count differs from the raw manifest")
    deadline = time.monotonic() + 120
    while True:
        rows, _ = search(
            lab,
            "("
            + " OR ".join(f"index={name}" for name in manifest["index_events"])
            + ") | stats count by index",
            *build_window,
        )
        actual = {row["index"]: int(row["count"]) for row in rows}
        if actual == manifest["index_events"]:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"indexed counts differ: {actual}, expected {manifest['index_events']}"
            )
        time.sleep(2)
    end = int(time.time()) + 1
    time.sleep(2)
    builders = []
    for name in BUILDERS:
        result = dispatch(lab, name, (start, end), build_window)
        builders.append(result)
        print(f"{name}: {result['result_count']} results", flush=True)
    evidence = {
        "qualification": "local synthetic parsing/pipeline only",
        "raw_dir": str(raw_dir.relative_to(ROOT)),
        "raw_manifest_sha256": hashlib.sha256(
            (raw_dir / "capture-manifest.json").read_bytes()
        ).hexdigest(),
        "window": dict(zip(("earliest", "latest"), window)),
        "scenario_window": {
            "earliest": str(scenario_start),
            "latest": str(scenario_end),
        },
        "build_window": dict(zip(("earliest", "latest"), build_window)),
        "indexed_counts": actual,
        "index_window": [start, end],
        "builders": builders,
        "fingerprints": evidence_fingerprints(lab, raw_dir),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


@with_lab_lock(root=ROOT)
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset",
        action="store_true",
        required=True,
        help="acknowledge replacing only the disposable localhost lab data",
    )
    parser.add_argument("--regenerate", action="store_true")
    parser.add_argument(
        "--raw-dir", type=Path, default=ROOT / "fixtures/raw-networking"
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/cisco-lab-initialization.json"
    )
    args = parser.parse_args()
    initialize(args.raw_dir.resolve(), args.output.resolve(), args.regenerate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
