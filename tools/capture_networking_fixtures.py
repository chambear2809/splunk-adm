#!/usr/bin/env python3
"""Capture the combined Cisco demo from an already initialized, locked lab.

No normalized rows are generated here. All graph, topology, catalog, scope and
Find rows come from the shipped searches, with complete-job evidence and hashes
of the source configuration and raw inputs. The caller owns the lab lifecycle.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import with_lab_lock  # noqa: E402

APPS = {
    "aci": ("cilium-aci-east", "10.61.0.20", "campus-aci"),
    "nxos": ("cilium-nxos-west", "10.71.0.20", "meraki-nxos"),
}
PRIMARY_CLIENT_MACS = {"aci": "02:61:00:00:00:20", "nxos": "02:71:00:00:00:20"}
CLIENT_QUERIES = (
    "10.61.0.20",
    "02:61:00:00:00:20",
    "10.71.0.20",
    "02:71:00:00:00:20",
)


def validate_window(earliest: str, latest: str) -> tuple[str, str]:
    for value in (earliest, latest):
        if not re.fullmatch(r"(?:0|[1-9][0-9]{0,11})", value):
            raise ValueError("capture bounds must be integer epochs")
        if int(value) > 253402300799:
            raise ValueError("capture bounds exceed supported timestamps")
    if int(earliest) >= int(latest):
        raise ValueError("capture window is empty or reversed")
    return earliest, latest


def require_complete(content: dict, rows: list[dict]) -> None:
    messages = content.get("messages")
    result_truncated = content.get("resultIsTruncated")
    if (
        content.get("dispatchState") != "DONE"
        or content.get("isDone") is not True
        or content.get("isFinalized") is not False
        or content.get("eventIsTruncated") is not False
        # Splunk 10.6 may omit resultIsTruncated for complete REST jobs; when
        # present, require an explicit false/zero value.
        or ("resultIsTruncated" in content and result_truncated not in (False, 0, "0"))
        or str(content.get("dropCount")) != "0"
        or str(content.get("resultCount")) != str(len(rows))
        or not isinstance(messages, list)
        or any(
            not isinstance(message, dict)
            or str(message.get("type", "")).upper() != "INFO"
            for message in messages
        )
    ):
        details = {
            key: content.get(key)
            for key in (
                "dispatchState",
                "isDone",
                "isFinalized",
                "eventIsTruncated",
                "resultIsTruncated",
                "dropCount",
                "resultCount",
            )
        }
        details["returnedRows"] = len(rows)
        # Source bodies and complete search text can contain sensitive data.
        # Only expose message severity here; the job SID locates the full log.
        details["messageTypes"] = [
            message.get("type")
            for message in (messages if isinstance(messages, list) else [])
            if isinstance(message, dict)
        ]
        raise RuntimeError(
            "capture search is incomplete, truncated, or has warnings: "
            + json.dumps(details, sort_keys=True)
        )


def search(lab, query: str, earliest: str, latest: str) -> tuple[list[dict], dict]:
    job = lab._json(
        "POST",
        "/servicesNS/admin/splunk_adm/search/v2/jobs",
        {
            "search": lab._query(query),
            "exec_mode": "blocking",
            "earliest_time": earliest,
            "latest_time": latest,
        },
    )
    sid = job["sid"]
    status = lab._wait_job(sid)
    rows = lab._results(sid)
    require_complete(status, rows)
    return rows, {
        "sid": sid,
        "dispatch_state": status["dispatchState"],
        "results": len(rows),
        "scan_count": status.get("scanCount"),
        "run_duration_seconds": status.get("runDuration"),
        "warnings": [],
    }


def require_client(rows: list[dict], platform: str) -> None:
    cluster, address, scope = APPS[platform]
    clients = [
        row
        for row in rows
        if row.get("row_type") == "node"
        and row.get("endpoint_kind") == "network_client"
        and address
        in (
            row.get("addresses")
            if isinstance(row.get("addresses"), list)
            else [row.get("addresses")]
        )
        and row.get("attr_scope") == scope
        and row.get("attr_client_mac") == PRIMARY_CLIENT_MACS[platform]
    ]
    if len(clients) != 1:
        raise RuntimeError(
            f"{platform} capture does not contain its unique scoped network client"
        )
    nodes = {row["id"]: row for row in rows if row.get("row_type") == "node"}
    client = clients[0]
    expected_basis = (
        "meraki_association_flow" if platform == "nxos" else "catalyst_client_snapshot"
    )
    if client.get("attr_attachment_basis") != expected_basis:
        raise RuntimeError(f"{platform} capture lacks the expected attachment evidence")
    frontends = {
        row["target"]
        for row in rows
        if row.get("row_type") == "edge"
        and row.get("source") == client["id"]
        and row.get("relationship") in ("communicates_with", "traffic_observation")
        and nodes.get(row.get("target"), {}).get("endpoint_kind") == "k8s_service"
        and nodes.get(row.get("target"), {}).get("cluster") == cluster
    }
    if not any(
        row.get("row_type") == "edge"
        and row.get("relationship") == "forwards_to"
        and row.get("source") in frontends
        and row.get("confidence") == "observed"
        and "hubble_client_tuple"
        in (
            row.get("evidence")
            if isinstance(row.get("evidence"), list)
            else [row.get("evidence")]
        )
        and nodes.get(row.get("target"), {}).get("cluster") == cluster
        and str(row.get("target", "")).startswith(f"pod:{cluster}/")
        for row in rows
    ):
        raise RuntimeError(
            f"{platform} capture lacks observed frontend/backend attribution"
        )
    if not any(
        row.get("row_type") == "node" and row.get("cluster") == cluster for row in rows
    ):
        raise RuntimeError(f"{platform} capture lacks its cluster identity")
    other = {value[0] for key, value in APPS.items() if key != platform}
    if any(
        row.get("row_type") == "node" and row.get("cluster") in other for row in rows
    ):
        raise RuntimeError(f"{platform} capture contains the other isolated cluster")


def handoff_query(platform: str) -> str:
    cluster, address, scope = APPS[platform]
    arguments = ",".join(
        json.dumps(value) for value in ("checkout", "demo", cluster, "shop")
    )
    return (
        f'| search `adm_graph_inputs_v2({arguments})` | `adm_graph_cluster_settings_v2("{cluster}")` '
        f'| `adm_graph_resolve({arguments})` | `adm_graph_cluster_settings_v2("{cluster}")` '
        f"| `adm_graph_handoffs({arguments})` "
        f'| where adm_row="hconn" AND client_ip="{address}" AND scope="{scope}" '
        "| table client_ip scope adm_cport adm_ct adm_cend adm_fe_id adm_targets handoff_basis server_port transport"
    )


def require_handoff(graph: list[dict], handoffs: list[dict], platform: str) -> None:
    """Bind the aggregate frontend edge to this client's own observed tuple."""
    _, address, scope = APPS[platform]
    nodes = {row["id"]: row for row in graph if row.get("row_type") == "node"}
    clients = {
        row["id"]
        for row in graph
        if row.get("endpoint_kind") == "network_client"
        and row.get("attr_scope") == scope
        and row.get("attr_client_mac") == PRIMARY_CLIENT_MACS[platform]
    }
    observations = [
        row
        for row in graph
        if row.get("row_type") == "edge"
        and row.get("relationship") == "traffic_observation"
        and row.get("source") in clients
    ]
    if not observations:
        raise RuntimeError(f"{platform} has no client flow observations to verify")

    def interval(row, start_field, end_field):
        values = [row.get(start_field), row.get(end_field)]
        try:
            if any(isinstance(value, bool) or value is None for value in values):
                raise ValueError
            start, end = (float(value) for value in values)
            if (
                not all(math.isfinite(value) for value in (start, end))
                or not 0 <= start <= end
            ):
                raise ValueError
            return start, end
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "backend proof requires valid observed time intervals"
            ) from exc

    for observation in observations:
        payload = observation.get("traffic_observations")
        try:
            records = json.loads(payload) if isinstance(payload, str) else payload
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "backend proof has invalid traffic observations"
            ) from exc
        if (
            not isinstance(records, list)
            or not records
            or not all(isinstance(row, dict) for row in records)
        ):
            raise RuntimeError(
                "backend proof requires the original traffic observations"
            )
        destination_addresses = nodes.get(observation.get("target"), {}).get(
            "addresses", []
        )
        if isinstance(destination_addresses, str):
            destination_addresses = [destination_addresses]
        remaining = set(range(len(records)))
        for record in records:
            interval(record, "first_seen", "last_seen")
        for handoff in handoffs:
            targets = handoff.get("adm_targets", [])
            if isinstance(targets, str):
                targets = [targets]
            if (
                handoff.get("client_ip") != address
                or handoff.get("scope") != scope
                or handoff.get("handoff_basis") != "hubble_client_tuple"
                or handoff.get("adm_fe_id") != observation.get("target")
                or not observation.get("source_port")
                or str(handoff.get("adm_cport")) != str(observation.get("source_port"))
            ):
                continue
            hstart, hend = interval(handoff, "adm_ct", "adm_cend")
            matched = any(
                row.get("row_type") == "edge"
                and row.get("relationship") == "forwards_to"
                and row.get("source") == observation.get("target")
                and row.get("target") in targets
                and row.get("confidence") == "observed"
                for row in graph
            )
            if matched:
                for index, record in enumerate(records):
                    start, end = interval(record, "first_seen", "last_seen")
                    if (
                        record.get("source_ip") == address
                        and record.get("destination_ip") in destination_addresses
                        and record.get("scope") == scope
                        and record.get("transport") in {"tcp", "udp"}
                        and record.get("transport") == handoff.get("transport")
                        and str(record.get("source_port"))
                        == str(handoff.get("adm_cport"))
                        and record.get("destination_port") is not None
                        and str(record.get("destination_port"))
                        == str(handoff.get("server_port"))
                        and start <= hend
                        and hstart <= end
                    ):
                        remaining.discard(index)
        if remaining:
            raise RuntimeError(
                f"{platform} client tuple has no matching observed backend handoff"
            )


def require_topology(rows: list[dict]) -> None:
    """Require the fixture's observed MS390/AP adjacencies, not a packet route."""
    authority = '["org-demo","network-demo"]'
    devices = {}
    for row in rows:
        if row.get("row_type") != "device" or row.get("device_authority") != authority:
            continue
        native_id = row.get("native_device_id")
        if native_id in devices:
            raise RuntimeError("Meraki topology contains an ambiguous native device")
        devices[native_id] = row
    serials = ("Q2XX-DEMO-0390", "Q2XX-DEMO-0001", "Q2XX-DEMO-0002")
    if any(serial not in devices for serial in serials):
        raise RuntimeError("Meraki topology is missing the switch or access points")
    for serial in serials:
        device = devices[serial]
        if (
            device.get("scope") != "meraki-nxos"
            or device.get("cluster") != "cilium-nxos-west"
        ):
            raise RuntimeError(
                "Meraki topology inventory has incorrect scope or cluster"
            )
    switch_id = devices[serials[0]]["device_id"]
    for serial, port in zip(serials[1:], ("10", "11"), strict=True):
        ap_id = devices[serial]["device_id"]
        if not any(
            row.get("row_type") == "link"
            and row.get("link_kind") == "physical"
            and row.get("link_source") == "meraki_switch_topology_lldp"
            and row.get("a_device") == switch_id
            and row.get("b_device") == ap_id
            and row.get("a_interface") == port
            and row.get("scope") == "meraki-nxos"
            and row.get("cluster") == "cilium-nxos-west"
            for row in rows
        ):
            raise RuntimeError(
                f"Meraki topology is missing the observed AP uplink on port {port}"
            )


def _digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def require_local_lab(lab) -> None:
    """Pin Docker to the same disposable localhost target used by REST/HEC."""
    from benchmark_pipeline import command, local_docker_endpoint, validate_ports

    local_docker_endpoint()
    if lab.MGMT != "https://127.0.0.1:8089" or lab.HEC != "https://127.0.0.1:8088":
        raise RuntimeError("Cisco fixture tools require the disposable localhost lab")
    validate_ports(
        json.loads(
            command(
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Ports}}",
                "adm-splunk-lab",
            )
        )
    )


def evidence_fingerprints(
    lab, raw_dir: Path, *, require_candidate: bool = False
) -> dict:
    """Bind capture to raw files, installed defaults, effective macros and KV state."""
    require_local_lab(lab)
    app = ROOT / "splunk_app/splunk_adm"
    archive = os.environ.get("ADM_LAB_PACKAGE")
    package_sha256 = None
    if archive:
        # Share only safe archive/source validation. Captures intentionally
        # record effective local overrides; benchmark's override guard does
        # not belong at this evidence boundary.
        from benchmark_pipeline import _package_default_configs

        packaged, package_sha256 = _package_default_configs(app, Path(archive))
        source = {
            path.relative_to(app / "default").as_posix(): path.read_bytes()
            for path in (app / "default").rglob("*.conf")
        }
        expected = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in packaged.items()
        }
        prefix = "/opt/splunk/etc/apps/splunk_adm/default/"
        listing = (
            subprocess.check_output(
                [
                    "docker",
                    "exec",
                    "adm-splunk-lab",
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
            raise RuntimeError(
                "installed default config set differs from provided package"
            )
    else:
        source = {
            path.name: path.read_bytes()
            for path in sorted((app / "default").glob("*.conf"))
        }
        expected = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in source.items()
        }
    candidate = {
        name: hashlib.sha256(content).hexdigest() for name, content in source.items()
    }
    prefix = "/opt/splunk/etc/apps/splunk_adm/default/"
    paths = [prefix + name for name in sorted(expected)]
    response = subprocess.run(
        ["docker", "exec", "-u", "splunk", "adm-splunk-lab", "sha256sum", *paths],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    installed = {}
    for line in response:
        digest, path = line.split(maxsplit=1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or path not in paths:
            raise RuntimeError("installed configuration fingerprint is malformed")
        name = path[len(prefix) :]
        if archive and name in installed:
            raise RuntimeError(
                "installed configuration fingerprint contains duplicates"
            )
        installed[name] = digest
    if set(installed) != set(expected):
        raise RuntimeError("installed configuration fingerprint is incomplete")
    if (archive or require_candidate) and installed != expected:
        origin = "provided package" if archive else "candidate source"
        raise RuntimeError(f"installed configuration differs from the {origin}")
    payload = lab._json(
        "GET", "/servicesNS/nobody/splunk_adm/configs/conf-macros?count=0"
    )
    entries = payload.get("entry", [])
    if int(payload.get("paging", {}).get("total", -1)) != len(entries):
        raise RuntimeError("effective macro configuration is incomplete")
    macros = {
        item["name"]: {
            key: item["content"].get(key)
            for key in ("definition", "args", "validation", "iseval")
        }
        for item in entries
        if item["name"].startswith("adm_")
    }
    if not macros:
        raise RuntimeError("no effective Atlas macros were returned")
    if require_candidate:
        expected = configparser.RawConfigParser(strict=False)
        expected.read_string(
            (ROOT / "splunk_app/splunk_adm/default/macros.conf")
            .read_text()
            .replace("\\\n", "")
        )
        for name in expected.sections():
            for field in ("definition", "args", "validation"):
                if not expected.has_option(name, field):
                    continue
                effective = macros.get(name, {}).get(field)
                if not isinstance(effective, str) or effective.replace(
                    "\n", ""
                ) != expected.get(name, field):
                    raise RuntimeError(
                        f"effective macro {name}/{field} differs from the candidate"
                    )
    response = lab._json("GET", "/servicesNS/nobody/splunk_adm/saved/searches?count=0")
    entries = response.get("entry", [])
    if int(response.get("paging", {}).get("total", -1)) != len(entries):
        raise RuntimeError("effective saved-search configuration is incomplete")
    writer_fields = (
        "search",
        "cron_schedule",
        "disabled",
        "is_scheduled",
        "dispatch.earliest_time",
        "dispatch.latest_time",
        "dispatch.index_earliest",
        "dispatch.index_latest",
    )
    writers = {
        item["name"]: {key: item["content"].get(key) for key in writer_fields}
        for item in entries
        if item["name"].startswith("ADM - ")
    }
    if not writers:
        raise RuntimeError("no effective Atlas saved searches were returned")
    if require_candidate:
        expected = configparser.RawConfigParser(strict=False)
        expected.read_string(
            (ROOT / "splunk_app/splunk_adm/default/savedsearches.conf")
            .read_text()
            .replace("\\\n", "")
        )
        for name in expected.sections():
            for field in writer_fields:
                # The lab deliberately disables schedules; manual dispatches
                # retain the shipped search and input-window definitions.
                if field in {"disabled", "is_scheduled"} or not expected.has_option(
                    name, field
                ):
                    continue
                if str(writers.get(name, {}).get(field)).replace(
                    "\n", ""
                ) != expected.get(name, field):
                    raise RuntimeError(
                        f"effective saved search {name}/{field} differs from the candidate"
                    )
    states = {}
    for collection in (
        "adm_network_source_scope",
        "adm_cilium_cluster_settings",
        "adm_observer_scope",
        "adm_ip_identity",
        "adm_network_client_history",
        "adm_service_workload",
        "adm_service_backends",
        "adm_service_routes",
        "adm_interfaces",
        "adm_aci_policy",
    ):
        rows = lab._json(
            "GET",
            f"/servicesNS/nobody/splunk_adm/storage/collections/data/{collection}?limit=20001",
        )
        if not isinstance(rows, list) or len(rows) > 20000:
            raise RuntimeError(
                f"capture state exceeds the bounded local fixture limit: {collection}"
            )
        if len({row.get("_key") for row in rows}) != len(rows):
            raise RuntimeError(f"duplicate state keys: {collection}")
        states[collection] = _digest(sorted(rows, key=lambda row: row["_key"]))
    raw_files = [
        *sorted(raw_dir.glob("*.ndjson")),
        *(
            raw_dir / name
            for name in (
                "scenario.json",
                "source-profiles.json",
                "capture-manifest.json",
            )
        ),
    ]
    manifest = json.loads((raw_dir / "capture-manifest.json").read_text())
    indices = sorted({*manifest["index_events"], "adm_summary", "adm_summary_v2"})
    if not all(re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in indices):
        raise RuntimeError("invalid local evidence index name")
    # This disposable lab is reset before initialization. Bind all indexed
    # payloads, including replay copies and receipt times, without exporting
    # raw content. The result cap fails closed if the local fixture grows.
    indexed, _ = search(
        lab,
        "search (" + " OR ".join(f"index={name}" for name in indices) + ") "
        "| eval evidence_id=sha256(json_array(index, source, sourcetype, host, tostring(_time), tostring(_indextime), _raw)) "
        "| stats count BY index evidence_id | sort 0 index evidence_id",
        "0",
        "+10y",
    )
    if len(indexed) > 20000:
        raise RuntimeError("indexed evidence exceeds the bounded local fixture limit")
    return {
        "installed_default_sha256": installed,
        **(
            {
                "source_default_sha256": candidate,
                "package_archive_sha256": package_sha256,
            }
            if archive
            else {}
        ),
        "effective_macros_sha256": _digest(macros),
        "effective_savedsearches_sha256": _digest(writers),
        "indexed_content_sha256": _digest(indexed),
        "indexed_record_count": sum(int(row["count"]) for row in indexed),
        "state_sha256": states,
        "raw_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in raw_files
        },
        "generator_sha256": hashlib.sha256(
            (ROOT / "tools/gen_raw_fixtures.py").read_bytes()
        ).hexdigest(),
    }


def capture(
    earliest: str, latest: str, raw_dir: Path, output: Path, initialization: Path
) -> None:
    earliest, latest = validate_window(earliest, latest)
    raw_dir = raw_dir.resolve()
    sys.path.insert(0, str(ROOT / "tests/splunk"))
    import lab

    initialized = json.loads(initialization.read_text())
    current_evidence = evidence_fingerprints(lab, raw_dir, require_candidate=True)
    if initialized.get("fingerprints") != current_evidence:
        raise RuntimeError(
            "raw inputs, configuration or derived state changed since initialization"
        )
    if initialized.get("window") != {"earliest": earliest, "latest": latest}:
        raise RuntimeError("capture window differs from the initialized scenario")
    raw_files = sorted(raw_dir.glob("*.ndjson"))
    if not raw_files:
        raise RuntimeError("raw Cisco scenario files are missing")
    files = [
        ROOT / "tools/gen_raw_fixtures.py",
        raw_dir / "scenario.json",
        raw_dir / "source-profiles.json",
        raw_dir / "capture-manifest.json",
        *raw_files,
    ]
    files += sorted((ROOT / "splunk_app/splunk_adm/default").glob("*.conf"))
    provenance = {
        "dataset": "campus-meraki-two-cluster",
        "method": "Complete Splunk search jobs against TA-shaped synthetic HEC events in the isolated local lab",
        "qualification": "Synthetic parsing and application behavior; actual API collection/exporter decoding not established",
        "captured_at": int(time.time()),
        "generated_input_manifest": json.loads(
            (raw_dir / "capture-manifest.json").read_text()
        ),
        "initialization": {
            key: initialized[key]
            for key in (
                "qualification",
                "window",
                "scenario_window",
                "build_window",
                "indexed_counts",
                "index_window",
                "builders",
            )
        },
        "initialized_lab": current_evidence,
        "initialization_sha256": hashlib.sha256(
            initialization.read_bytes()
        ).hexdigest(),
        "sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in files
        },
    }
    captures = {}

    def run(name, query, **extra):
        rows, evidence = search(lab, query, earliest, latest)
        if not rows:
            raise RuntimeError(f"{name} returned no rows")
        captures[name] = {
            "search": query,
            "earliest": earliest,
            "latest": latest,
            "provenance": {**provenance, "job": evidence},
            **extra,
            "rows": rows,
        }
        return rows

    for platform, (cluster, _, _) in APPS.items():
        args = {
            "service": "checkout",
            "environment": "demo",
            "cluster": cluster,
            "namespace": "shop",
        }
        call = ",".join(json.dumps(value) for value in args.values())
        rows = run(
            f"demo-networking-{platform}", f"| search `adm_graph_v2({call})`", args=args
        )
        require_client(rows, platform)
        query = handoff_query(platform)
        handoffs, evidence = search(lab, query, earliest, latest)
        require_handoff(rows, handoffs, platform)
        captures[f"demo-networking-{platform}"]["client_handoff_verification"] = {
            "search": query,
            "job": evidence,
            "rows": handoffs,
        }
    topology = run("demo-networking-topology", "| search `adm_topology_v2`")
    require_topology(topology)
    run("demo-networking-scopes", "| `adm_scope_options`")
    run("demo-networking-catalog", "| `adm_catalog_build_v2`")
    queries = []
    client_queries = []
    for query in ("checkout", *CLIENT_QUERIES):
        spl = f'| `adm_find_v2("{query}")`'
        rows, evidence = search(lab, spl, earliest, latest)
        queries.append({"query": query, "search": spl, "rows": rows, "job": evidence})
    for query in CLIENT_QUERIES:
        spl = f'| `adm_find_network_client("{query}")`'
        rows, evidence = search(lab, spl, earliest, latest)
        if not rows:
            raise RuntimeError(f"network client Find capture has no result for {query}")
        client_queries.append(
            {"query": query, "search": spl, "rows": rows, "job": evidence}
        )
    captures["demo-networking-find"] = {
        "earliest": earliest,
        "latest": latest,
        "provenance": provenance,
        "queries": queries,
        "network_client_queries": client_queries,
    }
    if evidence_fingerprints(lab, raw_dir, require_candidate=True) != current_evidence:
        raise RuntimeError("configuration or data changed while capturing")
    # Publish only after every capture and semantic check succeeds.
    output.mkdir(parents=True, exist_ok=True)
    for name, payload in captures.items():
        (output / f"{name}.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )


@with_lab_lock(root=ROOT)
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--earliest", required=True)
    parser.add_argument("--latest", required=True)
    parser.add_argument(
        "--raw-dir", type=Path, default=ROOT / "fixtures/raw-networking"
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "fixtures")
    parser.add_argument(
        "--initialization",
        type=Path,
        default=ROOT / "dist/cisco-lab-initialization.json",
    )
    args = parser.parse_args()
    capture(
        args.earliest, args.latest, args.raw_dir, args.output_dir, args.initialization
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
