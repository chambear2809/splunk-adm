"""Read-only pilot readiness analysis for Application Atlas.

The analyzer consumes a plain snapshot and never mutates Splunk.  ``--lab`` is
only a thin, localhost-only evidence collector for the validation lab; a real
connector can provide the same snapshot shape later.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP = "splunk_adm"
EXPECTED_VERSION = "0.3.0"

SOURCES: dict[str, dict[str, Any]] = {
    "netflow": {
        "label": "NetFlow",
        "index": "adm_index_netflow",
        "quality": "netflow",
        "fields": (
            "src_ip",
            "dest_ip",
            "timestamp",
            "endtime",
            "protoid",
            "exporter_ip",
        ),
    },
    "dcn": {
        "label": "DC Networking",
        "index": "adm_index_dcn",
        "quality": ("nd", "aci_acllog"),
        "fields": ("srcIp", "dstIp", "ts", "protocolName", "fabricName"),
    },
    "ftd": {
        "label": "FTD",
        "index": "adm_index_ftd",
        "quality": "ftd",
        "fields": (
            "InitiatorIP",
            "ResponderIP",
            "FirstPacketSecond",
            "Protocol",
            "DeviceIP",
        ),
    },
    "isovalent": {
        "label": "Isovalent",
        "index": "adm_index_isovalent",
        "quality": "isovalent",
        "fields": (
            "process_connect.source_ip",
            "process_connect.destination_ip",
            "time",
            "node_name",
        ),
    },
    "k8s": {
        "label": "Kubernetes",
        "index": "adm_index_k8s",
        "quality": "k8s",
        "fields": ("k8s.cluster.name", "k8s.namespace.name", "object"),
    },
    "traces": {
        "label": "Traces",
        "index": "adm_index_traces",
        "quality": "traces",
        "fields": ("trace_id", "k8s.cluster.name", "k8s.namespace.name"),
    },
    "hubble": {
        "label": "Hubble",
        "index": "adm_index_hubble",
        "quality": ("hubble", "hubble_l7", "hubble_xlate"),
        "fields": (
            "flow.Type",
            "flow.trace_observation_point",
            "flow.IP.source",
            "flow.IP.destination",
        ),
    },
    "summary": {
        "label": "Summary",
        "index": "adm_index_summary",
        "quality": "summary",
        "fields": ("adm_record", "client_ip", "server_ip"),
    },
    "catalyst": {
        "label": "Catalyst client observations",
        "health_names": ("Catalyst Center", "Catalyst client observations"),
        "index": "adm_index_catalyst",
        "quality": (),
        "fields": ("macAddress", "lastUpdatedTime"),
        "source_id": "catalyst_client_snapshot",
    },
    "meraki": {
        "label": "Meraki wireless associations",
        "health_names": ("Meraki", "Meraki wireless associations"),
        "index": "adm_index_meraki",
        "quality": (),
        "fields": ("occurredAt", "networkId", "organizationId", "type"),
        "source_id": "meraki_association",
    },
}
BUILDER_JOBS = (
    "ADM - Identity builder",
    "ADM - Service binding",
    "ADM - Service backends",
    "ADM - Interface inventory",
    "ADM - ACI policy",
    "ADM - Conversation rollup",
)
JOB_SOURCES = {
    "ADM - Identity builder": {"k8s", "dcn"},
    "ADM - Service binding": {"traces"},
    "ADM - Service backends": {"k8s"},
    "ADM - Interface inventory": {"netflow", "dcn", "ftd"},
    "ADM - ACI policy": {"dcn"},
    "ADM - Conversation rollup": {"netflow", "dcn", "ftd", "isovalent", "hubble"},
}
PRUNE_RE = re.compile(r"^ADM - .* prune$")
INVALID_REASONS = {
    "invalid_source_ip",
    "invalid_destination_ip",
    "invalid_observer_ip",
    "invalid_time",
    "invalid_transport",
    "missing_transport",
    "invalid_ports",
    "invalid_counters",
    "invalid_sampling",
    "missing_observer",
}


def _finding(
    check: str,
    status: str,
    message: str,
    source: str | None = None,
    evidence: Any = None,
) -> dict[str, Any]:
    out = {"check": check, "status": status, "message": message}
    if source:
        out["source"] = source
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _rows(snapshot: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = snapshot.get(key, [])
    return value if isinstance(value, list) else []


def _count(value: Any) -> int | None:
    return int(value) if re.fullmatch(r"[0-9]+", str(value)) else None


def _boolean(value: Any) -> bool | None:
    text = str(value).lower()
    if isinstance(value, bool) or text in {"1", "true", "yes", "0", "false", "no"}:
        return value is True or text in {"1", "true", "yes"}
    return None


PRUNE_JOBS = tuple(
    "ADM - " + name + " prune"
    for name in (
        "Identity",
        "Service binding",
        "Service backends",
        "Service routes",
        "ACI policy",
    )
)
ALL_JOBS = set(BUILDER_JOBS + PRUNE_JOBS)
NONFLOW = {"k8s", "traces", "summary", "catalyst", "meraki"}
NETWORK_CLIENT_SOURCES = {"catalyst", "meraki"}


def analyze(snapshot, selected_sources=()):
    """Evaluate bounded evidence; missing or malformed evidence stays unknown."""
    selected = set(selected_sources)
    findings = []

    def add(check, status, message, source=None, evidence=None):
        findings.append(_finding(check, status, message, source, evidence))

    def source_evidence_check(name, check, data, messages, states):
        """Report a narrow, explicit evidence status without treating absence as success."""
        row = data.get(name) if isinstance(data, dict) else None
        if not isinstance(row, dict):
            add(check, "unknown", messages["unavailable"], name)
            return
        state = str(row.get("status", "")).lower()
        status = states.get(state, "unknown")
        evidence = {k: v for k, v in row.items() if k != "status"}
        add(check, status, messages.get(state, messages["unavailable"]), name, evidence)

    for unknown in sorted(selected - SOURCES.keys()):
        add("source_selection", "blocked", f"unknown source: {unknown}")
    if not selected:
        add("source_selection", "unknown", "no sources selected")
    for name, spec in SOURCES.items():
        if name not in selected:
            if name in NETWORK_CLIENT_SOURCES:
                continue
            add("source_selection", "not_selected", "source was not selected", name)
            continue
        macro = snapshot.get("macros", {}).get(spec["index"])
        if macro is None:
            add("macro", "unknown", "index macro evidence unavailable", name)
        elif not isinstance(macro, str) or not re.search(r"\bindex\s*=\s*\S+", macro):
            add("macro", "blocked", "index macro is empty or invalid", name)
        else:
            add("macro", "pass", "index macro is configured", name)
        aliases = spec["quality"]
        aliases = (aliases,) if isinstance(aliases, str) else aliases
        accepted_health_names = set(spec.get("health_names", ())) | {spec["label"]}
        health = next(
            (
                r
                for r in _rows(snapshot, "source_health")
                if r.get("name") in accepted_health_names or r.get("source") in aliases
            ),
            {},
        )
        visible = _count(health.get("records"))
        add(
            "visibility",
            "pass" if visible and health.get("status") == "ok" else "unknown",
            "source records are visible"
            if visible and health.get("status") == "ok"
            else "visibility is unavailable or no records are visible",
            name,
        )
        if name in NETWORK_CLIENT_SOURCES:
            source_evidence_check(
                name,
                "source_permissions",
                snapshot.get("source_permissions", {}),
                {
                    "complete": "source permissions are configured and verified",
                    "partial": "source permissions are incomplete",
                    "unavailable": "source permission evidence is unavailable",
                },
                {"complete": "pass", "partial": "blocked", "unavailable": "unknown"},
            )
            schemas = snapshot.get("raw_schema")
            schema = schemas.get(name, {}) if isinstance(schemas, dict) else {}
            if isinstance(schema, dict) and schema.get("status") in {
                "complete",
                "partial",
            }:
                total, valid = (
                    _count(schema.get("records")),
                    _count(schema.get("valid")),
                )
                if total is None or valid is None or total == 0 or valid > total:
                    schema_status = "unknown"
                    schema_message = "raw schema evidence is unavailable or invalid"
                elif valid != total or schema.get("status") == "partial":
                    schema_status = "blocked"
                    schema_message = (
                        "raw records do not satisfy the source field contract"
                    )
                else:
                    schema_status = "pass"
                    schema_message = "raw records satisfy the source field contract"
                add(
                    "raw_schema",
                    schema_status,
                    schema_message,
                    name,
                    {
                        "records": total,
                        "valid": valid,
                        "required_fields": spec["fields"],
                    },
                )
            else:
                add("raw_schema", "unknown", "raw schema evidence is unavailable", name)
            source_evidence_check(
                name,
                "source_mapping",
                snapshot.get("source_scope", {}),
                {
                    "mapped": "source-to-scope mapping is explicit and unambiguous",
                    "ambiguous": "source-to-scope mapping is ambiguous",
                    "unmapped": "source-to-scope mapping is not configured",
                    "unavailable": "source mapping evidence is unavailable",
                },
                {
                    "mapped": "pass",
                    "ambiguous": "blocked",
                    "unmapped": "warning",
                    "unavailable": "unknown",
                },
            )
            source_evidence_check(
                name,
                "source_history",
                snapshot.get("source_history", {}),
                {
                    "complete": "source history coverage is verified for the qualification window",
                    "partial": "source history has gaps or capped intervals",
                    "unavailable": "source history coverage is unavailable",
                },
                {"complete": "pass", "partial": "warning", "unavailable": "unknown"},
            )
            source_evidence_check(
                name,
                "collection_evidence",
                snapshot.get("collection_evidence", {}),
                {
                    "actual": "actual source collection is verified",
                    "synthetic": "only synthetic test events are present; actual collection is unverified",
                    "unavailable": "actual source collection evidence is unavailable",
                },
                {"actual": "pass", "synthetic": "warning", "unavailable": "unknown"},
            )
            continue
        if name in NONFLOW:
            raw = (snapshot.get("raw_fields") or {}).get(name, {})
            total, valid = _count(raw.get("records")), _count(raw.get("valid"))
            if total is None or valid is None or total == 0 or valid > total:
                add(
                    "required_fields",
                    "unknown",
                    "raw field probe is unavailable or invalid",
                    name,
                )
            elif valid != total:
                add(
                    "required_fields",
                    "blocked",
                    "visible records lack required fields",
                    name,
                    {"records": total, "invalid": total - valid},
                )
            else:
                add(
                    "required_fields",
                    "pass",
                    "all probed records have required fields",
                    name,
                )
            if name == "summary" and total:
                replay = _count(raw.get("replay"))
                add(
                    "replay_identity",
                    "unknown"
                    if replay is None or replay > total
                    else ("warning" if replay < total else "pass"),
                    "summary replay identity coverage",
                    name,
                    {"records": total, "replay": replay},
                )
            continue
        rows = [r for r in _rows(snapshot, "quality") if r.get("source") in aliases]
        valid_counts = bool(rows) and all(
            _count(r.get("records")) is not None for r in rows
        )
        evaluated_rows = [r for r in rows if r.get("reason") == "evaluated"]
        valid_counts = valid_counts and all(
            r.get("status") in {"accepted", "accepted_with_warning", "excluded"}
            for r in evaluated_rows
        )
        evaluated = sum(_count(r.get("records")) or 0 for r in evaluated_rows)
        if not valid_counts or not evaluated:
            add("quality", "unknown", "quality evidence is missing or invalid", name)
            add("observer_mapping", "unknown", "observer coverage is unavailable", name)
            continue
        excluded = sum(
            int(r["records"]) for r in evaluated_rows if r["status"] == "excluded"
        )
        warned = sum(
            int(r["records"])
            for r in evaluated_rows
            if r["status"] == "accepted_with_warning"
        )
        add(
            "quality",
            "warning" if excluded or warned else "pass",
            f"quality evidence: {excluded} excluded, {warned} accepted with warnings",
            name,
            {"excluded": excluded, "warnings": warned},
        )
        reasons = sorted(
            {
                r.get("reason")
                for r in rows
                if r.get("reason") in INVALID_REASONS and int(r["records"]) > 0
            }
        )
        add(
            "required_fields",
            "blocked" if reasons else "pass",
            "invalid required fields detected"
            if reasons
            else "required flow fields passed",
            name,
            reasons,
        )
        unmapped = sum(
            int(r["records"]) for r in rows if r.get("reason") == "unmapped_scope"
        )
        add(
            "observer_mapping",
            "warning" if unmapped else "pass",
            f"{unmapped} visible record(s) have an unmapped observer scope",
            name,
        )

    jobs = {r.get("name"): r for r in _rows(snapshot, "jobs")}
    for name in BUILDER_JOBS:
        if not JOB_SOURCES[name] & selected:
            continue
        row = jobs.get(name, {})
        disabled, scheduled = (
            _boolean(row.get("disabled")),
            _boolean(row.get("is_scheduled")),
        )
        optional = name == "ADM - Interface inventory"
        state = (
            "unknown"
            if disabled is None or scheduled is None
            else (
                ("warning" if optional else "blocked")
                if disabled or not scheduled
                else "pass"
            )
        )
        add(
            "schedule",
            state,
            "builder enabled/scheduled state"
            + (" (optional enrichment)" if optional else ""),
            evidence=name,
        )
    prunes = [jobs.get(name, {}) for name in PRUNE_JOBS]
    if any(
        _boolean(r.get("disabled")) is None or _boolean(r.get("is_scheduled")) is None
        for r in prunes
    ):
        add(
            "prune_schedule",
            "unknown",
            "complete prune schedule evidence is unavailable",
        )
    else:
        paused = all(
            _boolean(r["disabled"]) and not _boolean(r["is_scheduled"]) for r in prunes
        )
        add(
            "prune_schedule",
            "pass" if paused else "warning",
            "maintenance prune schedules are disabled"
            if paused
            else "maintenance prunes are enabled",
        )
    permissions = snapshot.get("permissions") or {}
    entries = permissions.get("saved_searches")
    if not isinstance(entries, list):
        add(
            "permissions",
            "unknown",
            "effective ACL and owner-dispatch evidence is unavailable",
        )
    else:
        allowed = {"admin", "sc_admin"}

        def admin_roles(value):
            return isinstance(value, list) and bool(value) and set(value) <= allowed

        missing = []
        if permissions.get("app_read_roles") != ["*"] or not admin_roles(
            permissions.get("app_write_roles")
        ):
            missing.append("app_acl")
        if (
            len(entries) != len(ALL_JOBS)
            or {e.get("name") for e in entries} != ALL_JOBS
        ):
            missing.append("saved_search_names")
        for entry in entries:
            for kind in ("read", "write"):
                if not admin_roles(entry.get(kind + "_roles")):
                    missing.append(f"{entry.get('name')}:{kind}")
            if entry.get("dispatchAs") != "owner":
                missing.append(f"{entry.get('name')}:dispatchAs")
        add(
            "permissions",
            "blocked" if missing else "pass",
            "effective app/search permission contract",
            evidence={"missing": missing},
        )
    version = (snapshot.get("app") or {}).get("version")
    add(
        "app",
        "unknown"
        if not version
        else ("pass" if version == EXPECTED_VERSION else "warning"),
        "app version evidence",
        evidence={"expected": EXPECTED_VERSION, "version": version},
    )
    counts = {
        state: sum(f["status"] == state for f in findings)
        for state in ("blocked", "warning", "unknown", "not_selected")
    }
    status = next((s for s in ("blocked", "unknown", "warning") if counts[s]), "ready")
    return {
        "selected_sources": sorted(selected & SOURCES.keys()),
        "findings": findings,
        "summary": {
            "status": status,
            "blocked": counts["blocked"],
            "warnings": counts["warning"],
            "unknown": counts["unknown"],
            "not_selected": counts["not_selected"],
        },
    }


def _lab_snapshot(selected_sources: list[str] | None = None) -> dict[str, Any]:
    """Collect lab evidence using only GET/search requests; failures stay unknown."""
    sys.path.insert(0, str(ROOT / "tests" / "splunk"))
    import lab  # type: ignore

    sys.path.insert(0, str(ROOT / "tools"))
    from benchmark_pipeline import Runner

    runner = Runner(120)

    def search(query, earliest="0", latest="+10y"):
        rows, job = runner.search("readiness", query, earliest, latest)
        if job["status"] != "complete":
            raise RuntimeError("search evidence incomplete")
        return rows

    selected_sources = selected_sources or []

    snapshot: dict[str, Any] = {
        "macros": {},
        "source_health": [],
        "quality": [],
        "jobs": [],
        "app": {},
    }

    def collect(key: str, callback) -> None:
        try:
            snapshot[key] = callback()
        except Exception as exc:  # noqa: BLE001 - lab access is an evidence boundary
            snapshot.setdefault("collection_errors", {})[key] = type(exc).__name__

    for spec in SOURCES.values():
        key = spec["index"]
        try:
            snapshot["macros"][key] = lab._json(
                "GET", f"/servicesNS/nobody/{APP}/configs/conf-macros/{key}"
            )["entry"][0]["content"].get("definition", "")
        except Exception as exc:  # noqa: BLE001 - lab access is an evidence boundary
            snapshot.setdefault("collection_errors", {}).setdefault(
                "macros", type(exc).__name__
            )
    collect("source_health", lambda: search("| `adm_health_sources`"))
    collect("quality", lambda: search("| `adm_health_quality`"))

    def saved_search_evidence():
        result = lab._json("GET", f"/servicesNS/nobody/{APP}/saved/searches?count=0")
        jobs = []
        for entry in result.get("entry", []):
            content = entry.get("content", {})
            jobs.append(
                {
                    "name": entry.get("name"),
                    "disabled": content.get("disabled"),
                    "is_scheduled": content.get("is_scheduled"),
                    "dispatchAs": content.get("dispatchAs"),
                    "acl": entry.get("acl", {}),
                }
            )
        app = lab._json("GET", f"/services/apps/local/{APP}").get("entry", [{}])[0]
        app_acl = app.get("acl", {})
        perms = {"saved_searches": []}
        perms["app_read_roles"] = app_acl.get("perms", {}).get("read", [])
        perms["app_write_roles"] = app_acl.get("perms", {}).get("write", [])
        for job in jobs:
            acl = job["acl"]
            perms["saved_searches"].append(
                {
                    "name": job["name"],
                    "read_roles": acl.get("perms", {}).get("read", []),
                    "write_roles": acl.get("perms", {}).get("write", []),
                    "dispatchAs": job.get("dispatchAs"),
                }
            )
        return jobs, perms

    def set_saved_search_evidence():
        jobs, perms = saved_search_evidence()
        snapshot["jobs"] = jobs
        snapshot["permissions"] = perms

    collect("saved_searches", set_saved_search_evidence)

    raw_queries = {
        "k8s": """`adm_index_k8s` sourcetype="kube:object:pods" _index_earliest=-24h _index_latest=now
            | where coalesce(type, "")!="DELETED" AND coalesce('object.status.phase','status.phase', "")!="Pending"
            | eval uid=coalesce('object.metadata.uid','metadata.uid'), ns=coalesce('object.metadata.namespace','metadata.namespace'),
              ip=coalesce('object.status.podIPs{}.ip','status.podIPs{}.ip','object.status.podIP','status.podIP')
            | stats count AS records count(eval(isnotnull(uid) AND isnotnull(ns) AND isnotnull(ip) AND isnotnull('k8s.cluster.name'))) AS valid""",
        "traces": """`adm_index_traces` `adm_traces_sourcetype` _index_earliest=-24h _index_latest=now
            | stats count AS records count(eval(isnotnull(trace_id) AND isnotnull(span_id) AND isnotnull('service.name')
              AND isnotnull('k8s.cluster.name') AND isnotnull('k8s.namespace.name') AND isnotnull('k8s.pod.uid')
              AND tonumber(start_time)>0 AND tonumber(end_time)>=tonumber(start_time))) AS valid""",
        "summary": """`adm_index_summary` source="adm:conversation" _index_earliest=-24h _index_latest=now
            | stats count AS records count(eval(isnotnull(client_ip) AND isnotnull(server_ip) AND tonumber(records)>0)) AS valid
              count(eval(isnotnull(rollup_id) AND replay_protected=1)) AS replay""",
    }
    snapshot["raw_fields"] = {}
    for source in set(selected_sources) & raw_queries.keys():
        try:
            rows = search(raw_queries[source])
            snapshot["raw_fields"][source] = rows[0] if len(rows) == 1 else {}
        except Exception as exc:
            snapshot.setdefault("collection_errors", {})[source] = type(exc).__name__
    collect(
        "app",
        lambda: {
            "version": lab._json("GET", f"/services/apps/local/{APP}")["entry"][0][
                "content"
            ].get("version")
        },
    )
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        action="append",
        choices=sorted(SOURCES),
        help="flow/data source to include; repeat for multiple",
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        help="collect read-only evidence from the localhost validation lab",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    args = parser.parse_args(argv)
    if not args.source:
        parser.error(
            "at least one --source is required; absence is treated as not selected, not outage"
        )
    report = analyze(_lab_snapshot(args.source) if args.lab else {}, args.source)
    print(
        json.dumps(report, indent=2, sort_keys=True)
        if args.json
        else f"status: {report['summary']['status']}\n"
        + "\n".join(
            f"{f['status']:12} {f['check']}: {f['message']}" for f in report["findings"]
        )
    )
    return (
        1
        if report["summary"]["status"] == "blocked"
        else (2 if report["summary"]["status"] == "unknown" else 0)
    )


if __name__ == "__main__":
    raise SystemExit(main())
