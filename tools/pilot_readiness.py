"""Read-only pilot readiness analysis for Application Atlas.

The analyzer consumes a plain snapshot and never mutates Splunk.  ``--lab`` is
only a thin, localhost-only evidence collector for the validation lab; a real
connector can provide the same snapshot shape later.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP = "splunk_adm"
EXPECTED_VERSION = "0.4.0"

# One registry defines source names, freshness and builder applicability for the
# UI and this operator tool. Received events never select sources automatically.
REGISTRY = json.loads((ROOT / "config/deployment-health.json").read_text())
SOURCE_DEFINITIONS = {source["id"]: source for source in REGISTRY["sources"]}
SOURCES: dict[str, dict[str, Any]] = {
    source["id"]: {
        "label": source["label"],
        "health_names": tuple(source["healthNames"]),
        "index": source["indexMacros"][0],
        "quality": tuple(source["qualitySources"]),
        "quality_by_contract": source.get("qualitySourcesByContract", {}),
        "fields": tuple(source["requiredFields"]),
        "minimum_contract": source["minimumContract"],
        "cadence": source["cadenceSeconds"],
        "freshness": source["staleAfterSeconds"],
        "quiet": source["quiet"],
    }
    for source in REGISTRY["sources"]
    if (source["selectable"] or source["id"] == "summary")
    and source.get("readinessImpact", "core") != "optional_evidence"
}
BUILDER_JOBS = tuple(
    job["name"] for job in REGISTRY["jobs"] if job["stage"] == "active"
)
JOB_SOURCES = {job["name"]: set(job["sourceIds"]) for job in REGISTRY["jobs"]}
JOB_DEFINITIONS = {job["name"]: job for job in REGISTRY["jobs"]}
CLI_SOURCES = sorted(
    {source["id"] for source in REGISTRY["sources"] if source["selectable"]}
    | {"summary"}
)
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


def _timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        parsed = float(value)
    except (ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) and 0 <= parsed < 253402300800 else None


def _boolean(value: Any) -> bool | None:
    text = str(value).lower()
    if isinstance(value, bool) or text in {"1", "true", "yes", "0", "false", "no"}:
        return value is True or text in {"1", "true", "yes"}
    return None


def _index_names(name, value):
    if not isinstance(value, str):
        return None
    if name in {"adm_summary_index_name", "adm_summary_index_v2_name"}:
        return [value] if re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", value) else []
    if re.fullmatch(r"index=[a-z][a-z0-9_-]{0,79}", value):
        return [value[6:]]
    if re.fullmatch(
        r"\(index=[a-z][a-z0-9_-]{0,79}(?:\s+OR\s+index=[a-z][a-z0-9_-]{0,79})+\)",
        value,
    ):
        return [term[6:] for term in re.split(r"\s+OR\s+", value[1:-1])]
    return []


def _source_configuration(snapshot, source):
    if "source_configuration" in snapshot:
        observed = snapshot["source_configuration"].get(source["id"])
        if observed != "configured":
            return "not_configured" if observed == "not_configured" else "unavailable"
    indexes = [
        _index_names(name, snapshot.get("macros", {}).get(name))
        for name in source["indexMacros"]
    ]
    if any(value is None for value in indexes):
        return "unavailable"
    if any(not value for value in indexes):
        return "not_configured"
    if (
        "derived_traffic" in source["evidence"]
        and len(indexes) > 1
        and any(len(value) != 1 or value[0] != indexes[0][0] for value in indexes)
    ):
        return "not_configured"
    return "configured"


def _receipt_status(snapshot, health, freshness, quiet):
    checked_at = _timestamp(snapshot.get("checked_at"))
    latest_indexed = _timestamp(health.get("latest_indexed"))
    lookback = _count(health.get("probe_lookback_seconds"))
    if (
        checked_at is None
        or latest_indexed is None
        or latest_indexed > checked_at
        or lookback is None
        or lookback < freshness
    ):
        return (
            "unknown",
            "retained receipt evidence cannot establish configured freshness or collection continuity",
        )
    if checked_at - latest_indexed > freshness:
        return (
            "unknown" if quiet else "warning",
            "no recent receipt evidence; collector/checkpoint status remains unknown"
            if quiet
            else "indexed receipt evidence is stale for the configured cadence",
        )
    return (
        "pass",
        "indexed receipt is within the configured freshness window; this does not verify collector permissions",
    )


PRUNE_JOBS = tuple(
    job["name"] for job in REGISTRY["jobs"] if job["name"].endswith(" prune")
)
ALL_JOBS = set(
    re.findall(
        r"(?m)^\[(ADM - [^\]]+)\]$",
        (ROOT / "splunk_app/splunk_adm/default/savedsearches.conf").read_text(),
    )
)
NONFLOW = {"k8s", "traces", "summary", "catalyst", "meraki", "nxos"}
NETWORK_CLIENT_SOURCES = {"catalyst", "meraki"}


def _deployment_settings(snapshot):
    """Validate the same bounded intent schema as the UI, without coercion."""
    value = snapshot.get("deployment_settings")
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "revision",
        "sources",
    }:
        return None
    if value.get("schemaVersion") != 1 or isinstance(value["schemaVersion"], bool):
        return None
    if (
        not isinstance(value.get("revision"), str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value["revision"])
        or not isinstance(value.get("sources"), dict)
    ):
        return None
    selectable = {s["id"] for s in REGISTRY["sources"] if s["selectable"]}
    for source, expectation in value["sources"].items():
        if (
            source not in selectable
            or not isinstance(expectation, dict)
            or set(expectation) != {"state", "cadenceSeconds", "staleAfterSeconds"}
        ):
            return None
        cadence, freshness = (
            expectation["cadenceSeconds"],
            expectation["staleAfterSeconds"],
        )
        if (
            not isinstance(expectation["state"], str)
            or expectation["state"] not in {"active", "staged", "not_selected"}
            or (
                type(cadence) is not int
                or type(freshness) is not int
                or not 60 <= cadence <= freshness <= REGISTRY["probeLookbackSeconds"]
            )
        ):
            return None
    return value


def analyze(snapshot, selected_sources=()):
    """Evaluate bounded evidence; missing or malformed evidence stays unknown."""
    settings = _deployment_settings(snapshot)
    selected = set(selected_sources)
    explicit_selection = bool(selected)
    if not explicit_selection and settings:
        selected = {
            key
            for key, item in settings["sources"].items()
            if item["state"] != "not_selected"
        }
    selected_all = set(selected)
    optional_selected = {
        name
        for name in selected_all
        if SOURCE_DEFINITIONS.get(name, {}).get("readinessImpact")
        == "optional_evidence"
    }
    selected.difference_update(optional_selected)
    contract = snapshot.get("active_contract")
    contract = contract if type(contract) is int and contract in (1, 2) else None
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

    if not explicit_selection and settings is None:
        add(
            "deployment_expectations",
            "unknown",
            "shared deployment expectations are absent, invalid or unavailable",
        )
    if contract is None:
        add(
            "active_contract",
            "unknown",
            "the active data contract has not been verified",
        )
    active_sources = set()
    for unknown in sorted(selected_all - set(CLI_SOURCES)):
        add("source_selection", "blocked", f"unknown source: {unknown}")
    if not selected:
        add("source_selection", "unknown", "no sources selected")
    for name, spec in SOURCES.items():
        if name not in selected:
            if name in NETWORK_CLIENT_SOURCES:
                continue
            add("source_selection", "not_selected", "source was not selected", name)
            continue
        expectation = (settings or {}).get("sources", {}).get(name, {})
        staged = expectation.get("state") == "staged" or (
            contract is not None and spec["minimum_contract"] > contract
        )
        if staged:
            add(
                "source_selection",
                "staged",
                "source integration is intentionally staged for the active contract",
                name,
            )
            continue
        active_sources.add(name)
        configuration = _source_configuration(snapshot, SOURCE_DEFINITIONS[name])
        add(
            "macro",
            {
                "configured": "pass",
                "not_configured": "blocked",
                "unavailable": "unknown",
            }[configuration],
            {
                "configured": "index macros are configured",
                "not_configured": "selected source is not configured; index macros are invalid or inconsistent",
                "unavailable": "index macro evidence unavailable",
            }[configuration],
            name,
        )
        aliases = spec["quality_by_contract"].get(str(contract), spec["quality"])
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
            "pass"
            if visible and health.get("status") in {"ok", "visible"}
            else "unknown",
            "source records are visible"
            if visible and health.get("status") in {"ok", "visible"}
            else "visibility is unavailable or no records are visible",
            name,
        )
        status, message = _receipt_status(
            snapshot,
            health,
            expectation.get("staleAfterSeconds", spec["freshness"]),
            spec["quiet"],
        )
        add("freshness", status, message, name)
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
        if name in NONFLOW and name not in NETWORK_CLIENT_SOURCES:
            if not spec["fields"]:
                # Inventory sources without a raw-field probe have no such
                # acceptance requirement; do not invent a permanently unknown row.
                continue
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
            r.get("status")
            in {
                "accepted",
                "accepted_with_warning",
                "excluded",
                "mapped",
                "unmapped",
                "ambiguous",
                "unsupported",
                "incomplete",
            }
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
            if r["status"]
            in {
                "accepted_with_warning",
                "unmapped",
                "ambiguous",
                "unsupported",
                "incomplete",
            }
        )
        diagnostics = [
            r
            for r in rows
            if _count(r.get("records"))
            and r.get("reason")
            not in {"evaluated", "profile_mapped", "history_observation_valid"}
        ]
        add(
            "quality",
            "warning" if excluded or warned or diagnostics else "pass",
            f"quality evidence: {excluded} excluded, {warned} requiring review",
            name,
            {"excluded": excluded, "warnings": warned},
        )
        if diagnostics:
            add(
                "quality_diagnostics",
                "warning",
                "source-specific quality reasons require review",
                name,
                diagnostics,
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
            "invalid required candidate fields detected"
            if reasons
            else "probed required candidate fields passed",
            name,
            reasons,
        )
        unmapped = sum(
            int(r["records"])
            for r in rows
            if r.get("reason")
            in {
                "unmapped_scope",
                "profile_unmapped",
                "profile_ambiguous",
                "profile_unsupported",
            }
        )
        add(
            "observer_mapping",
            "warning" if unmapped else "pass",
            f"{unmapped} visible record(s) have an unmapped observer scope",
            name,
        )

    # Summaries and profile families are dependencies, not administrator choices.
    # Assess every applicable derived row returned by the selected probes.
    for source in REGISTRY["sources"]:
        name = source["id"]
        if (
            source["selectable"]
            or name in selected
            or contract is None
            or source["contract"] not in (None, contract)
            or not set(source["derivedFrom"]) & active_sources
        ):
            continue
        configuration = _source_configuration(snapshot, source)
        add(
            "macro",
            {
                "configured": "pass",
                "not_configured": "blocked",
                "unavailable": "unknown",
            }[configuration],
            "derived evidence index configuration: " + configuration,
            name,
        )
        names = set(source["healthNames"]) | {source["label"]}
        health = next(
            (
                row
                for row in _rows(snapshot, "source_health")
                if row.get("name") in names
            ),
            {},
        )
        total = _count(health.get("records"))
        if "configuration" in source["evidence"]:
            counts = [
                _count(health.get(field))
                for field in (
                    "mapped_records",
                    "unmapped_records",
                    "ambiguous_records",
                    "unsupported_records",
                    "incomplete_records",
                )
            ]
            if total == 0:
                status, message = (
                    "blocked",
                    "selected source profiles are not configured",
                )
            elif total is None or any(
                value is None or value > total for value in counts
            ):
                status, message = (
                    "unknown",
                    "source profile evidence is unavailable or incomplete",
                )
            elif (
                counts[0] != total
                or any(counts[1:])
                or health.get("status") not in {"mapped", "visible", "ok"}
            ):
                status, message = (
                    "warning",
                    "source profiles are unmapped, conflicting, unsupported or incomplete",
                )
            else:
                status, message = "pass", "source profiles are explicit and complete"
            add("source_mapping", status, message, name, health)
            continue
        add(
            "visibility",
            "pass"
            if total and health.get("status") in {"ok", "visible"}
            else "unknown",
            "derived records are visible"
            if total
            else "required derived records are not visible",
            name,
        )
        status, message = _receipt_status(
            snapshot, health, source["staleAfterSeconds"], source["quiet"]
        )
        add("freshness", status, message, name)

    if selected and not active_sources:
        add(
            "source_selection",
            "unknown",
            "no selected source is active under the verified contract",
        )
    jobs = {r.get("name"): r for r in _rows(snapshot, "jobs")}
    for name in BUILDER_JOBS:
        definition = JOB_DEFINITIONS[name]
        if (
            contract is not None
            and contract not in definition["contracts"]
            and _boolean(jobs.get(name, {}).get("disabled")) is False
        ):
            add(
                "contract_job_conflict",
                "blocked",
                "enabled builder is incompatible with the verified active contract; "
                "an administrator must reconcile its enabled state with the contract",
                evidence={"name": name, "active_contract": contract},
            )
        if (
            contract is None
            or contract not in definition["contracts"]
            or not JOB_SOURCES[name] & active_sources
        ):
            continue
        row = jobs.get(name, {})
        disabled, scheduled = (
            _boolean(row.get("disabled")),
            _boolean(row.get("is_scheduled")),
        )
        optional = not definition["required"]
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
        if definition["required"]:
            success, checked = (
                _timestamp(row.get("last_success")),
                _timestamp(snapshot.get("checked_at")),
            )
            if row.get("last_status") in {"failed", "failure", "error", "skipped"}:
                run_status, run_message = (
                    "blocked",
                    "latest required job failed or skipped",
                )
            elif (
                success is None
                or checked is None
                or success > checked
                or row.get("last_status") != "success"
            ):
                run_status, run_message = (
                    "unknown",
                    "successful required job evidence is unavailable",
                )
            elif (
                checked - success
                > definition["cadenceSeconds"] + definition["graceSeconds"]
            ):
                run_status, run_message = "blocked", "required job success is overdue"
            else:
                run_status, run_message = (
                    "pass",
                    "required job has a recent verified successful run",
                )
            add(
                "job_run",
                run_status,
                run_message,
                evidence={"name": name, "last_success": success},
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
        "optional_evidence": [
            {
                "source": name,
                "state": (
                    "active"
                    if explicit_selection
                    else settings["sources"].get(name, {}).get("state", "active")
                ),
                "status": (
                    "staged"
                    if not explicit_selection
                    and settings["sources"].get(name, {}).get("state") == "staged"
                    else "runtime_diagnostics_not_run"
                ),
                "message": "Optional DNS evidence does not affect core readiness; select an address and scope before requesting diagnostics.",
            }
            for name in sorted(optional_selected)
        ],
        "findings": findings,
        "summary": {
            "status": status,
            "blocked": counts["blocked"],
            "warnings": counts["warning"],
            "unknown": counts["unknown"],
            "not_selected": counts["not_selected"],
        },
    }


def selected_health_probes(snapshot, selected_sources=()):
    """Select approved registry macros before dispatch, including derived evidence."""
    contract = snapshot.get("active_contract")
    if type(contract) is not int or contract not in (1, 2):
        return {"sources": [], "quality": []}
    selected = set(selected_sources)
    shared = _deployment_settings(snapshot)
    if not selected and shared:
        selected = {
            key for key, item in shared["sources"].items() if item["state"] == "active"
        }
    active = {
        source["id"]
        for source in REGISTRY["sources"]
        if source["id"] in selected and source["minimumContract"] <= contract
    }
    sources, quality = [], []
    for source in REGISTRY["sources"]:
        applicable = source["id"] in active or (
            not source["selectable"] and bool(set(source["derivedFrom"]) & active)
        )
        if not applicable or source["contract"] not in (None, contract):
            continue
        if (
            "source_configuration" in snapshot
            and snapshot["source_configuration"].get(source["id"]) != "configured"
        ):
            continue
        sources.append(source["probeMacro"])
        for alias in source.get("qualitySourcesByContract", {}).get(
            str(contract), source["qualitySources"]
        ):
            if alias in REGISTRY["qualityProbes"]:
                quality.append(REGISTRY["qualityProbes"][alias])
    return {
        "sources": list(dict.fromkeys(sources)),
        "quality": list(dict.fromkeys(quality)),
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

    def active_contract():
        from urllib.parse import quote

        selectors = json.loads(
            (ROOT / "research/cisco-pipeline-interface.json").read_text()
        )["activation"]["cutover_selectors"]
        actual = [
            lab._json(
                "GET",
                f"/servicesNS/nobody/{APP}/configs/conf-macros/{quote(item['name'], safe='')}",
            )["entry"][0]["content"]["definition"]
            for item in selectors
        ]

        def normalized(value):
            return re.sub(r"\s+", " ", re.sub(r"\\\r?\n\s*", " ", value)).strip()

        for version, field in ((1, "before"), (2, "after")):
            if all(
                normalized(value) == normalized(item[field])
                for value, item in zip(actual, selectors, strict=True)
            ):
                return version
        raise ValueError("public contract selectors are inconsistent")

    collect("active_contract", active_contract)
    collect(
        "deployment_settings",
        lambda: lab._json(
            "GET",
            f"/servicesNS/nobody/{APP}/adm/deployment-settings",
        )["settings"],
    )
    for key in sorted(
        {name for source in REGISTRY["sources"] for name in source["indexMacros"]}
    ):
        try:
            snapshot["macros"][key] = lab._json(
                "GET", f"/servicesNS/nobody/{APP}/configs/conf-macros/{key}"
            )["entry"][0]["content"].get("definition", "")
        except Exception as exc:  # noqa: BLE001 - lab access is an evidence boundary
            snapshot.setdefault("collection_errors", {}).setdefault(
                "macros", type(exc).__name__
            )

    snapshot["source_configuration"] = {
        source["id"]: _source_configuration(snapshot, source)
        for source in REGISTRY["sources"]
    }
    for part, probes in selected_health_probes(snapshot, selected_sources).items():
        destination = "source_health" if part == "sources" else "quality"
        for probe in probes:
            try:
                snapshot[destination].extend(search(f"| `{probe}`"))
            except Exception as exc:  # noqa: BLE001 - attribute failures to selected probe
                snapshot.setdefault("collection_errors", {})[probe] = type(exc).__name__

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
    try:
        health_jobs = {
            row.get("name"): row for row in search("| `adm_health_jobs`", "-7d", "now")
        }
        for job in snapshot["jobs"]:
            evidence = health_jobs.get(job["name"], {})
            job.update(
                {
                    key: evidence[key]
                    for key in ("last_success", "last_run", "last_status")
                    if key in evidence
                }
            )
    except Exception as exc:  # noqa: BLE001 - unavailable scheduler evidence stays unknown
        snapshot.setdefault("collection_errors", {})["job_health"] = type(exc).__name__

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
    configured_probes = set(
        selected_health_probes(snapshot, selected_sources)["sources"]
    )
    for source in raw_queries:
        if SOURCE_DEFINITIONS[source]["probeMacro"] not in configured_probes:
            continue
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
    # Evidence can arrive while the sequential REST/search probes run.
    # Assess against completion time, while preserving future-clock detection.
    snapshot["checked_at"] = time.time()
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        action="append",
        choices=CLI_SOURCES,
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
    if not args.source and not args.lab:
        parser.error(
            "use --lab for shared deployment expectations or supply at least one --source"
        )
    report = analyze(_lab_snapshot(args.source) if args.lab else {}, args.source or ())
    if args.json:
        output = json.dumps(report, indent=2, sort_keys=True)
    else:
        output = (
            f"status: {report['summary']['status']}\n"
            + "\n".join(
                f"{f['status']:12} {f['check']}: {f['message']}"
                for f in report["findings"]
            )
            + "\noptional evidence:\n"
            + "\n".join(
                f"{item['status']:28} {item['source']}: {item['message']}"
                for item in report["optional_evidence"]
            )
        )
    print(output)
    return (
        1
        if report["summary"]["status"] == "blocked"
        else (2 if report["summary"]["status"] == "unknown" else 0)
    )


if __name__ == "__main__":
    raise SystemExit(main())
