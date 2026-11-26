"""Task-owned local Splunk execution and physical readback verifier for v2 scenarios.

This module bridges the offline connected-scenario foundations on main
(``change_scenarios_v2``, ``change_scenario_v2_capture``,
``change_scenario_authorization``, ``change_scenario_receipts``, and
``change_scenario_dispatch``) to an explicitly owned disposable local Splunk lab.

Qualification scope:
- Local disposable Splunk Enterprise 10.6.0.5 lab with TA-shaped synthetic HEC
  ingestion, real Splunk REST search job dispatch, and physical ``_bkt``/``_cd``/
  ``_indextime`` readback verification.
- Does NOT claim live customer/controller source qualification, Splunk Cloud
  qualification, or completion of all 11 timed demo captures.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Protocol

from tools.change_correlation.contracts import canonical_json
from tools.change_scenario_authorization import (
    issue_run_authorization,
    verify_run_authorization,
    write_private_authorization,
)
from tools.change_scenario_dispatch import (
    bind_local_readback,
    verify_local_readback_ownership,
)
from tools.change_scenario_receipts import (
    ReceiptContractError,
    build_expected_receipt_manifest,
    verify_physical_readback,
)
from tools.change_scenario_v2_capture import (
    build_connected_bundle,
    verify_connected_bundle,
)
from tools.change_scenarios_v2 import load_scenario, scenario_template_hash
from tools.raw_fixtures.change_scenarios_v2 import prepare_source_inputs

SCHEMA_VERSION = 1
KIND = "local_connected_scenario_execution_v1"
PHYSICAL_READBACK_QUERY_NAME = "physical_source_readback"


class LocalRunnerError(RuntimeError):
    """Raised when local connected-scenario execution fails closed."""


class LocalSplunkAdapter(Protocol):
    """Minimal task-owned local Splunk lab boundary."""

    def verify_task_owner(self, expected_task_id: str) -> dict[str, Any]: ...

    def wait_kvstore_ready(self, timeout: float = 180.0) -> None: ...

    def ingest_hec_events(self, raw_events: list[dict[str, Any]]) -> int: ...

    def dispatch_readback_search(
        self,
        *,
        spl: str,
        earliest: int | float,
        latest: int | float,
        expected_count: int,
        timeout: float = 120.0,
    ) -> dict[str, Any]: ...


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_value(value: Any) -> str:
    try:
        encoded = canonical_json(value)
    except Exception:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    return _sha_bytes(encoded)


def _spl_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_physical_readback_query(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Build a deterministic, bounded Splunk readback query for emitted records."""
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise LocalRunnerError("Expected receipt manifest has no entries.")
    selectors: set[tuple[str, str, str, str]] = set()
    times: list[float] = []
    for entry in entries:
        index = entry.get("index")
        source = entry.get("source")
        sourcetype = entry.get("sourcetype")
        host = entry.get("host")
        source_time = entry.get("source_time")
        if not all(
            isinstance(item, str) and item for item in (index, source, sourcetype, host)
        ):
            raise LocalRunnerError("Expected receipt entry is missing selector fields.")
        if isinstance(source_time, bool) or not isinstance(source_time, (int, float)):
            raise LocalRunnerError("Expected receipt entry has invalid source_time.")
        selectors.add((index, source, sourcetype, host))
        times.append(float(source_time))
    clauses = [
        (
            f"(index={_spl_quote(index)} source={_spl_quote(source)} "
            f"sourcetype={_spl_quote(sourcetype)} host={_spl_quote(host)})"
        )
        for index, source, sourcetype, host in sorted(selectors)
    ]
    spl = (
        "search "
        + " OR ".join(clauses)
        + " | eval adm_indextime=tonumber(_indextime), adm_event_time=tonumber(_time)"
        + " | table _bkt _cd adm_indextime adm_event_time index source sourcetype host _raw"
    )
    earliest = int(math.floor(min(times))) - 60
    latest = int(math.ceil(max(times))) + 60
    return {
        "name": PHYSICAL_READBACK_QUERY_NAME,
        "literal": spl,
        "sha256": _sha_bytes(spl.encode("utf-8")),
        "earliest": earliest,
        "latest": latest,
    }


def _coerce_epoch(value: Any, label: str) -> int | float:
    if isinstance(value, bool):
        raise LocalRunnerError(f"Physical readback {label} is boolean.")
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError as exc:
            raise LocalRunnerError(
                f"Physical readback {label} is not numeric."
            ) from exc
    else:
        raise LocalRunnerError(f"Physical readback {label} is missing.")
    if not math.isfinite(parsed) or parsed < 0:
        raise LocalRunnerError(f"Physical readback {label} is out of range.")
    rounded = round(parsed)
    return int(rounded) if abs(parsed - rounded) < 1e-6 else parsed


def _raw_payload_candidates(raw_value: Any) -> list[tuple[Any, str]]:
    if isinstance(raw_value, dict):
        return [(raw_value, _sha_value(raw_value))]
    if not isinstance(raw_value, str):
        raise LocalRunnerError("Physical readback row lacks _raw payload.")
    candidates: list[tuple[Any, str]] = [(raw_value, _sha_value(raw_value))]
    stripped = raw_value.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                candidates.append((parsed, _sha_value(parsed)))
        except json.JSONDecodeError:
            pass
    return candidates


def align_physical_readback_rows(
    manifest: dict[str, Any],
    raw_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize Splunk physical rows and align 1-to-1 with manifest order.

    Every returned physical row must carry real ``_bkt``, ``_cd``, and
    ``_indextime`` values and match an expected manifest entry exactly.
    """
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise LocalRunnerError("Receipt manifest entries are empty.")
    if not isinstance(raw_rows, list) or len(raw_rows) != len(entries):
        raise ReceiptContractError("Physical readback count differs from expectation.")

    expected_hashes = {entry["payload_sha256"] for entry in entries}
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        if not isinstance(row, dict):
            raise ReceiptContractError("Physical readback row is malformed.")
        bkt = row.get("_bkt")
        cd = row.get("_cd")
        if not isinstance(bkt, str) or not bkt.strip():
            raise ReceiptContractError("Physical readback lacks _bkt.")
        if not isinstance(cd, str) or not cd.strip():
            raise ReceiptContractError("Physical readback lacks _cd.")
        indextime = _coerce_epoch(
            row.get("adm_indextime", row.get("_indextime")), "_indextime"
        )
        source_time = _coerce_epoch(
            row.get("adm_event_time", row.get("_time")), "_time"
        )
        if "event" in row:
            event_payload = row["event"]
            payload_sha = _sha_value(event_payload)
        else:
            candidates = _raw_payload_candidates(row.get("_raw"))
            event_payload, payload_sha = next(
                (item for item in candidates if item[1] in expected_hashes),
                candidates[0],
            )
        normalized = {
            "_bkt": bkt,
            "_cd": cd,
            "_indextime": indextime,
            "_time": source_time,
            "index": row.get("index"),
            "source": row.get("source"),
            "sourcetype": row.get("sourcetype"),
            "host": row.get("host"),
            "event": event_payload,
            "record_id": f"{bkt}:{cd}",
        }
        key = (
            normalized["index"],
            normalized["source"],
            normalized["sourcetype"],
            normalized["host"],
            normalized["_time"],
            payload_sha,
        )
        buckets[key].append(normalized)

    aligned: list[dict[str, Any]] = []
    for entry in entries:
        key = (
            entry["index"],
            entry["source"],
            entry["sourcetype"],
            entry["host"],
            entry["source_time"],
            entry["payload_sha256"],
        )
        matched = buckets.get(key)
        if not matched:
            raise ReceiptContractError(
                f"Physical readback missing expected record {entry['event_id']}#{entry['ordinal']}."
            )
        aligned.append(matched.pop(0))
    return aligned


def execute_local_connected_scenario(
    scenario_id: str,
    *,
    task_id: str,
    execution_id: str,
    anchor_epoch: int,
    authorization_path: Path,
    adapter: LocalSplunkAdapter,
    variant_id: str | None = None,
    issued_epoch: int | None = None,
    readback_timeout: float = 120.0,
) -> dict[str, Any]:
    """Execute one v2 connected scenario against a task-owned local Splunk lab."""
    owner_info = adapter.verify_task_owner(task_id)
    if owner_info.get("task_id") != task_id:
        raise LocalRunnerError("Local lab task owner differs from requested task_id.")

    scenario = load_scenario(scenario_id, variant_id)
    bundle = build_connected_bundle(
        scenario_id,
        variant_id=variant_id,
        execution_id=execution_id,
        anchor_epoch=anchor_epoch,
    )
    verify_connected_bundle(bundle)

    manifest = build_expected_receipt_manifest(
        scenario_id,
        variant_id=variant_id,
        execution_id=execution_id,
        anchor_epoch=anchor_epoch,
    )
    manifest_sha256 = _sha_value(manifest)

    query = build_physical_readback_query(manifest)
    plan_body = {
        "schema_version": SCHEMA_VERSION,
        "scenario_id": scenario["scenario_id"],
        "variant_id": scenario["variant_id"],
        "template_sha256": scenario_template_hash(scenario),
        "execution_id": execution_id,
        "anchor_epoch": anchor_epoch,
        "bundle_sha256": bundle["bundle_sha256"],
        "manifest_sha256": manifest_sha256,
    }
    plan = {**plan_body, "plan_sha256": _sha_bytes(canonical_json(plan_body))}

    approved_entries = [
        {
            "name": query["name"],
            "sha256": query["sha256"],
            "earliest": query["earliest"],
            "latest": query["latest"],
        }
    ]
    authorization = issue_run_authorization(
        plan,
        task_id=task_id,
        approved_queries=approved_entries,
        issued_epoch=int(time.time()) if issued_epoch is None else issued_epoch,
    )
    write_private_authorization(authorization_path, authorization)
    stored_authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    verified_authorization = verify_run_authorization(
        stored_authorization,
        expected_task_id=task_id,
        expected_plan_sha256=plan["plan_sha256"],
        expected_execution_id=execution_id,
        expected_queries=approved_entries,
    )

    adapter.wait_kvstore_ready()
    inputs = prepare_source_inputs(
        scenario, execution_id=execution_id, anchor_epoch=anchor_epoch
    )
    raw_events = [
        raw for event in inputs["events"] for raw in event.get("raw_events", [])
    ]
    ingested_count = adapter.ingest_hec_events(raw_events)
    if ingested_count != len(raw_events):
        raise LocalRunnerError(
            f"Ingested event count ({ingested_count}) differs from emitted count ({len(raw_events)})."
        )

    dispatch_result = adapter.dispatch_readback_search(
        spl=query["literal"],
        earliest=query["earliest"],
        latest=query["latest"],
        expected_count=len(manifest["entries"]),
        timeout=readback_timeout,
    )
    if dispatch_result.get("dispatch_state") != "DONE":
        raise LocalRunnerError("Splunk readback search job did not finish cleanly.")
    sid = dispatch_result.get("sid")
    dispatch_epoch = dispatch_result.get("dispatch_epoch")
    raw_rows = dispatch_result.get("rows")
    if not isinstance(raw_rows, list):
        raise LocalRunnerError("Splunk readback did not return a row list.")

    aligned_rows = align_physical_readback_rows(manifest, raw_rows)
    receipt_verification = verify_physical_readback(
        manifest,
        aligned_rows,
        expected_manifest_sha256=manifest_sha256,
    )

    dispatch_rows = [
        {
            "_indextime": row["_indextime"],
            "record_id": row["record_id"],
            "index": row["index"],
            "source": row["source"],
            "sourcetype": row["sourcetype"],
            "host": row["host"],
            "_time": row["_time"],
        }
        for row in aligned_rows
    ]
    indextimes = [row["_indextime"] for row in dispatch_rows]
    index_time_bounds = {"earliest": min(indextimes), "latest": max(indextimes)}
    receipt_fingerprints = sorted(
        _sha_bytes(
            canonical_json(
                {
                    "_indextime": row["_indextime"],
                    "record_id": row["record_id"],
                }
            )
        )
        for row in dispatch_rows
    )
    readback_payload = {
        "complete": True,
        "sid": sid,
        "task_id": task_id,
        "plan_sha256": plan["plan_sha256"],
        "rows": dispatch_rows,
        "receipt_fingerprints": receipt_fingerprints,
        "index_time_bounds": index_time_bounds,
    }
    approved_query_hashes = {
        item["sha256"] for item in verified_authorization["approved_queries"]
    }
    ownership = bind_local_readback(
        plan,
        task_id=task_id,
        sid=sid,
        query_literal=query["literal"],
        dispatch_epoch=dispatch_epoch,
        readback=readback_payload,
        expected_task_id=task_id,
        expected_plan_sha256=plan["plan_sha256"],
        expected_execution_id=execution_id,
        expected_sid=sid,
        expected_query_sha256=query["sha256"],
        approved_query_sha256=approved_query_hashes,
    )
    verify_local_readback_ownership(
        ownership,
        expected_task_id=task_id,
        expected_plan_sha256=plan["plan_sha256"],
        expected_execution_id=execution_id,
        expected_sid=sid,
        expected_query_sha256=query["sha256"],
        approved_query_sha256=approved_query_hashes,
        expected_readback={
            "row_count": len(dispatch_rows),
            "rows_sha256": _sha_bytes(canonical_json(dispatch_rows)),
            "receipt_fingerprints": receipt_fingerprints,
            "index_time_bounds": index_time_bounds,
        },
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "scenario_id": scenario["scenario_id"],
        "variant_id": scenario["variant_id"],
        "task_id": task_id,
        "execution_id": execution_id,
        "plan_sha256": plan["plan_sha256"],
        "bundle_sha256": bundle["bundle_sha256"],
        "manifest_sha256": manifest_sha256,
        "authorization_sha256": verified_authorization["authorization_sha256"],
        "ownership_sha256": ownership["ownership_sha256"],
        "sid": sid,
        "caller": dispatch_result.get("caller"),
        "row_count": receipt_verification["row_count"],
        "index_time_bounds": index_time_bounds,
        "receipt_fingerprints": receipt_fingerprints,
        "qualification_scope": {
            "installed_local_splunk_synthetic_hec": True,
            "live_customer_sources_qualified": False,
            "all_eleven_timed_captures_qualified": False,
        },
    }


class SplunkLabAdapter:
    """Task-owned local Splunk lab adapter backed by ``tests.splunk.lab``."""

    def __init__(self, lab_module: Any | None = None) -> None:
        if lab_module is None:
            from tests.splunk import lab as default_lab

            lab_module = default_lab
        self._lab = lab_module

    def verify_task_owner(self, expected_task_id: str) -> dict[str, Any]:
        identity = self._lab.task_identity()
        if identity is None:
            raise LocalRunnerError("Installed execution requires an explicit task lab.")
        task_id, lab_name = identity
        if task_id != expected_task_id:
            raise LocalRunnerError(
                f"Active task lab ({task_id}) does not match expected task ({expected_task_id})."
            )
        self._lab.verify_target()
        return {"task_id": task_id, "lab_name": lab_name}

    def wait_kvstore_ready(self, timeout: float = 180.0) -> None:
        deadline = time.monotonic() + timeout
        last_status = None
        while time.monotonic() < deadline:
            try:
                info = self._lab._json("GET", "/services/kvstore/status")
                status = (
                    info.get("entry", [{}])[0]
                    .get("content", {})
                    .get("current", {})
                    .get("status")
                )
                last_status = status
                if status == "ready":
                    return
            except Exception as exc:
                last_status = str(exc)
            time.sleep(2)
        raise LocalRunnerError(f"KV Store did not become ready: {last_status}")

    def ingest_hec_events(self, raw_events: list[dict[str, Any]]) -> int:
        batch: list[bytes] = []
        size = 0
        count = 0
        for raw in raw_events:
            encoded = json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            if batch and size + len(encoded) > self._lab.MAX_BATCH_BYTES:
                self._lab._hec_post(b"\n".join(batch))
                batch, size = [], 0
            batch.append(encoded)
            size += len(encoded) + 1
            count += 1
        if batch:
            self._lab._hec_post(b"\n".join(batch))
        return count

    def dispatch_readback_search(
        self,
        *,
        spl: str,
        earliest: int | float,
        latest: int | float,
        expected_count: int,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last_result: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            dispatch_epoch = int(time.time())
            data = {
                "search": self._lab._query(spl),
                "exec_mode": "normal",
                "earliest_time": str(earliest),
                "latest_time": str(latest),
            }
            created = self._lab._json(
                "POST", f"/servicesNS/nobody/{self._lab.APP}/search/v2/jobs", data
            )
            sid = created["sid"]
            content = self._lab._wait_job(
                sid, timeout=max(10.0, deadline - time.monotonic())
            )
            rows = self._lab._results(sid)
            last_result = {
                "sid": sid,
                "dispatch_state": content.get("dispatchState"),
                "dispatch_epoch": dispatch_epoch,
                "caller": content.get("author") or "admin",
                "rows": rows,
            }
            if len(rows) >= expected_count:
                return last_result
            time.sleep(2)
        if last_result is None:
            raise LocalRunnerError("Splunk readback search was never dispatched.")
        return last_result
