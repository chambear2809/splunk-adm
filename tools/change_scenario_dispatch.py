"""Task-owned local dispatch/readback ownership contract.

This module does not dispatch searches. A local lab adapter supplies the SID and
readback; this verifier binds both to the immutable run plan and task owner.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from tools.change_correlation.contracts import canonical_json

HASH_RE = re.compile(r"^[a-f0-9]{64}$")
TASK_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class DispatchOwnershipError(ValueError):
    pass


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise DispatchOwnershipError(f"{label} must be a SHA-256 digest.")
    return value


def bind_local_readback(
    plan: dict[str, Any],
    *,
    task_id: str,
    sid: str,
    query_literal: str,
    dispatch_epoch: int | float,
    readback: dict[str, Any],
    expected_task_id: str,
    expected_plan_sha256: str,
    expected_execution_id: str,
    expected_sid: str,
    expected_query_sha256: str,
    approved_query_sha256: set[str],
) -> dict[str, Any]:
    """Bind a local task's returned SID and physical receipt readback."""
    if not isinstance(plan, dict) or not isinstance(plan.get("plan_sha256"), str):
        raise DispatchOwnershipError("Run plan hash is required.")
    _digest(plan["plan_sha256"], "plan_sha256")
    if plan["plan_sha256"] != expected_plan_sha256:
        raise DispatchOwnershipError("Run plan is not the independently approved plan.")
    plan_body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if _sha(canonical_json(plan_body)) != plan["plan_sha256"]:
        raise DispatchOwnershipError("Run plan body does not match its immutable hash.")
    if plan.get("execution_id") != expected_execution_id:
        raise DispatchOwnershipError("Run plan execution is not independently approved.")
    if not isinstance(task_id, str) or not TASK_RE.fullmatch(task_id):
        raise DispatchOwnershipError("Task owner ID is invalid.")
    if not isinstance(sid, str) or not SID_RE.fullmatch(sid):
        raise DispatchOwnershipError("Returned search SID is invalid.")
    if sid != expected_sid:
        raise DispatchOwnershipError("Returned SID is not independently approved.")
    if not isinstance(query_literal, str) or not query_literal.strip():
        raise DispatchOwnershipError("Dispatch query is empty.")
    query_sha256 = _sha(query_literal.encode("utf-8"))
    if query_sha256 != expected_query_sha256 or query_sha256 not in approved_query_sha256:
        raise DispatchOwnershipError("Dispatch query is not approved for this run.")
    if task_id != expected_task_id:
        raise DispatchOwnershipError("Task owner is not the independently allocated task.")
    if isinstance(dispatch_epoch, bool) or not isinstance(dispatch_epoch, (int, float)):
        raise DispatchOwnershipError("Dispatch epoch is invalid.")
    if not isinstance(readback, dict):
        raise DispatchOwnershipError("Physical readback is required.")
    if (
        readback.get("complete") is not True
        or readback.get("sid") != sid
        or readback.get("task_id") != task_id
        or readback.get("plan_sha256") != plan["plan_sha256"]
    ):
        raise DispatchOwnershipError("Readback is not bound to this task and plan.")
    rows = readback.get("rows")
    if not isinstance(rows, list) or not rows:
        raise DispatchOwnershipError("Readback must contain physical rows.")
    receipts = readback.get("receipt_fingerprints")
    if not isinstance(receipts, list) or receipts != sorted(set(receipts)):
        raise DispatchOwnershipError("Receipt fingerprints must be sorted and unique.")
    if any(not isinstance(item, str) or not HASH_RE.fullmatch(item) for item in receipts):
        raise DispatchOwnershipError("Receipt fingerprints are invalid.")
    if len(receipts) != len(rows):
        raise DispatchOwnershipError("Receipt count must match physical row count.")
    if any(not isinstance(row, dict) or "_indextime" not in row for row in rows):
        raise DispatchOwnershipError("Physical rows must retain _indextime.")
    bounds = readback.get("index_time_bounds")
    if (
        not isinstance(bounds, dict)
        or not isinstance(bounds.get("earliest"), (int, float))
        or not isinstance(bounds.get("latest"), (int, float))
        or bounds["earliest"] > bounds["latest"]
        or any(
            isinstance(row["_indextime"], bool)
            or not isinstance(row["_indextime"], (int, float))
            or not bounds["earliest"] <= row["_indextime"] <= bounds["latest"]
            for row in rows
        )
    ):
        raise DispatchOwnershipError("Physical index-time bounds are invalid.")
    derived_receipts = sorted(
        _sha(canonical_json({"_indextime": row["_indextime"], "record_id": row.get("record_id")}))
        for row in rows
    )
    if receipts != derived_receipts:
        raise DispatchOwnershipError("Receipt fingerprints do not match physical rows.")
    row_hash = _sha(canonical_json(rows))
    body = {
        "schema_version": 1,
        "kind": "local_connected_run_ownership_v1",
        "task_id": task_id,
        "scenario_id": plan.get("scenario_id"),
        "execution_id": plan.get("execution_id"),
        "plan_sha256": plan["plan_sha256"],
        "dispatch": {
            "sid": sid,
            "query_sha256": query_sha256,
            "dispatched_epoch": dispatch_epoch,
        },
        "readback": {
            "sid": sid,
            "task_id": task_id,
            "plan_sha256": plan["plan_sha256"],
            "row_count": len(rows),
            "rows_sha256": row_hash,
            "receipt_fingerprints": receipts,
            "index_time_bounds": readback.get("index_time_bounds"),
        },
    }
    return {**body, "ownership_sha256": _sha(canonical_json(body))}


def verify_local_readback_ownership(
    record: Any,
    *,
    expected_task_id: str,
    expected_plan_sha256: str,
    expected_execution_id: str,
    expected_sid: str,
    expected_query_sha256: str,
    approved_query_sha256: set[str],
    expected_readback: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("kind") != "local_connected_run_ownership_v1":
        raise DispatchOwnershipError("Ownership record kind is unsupported.")
    if not TASK_RE.fullmatch(record.get("task_id", "")):
        raise DispatchOwnershipError("Ownership task ID is invalid.")
    _digest(record.get("plan_sha256"), "ownership plan_sha256")
    if record["task_id"] != expected_task_id or record["plan_sha256"] != expected_plan_sha256:
        raise DispatchOwnershipError("Ownership is not bound to the approved task and plan.")
    if record.get("execution_id") != expected_execution_id:
        raise DispatchOwnershipError("Ownership execution is not approved.")
    ownership_hash = record.get("ownership_sha256")
    body = {key: value for key, value in record.items() if key != "ownership_sha256"}
    if ownership_hash != _sha(canonical_json(body)):
        raise DispatchOwnershipError("Ownership record hash does not match content.")
    dispatch, readback = record.get("dispatch"), record.get("readback")
    if not isinstance(dispatch, dict) or not SID_RE.fullmatch(dispatch.get("sid", "")):
        raise DispatchOwnershipError("Ownership SID is invalid.")
    if not isinstance(readback, dict) or readback.get("sid") != dispatch["sid"]:
        raise DispatchOwnershipError("Ownership SID/readback mismatch.")
    if dispatch["sid"] != expected_sid or dispatch.get("query_sha256") != expected_query_sha256:
        raise DispatchOwnershipError("Ownership dispatch differs from independent evidence.")
    if readback.get("task_id") != expected_task_id or readback.get("plan_sha256") != expected_plan_sha256:
        raise DispatchOwnershipError("Nested readback ownership differs from its parent.")
    _digest(readback.get("rows_sha256"), "readback rows_sha256")
    _digest(dispatch.get("query_sha256"), "dispatch query_sha256")
    for key in ("row_count", "rows_sha256", "receipt_fingerprints", "index_time_bounds"):
        if readback.get(key) != expected_readback.get(key):
            raise DispatchOwnershipError("Readback metadata differs from independent evidence.")
    if dispatch["query_sha256"] not in approved_query_sha256:
        raise DispatchOwnershipError("Ownership query is not approved.")
    return record
