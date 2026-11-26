"""Expected source selectors and physical readback contract for v2 scenarios."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from tools.change_correlation.contracts import canonical_json
from tools.change_scenarios_v2 import load_scenario
from tools.raw_fixtures.change_scenarios_v2 import prepare_source_inputs


class ReceiptContractError(ValueError):
    pass


def _sha(value: Any) -> str:
    try:
        encoded = canonical_json(value)
    except Exception:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_expected_receipt_manifest(
    scenario_id: str,
    *,
    variant_id: str | None = None,
    execution_id: str,
    anchor_epoch: int,
) -> dict[str, Any]:
    scenario = load_scenario(scenario_id, variant_id)
    inputs = prepare_source_inputs(
        scenario, execution_id=execution_id, anchor_epoch=anchor_epoch
    )
    entries = []
    for event in inputs["events"]:
        for ordinal, raw in enumerate(event.get("raw_events", []), start=1):
            if not isinstance(raw, dict):
                raise ReceiptContractError("Expected source event is malformed.")
            entries.append(
                {
                    "event_id": event["id"],
                    "ordinal": ordinal,
                    "source": raw.get("source"),
                    "sourcetype": raw.get("sourcetype"),
                    "index": raw.get("index"),
                    "host": raw.get("host"),
                    "payload_sha256": _sha(raw.get("event")),
                    "source_time": raw.get("time", event.get("planned_source_epoch")),
                }
            )
    if not entries:
        raise ReceiptContractError("Scenario has no emitted source records.")
    return {
        "schema_version": 1,
        "kind": "connected_source_receipt_manifest_v1",
        "scenario_id": scenario["scenario_id"],
        "variant_id": scenario["variant_id"],
        "execution_id": execution_id,
        "anchor_epoch": anchor_epoch,
        "entries": entries,
        "indexed": False,
    }


def verify_physical_readback(
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    """Validate physical identity fields without asserting indexed completeness."""
    if (
        manifest.get("kind") != "connected_source_receipt_manifest_v1"
        or manifest.get("indexed") is not False
    ):
        raise ReceiptContractError("Receipt manifest is not an offline expectation.")
    if _sha(manifest) != expected_manifest_sha256:
        raise ReceiptContractError("Receipt manifest is not independently approved.")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(rows) != len(entries):
        raise ReceiptContractError("Physical readback count differs from expectation.")
    identities = set()
    for expected, row in zip(entries, rows, strict=True):
        if not isinstance(row, dict) or not all(
            key in row for key in ("_bkt", "_cd", "_indextime")
        ):
            raise ReceiptContractError(
                "Physical readback lacks _bkt, _cd, or _indextime."
            )
        if (
            not isinstance(row["_bkt"], str)
            or not row["_bkt"].strip()
            or not isinstance(row["_cd"], str)
            or not row["_cd"].strip()
            or isinstance(row["_indextime"], bool)
            or not isinstance(row["_indextime"], (int, float))
            or not math.isfinite(float(row["_indextime"]))
            or row["_indextime"] < 0
        ):
            raise ReceiptContractError(
                "Physical readback identity fields are malformed."
            )
        identity = (row["_bkt"], row["_cd"])
        if identity in identities:
            raise ReceiptContractError(
                "Physical readback contains duplicate physical identities."
            )
        identities.add(identity)
        if (
            row.get("source") != expected["source"]
            or row.get("sourcetype") != expected["sourcetype"]
            or row.get("index") != expected["index"]
        ):
            raise ReceiptContractError(
                "Physical readback selector differs from expectation."
            )
        if row.get("host") != expected["host"]:
            raise ReceiptContractError(
                "Physical readback host differs from expectation."
            )
        if row.get("_time") != expected["source_time"]:
            raise ReceiptContractError(
                "Physical readback source timestamp differs from expectation."
            )
        if _sha(row.get("event")) != expected["payload_sha256"]:
            raise ReceiptContractError(
                "Physical readback payload differs from expectation."
            )
    return {
        "complete": True,
        "indexed": True,
        "row_count": len(rows),
        "manifest_execution_id": manifest["execution_id"],
    }
