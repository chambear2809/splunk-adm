#!/usr/bin/env python3
"""Prepare an offline plan or run a caller-supplied phase-clock driver.

The command-line interface never starts Splunk or contacts a source. Without a
readiness file it only validates and summarizes the template. The library clock
runner accepts an explicit delivery callback so a later, separately authorized
driver can schedule source-owned emitters without changing planned source times.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.change_scenarios import (  # noqa: E402
    DEFAULT_T_LEAD_SECONDS,
    MAX_PLAN_BYTES,
    SCENARIO_IDS,
    ScenarioError,
    build_run_plan,
    load_scenario,
    offline_preflight,
    verify_run_plan,
    write_once_json,
)
from tools.change_correlation.contracts import canonical_json  # noqa: E402


class ClockDriftError(RuntimeError):
    """Wall-clock movement diverged from the monotonic phase clock."""


def run_phase_clock(
    plan: dict[str, Any],
    deliver: Callable[[dict[str, Any]], Mapping[str, Any]],
    *,
    wall_clock: Callable[[], float] = time.time,
    monotonic_clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Deliver planned items at or after their source time and record callbacks.

    The callback owns source serialization and delivery. It must return the
    actual emission time measured at the point the event was emitted; any
    transport acknowledgment is recorded separately. Indexed receipt is never
    inferred here and remains null until an independent Splunk readback records
    it.
    """

    verify_run_plan(plan)
    tolerance = plan["clock"]["maximum_offset_milliseconds"] / 1000
    wall_start = wall_clock()
    monotonic_start = monotonic_clock()
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "scenario_execution_report_v1",
        "scenario_id": plan["scenario_id"],
        "execution_id": plan["execution_id"],
        "plan_sha256": plan["plan_sha256"],
        "execution_inventory_sha256": plan["readiness"]["execution_inventory_sha256"],
        "target_identity_sha256": plan["readiness"]["target_identity_sha256"],
        "contract_sha256": plan["readiness"]["contract_sha256"],
        "actual_run_started_epoch": wall_start,
        "events": [],
        "indexed_receipt_bounds": None,
        "readback_status": "not_performed",
        "status": "delivery_in_progress",
    }

    def wait_for(target_epoch: int) -> float:
        target_mono = monotonic_start + max(0.0, target_epoch - wall_start)
        while True:
            wall_now = wall_clock()
            monotonic_now = monotonic_clock()
            wall_elapsed = wall_now - wall_start
            monotonic_elapsed = monotonic_now - monotonic_start
            if abs(wall_elapsed - monotonic_elapsed) > tolerance:
                raise ClockDriftError(
                    "Wall and monotonic clocks diverged beyond tolerance."
                )
            remaining = target_mono - monotonic_now
            if remaining <= 0:
                if wall_now + tolerance < target_epoch:
                    raise ClockDriftError(
                        "Wall clock is behind the planned source time."
                    )
                return wall_now
            sleep(min(remaining, 1.0))

    for planned in plan["schedule"]:
        target = planned.get(
            "planned_source_epoch", planned.get("planned_collection_start_epoch")
        )
        if target is None:
            raise ScenarioError("Planned event has no scheduled source time.")
        if planned["status"] == "blocked":
            report["events"].append(
                {
                    "id": planned["id"],
                    "status": "blocked",
                    "planned_source_epoch": target,
                    "planned_collection_end_epoch": planned.get(
                        "planned_collection_end_epoch"
                    ),
                    "actual_emission_epoch": None,
                    "transport_acknowledgment_epoch": None,
                    "indexed_receipt_epoch": None,
                    "readback_epoch": None,
                }
            )
            continue
        wait_for(target)
        delivered = deliver(dict(planned))
        if not isinstance(delivered, Mapping):
            raise ScenarioError("Delivery callback must return measured time metadata.")
        emitted_at = delivered.get("actual_emission_epoch")
        if (
            not isinstance(emitted_at, (int, float))
            or isinstance(emitted_at, bool)
            or not math.isfinite(emitted_at)
            or emitted_at < 0
            or emitted_at > 253_402_300_799
        ):
            raise ScenarioError("Delivery callback must report actual emission time.")
        if emitted_at < target:
            raise ScenarioError(
                "Delivery callback reports an event emitted before plan time."
            )
        acknowledged_at = delivered.get("transport_acknowledgment_epoch")
        if acknowledged_at is not None and (
            not isinstance(acknowledged_at, (int, float))
            or isinstance(acknowledged_at, bool)
            or not math.isfinite(acknowledged_at)
            or acknowledged_at > 253_402_300_799
            or acknowledged_at < emitted_at
        ):
            raise ScenarioError("Transport acknowledgment must follow actual emission.")
        report["events"].append(
            {
                "id": planned["id"],
                "status": "delivered",
                "planned_source_epoch": target,
                "planned_collection_end_epoch": planned.get(
                    "planned_collection_end_epoch"
                ),
                "actual_emission_epoch": emitted_at,
                "transport_acknowledgment_epoch": acknowledged_at,
                "indexed_receipt_epoch": None,
                "readback_epoch": None,
                "delivery_status": str(delivered.get("delivery_status", "delivered")),
            }
        )
    report["actual_run_ended_epoch"] = wall_clock()
    report["status"] = "delivery_complete_readback_pending"
    return report


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScenarioError("Input file cannot be read as JSON.") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-id", required=True, choices=SCENARIO_IDS)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--lead-seconds", type=int, default=DEFAULT_T_LEAD_SECONDS)
    parser.add_argument("--anchor-epoch", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        scenario = load_scenario(args.scenario_id)
        if args.ready_file is None:
            result = offline_preflight(scenario)
            output = canonical_json(result) + b"\n"
            if args.output:
                write_once_json(args.output, result, max_bytes=MAX_PLAN_BYTES)
            else:
                sys.stdout.buffer.write(output)
            return 0

        readiness = _read_json(args.ready_file)
        plan = build_run_plan(
            scenario,
            readiness,
            now_epoch=int(time.time()),
            lead_seconds=args.lead_seconds,
            anchor_epoch=args.anchor_epoch,
        )
        if args.output:
            write_once_json(args.output, plan, max_bytes=MAX_PLAN_BYTES)
        else:
            sys.stdout.buffer.write(canonical_json(plan) + b"\n")
        return 0
    except ScenarioError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
