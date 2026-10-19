"""Opt-in evidence-gated v2 stage, cutover, resume, and rollback test."""

from __future__ import annotations

import os
from importlib import import_module
import json
import math
from pathlib import Path
import re
import secrets
import sys
import time
import unittest
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "splunk_app" / "splunk_adm" / "bin"))
sys.path.insert(0, str(ROOT / "splunk_app" / "splunk_adm" / "bin" / "lib"))
LabLock = import_module("tools.lab_lock").LabLock


def _stream_gap_envelope(template: dict, source_port: int, source: str, now: float):
    """Clone one TA-shaped standard Stream record at actual current event time."""
    if not 1 <= source_port <= 65535:
        raise ValueError("source port is outside the valid TCP/UDP range")
    if (
        template.get("index") != "netflow"
        or template.get("sourcetype") != "stream:netflow"
    ):
        raise ValueError("gap fixture must contain a standard Stream NetFlow record")
    event = template.get("event")
    if not isinstance(event, dict) or not {
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
        "protoid",
        "timestamp",
        "endtime",
    }.issubset(event):
        raise ValueError("Stream gap fixture is missing documented tuple/time fields")
    value = json.loads(json.dumps(template))
    instant = datetime.fromtimestamp(now, timezone.utc)
    end = datetime.fromtimestamp(now + 0.001, timezone.utc)
    value["time"] = now
    value["source"] = source
    value["index"] = "netflow"
    value["sourcetype"] = "stream:netflow"
    value["event"]["src_port"] = source_port
    value["event"]["timestamp"] = instant.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    value["event"]["endtime"] = end.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    return value


def _upgrade_resume_route(journal: dict | None) -> str:
    """Select the next durable migration phase without repeating staging."""
    if not journal:
        return "fresh"
    phase = journal.get("phase")
    routes = {
        "prepared": "backfill",
        "backfilled": "validate",
        "coverage_validated": "cutover",
        "cutover_in_progress": "cutover",
        "cutover": "rollback",
        "rollback_in_progress": "rollback",
        "rolled_back": "terminal",
    }
    if phase not in routes:
        raise AssertionError(f"unsupported migration journal phase: {phase!r}")
    return routes[phase]


def _assert_completed_cutover_evidence(migration, journal: dict) -> None:
    """Check durable activation success independently of staging eligibility.

    This only reads the interface and immutable journal origin; it performs no
    target requests. A partial activation may be safely rolled back without ever
    having qualified the candidate's activated behavior.
    """
    cutover = journal.get("cutover") or {}

    def epoch(value):
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    started, completed = cutover.get("started_at"), cutover.get("completed_at")
    if (
        cutover.get("state") != "complete"
        or not epoch(started)
        or not epoch(completed)
        or completed < started
    ):
        raise AssertionError("journal lacks durable completed cutover evidence")
    interface, _ = migration._interface()
    expected = migration._build_cutover_mutations(journal, interface)
    mutations = cutover.get("mutations")
    if (
        not isinstance(mutations, list)
        or not expected
        or any(not isinstance(item, dict) for item in mutations)
    ):
        raise AssertionError("completed cutover lacks its intended mutation plan")
    if [item.get("id") for item in mutations] != [item["id"] for item in expected]:
        raise AssertionError("completed cutover mutation plan is incomplete or changed")
    for recorded, intended in zip(mutations, expected):
        if any(
            recorded.get(field) != intended.get(field)
            for field in ("kind", "name", "field", "rest_target", "acl")
        ) or any(
            not migration._mutation_equal(
                intended, recorded.get(field), intended[field]
            )
            for field in ("before", "after")
        ):
            raise AssertionError(
                "completed cutover mutation differs from its origin plan"
            )
        if intended["kind"] == "macro_definition" and not migration._macro_args_equal(
            intended["name"], recorded.get("args", ""), intended.get("args", "")
        ):
            raise AssertionError("completed cutover macro arguments changed")
        verified = recorded.get("verified_at")
        if (
            recorded.get("state") != "applied"
            or not epoch(verified)
            or not started <= verified <= completed
        ):
            raise AssertionError(
                "completed cutover has an unverified intended mutation"
            )
    bounds = cutover.get("scheduled_cycle_bounds") or {}
    lower, upper = bounds.get("index_earliest"), bounds.get("index_latest")
    watermark = cutover.get("scheduled_watermark_at")
    if (
        not epoch(lower)
        or not epoch(upper)
        or lower >= upper
        or lower % 300
        or upper % 300
        or not epoch(watermark)
        or not started <= watermark <= completed
        or upper > watermark
    ):
        raise AssertionError("completed cutover lacks validated scheduled cycle bounds")
    required = set()
    for surface in interface["public_surfaces"]:
        if surface.get("surface") == "writers":
            continue
        for version in ("v2", "network_client_v2", "traffic_v2"):
            spec = surface.get(version)
            if isinstance(spec, dict) and (
                spec.get("public_after_invoke")
                or version in {"network_client_v2", "traffic_v2"}
                and spec.get("invoke")
            ):
                required.add((surface["surface"], version))
    evidence = cutover.get("public_selector_evidence")
    if not isinstance(evidence, list) or any(
        not isinstance(item, dict) for item in evidence
    ):
        raise AssertionError("completed cutover lacks public selector evidence")
    observed = [(item.get("surface"), item.get("version")) for item in evidence]
    if not required or len(observed) != len(required) or set(observed) != required:
        raise AssertionError("completed cutover public selector evidence is incomplete")
    last_mutation = max(item["verified_at"] for item in mutations)
    for item in evidence:
        validated = item.get("validated_at")
        count = item.get("row_count")
        if (
            item.get("phase") != "public_after_invoke"
            or not epoch(validated)
            or not last_mutation <= validated <= completed
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            or any(
                not isinstance(item.get(field), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item[field])
                for field in ("query_sha256", "rows_sha256")
            )
        ):
            raise AssertionError("completed cutover public selector proof is malformed")


def _restoration_checkpoint_origin(completed_rollback: dict) -> dict | None:
    """Bind restoration readiness to completed recovery, not controller time."""
    disabled = (
        completed_rollback.get("origin", {})
        .get("saved_searches", {})
        .get("ADM - Conversation rollup", {})
        .get("content", {})
        .get("disabled")
    )
    if str(disabled).lower() in {"1", "true"}:
        return None
    if str(disabled).lower() not in {"0", "false"}:
        raise AssertionError("restoration origin has no verified V1 writer state")
    rollback = completed_rollback.get("rollback") or {}
    recovery = rollback.get("v1_recovery") or {}
    fields = {
        "observation_epoch": recovery.get("observation_epoch"),
        "recovery_completed_at": recovery.get("completed_at"),
        "rollback_completed_at": rollback.get("completed_at"),
    }
    if "audit_observation_epoch" in recovery:
        fields["audit_observation_epoch"] = recovery["audit_observation_epoch"]
    if (
        completed_rollback.get("phase") != "rolled_back"
        or rollback.get("state") != "complete"
        or recovery.get("state") != "verified"
        or not isinstance(completed_rollback.get("migration_id"), str)
        or not completed_rollback["migration_id"]
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in fields.values()
        )
        or fields["recovery_completed_at"] < fields["observation_epoch"]
        or fields["recovery_completed_at"]
        < fields.get("audit_observation_epoch", fields["observation_epoch"])
        or fields["rollback_completed_at"] < fields["recovery_completed_at"]
    ):
        raise AssertionError(
            "restoration requires completed durable V1 recovery evidence"
        )
    return {
        "migration_id": completed_rollback["migration_id"],
        **fields,
        "boundary": max(fields.values()),
    }


def _await_restoration_v1_checkpoint(
    migration,
    completed_rollback: dict,
    deadline: float,
    *,
    monotonic=time.monotonic,
    sleep=time.sleep,
) -> dict | None:
    """Wait for a proven V1 checkpoint beyond the prior manual-write audit.

    The migration's existing capture performs the source, retained-row and
    empty-window checks unchanged. Refusals propagate; this waits only when
    the strict scheduler inventory has no later completed checkpoint yet.
    """
    origin = _restoration_checkpoint_origin(completed_rollback)
    if origin is None:
        return None
    journal = migration._load()
    readiness = journal.get("qualification_restoration_checkpoint")
    if readiness is not None and (
        not isinstance(readiness, dict) or readiness.get("origin") != origin
    ):
        raise AssertionError("restoration recovery boundary changed on resume")
    # Before activation, always re-run the product's current source/retained
    # checks and <=600-second freshness gate. A prior successful capture may
    # have aged while the controller was stopped. Once activation has begun,
    # its rollback anchor is immutable and V1 may already be paused.
    checkpoint = (
        journal.get("v1_pre_pause")
        if journal.get("phase") in {"cutover_in_progress", "cutover"}
        else None
    )
    if checkpoint is None:
        if journal.get("phase") != "coverage_validated":
            raise AssertionError(
                "restoration activation lacks its durable V1 checkpoint"
            )
        while True:
            if monotonic() >= deadline:
                raise AssertionError(
                    "timed out waiting for a fresh V1 restoration checkpoint"
                )
            cycles = migration._scheduled_writer_cycles(
                "ADM - Conversation rollup",
                journal,
                lower_epoch=origin["boundary"] + 1,
                upper_epoch=int(migration.clock()) + 1,
            )
            if cycles:
                checkpoint = migration._capture_v1_pre_pause(journal)
                break
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "timed out waiting for a fresh V1 restoration checkpoint"
                )
            sleep(min(15, remaining))
    if not isinstance(checkpoint, dict):
        raise AssertionError("restoration V1 checkpoint is malformed")
    anchor = checkpoint.get("anchor")
    if (
        not isinstance(anchor, int)
        or isinstance(anchor, bool)
        or anchor <= origin["boundary"]
    ):
        raise AssertionError(
            "restoration V1 checkpoint does not follow completed recovery"
        )
    if (
        not isinstance(checkpoint.get("sid"), str)
        or not checkpoint["sid"]
        or not isinstance(checkpoint.get("captured_at"), int)
        or isinstance(checkpoint["captured_at"], bool)
        or checkpoint["captured_at"] < anchor
    ):
        raise AssertionError("restoration V1 checkpoint lacks durable capture evidence")
    migration._write_journal(
        {
            **migration._load(),
            "qualification_restoration_checkpoint": {
                "origin": origin,
                "sid": checkpoint["sid"],
                "anchor": anchor,
                "captured_at": checkpoint["captured_at"],
            },
        }
    )
    return checkpoint


def _gap_injection_resume_action(journal: dict, evidence: dict | None) -> str:
    """Return reuse, inject, or fail-closed reconciliation for a gap marker."""
    if evidence is not None:
        return "reuse"
    marker = journal.get("gap_injection") or {}
    if marker.get("state") in {
        "request_pending",
        "posted",
        "receipt_unknown",
        "receipt_confirmed",
    }:
        return "reconcile_required"
    if marker:
        return "reconcile_required"
    return "inject"


def _read_gap_evidence(
    path: Path,
    migration_id: str,
    journal: dict | None = None,
    reader=None,
) -> dict | None:
    from tools.cisco_contract_migration import Migration, Refused

    if not path.exists() and not path.is_symlink():
        return None
    try:
        payload = (reader or Migration._read_result_artifact_file)(path)
        evidence = json.loads(payload.decode("utf-8"))
    except (OSError, ValueError, Refused) as exc:
        raise AssertionError(f"gap evidence is unreadable: {path}") from exc
    if not isinstance(evidence, dict) or evidence.get("state") not in {
        "injected_waiting_rollback",
        "recovered_and_selectors_restored",
    }:
        raise AssertionError("gap evidence has an invalid state")
    if evidence.get("migration_id") != migration_id:
        raise AssertionError("gap evidence belongs to a different migration")
    for field in (
        "source",
        "source_port",
        "raw_index_receipt",
        "index_slice",
        "rollup_id",
    ):
        if field not in evidence:
            raise AssertionError(f"gap evidence is missing {field}")
    source = evidence["source"]
    source_port = evidence["source_port"]
    receipt = evidence["raw_index_receipt"]
    bounds = evidence["index_slice"]
    if not isinstance(source, str) or not source:
        raise AssertionError("gap evidence source is invalid")
    if (
        isinstance(source_port, bool)
        or not isinstance(source_port, int)
        or not 1 <= source_port <= 65535
    ):
        raise AssertionError("gap evidence source port is invalid")
    if isinstance(receipt, bool) or not isinstance(receipt, (int, float)):
        raise AssertionError("gap evidence receipt is invalid")
    if not math.isfinite(float(receipt)) or float(receipt) <= 0:
        raise AssertionError("gap evidence receipt is invalid")
    if (
        not isinstance(bounds, list)
        or len(bounds) != 2
        or any(isinstance(v, bool) or not isinstance(v, int) for v in bounds)
        or bounds[0] < 0
        or bounds[0] % 300 != 0
        or bounds[1] != bounds[0] + 300
        or not bounds[0] <= float(receipt) < bounds[1]
    ):
        raise AssertionError("gap evidence receipt is outside its index slice")
    if not isinstance(evidence["rollup_id"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", evidence["rollup_id"]
    ):
        raise AssertionError("gap evidence rollup ID is invalid")
    expected_row = evidence.get("expected_row")
    if not isinstance(expected_row, dict) or not isinstance(
        expected_row.get("content"), dict
    ):
        raise AssertionError("gap evidence is missing its source-derived expected row")
    try:
        canonical_row = Migration._v1_record_map([expected_row["content"]])
    except Refused as exc:
        raise AssertionError("gap expected row is invalid") from exc
    if canonical_row != {evidence["rollup_id"]: expected_row} or str(
        source_port
    ) not in str(expected_row["content"].get("client_port_list", "")).split("|"):
        raise AssertionError("gap expected row identity or source port differs")
    if evidence["state"] == "recovered_and_selectors_restored":
        recovery = evidence.get("manual_recovery")
        if (
            evidence.get("selectors_restored") is not True
            or evidence.get("retained_row") != expected_row
            or not isinstance(recovery, dict)
        ):
            raise AssertionError("completed gap evidence lacks restoration proof")
        recovered_bounds = recovery.get("index_bounds")
        if (
            not isinstance(recovery.get("writer_sid"), str)
            or not recovery["writer_sid"]
            or not isinstance(recovery.get("slice_key"), str)
            or not recovery["slice_key"]
            or not isinstance(recovered_bounds, list)
            or len(recovered_bounds) != 2
            or any(
                isinstance(v, bool) or not isinstance(v, int) for v in recovered_bounds
            )
            or recovered_bounds[0] > bounds[0]
            or recovered_bounds[1] < bounds[1]
        ):
            raise AssertionError("completed gap evidence lacks bounded manual recovery")
    marker = (journal or {}).get("gap_injection") or {}
    if marker:
        if marker.get("source") != source or marker.get("source_port") != source_port:
            raise AssertionError("gap evidence does not match the journaled injection")
        if "raw_index_receipt" in marker and marker["raw_index_receipt"] != receipt:
            raise AssertionError("gap evidence receipt does not match the journal")
    return evidence


def _resume_staging(migration, start: int, end: int, scenario: dict):
    """Resume only the durable preparation stages still missing."""
    journal = migration.journal.read()
    if journal:
        journal = migration._load()
    route = _upgrade_resume_route(journal)
    if route == "terminal":
        return journal, route, None
    if route == "fresh":
        migration.prepare(start, end)
        route = "backfill"
    if route == "backfill":
        migration.backfill()
        route = "validate"
    if route == "validate":
        validation = migration.validate(scenario)
        if not validation.get("cutover_eligible"):
            raise AssertionError(
                "migration validation did not produce cutover eligibility"
            )
        route = "cutover"
    else:
        validation = {"status": "coverage_validated", "cutover_eligible": True}
    return migration._load(), route, validation


class QualificationInterrupted(RuntimeError):
    """Controlled harness interruption after a real durable mutation."""


def _qualification_cutover(migration, interrupt_once=False):
    original = migration._apply_mutation

    def apply(journal, mutation):
        original(journal, mutation)
        changed = not migration._mutation_equal(
            mutation, mutation["before"], mutation["after"]
        )
        if interrupt_once and changed and not journal.get("qualification_interrupt"):
            journal["qualification_interrupt"] = {
                "state": "after_verified_mutation",
                "mutation_id": mutation["id"],
                "phase": journal.get("phase"),
            }
            migration._write_journal(journal)
            raise QualificationInterrupted("controlled stop after durable mutation")

    migration._apply_mutation = apply
    try:
        return migration.cutover()
    finally:
        migration._apply_mutation = original


class CiscoMigrationGapEnvelopeTest(unittest.TestCase):
    def test_stream_gap_envelope_preserves_ta_shape_and_uses_current_time(self):
        template = json.loads(
            (ROOT / "fixtures" / "raw-networking" / "campus_netflow.ndjson")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        original = json.loads(json.dumps(template))
        now = 1_800_000_000.25
        value = _stream_gap_envelope(template, 61001, "adm-migration-gap-test", now)

        self.assertEqual(value["sourcetype"], "stream:netflow")
        self.assertEqual(value["index"], "netflow")
        self.assertEqual(value["event"]["src_port"], 61001)
        self.assertEqual(value["event"]["src_ip"], template["event"]["src_ip"])
        self.assertEqual(value["event"]["dest_ip"], template["event"]["dest_ip"])
        self.assertEqual(value["time"], now)
        self.assertTrue(value["event"]["timestamp"].startswith("2027-01-15T08:00:00"))
        self.assertEqual(template, original)


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1"
    and os.environ.get("ADM_CISCO_MIGRATION_RUN") == "1",
    "requires explicit ADM_LAB=1 and ADM_CISCO_MIGRATION_RUN=1 opt-in",
)
class CiscoContractUpgradeTest(unittest.TestCase):
    """Exercise the actual staged contract against the qualified local lab."""

    def _migration_query(self, migration, journal, query, label):
        return migration._query(
            journal,
            query,
            None,
            None,
            label=label,
            earliest_time="0",
            latest_time="+10y",
            persist_result_rows=False,
        )

    def _gap_fixture_template(self, fixture_path):
        for line in fixture_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(value, dict)
                and value.get("index") == "netflow"
                and value.get("sourcetype") == "stream:netflow"
                and isinstance(value.get("event"), dict)
                and {"src_ip", "dest_ip", "src_port", "dest_port", "protoid"}.issubset(
                    value["event"]
                )
            ):
                return value
        raise AssertionError("gap fixture has no documented standard Stream record")

    def _assert_v1_gap_absent(self, migration, evidence):
        from tools.cisco_contract_migration import V1_INDEX, V1_ROW_FIELDS

        query = (
            f'search index={V1_INDEX} source="adm:conversation" '
            f"rollup_id={json.dumps(evidence['rollup_id'])} | fields "
            + " ".join(V1_ROW_FIELDS)
        )
        rows = self._migration_query(
            migration,
            migration._load(),
            query,
            f"pre-rollback injected V1 absence {evidence['rollup_id']}",
        )
        if migration._v1_record_map(rows):
            self.fail("matching V1 summary row exists before rollback recovery")

    def _assert_v2_cutover_state(self, migration, *, v1_paused=True):
        from tools.cisco_contract_migration import _macro_definition_equal

        interface, _ = migration._interface()
        current = migration.snapshot(allow_activation=True)
        for selector in interface["activation"]["cutover_selectors"]:
            name = selector["name"]
            self.assertTrue(
                _macro_definition_equal(
                    current["macros"][name]["definition"], selector["after"]
                ),
                f"public selector {name} changed before V1 recovery completed",
            )
        v1_disabled = str(
            current["saved_searches"]["ADM - Conversation rollup"]["content"][
                "disabled"
            ]
        ).lower()
        self.assertIn(
            v1_disabled,
            {"1", "true"} if v1_paused else {"0", "false"},
            "legacy V1 writer state differs from the expected recovery phase",
        )
        self.assertIn(
            str(
                current["saved_searches"]["ADM - Conversation rollup v2"]["content"][
                    "disabled"
                ]
            ).lower(),
            {"0", "false"},
            "V2 writer should remain enabled while public readers use V2",
        )

    def _inject_v1_pause_gap_event(self, migration, journal, fixture_path):
        saved_searches = journal["origin"]["saved_searches"]
        if str(
            saved_searches["ADM - Conversation rollup"]["content"].get("disabled")
        ).lower() not in {"0", "false"}:
            self.fail(
                "nonempty V1 gap injection requires an originally enabled V1 writer"
            )
        cutover = journal.get("cutover") or {}
        if (
            cutover.get("state") != "awaiting_first_scheduled_cycle"
            or not cutover.get("legacy_writer_drained_at")
            or not cutover.get("post_pause_validation_at")
            or not isinstance(journal.get("v1_pre_pause"), dict)
        ):
            self.fail("journal does not prove V1 pause and drain before injection")
        mutations = cutover.get("mutations") or []
        if not any(
            item.get("name") == "ADM - Conversation rollup"
            and item.get("field") == "disabled"
            and item.get("state") == "applied"
            and item.get("verified_at")
            for item in mutations
        ):
            self.fail("journal has no applied readback for the V1 pause")

        current = migration.snapshot(allow_activation=True)
        current_searches = current["saved_searches"]
        if str(
            current_searches["ADM - Conversation rollup"]["content"].get("disabled")
        ).lower() not in {"1", "true"}:
            self.fail("V1 writer is not paused at the injection boundary")
        if str(
            current_searches["ADM - Conversation rollup v2"]["content"].get("disabled")
        ).lower() not in {"0", "false"}:
            self.fail("V2 writer is not enabled at the injection boundary")

        template = self._gap_fixture_template(fixture_path)
        sys.path.insert(0, str(ROOT / "tests" / "splunk"))
        lab = import_module("lab")
        source = f"adm-migration-gap-{uuid.uuid4().hex}"
        source_port = None
        for _ in range(64):
            candidate = secrets.randbelow(65535 - 49152 + 1) + 49152
            query = (
                'search index=netflow sourcetype="stream:netflow" '
                f"| spath input=_raw path=src_port output=adm_gap_src_port "
                f"| where adm_gap_src_port={candidate} | stats count AS matches"
            )
            found = self._migration_query(
                migration, journal, query, f"gap source-port uniqueness {candidate}"
            )
            count = int(found[0].get("matches", 0) or 0) if found else 0
            if count == 0:
                source_port = candidate
                break
        if source_port is None:
            self.fail("could not find an unused valid Stream source port")

        now = time.time()
        # Persist the intent before HEC: a crash or transport exception after
        # dispatch must never cause a resumed harness to inject a second tuple.
        journal["gap_injection"] = {
            "state": "request_pending",
            "source": source,
            "source_port": source_port,
            "created_at": int(now),
        }
        migration.journal.write(journal)
        envelope = _stream_gap_envelope(template, source_port, source, now)
        try:
            lab._hec_post((json.dumps(envelope, separators=(",", ":")) + "\n").encode())
        except BaseException:
            journal["gap_injection"]["state"] = "receipt_unknown"
            migration.journal.write(journal)
            raise
        journal["gap_injection"]["state"] = "posted"
        migration.journal.write(journal)
        receipt_query = (
            f"search index=netflow source={json.dumps(source)} "
            'sourcetype="stream:netflow" '
            "| spath input=_raw path=src_port output=adm_gap_src_port "
            f"| where adm_gap_src_port={source_port} "
            "| fields _indextime src_ip dest_ip src_port dest_port protoid"
        )
        receipt_deadline = time.monotonic() + 90
        raw_rows = []
        while time.monotonic() < receipt_deadline:
            raw_rows = self._migration_query(
                migration,
                migration._load(),
                receipt_query,
                f"gap raw receipt {source}",
            )
            if raw_rows:
                break
            time.sleep(1)
        if len(raw_rows) != 1:
            self.fail("injected Stream tuple was not uniquely indexed")
        receipt = int(float(raw_rows[0]["_indextime"]))
        journal = migration._load()
        marker = journal.get("gap_injection") or {}
        if marker.get("source") != source or marker.get("source_port") != source_port:
            self.fail("gap injection marker changed while waiting for receipt")
        journal["gap_injection"].update(
            state="receipt_confirmed", raw_index_receipt=receipt
        )
        migration.journal.write(journal)
        slice_start = receipt // 300 * 300
        slice_end = slice_start + 300
        anchor = slice_start + 600
        event_bounds = {
            "earliest_time": str(anchor - 24 * 60 * 60),
            "latest_time": str(anchor + 15 * 60),
        }
        expected = migration._v1_expected_rows(
            journal,
            (slice_start, slice_end),
            event_bounds,
            f"injected V1 pause-gap source {slice_start}",
        )
        matches = {
            rollup_id: row
            for rollup_id, row in expected.items()
            if str(row.get("content", {}).get("client_port_list") or "")
            .split("|")
            .count(str(source_port))
        }
        if len(matches) != 1:
            self.fail(
                "injected tuple did not produce exactly one source-derived V1 rollup"
            )
        rollup_id, expected_row = next(iter(matches.items()))
        if int(expected_row.get("content", {}).get("records") or 0) <= 0:
            self.fail("source-derived V1 rollup has no records")

        return {
            "state": "injected_waiting_rollback",
            "source": source,
            "source_port": source_port,
            "tuple": {
                field: envelope["event"].get(field)
                for field in ("src_ip", "dest_ip", "src_port", "dest_port", "protoid")
            },
            "raw_index_receipt": receipt,
            "index_slice": [slice_start, slice_end],
            "event_bounds": event_bounds,
            "rollup_id": rollup_id,
            "expected_row": expected_row,
            "pre_rollback_retained_rows": 0,
        }

    def _assert_v1_gap_recovered(self, migration, evidence):
        from tools.cisco_contract_migration import V1_INDEX, V1_ROW_FIELDS

        journal = migration._load()
        recovery = (journal.get("rollback") or {}).get("v1_recovery") or {}
        manual_matches = []
        for key, item in (recovery.get("expected_slices") or {}).items():
            expected = item.get("expected") or {}
            if evidence["rollup_id"] in expected:
                manual_matches.append((key, item, expected[evidence["rollup_id"]]))
        if len(manual_matches) != 1:
            self.fail("injected V1 rollup was not recovered by one manual gap slice")
        slice_key, manual_slice, recovered_expected = manual_matches[0]
        if recovered_expected != evidence["expected_row"]:
            self.fail("manual V1 gap expectation differs from the source-derived row")
        bounds = manual_slice.get("index_bounds") or []
        receipt_slice = evidence["index_slice"]
        if len(bounds) != 2 or not (
            int(bounds[0]) <= int(receipt_slice[0])
            and int(bounds[1]) >= int(receipt_slice[1])
        ):
            self.fail(
                "manual V1 recovery bounds do not cover the injected receipt slice"
            )
        manual_sids = manual_slice.get("manual_job_sids") or []
        if len(manual_sids) != 1 or manual_slice.get("state") != "verified":
            self.fail("manual V1 gap lacks a verified complete writer SID")
        matching_jobs = [
            job
            for job in journal.get("jobs", [])
            if job.get("sid") == manual_sids[0]
            and job.get("label") == "ADM - Conversation rollup"
            and job.get("state") == "complete"
            and job.get("request_bounds")
            == {
                "index_earliest": str(bounds[0]),
                "index_latest": str(bounds[1]),
                "earliest_time": str(manual_slice["event_bounds"]["earliest_time"]),
                "latest_time": str(manual_slice["event_bounds"]["latest_time"]),
            }
        ]
        if len(matching_jobs) != 1:
            self.fail(
                "manual V1 recovery SID bounds or completion evidence are invalid"
            )
        for item in (recovery.get("scheduler_cycles") or {}).values():
            if evidence["rollup_id"] in (item.get("expected") or {}):
                self.fail(
                    "injected V1 rollup was picked up by a resumed scheduler cycle"
                )
        query = (
            f'search index={V1_INDEX} source="adm:conversation" '
            f"rollup_id={json.dumps(evidence['rollup_id'])} | fields "
            + " ".join(V1_ROW_FIELDS)
        )
        rows = self._migration_query(
            migration,
            journal,
            query,
            f"post-rollback injected V1 readback {evidence['rollup_id']}",
        )
        actual = migration._v1_record_map(rows)
        if actual != {evidence["rollup_id"]: evidence["expected_row"]}:
            self.fail("rollback did not retain exact V1 material for injected rollup")

        origin = journal["origin"]
        current = migration.snapshot()
        interface, _ = migration._interface()
        for selector in interface["activation"]["cutover_selectors"]:
            name = selector["name"]
            self.assertEqual(
                current["macros"][name]["definition"],
                origin["macros"][name]["definition"],
                f"selector {name} was not restored to its origin definition",
            )
        self.assertEqual(
            str(
                current["saved_searches"]["ADM - Conversation rollup"]["content"][
                    "disabled"
                ]
            ).lower(),
            str(
                origin["saved_searches"]["ADM - Conversation rollup"]["content"][
                    "disabled"
                ]
            ).lower(),
        )
        self.assertEqual(
            str(
                current["saved_searches"]["ADM - Conversation rollup v2"]["content"][
                    "disabled"
                ]
            ).lower(),
            str(
                origin["saved_searches"]["ADM - Conversation rollup v2"]["content"][
                    "disabled"
                ]
            ).lower(),
            "V2 writer was not restored to its origin state",
        )
        evidence["state"] = "recovered_and_selectors_restored"
        evidence["retained_row"] = actual[evidence["rollup_id"]]
        evidence["selectors_restored"] = True
        evidence["manual_recovery"] = {
            "slice_key": slice_key,
            "index_bounds": bounds,
            "writer_sid": manual_sids[0],
        }
        migration.journal.write_artifact(
            migration.journal.path.with_suffix(".v1-gap-evidence.json"), evidence
        )

    def _restore_candidate_v2(
        self,
        api,
        journal_path,
        start,
        end,
        scenario,
        timeout_seconds,
        completed_rollback,
    ):
        """Fresh restore journal; outer lifecycle already holds the target lock."""
        from tools.cisco_contract_migration import Journal, Migration

        restored = Migration(api, Journal(journal_path))
        with restored.journal.locked(blocking=False):
            journal = restored.journal.read()
            if journal and journal.get("phase") == "cutover":
                _await_restoration_v1_checkpoint(
                    restored, completed_rollback, time.monotonic() + timeout_seconds
                )
                restored.cutover()  # revalidate actual active configuration
            else:
                _, route, _ = _resume_staging(restored, start, end, scenario)
                self.assertEqual(
                    route, "cutover", "restore journal must not recycle a rollback"
                )
                deadline = time.monotonic() + timeout_seconds
                _await_restoration_v1_checkpoint(restored, completed_rollback, deadline)
                while True:
                    result = restored.cutover()
                    if result["status"] == "cutover":
                        break
                    self.assertEqual(result["status"], "awaiting_first_scheduled_cycle")
                    if time.monotonic() >= deadline:
                        self.fail(
                            "timed out restoring tested candidate; retain the restore journal"
                        )
                    time.sleep(15)
            self._assert_v2_cutover_state(restored)
            self.assertEqual(restored.cutover()["status"], "cutover")
            final = restored._load()
            self.assertTrue(final.get("candidate_cutover_eligible"))
            self.assertEqual(final["phase"], "cutover")
            restored.journal.write_artifact(
                journal_path.with_suffix(".restoration-evidence.json"),
                {
                    "migration_id": final["migration_id"],
                    "phase": final["phase"],
                    "candidate_sha256": final["candidate_sha256"],
                    "selectors_verified": True,
                    "repeated_cutover_verified": True,
                },
            )

    def test_staging_cutover_resume_and_rollback(self):
        from tools.cisco_contract_migration import Journal, Migration, Refused
        from adm_recovery_lib.rest import Rest

        token_path = Path(os.environ["ADM_CISCO_MIGRATION_SESSION_FILE"])
        ca_path = Path(os.environ["ADM_CISCO_MIGRATION_CA_FILE"])
        journal_path = Path(os.environ["ADM_CISCO_MIGRATION_JOURNAL"])
        scenario_path = Path(os.environ["ADM_CISCO_MIGRATION_SCENARIO"])
        start = int(os.environ["ADM_CISCO_MIGRATION_START"])
        end = int(os.environ["ADM_CISCO_MIGRATION_END"])
        timeout_seconds = int(os.environ.get("ADM_CISCO_MIGRATION_TIMEOUT", "1800"))
        inject_gap = os.environ.get("ADM_CISCO_MIGRATION_V1_GAP_INJECTION", "")
        interrupt_once = os.environ.get("ADM_CISCO_MIGRATION_INTERRUPT_ONCE", "0")
        restore_v2 = os.environ.get("ADM_CISCO_MIGRATION_RESTORE_V2", "0")
        if interrupt_once not in {"0", "1"} or restore_v2 not in {"0", "1"}:
            self.fail("migration interruption/restoration opt-ins must be 0 or 1")
        restore_value = os.environ.get("ADM_CISCO_MIGRATION_RESTORE_JOURNAL", "")
        if restore_v2 == "1" and (
            not restore_value
            or not Path(restore_value).is_absolute()
            or Path(restore_value).resolve() == journal_path.resolve()
        ):
            self.fail("V2 restoration requires a distinct absolute restore journal")
        fixture_value = os.environ.get("ADM_CISCO_MIGRATION_V1_GAP_FIXTURE", "")
        if inject_gap not in {"", "0", "1"}:
            self.fail("ADM_CISCO_MIGRATION_V1_GAP_INJECTION must be 0 or 1")
        if inject_gap == "1":
            if not fixture_value:
                self.fail("V1 gap injection needs ADM_CISCO_MIGRATION_V1_GAP_FIXTURE")
            gap_fixture = Path(fixture_value)
            if not gap_fixture.is_absolute() or gap_fixture.is_symlink():
                self.fail("gap fixture path must be absolute and not a symlink")
            if not gap_fixture.is_file():
                self.fail("gap fixture path must name a readable TA-grounded fixture")
            try:
                gap_fixture.resolve().relative_to(ROOT.resolve())
            except ValueError:
                pass
            else:
                self.fail("gap fixture must be supplied outside the repository")
        elif fixture_value:
            self.fail("gap fixture path requires explicit V1 gap injection opt-in")
        if token_path.stat().st_mode & 0o077:
            self.fail("session file must be owner-only")
        token = token_path.read_text(encoding="utf-8").strip()
        if not token or "\n" in token or "\r" in token:
            self.fail("session file must contain one session key")
        if scenario_path.is_symlink() or scenario_path.stat().st_mode & 0o077:
            self.fail("validation scenario file must be owner-only and not a symlink")
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))

        api = Rest(token, uri="https://localhost:8089", ca_file=str(ca_path))
        migration = Migration(api, Journal(journal_path))
        # Cooperate with the repository-wide fixed-container lock. When the
        # suite is launched through tools/lab_lock.py this validates inherited
        # ownership; otherwise it acquires the same lock itself.
        with LabLock(ROOT), migration.operation_locked():
            try:
                journal = migration.journal.read()
                if journal:
                    journal = migration._load()
                if journal and (journal.get("origin") or {}).get("target", {}).get(
                    "guid"
                ) != (
                    migration._single_entry("/services/server/info").get("content")
                    or {}
                ).get("guid"):
                    self.fail("migration journal belongs to another target")
                route = _upgrade_resume_route(journal)
                if route == "terminal":
                    if journal.get("candidate_cutover_eligible") is not True:
                        self.fail(
                            "rolled-back journal lacks a completed eligible candidate"
                        )
                    _assert_completed_cutover_evidence(migration, journal)
                    if (journal.get("rollback") or {}).get("state") != "complete":
                        self.fail(
                            "rolled-back journal lacks completed rollback evidence"
                        )
                    evidence = _read_gap_evidence(
                        journal_path.with_suffix(".v1-gap-evidence.json"),
                        journal["migration_id"],
                        journal,
                        reader=Migration._read_result_artifact_file,
                    )
                    if (
                        inject_gap == "1" or journal.get("gap_injection")
                    ) and evidence is None:
                        self.fail(
                            "rolled-back gap qualification lacks durable evidence"
                        )
                    if restore_v2 == "1" and Path(restore_value).exists():
                        restore_state = Journal(Path(restore_value)).read()
                        if restore_state and restore_state.get("phase") == "cutover":
                            self._restore_candidate_v2(
                                api,
                                Path(restore_value),
                                start,
                                end,
                                scenario,
                                timeout_seconds,
                                journal,
                            )
                            return
                    if evidence is not None:
                        self._assert_v1_gap_recovered(migration, evidence)
                    else:
                        current = migration.snapshot()
                        self.assertEqual(current["macros"], journal["origin"]["macros"])
                        self.assertEqual(
                            current["saved_searches"],
                            journal["origin"]["saved_searches"],
                        )
                    if restore_v2 == "1":
                        self._restore_candidate_v2(
                            api,
                            Path(restore_value),
                            start,
                            end,
                            scenario,
                            timeout_seconds,
                            journal,
                        )
                    return
                journal, route, validation = _resume_staging(
                    migration, start, end, scenario
                )

                journal = migration._load()
                rollback_started = journal.get("phase") in {
                    "rollback_in_progress",
                }
                evidence_path = journal_path.with_suffix(".v1-gap-evidence.json")
                gap_evidence = _read_gap_evidence(
                    evidence_path,
                    journal["migration_id"],
                    journal,
                    reader=Migration._read_result_artifact_file,
                )
                deadline = time.monotonic() + timeout_seconds
                while route == "cutover":
                    try:
                        result = _qualification_cutover(
                            migration, interrupt_once == "1"
                        )
                    except QualificationInterrupted:
                        persisted = migration._load()
                        self.assertEqual(persisted["phase"], "cutover_in_progress")
                        self.assertEqual(
                            persisted["qualification_interrupt"]["state"],
                            "after_verified_mutation",
                        )
                        # Recreate the controller from durable state; the outer
                        # target and journal locks still protect this lifecycle.
                        migration = Migration(api, Journal(journal_path))
                        continue
                    if result["status"] == "cutover":
                        self.assertEqual(migration.cutover()["status"], "cutover")
                        route = "rollback"
                        break
                    self.assertEqual(result["status"], "awaiting_first_scheduled_cycle")
                    action = _gap_injection_resume_action(
                        migration._load(), gap_evidence
                    )
                    if inject_gap == "1" and action == "reconcile_required":
                        self.fail(
                            "gap injection outcome is ambiguous; reconcile the indexed receipt before retrying"
                        )
                    if inject_gap == "1" and action == "inject":
                        gap_evidence = self._inject_v1_pause_gap_event(
                            migration, migration._load(), gap_fixture
                        )
                        gap_evidence["migration_id"] = migration._load()["migration_id"]
                        migration.journal.write_artifact(evidence_path, gap_evidence)
                    if time.monotonic() >= deadline:
                        self.fail(
                            "timed out waiting for complete scheduled V2 writer evidence"
                        )
                    time.sleep(15)
                rollback_deadline = time.monotonic() + timeout_seconds
                if inject_gap == "1" and gap_evidence is None:
                    self.fail(
                        "enabled-origin gap injection requires an observed V1 pause boundary"
                    )
                if (
                    gap_evidence is not None
                    and route == "rollback"
                    and not rollback_started
                ):
                    self._assert_v2_cutover_state(migration)
                    # A resumed V1 job starts at least ten minutes before its
                    # aligned scheduler anchor. Age the injected receipt past
                    # that lookback so recovery must use a manual gap slice.
                    earliest_manual_epoch = (
                        int(gap_evidence["index_slice"][1]) + 11 * 60
                    )
                    age_deadline = time.monotonic() + min(
                        timeout_seconds,
                        max(0, earliest_manual_epoch - time.time() + 10),
                    )
                    while time.time() < earliest_manual_epoch:
                        if time.monotonic() >= age_deadline:
                            self.fail(
                                "timed out aging the injected receipt into a manual V1 gap"
                            )
                        time.sleep(min(15, max(1, earliest_manual_epoch - time.time())))
                    self._assert_v2_cutover_state(migration)
                    self._assert_v1_gap_absent(migration, gap_evidence)
                while route == "rollback":
                    rollback = migration.rollback()
                    if rollback["status"] == "rolled_back":
                        if gap_evidence is not None:
                            self._assert_v1_gap_recovered(migration, gap_evidence)
                        break
                    self.assertEqual(rollback["status"], "awaiting_v1_recovery")
                    if gap_evidence is not None:
                        self._assert_v2_cutover_state(migration, v1_paused=False)
                    if time.monotonic() >= rollback_deadline:
                        self.fail(
                            "timed out waiting for a confirmed V1 rollback recovery cycle"
                        )
                    time.sleep(15)
                if restore_v2 == "1":
                    self._restore_candidate_v2(
                        api,
                        Path(restore_value),
                        start,
                        end,
                        scenario,
                        timeout_seconds,
                        migration._load(),
                    )
            except Refused as exc:
                self.fail(
                    f"contract migration refused: {exc}; retained journal: {journal_path}. "
                    "Reconcile live state before further lab work."
                )
            except BaseException:
                print(
                    f"Migration qualification interrupted; retained journal: {journal_path}. "
                    "Live state may be staged. Reconcile before retrying or resetting the lab.",
                    file=sys.stderr,
                )
                raise
        final = migration._load()
        self.assertEqual(validation["status"], "coverage_validated")
        self.assertTrue(final.get("candidate_cutover_eligible"))
        self.assertEqual(final.get("phase"), "rolled_back")
        self.assertEqual((final.get("rollback") or {}).get("state"), "complete")


if __name__ == "__main__":
    unittest.main()
