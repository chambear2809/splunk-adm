"""Migration responsibility methods for recovery."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from .common import (
    APP,
    MAX_BACKFILL_SECONDS,
    MAX_CANDIDATE_BYTES,
    MAX_RESULTS,
    Refused,
    SLICE_SECONDS,
    STREAMS,
    SUMMARY_INDEX_WAIT_ATTEMPTS,
    V1_INDEX,
    V1_ROW_FIELDS,
    V2_INDEX,
    V2_ROW_FIELDS,
    _add_record_maps,
    _integer,
    _job_messages_complete,
    _strict_bool,
    _truth,
    fingerprint,
    plan_slices,
    rollback_recovery_horizon_seconds,
)


class MigrationRecovery:
    def _verify_v1_raw_retention(
        self, journal: dict[str, Any], start: int, end: int
    ) -> dict[str, Any]:
        entries = self._entries(
            APP + "/configs/conf-macros?count=10000", max_count=MAX_RESULTS
        )
        definitions = {
            str(entry.get("name")): (entry.get("content") or {}).get("definition", "")
            for entry in entries
            if entry.get("name")
        }
        pending = ["adm_conversation_rollup"]
        seen = set()
        source_indexes = set()
        ref_re = re.compile(r"`([^`]+)`")
        while pending:
            call = pending.pop()
            base = call.split("(", 1)[0]
            args = call[len(base) + 1 : -1] if call.startswith(base + "(") else ""
            depth = 0
            commas = 0
            for character in args:
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                elif character == "," and depth == 0:
                    commas += 1
            arity = 0 if not args else commas + 1
            name = f"{base}({arity})" if arity else base
            if name in seen:
                continue
            seen.add(name)
            definition = definitions.get(name)
            if definition is None and name.endswith("(0)"):
                definition = definitions.get(base)
            if not isinstance(definition, str):
                raise Refused("V1 raw-source macro dependency cannot be resolved")
            if name.startswith("adm_index_") or base.startswith("adm_index_"):
                match = re.search(r"\bindex\s*=\s*([A-Za-z0-9_.-]+)", definition)
                if match:
                    source_indexes.add(match.group(1))
            pending.extend(ref_re.findall(definition))
        if not source_indexes:
            raise Refused("V1 raw-source index dependencies are not identifiable")
        try:
            index_entries = self._entries(
                "/services/data/indexes?count=0", max_count=MAX_RESULTS
            )
        except Exception:
            raise Refused("V1 raw-source retention metadata is unavailable") from None
        indexed = {
            str(
                (entry.get("content") or {}).get("title", entry.get("name"))
            ): entry.get("content") or {}
            for entry in index_entries
        }
        retention = {}
        needed = end - start
        for name in sorted(source_indexes):
            value = _integer((indexed.get(name) or {}).get("frozenTimePeriodInSecs"))
            if value is None or value <= 0 or value < needed:
                raise Refused(
                    "raw-source retention does not cover the V1 recovery window"
                )
            retention[name] = value
        return {"from": start, "through": end, "indexes": retention}

    def _capture_v1_pre_pause(self, journal: dict[str, Any]) -> dict[str, Any]:
        """Require a real, complete V1 scheduler slice before pausing V1."""
        now = int(self.clock())
        lower = max(0, now - 3 * SLICE_SECONDS)
        cycles = self._scheduled_writer_cycles(
            "ADM - Conversation rollup",
            journal,
            lower_epoch=lower,
            upper_epoch=now + 1,
        )
        if not cycles:
            raise Refused(
                "enabled V1 writer has no confirmed scheduler slice to anchor rollback"
            )
        cycle = cycles[-1]
        if now - cycle["anchor"] > 2 * SLICE_SECONDS:
            raise Refused(
                "last successful V1 scheduler slice is too old to anchor rollback"
            )
        bounds = tuple(cycle["index_bounds"])
        expected = self._v1_expected_rows(
            journal, bounds, cycle["event_bounds"], "pre-pause V1 expected output"
        )
        observed_cycle_ids: set[str] = set()
        for observed_cycle in cycles:
            observed_expected = self._v1_expected_rows(
                journal,
                tuple(observed_cycle["index_bounds"]),
                observed_cycle["event_bounds"],
                f"pre-pause V1 observed cycle {observed_cycle['index_bounds'][0]}",
            )
            observed_cycle_ids.update(observed_expected)
        empty_summary_proof = None
        if cycle.get("empty_summary_warning") is True:
            if expected:
                raise Refused(
                    "V1 scheduler reported an empty summary while source rows exist"
                )
            empty_summary_proof = self._assert_empty_summary_index_window(
                journal,
                V1_INDEX,
                "adm:conversation",
                int(cycle["anchor"]),
                now,
                "pre-pause empty V1 summary audit",
                allowed_rollup_ids=observed_cycle_ids,
            )
        actual = self._v1_persisted_rows(
            journal, expected, cycle["event_bounds"], "pre-pause V1 summary readback"
        )
        if actual != expected:
            raise Refused(
                "last V1 scheduler slice is not completely retained in adm_summary"
            )
        state = {
            **cycle,
            "expected": expected,
            "expected_fingerprint": fingerprint(expected),
            "retained_fingerprint": fingerprint(actual),
            "captured_at": now,
            **(
                {"empty_summary_proof": empty_summary_proof}
                if empty_summary_proof is not None
                else {}
            ),
        }
        journal["v1_pre_pause"] = state
        self._write_journal(journal)
        return state

    def _verified_v1_manual_recovery_ids(
        self, journal: dict[str, Any], recovery: dict[str, Any]
    ) -> set[str]:
        """Return IDs from manual slices with durable, exact write evidence."""
        jobs_by_sid: dict[str, list[dict[str, Any]]] = {}
        for job in journal.get("jobs", []):
            sid = job.get("sid")
            if isinstance(sid, str) and sid:
                jobs_by_sid.setdefault(sid, []).append(job)

        allowed: set[str] = set()
        for key, item in recovery.get("expected_slices", {}).items():
            if not isinstance(item, dict) or item.get("state") != "verified":
                continue
            bounds = item.get("index_bounds")
            event_bounds = item.get("event_bounds")
            expected = item.get("expected")
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or not all(isinstance(value, int) for value in bounds)
                or key != f"{bounds[0]}:{bounds[1]}"
                or bounds[1] <= bounds[0]
                or not isinstance(event_bounds, dict)
                or not isinstance(expected, dict)
                or item.get("expected_fingerprint") != fingerprint(expected)
            ):
                raise Refused("verified V1 manual recovery manifest is malformed")
            normalized = self._v1_record_map(
                [
                    value["content"]
                    for value in expected.values()
                    for _ in range(value.get("copies", 0))
                ]
            )
            if normalized != expected:
                raise Refused("verified V1 manual recovery content changed")
            ids = set(expected)
            if not ids:
                continue
            sids = item.get("manual_job_sids")
            if not isinstance(sids, list) or not sids:
                raise Refused("V1 manual recovery manifest has no durable writer SID")
            matched = set()
            for sid in sids:
                records = jobs_by_sid.get(sid, []) if isinstance(sid, str) else []
                if len(records) != 1:
                    raise Refused("V1 manual recovery writer SID is ambiguous")
                job = records[0]
                request_bounds = job.get("request_bounds") or {}
                job_state = job.get("job_state") or {}
                if (
                    job.get("kind") != "saved_search"
                    or job.get("label") != "ADM - Conversation rollup"
                    or job.get("state") != "complete"
                    or str(request_bounds.get("index_earliest")) != str(bounds[0])
                    or str(request_bounds.get("index_latest")) != str(bounds[1])
                    or str(request_bounds.get("earliest_time"))
                    != str(event_bounds.get("earliest_time"))
                    or str(request_bounds.get("latest_time"))
                    != str(event_bounds.get("latest_time"))
                    or not job.get("search_fingerprint")
                    or _integer(job.get("result_count"))
                    != sum(item["copies"] for item in expected.values())
                    or job_state.get("dispatchState") != "DONE"
                    or not _truth(job_state.get("isDone"))
                    or _truth(job_state.get("isFinalized"))
                    or job_state.get("eventIsTruncated") not in (False, "0", 0)
                    or _integer(job_state.get("dropCount")) != 0
                    or _integer(job_state.get("resultCount"))
                    != sum(item["copies"] for item in expected.values())
                    or not _job_messages_complete(job_state.get("messages"))
                ):
                    raise Refused("V1 manual recovery writer evidence is incomplete")
                matched.add(sid)
            if matched != set(sids):
                raise Refused("V1 manual recovery writer SID set changed")
            allowed.update(ids)
        return allowed

    def _reconcile_pending_v1_manual_slices(
        self,
        journal: dict[str, Any],
        recovery: dict[str, Any],
        scheduled_expected: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Adopt completed manual SIDs before later empty-cycle audits."""
        jobs_by_bounds: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for job in journal.get("jobs", []):
            if (
                job.get("kind") == "saved_search"
                and job.get("label") == "ADM - Conversation rollup"
                and job.get("state") in {"complete", "running", "dispatch_unknown"}
                and isinstance(job.get("sid"), str)
                and job.get("sid")
            ):
                bounds = job.get("request_bounds") or {}
                first = str(bounds.get("index_earliest", ""))
                last = str(bounds.get("index_latest", ""))
                jobs_by_bounds.setdefault((first, last), []).append(job)

        for key, item in recovery.get("expected_slices", {}).items():
            if not isinstance(item, dict) or item.get("state") != "expected":
                continue
            bounds = item.get("index_bounds")
            event_bounds = item.get("event_bounds")
            expected = item.get("expected")
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or not all(isinstance(value, int) for value in bounds)
                or key != f"{bounds[0]}:{bounds[1]}"
                or bounds[1] <= bounds[0]
                or not isinstance(event_bounds, dict)
                or not isinstance(expected, dict)
                or item.get("expected_fingerprint") != fingerprint(expected)
            ):
                raise Refused("pending V1 manual recovery manifest is malformed")
            if not expected:
                continue
            expected = self._v1_record_map(
                [
                    value["content"]
                    for value in expected.values()
                    for _ in range(value.get("copies", 0))
                ]
            )
            if expected != item.get("expected"):
                raise Refused("pending V1 manual recovery content changed")
            writer_intent = fingerprint(
                {
                    "migration_id": journal["migration_id"],
                    "rollback_resume_epoch": recovery.get("resume_activation_epoch"),
                    "slice": bounds,
                    "expected": item["expected_fingerprint"],
                }
            )
            jobs = [
                job
                for job in jobs_by_bounds.get((str(bounds[0]), str(bounds[1])), [])
                if job.get("intent_fingerprint") == writer_intent
            ]
            if not jobs:
                continue
            if len(jobs) != 1:
                raise Refused("pending V1 recovery has ambiguous complete writer SIDs")
            job = jobs[0]
            output_rows = self._completed_job_rows(journal, job)
            if self._v1_record_map(output_rows) != expected:
                raise Refused("pending V1 manual recovery SID output changed")
            request_bounds = job.get("request_bounds") or {}
            job_state = job.get("job_state") or {}
            if (
                str(request_bounds.get("earliest_time"))
                != str(event_bounds.get("earliest_time"))
                or str(request_bounds.get("latest_time"))
                != str(event_bounds.get("latest_time"))
                or not job.get("sid")
                or not job.get("search_fingerprint")
                or _integer(job.get("result_count"))
                != sum(item["copies"] for item in expected.values())
                or job_state.get("dispatchState") != "DONE"
                or not _truth(job_state.get("isDone"))
                or _truth(job_state.get("isFinalized"))
                or job_state.get("eventIsTruncated") not in (False, "0", 0)
                or _integer(job_state.get("dropCount")) != 0
                or _integer(job_state.get("resultCount"))
                != sum(item["copies"] for item in expected.values())
                or not _job_messages_complete(job_state.get("messages"))
            ):
                raise Refused("pending V1 manual recovery writer SID is incomplete")
            source_expected = self._v1_expected_rows(
                journal,
                tuple(bounds),
                event_bounds,
                f"V1 pending recovery source verification {bounds[0]}",
            )
            pending_cumulative = {}
            for prior in recovery.get("expected_slices", {}).values():
                if prior is not item and prior.get("state") == "verified":
                    pending_cumulative = _add_record_maps(
                        pending_cumulative,
                        prior.get("expected") or {},
                        label="V1 pending recovery retained intents",
                    )
            pending_cumulative = _add_record_maps(
                pending_cumulative,
                expected,
                label="V1 pending recovery retained intents",
            )
            for scheduled_manifest in (scheduled_expected or {}).values():
                pending_cumulative = _add_record_maps(
                    pending_cumulative,
                    scheduled_manifest,
                    label="V1 pending recovery scheduled intents",
                )
            actual = self._v1_persisted_rows(
                journal,
                pending_cumulative,
                event_bounds,
                f"V1 pending recovery retained verification {bounds[0]}",
            )
            if source_expected != expected or actual != pending_cumulative:
                raise Refused(
                    "pending V1 manual recovery SID lacks exact source and retained parity"
                )
            item.update(
                state="verified",
                verified_at=int(self.clock()),
                manual_job_sids=[job["sid"]],
            )
            self._write_journal(journal)

    def _v1_recovery_window(
        self, journal: dict[str, Any], resume_epoch: int
    ) -> dict[str, Any] | None:
        """Backfill V1's missed raw slices through confirmed resumed schedules."""
        pre_pause = journal.get("v1_pre_pause")
        if not isinstance(pre_pause, dict):
            raise Refused("V1 rollback has no validated pre-pause scheduler boundary")
        observation = int(self.clock())
        cycles = self._scheduled_writer_cycles(
            "ADM - Conversation rollup",
            journal,
            lower_epoch=resume_epoch + 1,
            upper_epoch=observation + 1,
        )
        if not cycles:
            return None
        expected_first_anchor = (resume_epoch // SLICE_SECONDS + 1) * SLICE_SECONDS
        if cycles[0]["anchor"] != expected_first_anchor:
            raise Refused("first resumed V1 scheduler boundary is missing")
        pre_end = _integer(pre_pause.get("index_bounds", [None, None])[1])
        if pre_end is None or cycles[0]["index_bounds"][0] < pre_end:
            raise Refused("resumed V1 scheduler slice overlaps its pre-pause boundary")
        end = cycles[-1]["index_bounds"][1]
        if end - pre_end > MAX_BACKFILL_SECONDS:
            raise Refused(
                "V1 rollback recovery exceeds the seven-day slice bound; V1 is "
                "already resumed and the journal stays rollback_in_progress. See "
                "'If rollback refuses on the seven-day bound' in "
                "docs/CISCO_CONTRACT_MIGRATION.md"
            )
        retention = self._verify_v1_raw_retention(journal, pre_end, end)
        first_resumed_start = cycles[0]["index_bounds"][0]
        gap_slices = (
            plan_slices(pre_end, first_resumed_start, observation)
            if first_resumed_start > pre_end
            else []
        )
        if gap_slices and (
            gap_slices[0]["start"] != pre_end
            or gap_slices[-1]["end"] != cycles[0]["index_bounds"][0]
        ):
            raise Refused("V1 rollback gap is not a complete set of closed slices")

        rollback = journal.setdefault("rollback", {})
        recovery = rollback.setdefault(
            "v1_recovery",
            {
                "state": "recovering",
                "resume_activation_epoch": resume_epoch,
                "expected_slices": {},
                "scheduler_cycles": {},
            },
        )
        recovery.setdefault("expected_slices", {})
        recovery.setdefault("scheduler_cycles", {})
        empty_proofs = recovery.setdefault("empty_summary_proofs", {})
        if recovery.get("resume_activation_epoch") != resume_epoch:
            raise Refused("V1 rollback resume epoch changed in the durable journal")
        recovery["observation_epoch"] = observation
        recovery["raw_retention"] = retention
        # Record the empty-cycle proof before any manual V1 gap writes. That
        # makes retries idempotent. Other completed scheduler cycles can
        # legitimately have rows in this later observation window, so their
        # independently queried IDs form the allowlist for the retained-row
        # audit; the final recovery audit verifies their full contents.
        scheduled_expected: dict[str, dict[str, Any]] = {}
        for observed_cycle in cycles:
            bounds = tuple(observed_cycle["index_bounds"])
            scheduled_expected[observed_cycle["sid"]] = self._v1_expected_rows(
                journal,
                bounds,
                observed_cycle["event_bounds"],
                f"V1 resumed scheduler source audit {bounds[0]}",
            )
        self._reconcile_pending_v1_manual_slices(journal, recovery, scheduled_expected)
        allowed_scheduler_ids = {
            rollup_id
            for expected_rows in scheduled_expected.values()
            for rollup_id in expected_rows
        }
        allowed_manual_ids = self._verified_v1_manual_recovery_ids(journal, recovery)
        allowed_empty_audit_ids = allowed_scheduler_ids | allowed_manual_ids
        for cycle in cycles:
            if cycle.get("empty_summary_warning") is not True:
                continue
            bounds = tuple(cycle["index_bounds"])
            key = f"{bounds[0]}:{bounds[1]}"
            prior = empty_proofs.get(key)
            if prior is not None:
                if prior.get("sid") != cycle.get("sid"):
                    raise Refused("V1 empty-cycle proof SID changed on resume")
                continue
            expected = scheduled_expected[cycle["sid"]]
            if expected:
                raise Refused(
                    "resumed V1 scheduler reported empty output while source rows exist"
                )
            proof = self._assert_empty_summary_index_window(
                journal,
                V1_INDEX,
                "adm:conversation",
                int(cycle["anchor"]),
                observation,
                f"V1 resumed empty summary audit {bounds[0]}",
                allowed_rollup_ids=allowed_empty_audit_ids,
            )
            empty_proofs[key] = {
                "sid": cycle["sid"],
                "index_bounds": list(bounds),
                **proof,
            }
            self._write_journal(journal)

        def validate_expected(
            bounds: tuple[int, int], event_bounds: dict[str, str], label: str
        ) -> dict[str, dict[str, Any]]:
            return self._v1_expected_rows(journal, bounds, event_bounds, label)

        for raw_slice in gap_slices:
            start, finish = raw_slice["start"], raw_slice["end"]
            anchor = start + 2 * SLICE_SECONDS
            event_bounds = {
                "earliest_time": str(anchor - 24 * 60 * 60),
                "latest_time": str(anchor + 15 * 60),
            }
            intent = f"{start}:{finish}"
            existing_state = recovery["expected_slices"].get(intent)
            expected = validate_expected(
                (start, finish), event_bounds, f"V1 recovery expected {start}"
            )
            expected_hash = fingerprint(expected)
            if (
                existing_state
                and existing_state.get("expected_fingerprint") != expected_hash
            ):
                raise Refused("V1 recovery source changed after its bounded read")
            recovery["expected_slices"][intent] = {
                "index_bounds": [start, finish],
                "event_bounds": event_bounds,
                "expected": expected,
                "expected_fingerprint": expected_hash,
                "state": "expected",
            }
            self._write_journal(journal)
            cumulative_expected = {}
            for prior_intent, item in recovery["expected_slices"].items():
                if prior_intent != intent and item.get("state") == "verified":
                    cumulative_expected = _add_record_maps(
                        cumulative_expected,
                        item.get("expected") or {},
                        label="V1 recovery manual intents",
                    )
            for item in recovery["scheduler_cycles"].values():
                cumulative_expected = _add_record_maps(
                    cumulative_expected,
                    item.get("expected") or {},
                    label="V1 recovery scheduled intents",
                )
            for observed_cycle in cycles:
                observed_key = (
                    f"{observed_cycle['index_bounds'][0]}:"
                    f"{observed_cycle['index_bounds'][1]}"
                )
                if observed_key in recovery["scheduler_cycles"]:
                    continue
                cumulative_expected = _add_record_maps(
                    cumulative_expected,
                    scheduled_expected[observed_cycle["sid"]],
                    label="V1 recovery scheduled intents",
                )
            expected_with_current = _add_record_maps(
                cumulative_expected, expected, label="V1 recovery current intent"
            )
            already = self._v1_persisted_rows(
                journal,
                expected_with_current,
                event_bounds,
                f"V1 recovery existing rows {start}",
            )
            if already not in (cumulative_expected, expected_with_current):
                raise Refused(
                    "V1 recovery retained rows do not cover the expected source slice"
                )
            writer_intent = fingerprint(
                {
                    "migration_id": journal["migration_id"],
                    "rollback_resume_epoch": resume_epoch,
                    "slice": [start, finish],
                    "expected": expected_hash,
                }
            )
            matching_jobs = [
                job
                for job in journal.get("jobs", [])
                if job.get("kind") == "saved_search"
                and job.get("label") == "ADM - Conversation rollup"
                and job.get("request_bounds")
                == {
                    "index_earliest": str(start),
                    "index_latest": str(finish),
                    "earliest_time": event_bounds["earliest_time"],
                    "latest_time": event_bounds["latest_time"],
                }
                and job.get("intent_fingerprint") == writer_intent
            ]
            dispatch_jobs = [
                job
                for job in matching_jobs
                if job.get("sid")
                or job.get("state")
                not in {"rejected", "configuration_pending", "preparation_aborted"}
            ]
            if expected:
                if len(dispatch_jobs) > 1:
                    raise Refused("V1 recovery slice has ambiguous writer intents")
                if already == expected_with_current and not dispatch_jobs:
                    raise Refused(
                        "V1 recovery retained rows have no exact journaled writer SID"
                    )
                bounds = {
                    "index_earliest": str(start),
                    "index_latest": str(finish),
                    "earliest_time": event_bounds["earliest_time"],
                    "latest_time": event_bounds["latest_time"],
                }
                output_rows = self._dispatch_writer(
                    journal,
                    "ADM - Conversation rollup",
                    bounds,
                    label=f"V1 rollback recovery slice {start}",
                    intent_fingerprint=writer_intent,
                    persist_result_rows=True,
                )
                if self._v1_record_map(output_rows) != expected:
                    raise Refused(
                        "V1 recovery writer output differs from raw-source expectation"
                    )
                cumulative_expected = _add_record_maps(
                    cumulative_expected, expected, label="V1 recovery manual intents"
                )
                for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
                    observed = self._v1_persisted_rows(
                        journal,
                        cumulative_expected,
                        event_bounds,
                        f"V1 recovery readback {start}",
                    )
                    if observed == cumulative_expected:
                        break
                    self._wait_before_summary_retry(attempt)
                else:
                    raise Refused("V1 recovery summary rows did not become visible")
                matching_jobs = [
                    job
                    for job in journal.get("jobs", [])
                    if job.get("kind") == "saved_search"
                    and job.get("label") == "ADM - Conversation rollup"
                    and job.get("request_bounds")
                    == {
                        "index_earliest": str(start),
                        "index_latest": str(finish),
                        "earliest_time": event_bounds["earliest_time"],
                        "latest_time": event_bounds["latest_time"],
                    }
                    and job.get("intent_fingerprint") == writer_intent
                ]
            recovery["expected_slices"][intent] = {
                "index_bounds": [start, finish],
                "event_bounds": event_bounds,
                "expected": expected,
                "expected_fingerprint": expected_hash,
                "state": "verified",
                "verified_at": int(self.clock()),
                "manual_job_sids": [
                    job.get("sid")
                    for job in matching_jobs
                    if job.get("state") == "complete" and job.get("sid")
                ],
            }
            if (
                expected
                and len(recovery["expected_slices"][intent]["manual_job_sids"]) != 1
            ):
                raise Refused(
                    "V1 recovery slice has no complete exact-bound writer SID"
                )
            self._write_journal(journal)
            self._verified_v1_manual_recovery_ids(journal, recovery)

        for cycle in cycles:
            bounds = tuple(cycle["index_bounds"])
            key = f"{bounds[0]}:{bounds[1]}"
            expected = validate_expected(
                bounds,
                cycle["event_bounds"],
                f"V1 resumed scheduler expected {bounds[0]}",
            )
            if cycle.get("empty_summary_warning") is True and expected:
                raise Refused(
                    "resumed V1 scheduler reported empty output while source rows exist"
                )
            cumulative_expected = {}
            for item in recovery["expected_slices"].values():
                if item.get("state") == "verified":
                    cumulative_expected = _add_record_maps(
                        cumulative_expected,
                        item.get("expected") or {},
                        label="V1 recovery manual intents",
                    )
            observed_keys = {
                f"{item['index_bounds'][0]}:{item['index_bounds'][1]}"
                for item in cycles
            }
            for scheduled_key, scheduled_item in recovery["scheduler_cycles"].items():
                if scheduled_key not in observed_keys:
                    cumulative_expected = _add_record_maps(
                        cumulative_expected,
                        scheduled_item.get("expected") or {},
                        label="V1 recovery scheduled intents",
                    )
            for observed_cycle in cycles:
                scheduled_map = scheduled_expected[observed_cycle["sid"]]
                cumulative_expected = _add_record_maps(
                    cumulative_expected,
                    scheduled_map,
                    label="V1 observed scheduled recovery intents",
                )
            prior_cycle = recovery["scheduler_cycles"].get(key)
            expected_fingerprint = fingerprint(expected)
            if prior_cycle is not None:
                if (
                    prior_cycle.get("sid") != cycle["sid"]
                    or prior_cycle.get("expected_fingerprint") != expected_fingerprint
                ):
                    raise Refused("V1 scheduled recovery intent changed on resume")
            for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
                actual = self._v1_persisted_rows(
                    journal,
                    cumulative_expected,
                    cycle["event_bounds"],
                    f"V1 resumed scheduler readback {bounds[0]}",
                )
                if actual == cumulative_expected:
                    break
                self._wait_before_summary_retry(attempt)
            if actual != cumulative_expected:
                raise Refused("resumed V1 scheduler output is not completely retained")
            recovery["scheduler_cycles"][key] = {
                "sid": cycle["sid"],
                "index_bounds": list(bounds),
                "event_bounds": cycle["event_bounds"],
                "expected": expected,
                "expected_fingerprint": expected_fingerprint,
                "retained_fingerprint": fingerprint(actual),
                "state": "verified",
                "verified_at": int(self.clock()),
                **(
                    {"empty_summary_proof": empty_proofs[key]}
                    if key in empty_proofs
                    else {}
                ),
            }
            self._write_journal(journal)

        # The first observation drives gap planning; manual backfill runs and
        # readback happen afterwards. Re-inventory at a later, independent
        # boundary so the final raw-index audit includes those writes and
        # accounts for every scheduler dispatch visible through that boundary.
        audit_observation = int(self.clock())
        fresh_cycles = self._scheduled_writer_cycles(
            "ADM - Conversation rollup",
            journal,
            lower_epoch=resume_epoch + 1,
            upper_epoch=audit_observation + 1,
        )
        fresh_keys = [tuple(item["index_bounds"]) for item in fresh_cycles]
        original_keys = [tuple(item["index_bounds"]) for item in cycles]
        if fresh_keys[: len(original_keys)] != original_keys:
            raise Refused("V1 scheduler inventory changed previously validated cycles")
        if len(fresh_keys) > len(original_keys):
            retries = int(recovery.get("inventory_retries", 0)) + 1
            recovery.update(
                audit_observation_epoch=audit_observation,
                inventory_retries=retries,
            )
            self._write_journal(journal)
            if retries > 8:
                raise Refused("V1 scheduler kept advancing during bounded recovery")
            return self._v1_recovery_window(journal, resume_epoch)
        for previous, fresh in zip(cycles, fresh_cycles):
            if previous.get("sid") != fresh.get("sid") or previous.get(
                "event_bounds"
            ) != fresh.get("event_bounds"):
                raise Refused("V1 scheduler slice source bounds changed on re-audit")
        observation = audit_observation
        recovery["audit_observation_epoch"] = observation
        recovery["observation_epoch"] = observation
        self._write_journal(journal)

        expected_all = {}
        for group in (recovery["expected_slices"], recovery["scheduler_cycles"]):
            for item in group.values():
                for rollup_id, row in item["expected"].items():
                    expected_all = _add_record_maps(
                        expected_all,
                        {rollup_id: row},
                        label="V1 recovery source slices",
                    )
        if expected_all:
            query = (
                f'search index={V1_INDEX} source="adm:conversation" '
                f"| where _indextime>={resume_epoch} AND _indextime<={observation} "
                "| fields " + " ".join(V1_ROW_FIELDS)
            )
            retained_rows = self._query(
                journal,
                query,
                0,
                observation + 900,
                label="complete V1 rollback recovery window",
                earliest_time="0",
                latest_time=str(observation + 900),
                persist_result_rows=False,
            )
            retained = self._v1_record_map(retained_rows)
            if retained != expected_all:
                raise Refused(
                    "V1 rollback window has missing or unexplained summary rows"
                )
        else:
            # Empty expected windows must still prove there were no retained rows.
            query = (
                f'search index={V1_INDEX} source="adm:conversation" '
                f"| where _indextime>={resume_epoch} AND _indextime<={observation} "
                "| fields " + " ".join(V1_ROW_FIELDS)
            )
            if self._query(
                journal,
                query,
                0,
                observation + 900,
                label="empty V1 rollback recovery window",
                earliest_time="0",
                latest_time=str(observation + 900),
                persist_result_rows=False,
            ):
                raise Refused(
                    "V1 rollback expected an empty retained window but found rows"
                )
        recovery.update(
            state="verified",
            completed_at=int(self.clock()),
            observed_through=cycles[-1]["index_bounds"][1],
            expected_rollups=len(expected_all),
            expected_fingerprint=fingerprint(expected_all),
            retained_fingerprint=fingerprint(expected_all),
        )
        self._write_journal(journal)
        return recovery

    def _bridge_to_first_scheduled_cycle(
        self, journal: dict[str, Any], scenario: dict[str, Any]
    ) -> bool:
        """Validate every scheduler cycle available through a durable watermark."""
        writer_enable_times = [
            _integer(item.get("verified_at"))
            for item in journal["cutover"]["mutations"]
            if item.get("kind") == "saved_search"
            and item.get("name") in {spec["saved_search"] for spec in STREAMS.values()}
            and _strict_bool(item.get("after")) is False
            and item.get("state") == "applied"
        ]
        if len(writer_enable_times) != len(STREAMS) or any(
            value is None for value in writer_enable_times
        ):
            raise Refused("both V2 writer enablement times are not journaled")
        enabled_after = max(writer_enable_times)
        # Freeze an independent wall-clock boundary before listing jobs. A
        # maximum timestamp from expected rows can hide a later unexpected
        # writer row, so the final index audit is bounded by this observation.
        observed_at = int(self.clock())
        journal["cutover"]["schedule_observation_epoch"] = observed_at
        journal["cutover"]["schedule_observation_recorded_at"] = observed_at
        event_latest = _integer(journal.get("event_latest"))
        journal["event_latest"] = str(max(event_latest or 0, observed_at + 15 * 60))
        self._write_journal(journal)
        cycles_by_stream = {
            stream: self._scheduled_writer_cycles(
                spec["saved_search"],
                journal,
                lower_epoch=enabled_after + 1,
                upper_epoch=observed_at + 1,
            )
            for stream, spec in STREAMS.items()
        }
        history_enabled_after = self._history_writer_activation_epoch(journal)
        history_cycles = (
            self._scheduled_history_cycles(
                journal,
                lower_epoch=history_enabled_after,
                upper_epoch=observed_at + 1,
            )
            if history_enabled_after is not None
            else []
        )
        cycle_keys = {
            stream: [tuple(cycle["index_bounds"]) for cycle in cycles]
            for stream, cycles in cycles_by_stream.items()
        }
        if any(not cycles for cycles in cycles_by_stream.values()) or (
            history_enabled_after is not None and not history_cycles
        ):
            journal["cutover"]["state"] = "awaiting_first_scheduled_cycle"
            journal["cutover"]["scheduled_cycle_checked_at"] = int(self.clock())
            journal["cutover"]["scheduled_cycle_evidence"] = cycle_keys
            journal["cutover"]["history_cycle_evidence"] = [
                cycle["index_bounds"] for cycle in history_cycles
            ]
            self._write_journal(journal)
            return False
        if len({tuple(value) for value in cycle_keys.values()}) != 1:
            raise Refused("V2 scheduled writers do not share the same completed slices")
        common_bounds = [tuple(value) for value in cycle_keys.values()][0]
        if not common_bounds:
            return False
        expected_first_anchor = (enabled_after // SLICE_SECONDS + 1) * SLICE_SECONDS
        if common_bounds[0][0] + 2 * SLICE_SECONDS != expected_first_anchor:
            raise Refused("first scheduled V2 cycle is missing after writer enablement")
        if history_enabled_after is not None:
            expected_history_anchor = self._history_next_anchor(history_enabled_after)
            if history_cycles[0]["anchor"] != expected_history_anchor:
                raise Refused("first scheduled history builder cycle is missing")
            self._stage_scheduled_history_evidence(journal, history_cycles)
            self._stage_history_gap_before_first_cycle(
                journal,
                int(history_cycles[0]["index_bounds"][0]),
            )
        empty_proofs = journal["cutover"].setdefault("empty_summary_proofs", {})
        cycle_expected: dict[str, dict[str, dict[str, Any]]] = {
            stream: {} for stream in cycles_by_stream
        }
        for stream, cycles in cycles_by_stream.items():
            spec = STREAMS[stream]
            for cycle in cycles:
                query = (
                    self._writer_query(spec, journal)
                    + " | fields "
                    + " ".join(V2_ROW_FIELDS[stream])
                )
                rows = self._query(
                    journal,
                    query,
                    cycle["index_bounds"][0],
                    cycle["index_bounds"][1],
                    label=f"scheduled {stream} manifest {cycle['index_bounds'][0]}",
                    earliest_time=cycle["event_bounds"]["earliest_time"],
                    latest_time=cycle["event_bounds"]["latest_time"],
                )
                cycle_expected[stream][cycle["sid"]] = self._record_map(rows, stream)

        def expected_with_observed_schedules(stream: str) -> dict[str, Any]:
            combined = self._cumulative_v2_expected(journal, stream)
            recorded_bounds = {
                tuple(item.get("index_bounds", []))
                for item in (
                    journal["cutover"]
                    .get("scheduled_streams", {})
                    .get(stream, {})
                    .get("cycles", [])
                )
            }
            for observed_cycle in cycles_by_stream[stream]:
                if tuple(observed_cycle["index_bounds"]) in recorded_bounds:
                    continue
                combined = _add_record_maps(
                    combined,
                    cycle_expected[stream][observed_cycle["sid"]],
                    label=f"V2 observed scheduled {stream} intents",
                )
            return combined

        allowed_v2_ids = {
            rollup_id
            for expected_by_sid in cycle_expected.values()
            for expected_rows in expected_by_sid.values()
            for rollup_id in expected_rows
        }
        for slice_record in journal.get("slices", []):
            for stream in STREAMS:
                allowed_v2_ids.update(
                    (slice_record.get("streams", {}).get(stream) or {})
                    .get("expected", {})
                    .keys()
                )
        for stream, cycles in cycles_by_stream.items():
            spec = STREAMS[stream]
            for cycle in cycles:
                if cycle.get("empty_summary_warning") is not True:
                    continue
                bounds = tuple(cycle["index_bounds"])
                proof_key = f"{stream}:{cycle['sid']}"
                prior = empty_proofs.get(proof_key)
                if prior is not None:
                    if prior.get("index_bounds") != list(bounds):
                        raise Refused("V2 empty-cycle proof bounds changed on resume")
                    continue
                if cycle_expected[stream][cycle["sid"]]:
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
                proof = self._assert_empty_summary_index_window(
                    journal,
                    V2_INDEX,
                    spec["source"],
                    int(cycle["anchor"]),
                    observed_at,
                    f"empty scheduled {stream} retained-row audit {bounds[0]}",
                    allowed_rollup_ids=allowed_v2_ids,
                )
                empty_proofs[proof_key] = {
                    "sid": cycle["sid"],
                    "index_bounds": list(bounds),
                    **proof,
                }
                self._write_journal(journal)
        # Stage each gap once, then validate both writers for the same cycle
        # before moving the range watermark. Processing a stream at a time
        # used to advance `range.end` on the first stream and make the second
        # stream look like an overlap on every real non-empty handoff.
        staged_extra = sum(
            1 for item in journal["slices"] if item.get("handoff_bridge") is True
        )
        prior_by_stream = {
            stream: {
                tuple(item.get("index_bounds", [])): item
                for item in (
                    journal["cutover"]
                    .get("scheduled_streams", {})
                    .get(stream, {})
                    .get("cycles", [])
                )
            }
            for stream in STREAMS
        }
        for cycle_bounds in common_bounds:
            start, end = cycle_bounds
            range_end = int(journal["range"]["end"])
            previously_checkpointed = end <= range_end
            if start < range_end and not previously_checkpointed:
                raise Refused("scheduled V2 slice overlaps a staged or earlier slice")
            if previously_checkpointed:
                for stream, cycles in cycles_by_stream.items():
                    cycle = next(
                        item
                        for item in cycles
                        if tuple(item["index_bounds"]) == cycle_bounds
                    )
                    prior = prior_by_stream[stream].get(cycle_bounds)
                    if (
                        not isinstance(prior, dict)
                        or prior.get("sid") != cycle.get("sid")
                        or prior.get("event_bounds") != cycle.get("event_bounds")
                        or prior.get("index_bounds") != list(cycle_bounds)
                    ):
                        raise Refused(
                            "scheduled V2 cycle overlaps the staged range without matching durable evidence"
                        )
                    spec = STREAMS[stream]
                    query = (
                        self._writer_query(spec, journal)
                        + " | fields "
                        + " ".join(V2_ROW_FIELDS[stream])
                    )
                    expected_rows = self._query(
                        journal,
                        query,
                        start,
                        end,
                        label=f"resumed scheduled {stream} expected output {start}",
                        earliest_time=cycle["event_bounds"]["earliest_time"],
                        latest_time=cycle["event_bounds"]["latest_time"],
                    )
                    expected = self._record_map(expected_rows, stream)
                    if cycle.get("empty_summary_warning") is True and expected:
                        raise Refused(
                            "scheduled writer reported empty output while source rows exist"
                        )
                    if cycle.get("empty_summary_warning") is True and not isinstance(
                        prior.get("empty_summary_proof"), dict
                    ):
                        raise Refused(
                            "empty scheduled writer has no independent retained-index proof"
                        )
                    cumulative_expected = expected_with_observed_schedules(stream)
                    actual = self._poll_persisted_rows(
                        journal,
                        cumulative_expected,
                        stream,
                        label=f"resumed scheduled {stream} output {start}",
                    )
                    if actual != cumulative_expected or fingerprint(
                        expected
                    ) != prior.get("expected_fingerprint"):
                        raise Refused(
                            "previously checkpointed scheduled V2 evidence changed"
                        )
                continue
            if start > range_end:
                gap = plan_slices(range_end, start, int(self.clock()))
                if not gap or gap[0]["start"] != range_end or gap[-1]["end"] != start:
                    raise Refused("scheduled V2 handoff gap is not fully sliceable")
                by_bounds = {
                    (item.get("start"), item.get("end")): item
                    for item in journal["slices"]
                    if item.get("handoff_bridge") is True
                }
                bridge_slices = []
                for time_slice in gap:
                    key = (time_slice["start"], time_slice["end"])
                    slice_record = by_bounds.get(key)
                    if slice_record is None:
                        slice_record = {
                            **time_slice,
                            "streams": {name: {"state": "pending"} for name in STREAMS},
                            "history": {"state": "pending"},
                            "handoff_bridge": True,
                        }
                        journal["slices"].append(slice_record)
                        by_bounds[key] = slice_record
                        staged_extra += 1
                        self._write_journal(journal)
                    bridge_slices.append(slice_record)
                for slice_record in bridge_slices:
                    for bridge_stream in STREAMS:
                        recorded_bounds = {
                            tuple(item.get("index_bounds", []))
                            for item in (
                                journal["cutover"]
                                .get("scheduled_streams", {})
                                .get(bridge_stream, {})
                                .get("cycles", [])
                            )
                        }
                        observed_manifests = [
                            cycle_expected[bridge_stream][cycle["sid"]]
                            for cycle in cycles_by_stream[bridge_stream]
                            if tuple(cycle["index_bounds"]) not in recorded_bounds
                        ]
                        self._stage_stream(
                            journal,
                            slice_record,
                            bridge_stream,
                            observed_scheduled_expected=observed_manifests,
                        )
                    self._stage_history_slice(journal, slice_record)

            cycle_evidence = {}
            for stream, cycles in cycles_by_stream.items():
                cycle = next(
                    item
                    for item in cycles
                    if tuple(item["index_bounds"]) == cycle_bounds
                )
                spec = STREAMS[stream]
                query = (
                    self._writer_query(spec, journal)
                    + " | fields "
                    + " ".join(V2_ROW_FIELDS[stream])
                )
                expected_rows = self._query(
                    journal,
                    query,
                    start,
                    end,
                    label=f"scheduled {stream} expected output {start}",
                    earliest_time=cycle["event_bounds"]["earliest_time"],
                    latest_time=cycle["event_bounds"]["latest_time"],
                )
                expected = self._record_map(expected_rows, stream)
                if cycle.get("empty_summary_warning") is True and expected:
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
                actual = self._poll_persisted_rows(
                    journal,
                    expected_with_observed_schedules(stream),
                    stream,
                    label=f"scheduled {stream} output {start}",
                )
                cumulative_expected = expected_with_observed_schedules(stream)
                if actual != cumulative_expected:
                    raise Refused(
                        f"scheduled {stream} output is not fully indexed and validated"
                    )
                cycle_evidence[stream] = {
                    "state": "verified",
                    **cycle,
                    "expected": expected,
                    "expected_fingerprint": fingerprint(expected),
                    "actual_fingerprint": fingerprint(actual),
                    "rows": len(expected),
                    "validated_at": int(self.clock()),
                    **(
                        {
                            "empty_summary_proof": empty_proofs[
                                f"{stream}:{cycle['sid']}"
                            ]
                        }
                        if cycle.get("empty_summary_warning") is True
                        else {}
                    ),
                }

            for stream, evidence in cycle_evidence.items():
                journal["cutover"].setdefault("scheduled_streams", {}).setdefault(
                    stream, {"cycles": []}
                )["cycles"].append(evidence)
            journal["range"]["end"] = end
            self._write_journal(journal)
        for stream in STREAMS:
            recorded = [
                tuple(cycle["index_bounds"])
                for cycle in journal["cutover"]["scheduled_streams"][stream]["cycles"]
            ]
            if recorded != list(common_bounds):
                raise Refused("scheduled writer evidence is missing a contiguous cycle")
        journal["cutover"]["bridge_slices"] = staged_extra
        journal["cutover"]["manual_bridge_writes"] = [
            {
                "index_bounds": [item["start"], item["end"]],
                "history_fingerprint": item.get("history", {}).get(
                    "actual_fingerprint"
                ),
                "stream_fingerprints": {
                    stream: item.get("streams", {})
                    .get(stream, {})
                    .get("actual_fingerprint")
                    for stream in STREAMS
                },
                "job_sids": [
                    job.get("sid")
                    for job in journal.get("jobs", [])
                    if job.get("state") == "complete"
                    and job.get("request_bounds", {}).get("index_earliest")
                    == str(item["start"])
                    and job.get("request_bounds", {}).get("index_latest")
                    == str(item["end"])
                ],
            }
            for item in journal["slices"]
            if item.get("handoff_bridge") is True
        ]
        journal["cutover"]["state"] = "validating_scheduled_cycles"

        # Manual bridge output is written after the first schedule inventory.
        # Take a later independent boundary, then inventory scheduler jobs
        # again through that boundary before auditing the summary index. This
        # both covers the manual SIDs and proves there is no unaccounted
        # scheduled writer output after the initial inventory.
        if history_enabled_after is not None:
            self._stage_history_tail_through_summary(journal, int(common_bounds[-1][1]))
        audit_observed_at = int(self.clock())
        fresh_cycles = {
            stream: self._scheduled_writer_cycles(
                spec["saved_search"],
                journal,
                lower_epoch=enabled_after + 1,
                upper_epoch=audit_observed_at + 1,
            )
            for stream, spec in STREAMS.items()
        }
        fresh_history_cycles = (
            self._scheduled_history_cycles(
                journal,
                lower_epoch=history_enabled_after,
                upper_epoch=audit_observed_at + 1,
            )
            if history_enabled_after is not None
            else []
        )
        fresh_bounds = {
            stream: [tuple(item["index_bounds"]) for item in cycles]
            for stream, cycles in fresh_cycles.items()
        }
        if any(
            bounds != fresh_bounds[next(iter(STREAMS))]
            for bounds in fresh_bounds.values()
        ):
            raise Refused("V2 scheduler inventories disagree at the audit boundary")
        latest_bounds = next(iter(fresh_bounds.values()))
        if latest_bounds[: len(common_bounds)] != list(common_bounds):
            raise Refused("V2 scheduler inventory changed previously validated cycles")
        if len(latest_bounds) > len(common_bounds):
            retries = int(journal["cutover"].get("bridge_inventory_retries", 0)) + 1
            journal["cutover"].update(
                schedule_observation_epoch=audit_observed_at,
                schedule_observation_recorded_at=audit_observed_at,
                bridge_inventory_retries=retries,
            )
            self._write_journal(journal)
            if retries > 8:
                raise Refused(
                    "V2 scheduler kept advancing during bounded migration audit"
                )
            return self._bridge_to_first_scheduled_cycle(journal, scenario)
        if history_enabled_after is not None:
            current_history = [tuple(item["index_bounds"]) for item in history_cycles]
            latest_history = [
                tuple(item["index_bounds"]) for item in fresh_history_cycles
            ]
            if latest_history[: len(current_history)] != current_history:
                raise Refused("history scheduler inventory changed validated cycles")
            if len(latest_history) > len(current_history):
                retries = (
                    int(journal["cutover"].get("history_inventory_retries", 0)) + 1
                )
                journal["cutover"].update(
                    history_observation_epoch=audit_observed_at,
                    history_inventory_retries=retries,
                )
                self._write_journal(journal)
                if retries > 8:
                    raise Refused(
                        "history scheduler kept advancing during bounded migration audit"
                    )
                return self._bridge_to_first_scheduled_cycle(journal, scenario)
            for previous, current in zip(history_cycles, fresh_history_cycles):
                if (
                    previous["sid"] != current["sid"]
                    or previous["event_bounds"] != current["event_bounds"]
                ):
                    raise Refused("history scheduler source bounds changed on re-audit")
            self._stage_scheduled_history_evidence(journal, fresh_history_cycles)
            journal["cutover"]["history_observation_epoch"] = audit_observed_at
            journal["cutover"]["scheduled_history"]["observation_epoch"] = (
                audit_observed_at
            )
        for stream, cycles in fresh_cycles.items():
            for cycle in cycles:
                if tuple(cycle["index_bounds"]) not in common_bounds:
                    raise Refused("V2 scheduler audit found an unvalidated cycle")
                prior = {
                    tuple(item.get("index_bounds", [])): item
                    for item in journal["cutover"]
                    .get("scheduled_streams", {})
                    .get(stream, {})
                    .get("cycles", [])
                }.get(tuple(cycle["index_bounds"]))
                if prior and (
                    prior.get("sid") != cycle.get("sid")
                    or prior.get("event_bounds") != cycle.get("event_bounds")
                ):
                    raise Refused(
                        "V2 scheduled cycle source bounds changed on re-audit"
                    )
        journal["cutover"]["schedule_observation_epoch"] = audit_observed_at
        journal["cutover"]["schedule_observation_recorded_at"] = audit_observed_at
        journal["event_latest"] = str(
            max(int(journal["event_latest"]), audit_observed_at + 15 * 60)
        )
        self._write_journal(journal)
        # Refresh history/catalog/public-surface evidence against all bridged
        # and scheduler-produced rows. The ingestion audit uses the journaled
        # row-derived watermark, so later ordinary scheduler writes are outside
        # this completed migration window.
        self.validate(scenario)
        journal = self._load()
        journal["cutover"]["scheduled_cycle_bounds"] = {
            "index_earliest": common_bounds[0][0],
            "index_latest": common_bounds[-1][1],
        }
        journal["cutover"]["scheduled_watermark_at"] = int(self.clock())
        journal["cutover"]["state"] = "scheduled_cycle_validated"
        self._write_journal(journal)
        return True

    def cutover(self) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        if journal.get("phase") not in {"coverage_validated", "cutover_in_progress"}:
            if journal.get("phase") == "cutover":
                self._assert_cutover_origin_compatible(journal)
                for mutation in (journal.get("cutover") or {}).get("mutations", []):
                    if not self._mutation_equal(
                        mutation,
                        self._mutation_target(mutation)["value"],
                        mutation["after"],
                    ):
                        raise Refused(
                            "completed cutover is no longer fully active; reconcile the journaled target"
                        )
                return {"status": "cutover", "migration_id": journal["migration_id"]}
            raise Refused("coverage must be validated before cutover")
        # Derived from the locked journal, never from a path stored in it.
        candidate_path = self.journal.path.with_suffix(".candidate.json")
        try:
            candidate_bytes = self._read_result_artifact_file(
                candidate_path, MAX_CANDIDATE_BYTES
            )
            candidate = json.loads(candidate_bytes)
        except (Refused, UnicodeError, json.JSONDecodeError):
            raise Refused("validated candidate evidence is unavailable") from None
        if hashlib.sha256(candidate_bytes).hexdigest() != journal.get(
            "candidate_sha256"
        ):
            raise Refused("validated candidate evidence changed")
        if (
            not isinstance(candidate, dict)
            or candidate.get("migration_id") != journal.get("migration_id")
            or candidate.get("interface_sha256") != journal.get("interface_sha256")
            or candidate.get("origin_fingerprint") != journal.get("origin_fingerprint")
            or candidate.get("cutover_eligible") is not True
        ):
            raise Refused(
                "catalog, topology, Find, health, drilldown and public reader smoke evidence is incomplete"
            )
        scenario = candidate.get("scenario")
        if not isinstance(scenario, dict) or fingerprint(scenario) != candidate.get(
            "scenario_sha256"
        ):
            raise Refused(
                "candidate does not contain its deployment validation scenario"
            )
        interface, _ = self._interface()
        if journal.get("phase") == "coverage_validated":
            self._assert_origin_unchanged(journal)
            legacy_enabled = (
                (journal.get("origin") or {})
                .get("saved_searches", {})
                .get("ADM - Conversation rollup", {})
                .get("content", {})
                .get("disabled")
            )
            if _strict_bool(legacy_enabled) is False and not isinstance(
                journal.get("v1_pre_pause"), dict
            ):
                self._capture_v1_pre_pause(journal)
            mutations = self._build_cutover_mutations(journal, interface)
            journal["cutover"] = {
                "state": "in_progress",
                "started_at": int(self.clock()),
                "mutations": mutations,
                "scenario_sha256": candidate["scenario_sha256"],
                "scenario": scenario,
            }
            journal["phase"] = "cutover_in_progress"
            self._write_journal(journal)
        else:
            self._assert_cutover_origin_compatible(journal)
            mutations = journal.get("cutover", {}).get("mutations")
            if not isinstance(mutations, list) or not mutations:
                raise Refused(
                    "partial cutover journal has no allowlisted mutation plan"
                )
        mutation_ids = [item["id"] for item in mutations]
        for mutation_id in mutation_ids:
            # Always mutate the object held by the latest durable journal. The
            # catch-up validation below rewrites the journal, so references
            # captured before that point are stale and would lose readbacks.
            journal = self._load()
            mutations = journal.get("cutover", {}).get("mutations", [])
            mutation = next(
                (item for item in mutations if item.get("id") == mutation_id), None
            )
            if mutation is None:
                raise Refused("cutover mutation disappeared from its journal")
            if (
                mutation.get("name") == "ADM - Conversation rollup"
                and mutation.get("field") == "disabled"
                and _strict_bool(mutation.get("after")) is True
                and (journal.get("origin") or {})
                .get("saved_searches", {})
                .get("ADM - Conversation rollup", {})
                .get("content", {})
                .get("disabled")
                is not None
                and _strict_bool(
                    journal["origin"]["saved_searches"]["ADM - Conversation rollup"][
                        "content"
                    ]["disabled"]
                )
                is False
                and not isinstance(journal.get("v1_pre_pause"), dict)
            ):
                self._capture_v1_pre_pause(journal)
                journal = self._load()
                mutation = next(
                    item
                    for item in journal["cutover"]["mutations"]
                    if item["id"] == mutation_id
                )
            if mutation["kind"] == "macro_definition" and not journal["cutover"].get(
                "scheduled_cycle_bounds"
            ):
                if not self._bridge_to_first_scheduled_cycle(journal, scenario):
                    return {
                        "status": "awaiting_first_scheduled_cycle",
                        "migration_id": journal["migration_id"],
                    }
                journal = self._load()
                mutation = next(
                    item
                    for item in journal["cutover"]["mutations"]
                    if item["id"] == mutation_id
                )
            self._assert_cutover_origin_compatible(journal)
            self._apply_mutation(journal, mutation)
            if mutation.get("drain_after") and not journal["cutover"].get(
                "post_pause_validation_at"
            ):
                self._drain_legacy_writer(journal)
                self._catch_up_after_pause(journal, scenario)
                journal = self._load()
                mutations = journal["cutover"]["mutations"]
        journal = self._load()
        if not journal["cutover"].get("scheduled_cycle_bounds"):
            raise Refused("first scheduled v2 writer cycle is not validated")
        journal["cutover"]["public_selector_evidence"] = self._public_selector_smoke(
            journal,
            interface,
            scenario,
            phase="public_after_invoke",
        )
        journal["phase"] = "cutover"
        journal["cutover"].update(state="complete", completed_at=int(self.clock()))
        self._write_journal(journal)
        return {"status": "cutover", "migration_id": journal["migration_id"]}

    def rollback(self) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        if journal.get("phase") not in {
            "cutover",
            "cutover_in_progress",
            "rollback_in_progress",
        }:
            raise Refused(
                "rollback is available only for a journaled complete or partial cutover"
            )
        origin_legacy = (
            (journal.get("origin") or {})
            .get("saved_searches", {})
            .get("ADM - Conversation rollup", {})
            .get("content", {})
            .get("disabled")
        )
        if _strict_bool(origin_legacy) is False:
            if not isinstance(journal.get("v1_pre_pause"), dict):
                raise Refused(
                    "enabled-origin rollback lacks a validated pre-pause V1 slice"
                )
            # request_pending, request_unknown, readback_failed and applied may
            # all have enabled V1 and must reach the reconcile path below. A
            # not-started request proves nothing by itself, and a rejected one
            # only means the readback differed (e.g. ACL) while the value may
            # already equal the target, so a live read decides both.
            v1_resume = next(
                (
                    item
                    for item in (journal.get("rollback") or {}).get("mutations", [])
                    if item.get("name") == "ADM - Conversation rollup"
                    and item.get("field") == "disabled"
                ),
                None,
            )
            v1_possibly_resumed = v1_resume is not None and (
                v1_resume.get("state") not in {"pending", "rejected"}
                or not self._mutation_equal(
                    v1_resume,
                    self._mutation_target(v1_resume)["value"],
                    v1_resume["before"],
                )
            )
            pre_end = _integer(
                (journal["v1_pre_pause"].get("index_bounds") or [None, None])[-1]
            )
            if pre_end is None:
                raise Refused(
                    "enabled-origin rollback lacks a validated pre-pause V1 slice"
                )
            if not v1_possibly_resumed and (
                rollback_recovery_horizon_seconds(int(self.clock()) - pre_end)
                > MAX_BACKFILL_SECONDS
            ):
                consequence = (
                    "the journal stays rollback_in_progress with V1 paused and V2 public"
                    if journal.get("phase") == "rollback_in_progress"
                    else "nothing was changed"
                )
                raise Refused(
                    "enabled-origin rollback can no longer recover the paused V1 "
                    "window and finish inside the seven-day bound (the gap slices "
                    "are written one search each, so the required time grows with "
                    f"the gap); {consequence}. See 'If rollback refuses on the "
                    "seven-day bound' in docs/CISCO_CONTRACT_MIGRATION.md"
                )
        if journal.get("phase") == "rollback_in_progress":
            rollback_mutations = journal.get("rollback", {}).get("mutations", [])
        else:
            self._assert_cutover_origin_compatible(journal)
            forward = journal.get("cutover", {}).get("mutations")
            if not isinstance(forward, list) or not forward:
                raise Refused("cutover journal has no mutation plan to restore")
            rollback_mutations = []
            for mutation in reversed(forward):
                reverse = {
                    key: mutation[key]
                    for key in (
                        "id",
                        "kind",
                        "name",
                        "rest_target",
                        "field",
                        "acl",
                        "args",
                    )
                    if key in mutation
                }
                reverse.update(
                    before=mutation["after"],
                    after=mutation["before"],
                    state="pending",
                    drain_after=False,
                )
                rollback_mutations.append(reverse)
            journal["rollback"] = {
                "state": "in_progress",
                "started_at": int(self.clock()),
                "mutations": rollback_mutations,
            }
            journal["phase"] = "rollback_in_progress"
            self._write_journal(journal)

        if _strict_bool(origin_legacy) is False:
            # Resume only the immutable V1 writer first. Keep public V2
            # selectors and V2 writers in their cutover state until every
            # missed raw slice and the first resumed scheduler boundary have
            # exact expected-versus-retained coverage.
            v1_mutation = next(
                (
                    item
                    for item in rollback_mutations
                    if item.get("kind") == "saved_search"
                    and item.get("name") == "ADM - Conversation rollup"
                    and item.get("field") == "disabled"
                ),
                None,
            )
            if v1_mutation is None:
                raise Refused("rollback plan has no V1 writer resume mutation")
            journal = self._load()
            v1_mutation = next(
                item
                for item in journal["rollback"]["mutations"]
                if item.get("id") == v1_mutation["id"]
            )
            self._assert_cutover_origin_compatible(journal)
            if v1_mutation.get("state") != "applied":
                self._apply_mutation(journal, v1_mutation)
            journal = self._load()
            v1_mutation = next(
                item
                for item in journal["rollback"]["mutations"]
                if item.get("name") == "ADM - Conversation rollup"
                and item.get("field") == "disabled"
            )
            resume_epoch = _integer(
                journal.get("rollback", {})
                .get("v1_recovery", {})
                .get("resume_activation_epoch")
            )
            if resume_epoch is None:
                resume_epoch = _integer(v1_mutation.get("verified_at"))
                if resume_epoch is None:
                    raise Refused("V1 writer resume time is not durably verified")
                journal["rollback"].setdefault("v1_recovery", {})[
                    "resume_activation_epoch"
                ] = resume_epoch
                self._write_journal(journal)
            recovery = self._v1_recovery_window(journal, resume_epoch)
            if recovery is None:
                journal = self._load()
                journal["rollback"]["state"] = "awaiting_v1_recovery"
                journal["rollback"]["checked_at"] = int(self.clock())
                self._write_journal(journal)
                return {
                    "status": "awaiting_v1_recovery",
                    "migration_id": journal["migration_id"],
                }
            rollback_mutations = journal["rollback"].get("mutations", [])

        rollback_ids = [item.get("id") for item in rollback_mutations]
        if any(not isinstance(item, str) for item in rollback_ids):
            raise Refused("rollback journal contains a malformed mutation")
        for mutation_id in rollback_ids:
            journal = self._load()
            rollback_mutations = journal.get("rollback", {}).get("mutations", [])
            mutation = next(
                (item for item in rollback_mutations if item.get("id") == mutation_id),
                None,
            )
            if mutation is None:
                raise Refused("rollback mutation disappeared from its journal")
            if (
                _strict_bool(origin_legacy) is False
                and mutation.get("name") == "ADM - Conversation rollup"
                and mutation.get("field") == "disabled"
                and mutation.get("state") == "applied"
            ):
                continue
            self._assert_cutover_origin_compatible(journal)
            self._apply_mutation(journal, mutation)
        interface, _ = self._interface()
        scenario = journal.get("cutover", {}).get("scenario")
        if not isinstance(scenario, dict):
            raise Refused("rollback journal has no public validation scenario")
        journal["rollback"]["public_selector_evidence"] = self._public_selector_smoke(
            journal,
            interface,
            scenario,
            phase="rollback_before_invoke",
        )
        journal["phase"] = "rolled_back"
        journal["rollback"].update(state="complete", completed_at=int(self.clock()))
        self._write_journal(journal)
        return {"status": "rolled_back", "migration_id": journal["migration_id"]}
