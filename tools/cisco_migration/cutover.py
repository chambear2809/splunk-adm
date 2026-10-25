"""Migration responsibility methods for cutover."""

from __future__ import annotations

import json
import re
from typing import Any
from .common import (
    JOBS,
    MAX_BACKFILL_SECONDS,
    MigrationError,
    ROLLUP_ID_QUERY_BATCH,
    ROLLUP_ID_RE,
    Refused,
    SAVEDSEARCH_DISPATCH_OWNER,
    SLICE_SECONDS,
    STREAMS,
    SUMMARY_CANONICALIZER_VERSION,
    Uncertain,
    V1_INDEX,
    V1_ROW_FIELDS,
    _add_record_maps,
    _config_equal,
    _integer,
    _job_active,
    _job_messages_complete,
    _job_sid,
    _macro_definition_equal,
    _number,
    _observations_without_netflow_interfaces,
    _strict_bool,
    _vlan_observations_without_interface_names,
    fingerprint,
    plan_slices,
)


class MigrationCutover:
    def _mutation_target(self, mutation: dict[str, Any]) -> dict[str, Any]:
        entry = self._single_entry(mutation["rest_target"])
        content = entry.get("content") or {}
        if mutation["field"] not in content:
            raise Refused("cutover target field is unavailable")
        return {
            "value": content[mutation["field"]],
            "args": content.get("args", ""),
            "acl": entry.get("acl") or {},
        }

    @staticmethod
    def _macro_args_parts(name: str, value: Any) -> tuple[str, ...]:
        if isinstance(value, str):
            parts = tuple(part.strip() for part in value.split(",")) if value else ()
        elif isinstance(value, list) and all(isinstance(part, str) for part in value):
            parts = tuple(part.strip() for part in value)
        else:
            raise Refused("parameterized macro args have an unsupported REST type")
        if any(not part or "," in part for part in parts):
            raise Refused("parameterized macro args contain an invalid argument")
        match = re.search(r"\((\d+)\)$", name)
        expected_count = int(match.group(1)) if match else 0
        if len(parts) != expected_count:
            raise Refused("parameterized macro args do not match the macro arity")
        return parts

    @classmethod
    def _macro_args_equal(cls, name: str, actual: Any, expected: Any) -> bool:
        return cls._macro_args_parts(name, actual) == cls._macro_args_parts(
            name, expected
        )

    @classmethod
    def _macro_args_payload(cls, name: str, value: Any) -> str:
        parts = cls._macro_args_parts(name, value)
        return ", ".join(parts) if isinstance(value, list) else value

    @staticmethod
    def _mutation_equal(mutation: dict[str, Any], actual: Any, expected: Any) -> bool:
        if mutation["kind"] == "saved_search":
            return _config_equal(mutation["field"], actual, expected)
        if mutation["kind"] == "macro_definition":
            return _macro_definition_equal(actual, expected)
        return actual == expected

    def _assert_cutover_origin_compatible(self, journal: dict[str, Any]) -> None:
        for execution in reversed(journal.get("temporary_manual_executions", [])):
            if execution.get("state") != "restored":
                self._recover_temporary_manual_writer(journal, execution["name"])
        plan = journal.get("cutover", {}).get("mutations", [])
        for mutation in plan:
            actual = self._mutation_target(mutation)
            if actual["acl"] != mutation["acl"]:
                raise Refused("cutover target ACL drifted from the journaled snapshot")
            if mutation["kind"] == "macro_definition" and not self._macro_args_equal(
                mutation["name"], actual["args"], mutation.get("args", "")
            ):
                raise Refused("parameterized macro arguments drifted from the journal")
            if not any(
                self._mutation_equal(mutation, actual["value"], expected)
                for expected in (mutation["before"], mutation["after"])
            ):
                raise Refused("cutover target drifted from both journaled states")
        current_snapshot = self.snapshot(allow_activation=True)
        origin = journal.get("origin") or {}
        # Normalize only the allowlisted fields that this journal may mutate;
        # all other effective configuration, ACL and mapping inputs must
        # continue to match the original fingerprint.
        for name, macro in current_snapshot["macros"].items():
            origin_macro = origin["macros"][name]
            if not self._macro_args_equal(
                name, macro["args"], origin_macro.get("args", "")
            ):
                raise Refused(
                    "parameterized macro arguments drifted from the origin snapshot"
                )
            # REST clients may expose repeated args as a list or as one string.
            # Retain the immutable origin representation for fingerprinting.
            macro["args"] = origin_macro.get("args", "")
        for mutation in plan:
            if mutation["kind"] == "macro_definition":
                current_snapshot["macros"][mutation["name"]]["definition"] = origin[
                    "macros"
                ][mutation["name"]]["definition"]
            else:
                current_snapshot["saved_searches"][mutation["name"]]["content"][
                    mutation["field"]
                ] = origin["saved_searches"][mutation["name"]]["content"][
                    mutation["field"]
                ]
        if fingerprint(current_snapshot) != journal.get("origin_fingerprint"):
            raise Refused("non-selector configuration, ACL, profile, or target drifted")

    def _apply_mutation(
        self, journal: dict[str, Any], mutation: dict[str, Any]
    ) -> None:
        actual = self._mutation_target(mutation)
        if actual["acl"] != mutation["acl"]:
            raise Refused(
                "cutover target ACL changed; refusing to write grants or overwrite ACLs"
            )
        value = actual["value"]
        if mutation["kind"] == "macro_definition" and not self._macro_args_equal(
            mutation["name"], actual["args"], mutation.get("args", "")
        ):
            raise Refused("parameterized macro arguments drifted from the journal")
        if mutation.get("state") == "request_unknown" and self._mutation_equal(
            mutation, value, mutation["before"]
        ):
            raise Uncertain(
                "configuration update remains ambiguous; inspect target and reconcile manually"
            )
        if self._mutation_equal(mutation, value, mutation["after"]):
            mutation["state"] = "applied"
            if _integer(mutation.get("verified_at")) is None:
                mutation["verified_at"] = int(self.clock())
            else:
                mutation["revalidated_at"] = int(self.clock())
            self._write_journal(journal)
            return
        if not self._mutation_equal(mutation, value, mutation["before"]):
            raise Refused("cutover target value changed outside this journal")
        mutation["state"] = "request_pending"
        mutation["request_started_at"] = int(self.clock())
        self._write_journal(journal)
        try:
            payload = {mutation["field"]: mutation["after"]}
            if mutation["kind"] == "macro_definition":
                payload["args"] = self._macro_args_payload(
                    mutation["name"], mutation.get("args", "")
                )
            self._request(
                "POST",
                mutation["rest_target"],
                payload,
            )
        except Refused:
            observed = self._mutation_target(mutation)
            args_match = mutation[
                "kind"
            ] != "macro_definition" or self._macro_args_equal(
                mutation["name"], observed["args"], mutation.get("args", "")
            )
            if (
                observed["acl"] != mutation["acl"]
                or not args_match
                or not self._mutation_equal(
                    mutation, observed["value"], mutation["after"]
                )
            ):
                mutation["state"] = "rejected"
                self._write_journal(journal)
                raise
        except MigrationError:
            observed = self._mutation_target(mutation)
            args_match = mutation[
                "kind"
            ] != "macro_definition" or self._macro_args_equal(
                mutation["name"], observed["args"], mutation.get("args", "")
            )
            if (
                observed["acl"] == mutation["acl"]
                and args_match
                and self._mutation_equal(mutation, observed["value"], mutation["after"])
            ):
                pass
            elif args_match and self._mutation_equal(
                mutation, observed["value"], mutation["before"]
            ):
                mutation["state"] = "request_unknown"
                self._write_journal(journal)
                raise Uncertain(
                    "configuration update outcome is unknown; readback shows the prior value"
                ) from None
            else:
                raise Refused(
                    "configuration update left an unrecognized value"
                ) from None
        observed = self._mutation_target(mutation)
        if observed["acl"] != mutation["acl"]:
            raise Refused(
                "configuration update changed ACLs; refusing further migration writes"
            )
        if mutation["kind"] == "macro_definition" and not self._macro_args_equal(
            mutation["name"], observed["args"], mutation.get("args", "")
        ):
            raise Refused("configuration update changed parameterized macro arguments")
        if not self._mutation_equal(mutation, observed["value"], mutation["after"]):
            mutation["state"] = "readback_failed"
            self._write_journal(journal)
            raise Refused("configuration update did not match its journaled target")
        mutation["state"] = "applied"
        if _integer(mutation.get("verified_at")) is None:
            mutation["verified_at"] = int(self.clock())
        else:
            mutation["revalidated_at"] = int(self.clock())
        self._write_journal(journal)

    def _build_cutover_mutations(
        self, journal: dict[str, Any], interface: dict[str, Any]
    ) -> list[dict[str, Any]]:
        origin = journal["origin"]
        mutations = []
        selectors = interface["activation"]["cutover_selectors"]
        # Pause the legacy writer first. Drain is a separate gate before any V2
        # schedule or public reader is activated.
        writer_contracts = interface["activation"]["writer_contracts"]
        legacy = next(
            item
            for item in writer_contracts
            if item["name"] == "ADM - Conversation rollup"
        )
        for writer in [legacy] + [
            item for item in writer_contracts if item is not legacy
        ]:
            name = writer["name"]
            transition = writer["state_transition"]
            before = origin["saved_searches"][name]["content"].get("disabled")
            if before is None:
                raise Refused(
                    "writer disabled state is missing from the origin snapshot"
                )
            after = transition.get("disabled_after")
            if name == legacy["name"]:
                after = 1
            elif _config_equal("disabled", before, after):
                continue
            mutations.append(
                {
                    "id": writer["id"] + ":disabled",
                    "kind": "saved_search",
                    "name": name,
                    "rest_target": writer["rest_target"],
                    "field": "disabled",
                    "before": before,
                    "after": after,
                    "acl": origin["saved_searches"][name]["acl"],
                    "state": "pending",
                }
            )
            if name == legacy["name"]:
                mutations[-1]["drain_after"] = True
        selector_order = [
            item for item in selectors if item["name"] != "adm_data_contract_version"
        ]
        selector_order.extend(
            item for item in selectors if item["name"] == "adm_data_contract_version"
        )
        for selector in selector_order:
            name = selector["name"]
            prior = origin["macros"][name]
            if not _macro_definition_equal(prior["definition"], selector["before"]):
                raise Refused(
                    "selector does not match the captured v1 effective definition"
                )
            mutations.append(
                {
                    "id": selector["id"],
                    "kind": "macro_definition",
                    "name": name,
                    "rest_target": selector["rest_target"],
                    "field": "definition",
                    # Keep the exact REST bytes for rollback; comparisons use
                    # the canonical SPL form above.
                    "before": prior["definition"],
                    "after": selector["after"],
                    "args": prior.get("args", ""),
                    "acl": prior["acl"],
                    "state": "pending",
                }
            )
        return mutations

    def _drain_legacy_writer(self, journal: dict[str, Any], timeout: int = 30) -> None:
        for _ in range(timeout):
            entries = self._entries(JOBS + "?count=0")
            active = []
            for entry in entries:
                content = entry.get("content") or {}
                label = content.get("savedsearch_name") or content.get("label")
                if label == "ADM - Conversation rollup" and _job_active(content):
                    active.append(_job_sid(entry))
            if not active:
                journal["cutover"]["legacy_writer_drained_at"] = int(self.clock())
                self._write_journal(journal)
                return
            self.sleep(1)
        raise Refused("legacy writer did not drain within the bounded wait")

    def _catch_up_after_pause(
        self, journal: dict[str, Any], scenario: dict[str, Any]
    ) -> None:
        watermark = (
            int(self.clock()) // SLICE_SECONDS * SLICE_SECONDS - 2 * SLICE_SECONDS
        )
        old_end = int(journal["range"]["end"])
        if watermark > old_end:
            if watermark - int(journal["range"]["start"]) > MAX_BACKFILL_SECONDS:
                raise Refused(
                    "paused-writer catch-up would exceed the seven-day bound; rollback or prepare a new range"
                )
            extra = plan_slices(old_end, watermark, int(self.clock()))
            journal["slices"].extend(
                {
                    **time_slice,
                    "streams": {name: {"state": "pending"} for name in STREAMS},
                    "history": {"state": "pending"},
                    "handoff_catchup": True,
                }
                for time_slice in extra
            )
            journal["range"]["end"] = watermark
            # The absolute event-time bound is refreshed only after the legacy
            # writer is paused; each dispatch still journals its exact bounds.
            journal["event_latest"] = str(int(self.clock()) + 15 * 60)
            journal["cutover"]["source_watermark"] = watermark
            journal["cutover"]["catchup_slices"] = len(extra)
            self._write_journal(journal)
            for slice_record in journal["slices"]:
                if not slice_record.get("handoff_catchup"):
                    continue
                for stream in STREAMS:
                    self._stage_stream(journal, slice_record, stream)
                self._stage_history_slice(journal, slice_record)
        else:
            journal["cutover"]["source_watermark"] = old_end
            journal["cutover"]["catchup_slices"] = 0
            self._write_journal(journal)
        # Re-run every closed-slice comparison and all public smoke queries
        # against the post-pause watermark before changing any reader selector.
        self.validate(scenario)
        refreshed = self.journal.read()
        if not refreshed:
            raise Refused("journal disappeared during paused-writer validation")
        refreshed["phase"] = "cutover_in_progress"
        refreshed["cutover"] = journal["cutover"]
        refreshed["cutover"]["post_pause_validation_at"] = int(self.clock())
        self._write_journal(refreshed)

    @staticmethod
    def _absolute_index_bounds(entry: dict[str, Any]) -> tuple[int, int] | None:
        """Resolve the shipped V2 scheduler window from explicit job metadata.

        Splunk's `indexEarliestTime`/`indexLatestTime` are observed event times,
        not dispatch bounds. Accept only the shipped relative index pair and
        a matching absolute search window, which gives a verified scheduler
        anchor. Do not infer the anchor from the SID or job creation time.
        """
        content = entry.get("content") or {}
        request = content.get("request") or {}
        if (
            request.get("index_earliest") != "-10m@m"
            or request.get("index_latest") != "-5m@m"
        ):
            return None
        earliest = _integer(content.get("searchEarliestTime"))
        latest = _integer(content.get("searchLatestTime"))
        if earliest is None or latest is None:
            return None
        anchor_from_earliest = earliest + 24 * 60 * 60
        anchor_from_latest = latest - 15 * 60
        if (
            anchor_from_earliest != anchor_from_latest
            or anchor_from_earliest % SLICE_SECONDS
        ):
            return None
        anchor = anchor_from_earliest
        lower = anchor // SLICE_SECONDS * SLICE_SECONDS - 2 * SLICE_SECONDS
        upper = lower + SLICE_SECONDS
        return lower, upper

    @staticmethod
    def _absolute_history_bounds(entry: dict[str, Any]) -> tuple[int, int] | None:
        """Resolve the history builder's distinct ten-minute-to-now window."""
        content = entry.get("content") or {}
        request = content.get("request") or {}
        if (
            request.get("earliest_time") != "0"
            or request.get("latest_time") != "+15m"
            or request.get("index_earliest") != "-10m@m"
            or request.get("index_latest") != "@m"
        ):
            return None
        earliest = _integer(content.get("searchEarliestTime"))
        latest = _integer(content.get("searchLatestTime"))
        if earliest not in (None, 0) or latest is None:
            return None
        anchor = latest - 15 * 60
        if anchor % SLICE_SECONDS != 60:
            return None
        return anchor - 2 * SLICE_SECONDS, anchor

    def _first_scheduled_writer_bounds(
        self,
        name: str,
        journal: dict[str, Any] | None = None,
        *,
        lower_epoch: int | None = None,
        upper_epoch: int | None = None,
        latest: bool = False,
    ) -> tuple[int, int] | None:
        """Find a confirmed scheduled slice, never a manual backfill dispatch."""
        cycles = self._scheduled_writer_cycles(
            name,
            journal,
            lower_epoch=lower_epoch,
            upper_epoch=upper_epoch,
        )
        if not cycles:
            return None
        selected = cycles[-1] if latest else cycles[0]
        return tuple(selected["index_bounds"])

    def _scheduled_writer_cycles(
        self,
        name: str,
        journal: dict[str, Any] | None,
        *,
        lower_epoch: int | None = None,
        upper_epoch: int | None = None,
    ) -> list[dict[str, Any]]:
        """List scheduler-owned slices with matching scheduler.log successes."""
        jobs = self._entries(JOBS + "?count=0")
        candidates: list[dict[str, Any]] = []
        manual_sids = {
            item.get("sid")
            for item in (journal or {}).get("jobs", [])
            if item.get("sid")
        }
        for entry in jobs:
            job = entry.get("content") or {}
            if not (
                _strict_bool(job.get("isSavedSearch")) is True
                and (job.get("savedsearch_name") or job.get("label")) == name
            ):
                continue
            sid = _job_sid(entry)
            label = job.get("label")
            # Splunk scheduler invocations have scheduler-owned SIDs/labels;
            # saved-search dispatch endpoints produce the saved-search label
            # and are separately recorded in this migration's journal.
            if sid in manual_sids or not (
                isinstance(sid, str)
                and sid.startswith("scheduler__")
                or isinstance(label, str)
                and label.startswith("scheduler__")
            ):
                continue
            try:
                saved_search_label = json.loads(job.get("savedSearchLabel", "{}"))
            except (TypeError, json.JSONDecodeError):
                raise Refused("scheduler-owned writer job has invalid saved-search ACL")
            if (
                job.get("provenance") != "scheduler"
                or job.get("label") != name
                or saved_search_label
                != {"owner": "nobody", "app": "splunk_adm", "sharing": "app"}
            ):
                raise Refused("scheduler-owned writer job identity is ambiguous")
            if (entry.get("acl") or {}).get("app") != "splunk_adm" or (
                entry.get("acl") or {}
            ).get("owner") != SAVEDSEARCH_DISPATCH_OWNER:
                raise Refused(
                    "scheduled writer job identity does not match the contract"
                )
            bounds = self._absolute_index_bounds(entry)
            if bounds is None:
                raise Refused(
                    "scheduler-owned writer job has unresolved request bounds"
                )
            anchor = bounds[0] + 2 * SLICE_SECONDS
            in_scope = (lower_epoch is None or anchor >= lower_epoch) and (
                upper_epoch is None or anchor < upper_epoch
            )
            exact_empty_warning = self._expected_empty_summary_warning(name, job)
            complete = (
                job.get("dispatchState") == "DONE"
                and _strict_bool(job.get("isDone")) is True
                and _strict_bool(job.get("isFinalized")) is False
                and _strict_bool(job.get("eventIsTruncated")) is False
                and _integer(job.get("dropCount")) == 0
                and _job_messages_complete(job.get("messages"), exact_empty_warning)
            )
            if in_scope and not complete:
                raise Refused("scheduled writer job overlaps the observation boundary")
            if not complete:
                continue
            if in_scope and self._scheduler_log_confirms(
                journal,
                sid,
                name,
                bounds,
                lower_epoch=lower_epoch,
                upper_epoch=upper_epoch,
            ):
                event_start = _integer(job.get("searchEarliestTime"))
                event_end = _integer(job.get("searchLatestTime"))
                if event_start is None or event_end is None:
                    continue
                candidates.append(
                    {
                        "sid": sid,
                        "index_bounds": list(bounds),
                        "event_bounds": {
                            "earliest_time": str(event_start),
                            "latest_time": str(event_end),
                        },
                        "anchor": anchor,
                        "empty_summary_warning": exact_empty_warning,
                    }
                )
        candidates.sort(key=lambda item: item["index_bounds"][0])
        if len({tuple(item["index_bounds"]) for item in candidates}) != len(candidates):
            raise Refused("multiple scheduler jobs claim the same source slice")
        anchors = [item["anchor"] for item in candidates]
        if any(
            right - left != SLICE_SECONDS for left, right in zip(anchors, anchors[1:])
        ):
            raise Refused(
                "scheduled writer evidence has a missing or overlapping cycle"
            )
        return candidates

    def _scheduled_history_cycles(
        self,
        journal: dict[str, Any],
        *,
        lower_epoch: int,
        upper_epoch: int,
    ) -> list[dict[str, Any]]:
        """Inventory complete scheduler-owned history windows through a boundary."""
        name = "ADM - Network client history builder"
        jobs = self._entries(JOBS + "?count=0")
        candidates = []
        manual_sids = {
            item.get("sid") for item in journal.get("jobs", []) if item.get("sid")
        }
        for entry in jobs:
            content = entry.get("content") or {}
            if not (
                _strict_bool(content.get("isSavedSearch")) is True
                and (content.get("savedsearch_name") or content.get("label")) == name
            ):
                continue
            sid = _job_sid(entry)
            label = content.get("label")
            if sid in manual_sids or not (
                isinstance(sid, str)
                and sid.startswith("scheduler__")
                or isinstance(label, str)
                and label.startswith("scheduler__")
            ):
                continue
            try:
                saved_search_label = json.loads(content.get("savedSearchLabel", "{}"))
            except (TypeError, json.JSONDecodeError):
                raise Refused("scheduled history job has invalid saved-search ACL")
            if (
                content.get("provenance") != "scheduler"
                or content.get("label") != name
                or saved_search_label
                != {"owner": "nobody", "app": "splunk_adm", "sharing": "app"}
                or (entry.get("acl") or {}).get("app") != "splunk_adm"
                or (entry.get("acl") or {}).get("owner") != SAVEDSEARCH_DISPATCH_OWNER
            ):
                raise Refused("scheduled history job identity is ambiguous")
            bounds = self._absolute_history_bounds(entry)
            if bounds is None:
                raise Refused("scheduled history job has unresolved request bounds")
            anchor = bounds[1]
            in_scope = lower_epoch < anchor < upper_epoch
            complete = (
                content.get("dispatchState") == "DONE"
                and _strict_bool(content.get("isDone")) is True
                and _strict_bool(content.get("isFinalized")) is False
                and _strict_bool(content.get("eventIsTruncated")) is False
                and _integer(content.get("dropCount")) == 0
                and _job_messages_complete(content.get("messages"))
            )
            if in_scope and not complete:
                raise Refused("scheduled history job overlaps the observation boundary")
            if not complete:
                continue
            if in_scope and self._scheduler_log_confirms(
                journal,
                sid,
                name,
                bounds,
                lower_epoch=lower_epoch,
                upper_epoch=upper_epoch,
                history_window=True,
            ):
                candidates.append(
                    {
                        "sid": sid,
                        "index_bounds": list(bounds),
                        "event_bounds": {
                            "earliest_time": "0",
                            "latest_time": str(anchor + 15 * 60),
                        },
                        "anchor": anchor,
                    }
                )
        candidates.sort(key=lambda item: item["index_bounds"][0])
        if len({tuple(item["index_bounds"]) for item in candidates}) != len(candidates):
            raise Refused("multiple history scheduler jobs claim the same slice")
        anchors = [item["anchor"] for item in candidates]
        if any(
            right - left != SLICE_SECONDS for left, right in zip(anchors, anchors[1:])
        ):
            raise Refused(
                "scheduled history evidence has a missing or overlapping cycle"
            )
        return candidates

    @staticmethod
    def _history_next_anchor(enabled_after: int) -> int:
        first = enabled_after // SLICE_SECONDS * SLICE_SECONDS + 60
        return first if first > enabled_after else first + SLICE_SECONDS

    def _history_writer_activation_epoch(self, journal: dict[str, Any]) -> int | None:
        name = "ADM - Network client history builder"
        activation = [
            _integer(item.get("verified_at"))
            for item in (journal.get("cutover") or {}).get("mutations", [])
            if item.get("kind") == "saved_search"
            and item.get("name") == name
            and _strict_bool(item.get("after")) is False
            and item.get("state") == "applied"
        ]
        if activation:
            if len(activation) != 1 or activation[0] is None:
                raise Refused("history writer activation time is ambiguous")
            return activation[0]
        origin_disabled = (
            ((journal.get("origin") or {}).get("saved_searches") or {})
            .get(name, {})
            .get("content", {})
            .get("disabled")
        )
        if _strict_bool(origin_disabled) is False:
            return _integer(journal.get("created_at"))
        return None

    def _stage_scheduled_history_evidence(
        self, journal: dict[str, Any], cycles: list[dict[str, Any]]
    ) -> None:
        interface, _ = self._interface()
        contract = interface["staged_collections"]["network_client_history"]
        state = journal["cutover"].setdefault("scheduled_history", {"cycles": []})
        prior = {
            tuple(item.get("index_bounds", [])): item
            for item in state.get("cycles", [])
        }
        current = []
        for cycle in cycles:
            bounds = tuple(cycle["index_bounds"])
            expected = self._history_expected(
                journal,
                contract,
                bounds[0],
                bounds[1],
                event_bounds=cycle["event_bounds"],
            )
            expected_fp = fingerprint(expected)
            previous = prior.get(bounds)
            if previous and previous.get("sid") != cycle.get("sid"):
                raise Refused("history scheduler SID changed for a validated window")
            item = {
                **cycle,
                "expected_fingerprint": expected_fp,
                "expected_receipts": self._history_receipt_manifest(expected),
                "rows": len(expected),
                "validated_at": int(self.clock()),
            }
            if previous and previous.get("expected_fingerprint") != expected_fp:
                item["prior_expected_fingerprints"] = [
                    *previous.get("prior_expected_fingerprints", []),
                    previous["expected_fingerprint"],
                ]
                item["source_revision_at"] = int(self.clock())
            current.append(item)
        state.update(cycles=current)
        self._write_journal(journal)

    def _stage_history_gap_before_first_cycle(
        self,
        journal: dict[str, Any],
        first_cycle_start: int,
    ) -> None:
        history_slices = [
            *journal.get("slices", []),
            *((journal.get("cutover") or {}).get("history_bridge_slices") or []),
        ]
        covered_end = max(
            (
                int(item["end"])
                for item in history_slices
                if item.get("history", {}).get("state") == "verified"
            ),
            default=int(journal["range"]["end"]),
        )
        if first_cycle_start <= covered_end:
            return
        if first_cycle_start - covered_end > MAX_BACKFILL_SECONDS:
            raise Refused("history scheduler gap exceeds the seven-day recovery bound")
        self._stage_history_gap(journal, covered_end, first_cycle_start)

    def _stage_history_gap(self, journal: dict[str, Any], start: int, end: int) -> None:
        if end <= start:
            return
        if end - start > MAX_BACKFILL_SECONDS:
            raise Refused("history scheduler gap exceeds the seven-day recovery bound")
        if start % 60 or end % 60:
            raise Refused("history scheduler gap is not minute aligned")
        gap = []
        cursor = start
        while cursor < end:
            next_end = min(cursor + 60, end)
            gap.append(
                {
                    "start": cursor,
                    "end": next_end,
                    "history": {"state": "pending"},
                    "history_bridge": True,
                }
            )
            cursor = next_end
        bridge = journal["cutover"].setdefault("history_bridge_slices", [])
        existing = {(item["start"], item["end"]): item for item in bridge}
        for item in gap:
            key = (item["start"], item["end"])
            existing.setdefault(key, item)
        bridge[:] = sorted(existing.values(), key=lambda item: item["start"])
        self._write_journal(journal)
        for item in bridge:
            if item["start"] >= start and item["end"] <= end:
                self._stage_history_slice(journal, item)

    def _stage_history_tail_through_summary(
        self, journal: dict[str, Any], summary_end: int
    ) -> None:
        verified_ends = [
            int(item["end"])
            for item in [
                *journal.get("slices", []),
                *((journal.get("cutover") or {}).get("history_bridge_slices") or []),
            ]
            if item.get("history", {}).get("state") == "verified"
        ]
        scheduled_ends = [
            int(bounds[1])
            for cycle in (
                (journal.get("cutover") or {})
                .get("scheduled_history", {})
                .get("cycles", [])
            )
            for bounds in [cycle.get("index_bounds") or []]
            if len(bounds) == 2
        ]
        covered_end = max(
            [*verified_ends, *scheduled_ends],
            default=int(journal["range"]["end"]),
        )
        if covered_end < summary_end:
            self._stage_history_gap(journal, covered_end, summary_end)

    def _scheduler_log_confirms(
        self,
        journal: dict[str, Any] | None,
        sid: str,
        name: str,
        bounds: tuple[int, int],
        *,
        lower_epoch: int | None = None,
        upper_epoch: int | None = None,
        history_window: bool = False,
    ) -> bool:
        """Require one successful scheduler.log row matching this exact SID."""
        if not isinstance(journal, dict):
            return False
        started = (
            lower_epoch
            if lower_epoch is not None
            else _integer((journal.get("cutover") or {}).get("started_at"))
        )
        if started is None:
            return False
        lower, upper = bounds
        anchor = lower + 2 * SLICE_SECONDS
        query = (
            'search index=_internal source=*scheduler.log* app="splunk_adm" '
            f"| where sid={json.dumps(sid)} AND savedsearch_name={json.dumps(name)} "
            "| table sid savedsearch_name scheduled_time dispatch_time status"
        )
        observation_upper = int(self.clock()) + 60
        if upper_epoch is not None:
            observation_upper = min(observation_upper, upper_epoch)
        rows = self._query(
            journal,
            query,
            started,
            observation_upper,
            label=f"scheduler log confirmation {name} {sid}",
            earliest_time=str(started),
            latest_time=str(observation_upper),
            persist_result_rows=False,
        )
        matches = [
            row
            for row in rows
            if row.get("sid") == sid
            and row.get("savedsearch_name") == name
            and row.get("status") == "success"
            and _integer(row.get("scheduled_time")) == anchor
            and (
                (dispatch := _integer(row.get("dispatch_time"))) is not None
                and dispatch >= anchor
                and dispatch < observation_upper
            )
        ]
        expected_upper = anchor if history_window else anchor - SLICE_SECONDS
        return len(rows) == 1 and len(matches) == 1 and upper == expected_upper

    @staticmethod
    def _v1_stable_row(row: dict[str, Any]) -> dict[str, Any]:
        numeric = {
            "_time",
            "server_port",
            "bytes_c2s",
            "bytes_s2c",
            "packets",
            "records",
            "client_ports",
            "conns_capped",
            "sampled",
            "first_seen",
            "last_seen",
            "acl_permits",
            "acl_drops",
            "vlan_observations_truncated",
        }
        stable = {}
        for field in V1_ROW_FIELDS:
            if field == "encapsulation":
                continue
            value = row.get(field)
            if value in ("", "null", "None"):
                value = None
            if field in numeric and value is not None:
                parsed = _number(value)
                if parsed is not None:
                    value = int(parsed) if parsed.is_integer() else parsed
            if field == "observations":
                value = _observations_without_netflow_interfaces(
                    value, row.get("observer")
                )
            elif field == "vlan_observations":
                value = _vlan_observations_without_interface_names(
                    value, row.get("vlan_observations_truncated")
                )
            stable[field] = value
        return stable

    @classmethod
    def _v1_record_map(cls, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        observed = {}
        for row in rows:
            rollup_id = str(row.get("rollup_id") or "")
            records = _integer(row.get("records"))
            if (
                not ROLLUP_ID_RE.fullmatch(rollup_id)
                or records is None
                or records <= 0
                or row.get("adm_record")
                not in {"conversation", "hubble_xlate", "hubble_l7"}
            ):
                raise Refused("V1 recovery output has invalid stable rollup material")
            content = cls._v1_stable_row(row)
            digest = fingerprint(
                {"canonicalizer": SUMMARY_CANONICALIZER_VERSION, "row": content}
            )
            if rollup_id in observed:
                if observed[rollup_id]["content_digest"] != digest:
                    raise Refused("V1 recovery output conflicts for a stable rollup ID")
                observed[rollup_id]["copies"] += 1
            else:
                observed[rollup_id] = {
                    "content": content,
                    "content_digest": digest,
                    "copies": 1,
                }
        return observed

    def _v1_source_query(self, journal: dict[str, Any]) -> str:
        interface, _ = self._interface()
        writer = next(
            item
            for item in interface["activation"]["writer_contracts"]
            if item["name"] == "ADM - Conversation rollup"
        )
        entry = self._saved_search(writer["name"])
        content = self._normalize_saved_search_schedule(
            entry.get("content") or {}, writer["fields"]
        )
        for field, expected in writer["fields"].items():
            if field == "disabled":
                if _strict_bool(content.get(field)) is True:
                    continue
                origin_disabled = (
                    (journal.get("origin") or {})
                    .get("saved_searches", {})
                    .get(writer["name"], {})
                    .get("content", {})
                    .get("disabled")
                )
                if _strict_bool(
                    origin_disabled
                ) is not False and not self._writer_enabled_by_journal(
                    journal, writer["name"]
                ):
                    raise Refused("V1 recovery writer is enabled outside its journal")
            elif not _config_equal(field, content.get(field), expected):
                raise Refused(
                    "V1 recovery writer no longer matches its immutable contract"
                )
        current = self.snapshot(allow_activation=True)
        if current.get("macro_inventory") != (journal.get("origin") or {}).get(
            "macro_inventory"
        ):
            raise Refused("V1 writer macro dependencies changed during cutover")
        return writer["source_query"].strip()

    def _v1_expected_rows(
        self,
        journal: dict[str, Any],
        bounds: tuple[int, int],
        event_bounds: dict[str, str],
        label: str,
    ) -> dict[str, dict[str, Any]]:
        query = self._v1_source_query(journal) + " | fields " + " ".join(V1_ROW_FIELDS)
        rows = self._query(
            journal,
            query,
            bounds[0],
            bounds[1],
            label=label,
            earliest_time=event_bounds["earliest_time"],
            latest_time=event_bounds["latest_time"],
        )
        return self._v1_record_map(rows)

    def _v1_persisted_rows(
        self,
        journal: dict[str, Any],
        expected: dict[str, dict[str, Any]],
        event_bounds: dict[str, str],
        label: str,
    ) -> dict[str, dict[str, Any]]:
        if not expected:
            return {}
        # A later scheduler cycle can have a narrower raw-event window than
        # an earlier retained summary row. Rollup _time is derived from the
        # flow bucket and can precede that raw-event window, so use bounds
        # that cover every expected retained row as well as the caller's
        # window. ID, material, and multiplicity checks below remain exact.
        retained_times = [
            number
            for row in expected.values()
            if (number := _number(row.get("content", {}).get("_time"))) is not None
        ]
        requested_earliest = _number(event_bounds.get("earliest_time"))
        requested_latest = _number(event_bounds.get("latest_time"))
        retained_earliest = min(retained_times, default=None)
        retained_latest = max(retained_times, default=None)
        read_earliest = min(
            (
                value
                for value in (requested_earliest, retained_earliest)
                if value is not None
            ),
            default=0,
        )
        read_latest = max(
            (
                value
                for value in (
                    requested_latest,
                    retained_latest + 1 if retained_latest is not None else None,
                )
                if value is not None
            ),
            default=read_earliest + 1,
        )
        retained_event_bounds = {
            "earliest_time": f"{read_earliest:.15g}",
            "latest_time": f"{read_latest:.15g}",
        }
        observed: dict[str, dict[str, Any]] = {}
        ids = sorted(expected)
        for offset in range(0, len(ids), ROLLUP_ID_QUERY_BATCH):
            chunk = ids[offset : offset + ROLLUP_ID_QUERY_BATCH]
            query = (
                f'| search index={V1_INDEX} source="adm:conversation" '
                f"rollup_id IN ({', '.join(json.dumps(item) for item in chunk)}) "
                "| fields " + " ".join(V1_ROW_FIELDS)
            )
            rows = self._query(
                journal,
                query,
                None,
                None,
                label=f"{label} batch {offset // ROLLUP_ID_QUERY_BATCH + 1}",
                earliest_time=retained_event_bounds["earliest_time"],
                latest_time=retained_event_bounds["latest_time"],
                persist_result_rows=False,
            )
            observed = _add_record_maps(
                observed,
                self._v1_record_map(rows),
                label="V1 retained summary rows",
            )
        if any(key not in expected for key in observed):
            raise Refused("V1 summary index contains unexplained rollup IDs")
        return observed

    def _assert_empty_summary_index_window(
        self,
        journal: dict[str, Any],
        index: str,
        source: str,
        lower_indextime: int,
        upper_indextime: int,
        label: str,
        *,
        allowed_rollup_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Prove a zero-result dispatch added no unexplained retained rows.

        A later successful cycle can legitimately write to the same source
        while the empty cycle is being audited. Those rows are accepted only
        when their IDs were independently derived from bounded, validated
        cycle or manual-write manifests; the complete-window audit still
        compares all retained material fields against those manifests.
        """
        if lower_indextime < 0 or upper_indextime < lower_indextime:
            raise Refused("empty summary audit has invalid index-time bounds")
        query = (
            f"search index={index} source={json.dumps(source)} "
            f"| where _indextime>={lower_indextime} "
            f"AND _indextime<={upper_indextime} "
            "| fields " + " ".join(V1_ROW_FIELDS)
        )
        rows = self._query(
            journal,
            query,
            lower_indextime,
            upper_indextime + 1,
            label=label,
            earliest_time="0",
            latest_time="+10y",
            persist_result_rows=False,
        )
        allowed = allowed_rollup_ids or set()
        observed_ids = []
        for row in rows:
            rollup_id = str(row.get("rollup_id", ""))
            if not ROLLUP_ID_RE.fullmatch(rollup_id) or rollup_id not in allowed:
                raise Refused(
                    "zero-result summary writer has retained rows in its audit window outside validated manifests"
                )
            observed_ids.append(rollup_id)
        return {
            "index": index,
            "source": source,
            "lower_indextime": lower_indextime,
            "upper_indextime": upper_indextime,
            "retained_rows": 0,
            "observed_manifest_rows": len(observed_ids),
            "allowed_manifest_fingerprint": fingerprint(sorted(allowed)),
            "retained_fingerprint": fingerprint(sorted(observed_ids)),
            "validated_at": int(self.clock()),
        }
