"""Migration responsibility methods for dispatch."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import quote
import uuid
from .common import (
    CATALOG_SETTLED_JOB_STATES,
    CONTRACT_VERSION,
    CREATE_JOBS,
    EMPTY_SUMMARY_WARNING,
    EMPTY_SUMMARY_WRITERS,
    JOBS,
    JOB_METADATA_WAIT_ATTEMPTS,
    JOB_METADATA_WAIT_SECONDS,
    MAX_RESULTS,
    ROLLUP_ID_QUERY_BATCH,
    ROLLUP_ID_RE,
    Refused,
    SAVEDSEARCH_DISPATCH_OWNER,
    SEARCHES,
    STREAMS,
    SUMMARY_CANONICALIZER_VERSION,
    SUMMARY_INDEX_WAIT_ATTEMPTS,
    SUMMARY_INDEX_WAIT_DELAYS,
    Uncertain,
    V2_INDEX,
    V2_LOOKUP_DERIVED_FIELDS,
    V2_ROW_FIELDS,
    _add_record_maps,
    _config_equal,
    _integer,
    _job_pre_execution,
    _strict_bool,
    _summary_content,
    _truth,
    canonical,
    fingerprint,
)


class MigrationDispatch:
    def _query(
        self,
        journal,
        query: str,
        index_earliest: int | None,
        index_latest: int | None,
        *,
        label: str,
        earliest_time: str | None = None,
        latest_time: str | None = None,
        persist_result_rows: bool = True,
    ) -> list[dict[str, Any]]:
        original_query_hash = fingerprint(query)
        # REST job creation requires an explicit command; manifest expressions
        # may use the same implicit-search form as saved searches and the UI.
        query = query.strip()
        if not query.startswith("|") and not re.match(r"search(?:\s|$)", query):
            query = "search " + query
        query_hash = fingerprint(query)
        request_bounds = {
            "earliest_time": str(earliest_time or journal["event_earliest"]),
            "latest_time": str(latest_time or journal["event_latest"]),
        }
        if index_earliest is not None:
            request_bounds["index_earliest"] = str(index_earliest)
        if index_latest is not None:
            request_bounds["index_latest"] = str(index_latest)
        if original_query_hash != query_hash:
            for prior in journal.get("jobs", []):
                if (
                    prior.get("kind") == "search"
                    and prior.get("label") == label
                    and prior.get("query_fingerprint") == original_query_hash
                    and prior.get("request_bounds") == request_bounds
                    and prior.get("state") != "rejected"
                ):
                    raise Uncertain(
                        "legacy implicit-search attempt requires reconciliation before normalized dispatch"
                    )
        for prior in journal.get("jobs", []):
            if (
                prior.get("kind") == "search"
                and prior.get("label") == label
                and prior.get("query_fingerprint") == query_hash
                and prior.get("request_bounds") == request_bounds
            ):
                if prior.get("state") in {"dispatch_pending", "dispatch_unknown"}:
                    raise Uncertain(
                        f"{label} has an ambiguous dispatch; reconcile by SID"
                    )
                if prior.get("state") == "running":
                    return self._read_job(journal, prior)
                if prior.get("state") == "complete":
                    rows = self._cached_result_rows(journal, prior)
                    if isinstance(rows, list):
                        return rows
                    if prior.get("persist_result_rows") is False:
                        continue
                    raise Refused("completed search journal is missing its result rows")
        record = {
            "id": uuid.uuid4().hex,
            "kind": "search",
            "label": label,
            "state": "dispatch_pending",
            "query_fingerprint": query_hash,
            "request_bounds": request_bounds,
            "persist_result_rows": persist_result_rows,
            **self._evidence_class(journal),
        }
        self._save_job(journal, record)
        try:
            response = self._request(
                "POST",
                CREATE_JOBS,
                {
                    "search": query,
                    "exec_mode": "normal",
                    **request_bounds,
                },
            )
        except Refused:
            # A REST 4xx is a known rejection; it is safe to record as failed
            # and report, but it must never be mistaken for an unknown dispatch.
            record["state"] = "rejected"
            self._write_journal(journal)
            raise
        except Exception:
            record["state"] = "dispatch_unknown"
            self._write_journal(journal)
            raise Uncertain(
                f"{label} search dispatch outcome is unknown; reconcile by SID"
            ) from None
        sid = response.get("sid")
        if not isinstance(sid, str) or not sid:
            record["state"] = "dispatch_unknown"
            self._write_journal(journal)
            raise Uncertain(
                f"{label} search returned no SID; reconcile before continuing"
            )
        record.update(state="running", sid=sid)
        self._write_journal(journal)
        return self._read_job(journal, record)

    @staticmethod
    def _job_search_matches(journal, record, actual):
        if not isinstance(actual, str) or not actual:
            return False
        expected = (
            record.get("search_fingerprint")
            if record.get("kind") == "saved_search"
            else record.get("query_fingerprint")
        )
        if fingerprint(actual) == expected:
            return True
        if record.get("kind") != "saved_search":
            return False
        # Splunk prefixes implicit saved-search expressions when executing.
        # Bind that one syntax normalization to the immutable origin definition;
        # do not rewrite a recorded fingerprint or normalize quoted literals.
        origin = (
            journal.get("origin", {})
            .get("saved_searches", {})
            .get(record.get("label"), {})
            .get("content")
            or {}
        ).get("search")
        if not isinstance(origin, str) or fingerprint(origin) != expected:
            return False
        submitted = origin.strip()
        if not submitted.startswith("|") and not re.match(r"search(?:\s|$)", submitted):
            submitted = "search " + submitted
        return actual == submitted

    def _read_job(
        self, journal: dict[str, Any], record: dict[str, Any]
    ) -> list[dict[str, Any]]:
        sid = record.get("sid")
        if not isinstance(sid, str) or not sid:
            raise Refused("search job has no recorded SID")
        path = JOBS + "/" + quote(sid, safe="")
        while True:
            response = self._request("GET", path)
            entries = response.get("entry")
            if not isinstance(entries, list) or len(entries) != 1:
                raise Uncertain("search job state is unavailable")
            entry = entries[0]
            content = entry.get("content") or {}
            self._validate_job_identity(
                journal, record, entry, allow_pre_execution=True
            )
            observed_name = (
                content.get("savedsearch_name") or content.get("label")
                if record.get("kind") == "saved_search"
                else None
            )
            name_missing = record.get("kind") == "saved_search" and not observed_name
            if (
                record.get("kind") == "saved_search"
                and observed_name
                and observed_name != record.get("label")
            ):
                raise Refused("SID does not belong to the journaled saved search")
            actual_search = content.get("search")
            pre_execution = _job_pre_execution(content)
            deadline = record.get("metadata_wait_deadline")
            search_missing = not isinstance(actual_search, str) or not actual_search
            if not search_missing and not self._job_search_matches(
                journal, record, actual_search
            ):
                if record.get("kind") == "saved_search":
                    raise Refused("SID does not match the journaled writer definition")
                raise Refused("SID does not match the journaled search query")
            type_missing = record.get("kind") == "saved_search" and not _truth(
                content.get("isSavedSearch")
            )
            if name_missing or search_missing or type_missing:
                if not pre_execution:
                    if name_missing:
                        raise Refused(
                            "terminal saved-search job is missing its identity"
                        )
                    raise Refused(
                        "terminal search job is missing executed search identity"
                    )
                if record.get("metadata_wait_timed_out"):
                    raise Uncertain(
                        "search identity metadata deadline expired; reconcile the recorded SID"
                    )
                attempts = int(record.get("metadata_wait_attempts", 0)) + 1
                record["metadata_wait_attempts"] = attempts
                if deadline is None:
                    deadline = float(self.clock()) + JOB_METADATA_WAIT_SECONDS
                    record["metadata_wait_deadline"] = deadline
                if (
                    attempts > JOB_METADATA_WAIT_ATTEMPTS
                    or float(self.clock()) >= deadline
                ):
                    record["metadata_wait_timed_out"] = True
                    self._write_journal(journal)
                    raise Uncertain(
                        "search identity metadata deadline expired; reconcile the recorded SID"
                    )
                record["job_state"] = {
                    "dispatchState": content.get("dispatchState"),
                    "isDone": content.get("isDone"),
                }
                self._write_journal(journal)
                self.sleep(0.25)
                continue
            if record.get("metadata_wait_timed_out"):
                record["metadata_wait_recovered_at"] = float(self.clock())
                record.pop("metadata_wait_timed_out", None)
                self._write_journal(journal)
            record["job_state"] = {
                key: content.get(key)
                for key in (
                    "dispatchState",
                    "isDone",
                    "isFinalized",
                    "eventIsTruncated",
                    "dropCount",
                    "resultCount",
                    "messages",
                )
            }
            self._write_journal(journal)
            if content.get("dispatchState") == "FAILED" or _truth(
                content.get("isFailed")
            ):
                record["state"] = "failed"
                self._write_journal(journal)
                raise Refused("search failed")
            if _truth(content.get("isDone")):
                break
            self.sleep(0.25)
        if (
            content.get("dispatchState") != "DONE"
            or not _truth(content.get("isDone"))
            or _truth(content.get("isFinalized"))
            or content.get("eventIsTruncated") not in (False, "0", 0)
            or _integer(content.get("dropCount")) != 0
        ):
            record["state"] = "failed"
            self._write_journal(journal)
            raise Refused("search did not complete without truncation or drops")
        total = _integer(content.get("resultCount"))
        if total is None or total > MAX_RESULTS:
            raise Refused("search result count is invalid or exceeds the bound")
        messages = content.get("messages")
        saved_search_name = (
            record.get("label") if record.get("kind") == "saved_search" else None
        )
        empty_summary_warning = (
            self._expected_empty_summary_warning(saved_search_name, content)
            and record.get("expected_empty") is True
        )
        info_messages_valid = isinstance(messages, list) and all(
            isinstance(message, dict)
            and message.get("type") == "INFO"
            and isinstance(message.get("text"), str)
            and bool(message.get("text"))
            for message in messages
        )
        if not isinstance(messages, list) or (
            messages and not info_messages_valid and not empty_summary_warning
        ):
            record["state"] = "failed"
            self._write_journal(journal)
            raise Refused("search reported warnings or errors")
        rows: list[dict[str, Any]] = []
        for offset in range(0, max(total, 1), 500):
            page = self._request("GET", path + f"/results?count=500&offset={offset}")
            if _truth(page.get("preview")):
                raise Refused("preview search results are not acceptable")
            batch = page.get("results")
            if not isinstance(batch, list):
                raise Refused("search results are malformed")
            rows.extend(batch)
        if len(rows) != total:
            raise Refused("search result count does not match returned rows")
        record.update(state="complete", result_count=total)
        if record.get("kind") in {"search", "saved_search"} and record.get(
            "persist_result_rows", True
        ):
            record["result_rows"] = rows
        else:
            record["result_digest"] = hashlib.sha256(canonical(rows)).hexdigest()
        self._write_journal(journal)
        return rows

    def _completed_job_rows(
        self, journal: dict[str, Any], record: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Reuse durable results of a validated complete job instead of its artifact."""
        if record.get("state") == "complete":
            rows = self._cached_result_rows(journal, record)
            if isinstance(rows, list):
                return rows
            if record.get("persist_result_rows") is False:
                raise Refused("completed writer job did not retain its result rows")
        return self._read_job(journal, record)

    def _validate_job_identity(
        self,
        journal,
        record,
        entry,
        *,
        persist_owner: bool = True,
        allow_pre_execution: bool = False,
    ) -> None:
        content = entry.get("content") or {}
        acl = entry.get("acl") or {}
        if acl.get("app") != "splunk_adm":
            raise Refused("SID belongs to a different app namespace")
        actual_request = content.get("request")
        expected_request = record.get("request_bounds")
        if not isinstance(actual_request, dict) or not isinstance(
            expected_request, dict
        ):
            raise Refused("SID is missing its exact dispatch bounds")
        if any(
            str(actual_request.get(key, "")) != str(value)
            for key, value in expected_request.items()
        ):
            raise Refused("SID dispatch bounds do not match this migration slice")
        if record.get("kind") == "search":
            request_search = actual_request.get("search")
            if not isinstance(request_search, str) or not request_search:
                raise Refused("SID request is missing its submitted search")
            if fingerprint(request_search) != record.get("query_fingerprint"):
                raise Refused("SID request search does not match the journaled query")
            expected_owner = (journal.get("origin", {}).get("principal") or {}).get(
                "username"
            )
            if (
                acl.get("owner") != expected_owner
                or not expected_owner
                or _truth(content.get("isSavedSearch"))
            ):
                raise Refused("SID owner or dispatch type does not match the request")
            return
        if record.get("kind") != "saved_search":
            raise Refused("journal contains an unsupported job kind")
        label = record.get("label")
        if not _truth(content.get("isSavedSearch")) and not (
            allow_pre_execution and _job_pre_execution(content)
        ):
            raise Refused("SID does not belong to the journaled saved search")
        observed_name = content.get("savedsearch_name") or content.get("label")
        if observed_name and observed_name != label:
            raise Refused("SID does not belong to the journaled saved search")
        if not observed_name and not _job_pre_execution(content):
            raise Refused("terminal saved-search job is missing its identity")
        owner = acl.get("owner")
        if not isinstance(owner, str) or not owner:
            raise Refused("saved-search SID has no effective dispatch owner")
        owners = journal.setdefault("saved_search_dispatch_owners", {})
        expected_owner = owners.get(label, SAVEDSEARCH_DISPATCH_OWNER)
        if owner != expected_owner:
            raise Refused("saved-search SID effective dispatch owner changed")
        if persist_owner:
            owners[label] = owner
            self._write_journal(journal)

    def _validate_reconcile_identity(self, journal, record, entry) -> None:
        """Require complete terminal identity before adopting an operator SID."""
        self._validate_job_identity(journal, record, entry, persist_owner=False)
        content = entry.get("content") or {}
        if record.get("kind") == "saved_search":
            observed_name = content.get("savedsearch_name") or content.get("label")
            if observed_name != record.get("label"):
                raise Refused("discovered SID has no exact saved-search identity")
            message = "discovered SID does not match the pending writer definition"
        else:
            message = "discovered SID does not match the pending search query"
        actual_search = content.get("search")
        if (
            not isinstance(actual_search, str)
            or not actual_search
            or not self._job_search_matches(journal, record, actual_search)
        ):
            raise Refused(message)

    def reconcile(self, sid: str) -> dict[str, Any]:
        """Adopt an operator-discovered SID for a pending unknown dispatch, never resend it."""
        self.qualify()
        journal = self._load()
        if journal.get("phase") in {
            "cutover_in_progress",
            "cutover",
            "rollback_in_progress",
        }:
            self._assert_cutover_origin_compatible(journal)
        elif fingerprint(self.snapshot()) != journal.get("origin_fingerprint"):
            raise Refused("effective configuration drifted before SID reconciliation")
        record = next(
            (
                item
                for item in reversed(journal.get("jobs", []))
                if item.get("state") in {"dispatch_pending", "dispatch_unknown"}
            ),
            None,
        )
        if not record:
            raise Refused("journal has no ambiguous dispatch to reconcile")
        if not isinstance(sid, str) or not sid.strip():
            raise Refused("a discovered SID is required")
        sid = sid.strip()
        entry = self._single_entry(JOBS + "/" + quote(sid, safe=""))
        self._validate_reconcile_identity(journal, record, entry)
        label = record.get("label", "")
        record.update(sid=sid, state="running", reconciled_at=int(self.clock()))
        self._write_journal(journal)
        self._read_job(journal, record)
        if record.get("kind") == "saved_search":
            if record.get("stream") in STREAMS:
                slice_record = next(
                    (
                        item
                        for item in journal["slices"]
                        if item["start"] == int(record["slice_start"])
                        and item["end"] == int(record["slice_end"])
                    ),
                    None,
                )
                if slice_record is None:
                    raise Refused("writer SID does not reference a journaled slice")
                stream_state = slice_record["streams"][record["stream"]]
                stream_state.update(state="backfill_done", sid=sid)
                self._write_journal(journal)
            elif record.get("writer_role") == "network_client_history":
                history_slices = [
                    *journal["slices"],
                    *(
                        (journal.get("cutover") or {}).get("history_bridge_slices")
                        or []
                    ),
                ]
                slice_record = next(
                    (
                        item
                        for item in history_slices
                        if item["start"] == int(record["slice_start"])
                        and item["end"] == int(record["slice_end"])
                    ),
                    None,
                )
                if slice_record is None:
                    raise Refused("history SID does not reference a journaled slice")
                slice_record["history"]["sid"] = sid
                self._write_journal(journal)
            elif record.get("writer_role") == "application_catalog_v2":
                journal.setdefault("catalog", {})["sid"] = sid
                self._write_journal(journal)
        return {"status": "reconciled", "sid": sid, "label": label}

    def _verify_preexisting_index(
        self, journal: dict[str, Any], *, final_pass: bool = False
    ) -> None:
        query = f"search index={V2_INDEX} | fields source " + " ".join(
            sorted(set(V2_ROW_FIELDS["conversation"] + V2_ROW_FIELDS["traffic"]))
        )
        rows = self._query(
            journal,
            query,
            0,
            int(self.clock()),
            label=(
                "final v2 index contract"
                if final_pass
                else "preexisting v2 index contract"
            ),
        )
        by_stream: dict[str, list[dict[str, Any]]] = {name: [] for name in STREAMS}
        for row in rows:
            if row.get("source") == "adm:conversation":
                stream = "conversation"
            elif row.get("source") == "adm:traffic_observation":
                stream = "traffic"
            else:
                raise Refused(
                    "v2 summary index contains a row from an unknown contract source"
                )
            records = _integer(row.get("records"))
            if (
                str(row.get("contract_version")) != CONTRACT_VERSION
                or row.get("adm_record") not in STREAMS[stream]["records"]
                or not ROLLUP_ID_RE.fullmatch(str(row.get("rollup_id", "")))
                or records is None
                or records <= 0
            ):
                raise Refused(
                    "v2 summary index contains a row outside contract version 2"
                )
            by_stream[stream].append(row)
        baseline = {}
        for stream, stream_rows in by_stream.items():
            mapped = self._record_map(stream_rows, stream)
            baseline.update(
                {
                    (STREAMS[stream]["source"], key): value
                    for key, value in mapped.items()
                }
            )
        if final_pass:
            expected = self._preexisting_v2_map(journal)
            if any(
                key not in baseline
                or baseline[key].get("content_digest") != value.get("content_digest")
                or int(baseline[key].get("copies", 1)) < int(value.get("copies", 1))
                for key, value in expected.items()
            ):
                raise Refused(
                    "pre-existing v2 summary baseline changed during migration"
                )
        else:
            prior_raw = journal.get("preexisting_v2_baseline")
            prior = self._preexisting_v2_map(journal) if prior_raw is not None else None
            if prior is not None and prior != baseline:
                raise Refused("pre-existing v2 summary baseline changed on resume")
            journal["preexisting_v2_baseline"] = [
                {"source": source, "rollup_id": rollup_id, **value}
                for (source, rollup_id), value in sorted(baseline.items())
            ]
            journal["preexisting_v2_rows"] = sum(
                int(value.get("copies", 1)) for value in baseline.values()
            )
            journal["preexisting_v2_fingerprint"] = fingerprint(
                journal["preexisting_v2_baseline"]
            )
            journal["preexisting_rollup_ids"] = [
                {"source": source, "rollup_id": rollup_id}
                for source, rollup_id in sorted(baseline)
            ]
        self._write_journal(journal)

    @staticmethod
    def _preexisting_v2_map(
        journal: dict[str, Any],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        raw = journal.get("preexisting_v2_baseline", [])
        if not isinstance(raw, list):
            raise Refused("pre-existing v2 summary baseline is malformed")
        result = {}
        for item in raw:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("source"), str)
                or not isinstance(item.get("rollup_id"), str)
            ):
                raise Refused("pre-existing v2 summary baseline is malformed")
            key = (item["source"], item["rollup_id"])
            value = {
                field: val
                for field, val in item.items()
                if field not in {"source", "rollup_id"}
            }
            if key in result:
                raise Refused(
                    "pre-existing v2 summary baseline has duplicate identities"
                )
            result[key] = value
        return result

    @staticmethod
    def _writer_enabled_by_journal(journal: dict[str, Any] | None, name: str) -> bool:
        if not isinstance(journal, dict):
            return False
        if journal.get("phase") in {"cutover_in_progress", "cutover"}:
            mutations = journal.get("cutover", {}).get("mutations") or []
        elif journal.get("phase") == "rollback_in_progress":
            mutations = journal.get("rollback", {}).get("mutations") or []
        else:
            return False
        return any(
            item.get("kind") == "saved_search"
            and item.get("name") == name
            and item.get("field") == "disabled"
            and item.get("state") == "applied"
            and _strict_bool(item.get("after")) is False
            for item in mutations
        )

    @staticmethod
    def _expected_empty_summary_warning(
        name: str | None, content: dict[str, Any]
    ) -> bool:
        return (
            name in EMPTY_SUMMARY_WRITERS
            and _integer(content.get("resultCount")) == 0
            and content.get("messages") == [EMPTY_SUMMARY_WARNING]
        )

    def _writer_query(
        self, spec: dict[str, str], journal: dict[str, Any] | None = None
    ) -> str:
        entry = self._saved_search(spec["saved_search"])
        interface, _ = self._interface()
        writer = next(
            item
            for item in interface["activation"]["writer_contracts"]
            if item["name"] == spec["saved_search"]
        )
        expected_fields = writer["fields"]
        content = self._normalize_saved_search_schedule(
            entry.get("content") or {}, expected_fields
        )
        for field, value in expected_fields.items():
            actual = content.get(field)
            if field == "disabled":
                if _strict_bool(actual) is True:
                    continue
                if _strict_bool(actual) is False and self._writer_enabled_by_journal(
                    journal, spec["saved_search"]
                ):
                    continue
                raise Refused("staged writer is enabled outside journaled cutover")
            if not _config_equal(field, actual, value):
                raise Refused("staged writer changed after preparation")
        return writer["source_query"].strip()

    @staticmethod
    def _record_map(
        rows: list[dict[str, Any]], stream: str
    ) -> dict[str, dict[str, Any]]:
        spec = STREAMS[stream]
        observed = {}
        for row in rows:
            key = str(row.get("rollup_id", ""))
            records = _integer(row.get("records"))
            if (
                not ROLLUP_ID_RE.fullmatch(key)
                or records is None
                or records <= 0
                or str(row.get("contract_version")) != CONTRACT_VERSION
                or row.get("adm_record") not in spec["records"]
            ):
                raise Refused(f"{stream} output failed row validation")
            content = _summary_content(
                row,
                tuple(
                    field
                    for field in V2_ROW_FIELDS[stream]
                    if field not in V2_LOOKUP_DERIVED_FIELDS[stream]
                ),
            )
            digest = fingerprint(
                {"canonicalizer": SUMMARY_CANONICALIZER_VERSION, "row": content}
            )
            if key in observed:
                if observed[key]["content_digest"] != digest:
                    raise Refused(
                        f"{stream} output contains conflicting material for a rollup ID"
                    )
                observed[key]["copies"] += 1
            else:
                observed[key] = {
                    "content": content,
                    "content_digest": digest,
                    "copies": 1,
                    "records": records,
                    "adm_record": row["adm_record"],
                }
        return observed

    def _wait_before_summary_retry(self, attempt: int) -> None:
        if attempt <= len(SUMMARY_INDEX_WAIT_DELAYS):
            self.sleep(SUMMARY_INDEX_WAIT_DELAYS[attempt - 1])

    def _persisted_query(
        self, journal, spec, expected, label: str, attempt: int
    ) -> dict[str, dict[str, Any]]:
        if not expected:
            return {}
        ids = sorted(expected)
        id_filter = ", ".join(f'"{item}"' for item in ids)
        # Cumulative expectations include the immutable retained baseline, which
        # may predate migration creation by an arbitrary amount.
        lower = 0
        upper = int(self.clock()) + 60
        query = (
            f'| search index={V2_INDEX} source="{spec["source"]}" '
            f"contract_version=2 rollup_id IN ({id_filter}) "
            f"| where _indextime>={lower} AND _indextime<={upper} "
            "| fields "
            + " ".join(V2_ROW_FIELDS["conversation"] + V2_ROW_FIELDS["traffic"])
        )
        rows = self._query(
            journal,
            query,
            None,
            None,
            label=f"{label} poll {attempt}",
        )
        return self._record_map(
            rows, next(name for name, item in STREAMS.items() if item is spec)
        )

    def _poll_persisted_rows(self, journal, expected, stream, label):
        spec = STREAMS[stream]
        if not expected:
            return {}
        ids = sorted(expected)
        if len(ids) > MAX_RESULTS:
            raise Refused(
                f"cumulative {stream} rollup IDs exceed the {MAX_RESULTS}-ID "
                "migration bound; prepare a shorter backfill range"
            )
        actual = {}
        for offset in range(0, len(ids), ROLLUP_ID_QUERY_BATCH):
            batch_number = offset // ROLLUP_ID_QUERY_BATCH + 1
            wanted = {
                key: expected[key]
                for key in ids[offset : offset + ROLLUP_ID_QUERY_BATCH]
            }
            for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
                observed = self._persisted_query(
                    journal, spec, wanted, f"{label} batch {batch_number}", attempt
                )
                if observed == wanted:
                    actual.update(observed)
                    break
                self._wait_before_summary_retry(attempt)
            else:
                raise Refused(
                    f"{stream} staged rollup IDs, record kinds, or event counts do not match source slice"
                )
        return actual

    def _cumulative_v2_expected(self, journal, stream, additional=()):
        """Return every physical V2 copy a migration-wide readback can see."""
        spec = STREAMS[stream]
        expected = {}
        for (source, rollup_id), value in self._preexisting_v2_map(journal).items():
            if source == spec["source"]:
                expected = _add_record_maps(
                    expected, {rollup_id: value}, label=f"{stream} immutable baseline"
                )
        for slice_record in journal.get("slices", []):
            stream_state = slice_record.get("streams", {}).get(stream) or {}
            manifest = stream_state.get("expected")
            if stream_state.get("state") != "verified":
                continue
            if isinstance(manifest, dict):
                expected = _add_record_maps(
                    expected, manifest, label=f"{stream} verified manual intents"
                )
        scheduled = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        for cycle in (scheduled.get(stream) or {}).get("cycles", []):
            if cycle.get("state") != "verified":
                continue
            manifest = cycle.get("expected")
            if isinstance(manifest, dict):
                expected = _add_record_maps(
                    expected, manifest, label=f"{stream} verified scheduled intents"
                )
        for manifest in additional:
            expected = _add_record_maps(
                expected, manifest, label=f"{stream} current scheduled intent"
            )
        return expected

    def _retire_undispatched_attempt(self, journal, record):
        """Retain a proven no-dispatch attempt before allowing a new intent."""
        if record.get("state") not in {
            "configuration_pending",
            "preparation_aborted",
            "rejected",
        } or record.get("sid"):
            raise Uncertain("writer attempt is not proven safe to retry")
        for execution in journal.get("temporary_manual_executions", []):
            if (
                execution.get("job_id") == record.get("id")
                and execution.get("state") != "restored"
            ):
                self._restore_manual_writer(journal, execution)
        if record["state"] == "configuration_pending":
            record["state"] = "preparation_aborted"
            record["preparation_aborted_at"] = int(self.clock())
            self._write_journal(journal)
        return record["id"]

    def _settle_prior_catalog_writer_jobs(
        self, journal: dict[str, Any], writer_search: str
    ) -> None:
        for job in journal.get("jobs", []):
            if (
                job.get("kind") != "saved_search"
                or job.get("label") != writer_search
                or job.get("state") in CATALOG_SETTLED_JOB_STATES
            ):
                continue
            if job.get("sid"):
                try:
                    self._read_job(journal, job)
                except Refused as exc:
                    if job.get("state") not in CATALOG_SETTLED_JOB_STATES:
                        raise Refused(
                            f"prior catalog writer job {job['sid']} could not be "
                            f"settled ({exc}); confirm its outcome in Splunk Job "
                            f"Manager/audit evidence and run `reconcile --sid "
                            f"{job['sid']}` (see 'Interrupted and failed operations' "
                            "in docs/CISCO_CONTRACT_MIGRATION.md) before resuming"
                        ) from exc
            elif job.get("state") == "configuration_pending":
                self._retire_undispatched_attempt(journal, job)
            else:
                raise Refused(
                    "catalog output changed while a prior catalog writer dispatch "
                    "has an unknown outcome and no recorded SID; find its SID in "
                    "Splunk Job Manager/audit evidence and run `reconcile --sid "
                    "<SID>` (see 'Interrupted and failed operations' in "
                    "docs/CISCO_CONTRACT_MIGRATION.md) before resuming"
                )

    def _dispatch_writer(
        self,
        journal: dict[str, Any],
        name: str,
        request_bounds: dict[str, str],
        *,
        label: str,
        intent_fingerprint: str | None = None,
        persist_result_rows: bool = False,
    ) -> list[dict[str, Any]] | None:
        """Dispatch one exact allowlisted saved-search slice with SID journaling.

        Rows are returned (and durably retained) only when the caller reads them
        back; otherwise a completed job keeps its count and result digest.
        """
        interface, _ = self._interface()
        writer = next(
            (
                item
                for item in interface["activation"]["writer_contracts"]
                if item.get("name") == name
            ),
            None,
        )
        if writer is None:
            raise Refused("writer is absent from the authoritative allowlist")
        self._recover_temporary_manual_writer(journal, name)
        entry = self._saved_search(name)
        content = self._normalize_saved_search_schedule(
            entry.get("content") or {}, writer["fields"]
        )
        for field, expected in writer["fields"].items():
            actual = content.get(field)
            if field == "disabled":
                if _strict_bool(actual) is True:
                    continue
                if _strict_bool(actual) is False and self._writer_enabled_by_journal(
                    journal, name
                ):
                    continue
                raise Refused("staged writer is enabled outside journaled cutover")
            if not _config_equal(field, actual, expected):
                raise Refused("staged writer changed after preparation")
        search = str(content.get("search", ""))
        bounds = {key: str(value) for key, value in request_bounds.items()}
        record = next(
            (
                item
                for item in reversed(journal.get("jobs", []))
                if item.get("kind") == "saved_search"
                and item.get("label") == name
                and item.get("request_bounds") == bounds
                and item.get("intent_fingerprint") == intent_fingerprint
            ),
            None,
        )
        retry_of = None
        if record is not None and record.get("state") in {
            "configuration_pending",
            "preparation_aborted",
            "rejected",
        }:
            retry_of = self._retire_undispatched_attempt(journal, record)
            record = None
        if record is not None and record.get("state") in {
            "dispatch_pending",
            "dispatch_unknown",
        }:
            execution = next(
                (
                    item
                    for item in reversed(journal.get("temporary_manual_executions", []))
                    if item.get("job_id") == record.get("id")
                    and item.get("state") != "restored"
                ),
                None,
            )
            if execution:
                self._restore_manual_writer(journal, execution)
            raise Uncertain(f"{label} preparation or dispatch requires reconciliation")
        if record is not None and record.get("state") == "complete":
            if persist_result_rows:
                return self._completed_job_rows(journal, record)
            return None
        if record is None:
            self._assert_origin_unchanged(journal)
            self._assert_no_competing_staged_jobs(journal)
            record = {
                "id": uuid.uuid4().hex,
                "kind": "saved_search",
                "retry_of": retry_of,
                "label": name,
                "state": "configuration_pending",
                "request_bounds": bounds,
                "search_fingerprint": fingerprint(search),
                "writer_contract_id": writer["id"],
                "writer_role": writer.get("role"),
                "intent_fingerprint": intent_fingerprint,
                "persist_result_rows": persist_result_rows,
                **self._evidence_class(journal),
                **(
                    {
                        "slice_start": request_bounds["index_earliest"],
                        "slice_end": request_bounds["index_latest"],
                    }
                    if "index_earliest" in request_bounds
                    and "index_latest" in request_bounds
                    else {}
                ),
            }
            self._save_job(journal, record)
            execution = self._temporary_manual_writer(journal, name, bounds, record)
            record["state"] = "dispatch_pending"
            self._write_journal(journal)
            try:
                try:
                    response = self._request(
                        "POST",
                        SEARCHES + quote(name, safe="") + "/dispatch",
                        {
                            **{
                                f"dispatch.{key}": value
                                for key, value in bounds.items()
                            },
                            "trigger_actions": "0",
                        },
                    )
                except Refused:
                    record["state"] = "rejected"
                    self._write_journal(journal)
                    raise
                except Exception:
                    record["state"] = "dispatch_unknown"
                    self._write_journal(journal)
                    raise Uncertain(
                        f"{label} outcome is unknown; reconcile by SID without retry"
                    ) from None
                sid = response.get("sid")
                if not isinstance(sid, str) or not sid:
                    record["state"] = "dispatch_unknown"
                    self._write_journal(journal)
                    raise Uncertain(f"{label} returned no SID; reconcile before retry")
                record.update(state="running", sid=sid)
                self._write_journal(journal)
                rows = self._read_job(journal, record)
                return rows if persist_result_rows else None
            finally:
                if execution is not None and execution.get("state") != "restored":
                    self._restore_manual_writer(journal, execution)
        rows = self._read_job(journal, record)
        return rows if persist_result_rows else None

    def _validate_migration_ingestion_window(
        self, journal, *, upper_bound: int | None = None
    ) -> dict[str, Any]:
        lower = 0
        upper = int(self.clock()) + 60 if upper_bound is None else upper_bound
        if upper < lower:
            raise Refused("staged ingestion watermark precedes the migration window")
        query = (
            f"search index={V2_INDEX} | where _indextime>={lower} AND _indextime<={upper} "
            "| fields source "
            + " ".join(
                sorted(set(V2_ROW_FIELDS["conversation"] + V2_ROW_FIELDS["traffic"]))
            )
        )
        rows = self._query(
            journal,
            query,
            None,
            None,
            label="complete staged ingestion window",
            earliest_time="0",
            latest_time=str(upper + 900),
            # This audit must observe the index again on every pass. Reusing
            # a completed search from the journal would hide later missing or
            # surplus physical copies.
            persist_result_rows=False,
        )
        expected: dict[tuple[str, str], dict[str, Any]] = self._preexisting_v2_map(
            journal
        )
        for slice_record in journal["slices"]:
            for stream, spec in STREAMS.items():
                for rollup_id, value in slice_record["streams"][stream][
                    "expected"
                ].items():
                    key = (spec["source"], rollup_id)
                    if key in expected:
                        prior = expected[key]
                        if prior.get("content_digest") != value.get("content_digest"):
                            raise Refused(
                                "source rollup ID conflicts across migration evidence"
                            )
                        prior = dict(prior)
                        prior["copies"] = int(prior.get("copies", 1)) + int(
                            value.get("copies", 1)
                        )
                        expected[key] = prior
                    else:
                        expected[key] = value
        # The first scheduler-owned cycle is part of the migration's write
        # window too. It is deliberately kept in its own journal section
        # because it was produced by the scheduler, not by our bounded
        # backfill dispatches.
        scheduled = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        for stream, spec in STREAMS.items():
            scheduled_state = scheduled.get(stream) or {}
            cycles = scheduled_state.get("cycles")
            if cycles is None and scheduled_state.get("expected") is not None:
                cycles = [{"expected": scheduled_state["expected"]}]
            for cycle in cycles or []:
                scheduled_expected = cycle.get("expected")
                if not isinstance(scheduled_expected, dict):
                    raise Refused(
                        "scheduled writer evidence is missing its expected manifest"
                    )
                for rollup_id, value in scheduled_expected.items():
                    key = (spec["source"], rollup_id)
                    if key in expected:
                        prior = expected[key]
                        if prior.get("content_digest") != value.get("content_digest"):
                            raise Refused(
                                "scheduled rollup ID conflicts with migration evidence"
                            )
                        prior = dict(prior)
                        prior["copies"] = int(prior.get("copies", 1)) + int(
                            value.get("copies", 1)
                        )
                        expected[key] = prior
                    else:
                        expected[key] = value
                if cycle.get("empty_summary_warning") is True and scheduled_expected:
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
        actual = {}
        for source in {str(row.get("source", "")) for row in rows}:
            stream = next(
                (name for name, spec in STREAMS.items() if spec["source"] == source),
                None,
            )
            if stream is None:
                raise Refused("staged ingestion window contains an unknown v2 source")
            source_rows = [row for row in rows if row.get("source") == source]
            for rollup_id, value in self._record_map(source_rows, stream).items():
                key = (source, rollup_id)
                actual[key] = value
        if actual != expected:
            raise Refused(
                "staged ingestion window contains missing or unexpected summary rollups"
            )
        empty_summary_proofs = []
        for stream, state in scheduled.items():
            for cycle in state.get("cycles", []):
                if cycle.get("empty_summary_warning") is not True:
                    continue
                if cycle.get("expected"):
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
                proof = cycle.get("empty_summary_proof")
                if not isinstance(proof, dict) or proof.get("retained_rows") != 0:
                    raise Refused(
                        "empty scheduled writer has no independent retained-index proof"
                    )
                if not cycle.get("expected"):
                    cycle["empty_summary_proof"] = {
                        **proof,
                        "expected_rows": 0,
                        "retained_rows": 0,
                        "audit_lower_indextime": lower,
                        "audit_upper_indextime": upper,
                        "global_actual_equals_expected": True,
                    }
                    empty_summary_proofs.append(
                        {
                            "stream": stream,
                            "sid": cycle.get("sid"),
                            **cycle["empty_summary_proof"],
                        }
                    )
        if empty_summary_proofs:
            self._write_journal(journal)
        return {
            "lower_indextime": lower,
            "upper_indextime": upper,
            "rows": len(actual),
            "empty_summary_proofs": empty_summary_proofs,
            "fingerprint": fingerprint(
                [
                    {
                        "source": source,
                        "rollup_id": rollup_id,
                        **value,
                    }
                    for (source, rollup_id), value in sorted(actual.items())
                ]
            ),
        }

    def _scheduled_output_watermark(self, journal) -> int:
        """Return the independent observation boundary used for full-window audit."""
        observed = _integer(
            (journal.get("cutover") or {}).get("schedule_observation_epoch")
        )
        if observed is None:
            raise Refused("scheduled output observation boundary is not journaled")
        return observed

    def _stage_stream(
        self,
        journal,
        slice_record,
        stream: str,
        *,
        observed_scheduled_expected: list[dict[str, Any]] | None = None,
    ) -> None:
        spec = STREAMS[stream]
        self._recover_temporary_manual_writer(journal, spec["saved_search"])
        self._assert_origin_unchanged(journal)
        stream_state = slice_record["streams"][stream]
        if stream_state.get("state") == "verified":
            return
        if stream_state.get("state") in {"dispatch_pending", "dispatch_unknown"}:
            raise Uncertain("an earlier dispatch requires SID reconciliation")
        start, end = slice_record["start"], slice_record["end"]
        if stream_state.get("state") == "backfill_done":
            expected = stream_state.get("expected")
            if not isinstance(expected, dict):
                raise Refused(
                    "reconciled writer is missing its expected output manifest"
                )
        else:
            query = (
                self._writer_query(spec, journal)
                + " | fields "
                + " ".join(V2_ROW_FIELDS[stream])
            )
            expected_rows = self._query(
                journal, query, start, end, label=f"{stream} expected output {start}"
            )
            expected = self._record_map(expected_rows, stream)
            baseline = self._preexisting_v2_map(journal)
            for rollup_id, row in expected.items():
                prior = baseline.get((spec["source"], rollup_id))
                if prior and prior.get("content_digest") != row.get("content_digest"):
                    raise Refused(
                        "source rollup ID conflicts with pre-existing summary material"
                    )
            stream_state.update(state="backfill_pending", expected=expected)
            self._write_journal(journal)
        matching_writer = next(
            (
                item
                for item in reversed(journal.get("jobs", []))
                if item.get("kind") == "saved_search"
                and item.get("stream") == stream
                and item.get("slice_start") == start
                and item.get("slice_end") == end
            ),
            None,
        )
        retry_of = None
        if matching_writer and matching_writer.get("state") in {
            "configuration_pending",
            "preparation_aborted",
            "rejected",
        }:
            retry_of = self._retire_undispatched_attempt(journal, matching_writer)
            matching_writer = None
        if matching_writer and matching_writer.get("state") in {
            "dispatch_pending",
            "dispatch_unknown",
        }:
            execution = next(
                (
                    item
                    for item in reversed(journal.get("temporary_manual_executions", []))
                    if item.get("job_id") == matching_writer.get("id")
                    and item.get("state") != "restored"
                ),
                None,
            )
            if execution:
                self._restore_manual_writer(journal, execution)
            raise Uncertain(
                "an earlier writer preparation or dispatch requires reconciliation"
            )
        if expected and stream_state.get("state") != "backfill_done":
            self._assert_origin_unchanged(journal)
            # Persist intent before the side-effecting dispatch. If the request
            # outcome is ambiguous, only a discovered SID can resume it.
            writer_job = matching_writer or {
                "id": uuid.uuid4().hex,
                "kind": "saved_search",
                "retry_of": retry_of,
                "label": spec["saved_search"],
                "state": "configuration_pending",
                "stream": stream,
                "slice_start": start,
                "slice_end": end,
                "persist_result_rows": False,
                **self._evidence_class(journal),
                "request_bounds": {
                    "earliest_time": str(journal["event_earliest"]),
                    "latest_time": str(journal["event_latest"]),
                    "index_earliest": str(start),
                    "index_latest": str(end),
                },
                "search_fingerprint": fingerprint(
                    str(self._saved_search(spec["saved_search"])["content"]["search"])
                ),
            }
            if matching_writer is None:
                self._save_job(journal, writer_job)
                execution = self._temporary_manual_writer(
                    journal,
                    spec["saved_search"],
                    writer_job["request_bounds"],
                    writer_job,
                )
                writer_job["state"] = "dispatch_pending"
                self._write_journal(journal)
                try:
                    try:
                        response = self._request(
                            "POST",
                            SEARCHES
                            + quote(spec["saved_search"], safe="")
                            + "/dispatch",
                            {
                                "dispatch.earliest_time": str(
                                    journal["event_earliest"]
                                ),
                                "dispatch.latest_time": str(journal["event_latest"]),
                                "dispatch.index_earliest": str(start),
                                "dispatch.index_latest": str(end),
                                "trigger_actions": "0",
                            },
                        )
                    except Refused:
                        writer_job["state"] = "rejected"
                        stream_state["state"] = "rejected"
                        self._write_journal(journal)
                        raise
                    except Exception:
                        writer_job["state"] = "dispatch_unknown"
                        stream_state["state"] = "dispatch_unknown"
                        self._write_journal(journal)
                        raise Uncertain(
                            "writer dispatch outcome is unknown; reconcile by SID"
                        ) from None
                    sid = response.get("sid")
                    if not isinstance(sid, str) or not sid:
                        writer_job["state"] = "dispatch_unknown"
                        stream_state["state"] = "dispatch_unknown"
                        self._write_journal(journal)
                        raise Uncertain(
                            "writer returned no SID; reconcile before continuing"
                        )
                    writer_job.update(state="running", sid=sid)
                    stream_state.update(state="running", sid=sid)
                    self._write_journal(journal)
                finally:
                    if execution is not None and execution.get("state") != "restored":
                        self._restore_manual_writer(journal, execution)
            elif matching_writer.get("state") == "running":
                writer_job = matching_writer
            # A complete record was fully validated when it was marked complete;
            # its Splunk artifact may have expired since.
            if writer_job.get("state") != "complete":
                self._read_job(journal, writer_job)
            stream_state["state"] = "backfill_done"
            self._write_journal(journal)
        self._assert_origin_unchanged(journal)
        cumulative = {}
        # The poll window intentionally spans the migration's complete
        # ingestion window. Include the immutable baseline and every verified
        # write intent whose output can be visible in that window.
        baseline = self._preexisting_v2_map(journal)
        for (source, rollup_id), value in baseline.items():
            if source == STREAMS[stream]["source"]:
                cumulative = _add_record_maps(
                    cumulative, {rollup_id: value}, label=f"{stream} staged baseline"
                )
        for prior_slice in journal["slices"]:
            if prior_slice["start"] > start:
                continue
            prior_manifest = prior_slice["streams"][stream].get("expected")
            if isinstance(prior_manifest, dict):
                cumulative = _add_record_maps(
                    cumulative, prior_manifest, label=f"{stream} staged slices"
                )
        scheduled = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        for cycle in (scheduled.get(stream) or {}).get("cycles", []):
            if cycle.get("state") == "verified" and isinstance(
                cycle.get("expected"), dict
            ):
                cumulative = _add_record_maps(
                    cumulative,
                    cycle["expected"],
                    label=f"{stream} staged scheduled intents",
                )
        for manifest in observed_scheduled_expected or []:
            cumulative = _add_record_maps(
                cumulative,
                manifest,
                label=f"{stream} staged observed scheduled intents",
            )
        actual = self._poll_persisted_rows(
            journal,
            cumulative,
            stream,
            label=f"{stream} staged records {start}",
        )
        if actual != cumulative:
            raise Refused(
                f"{stream} staged rollup IDs/event counts do not match source slice"
            )
        stream_state.update(
            state="verified",
            verified_at=int(self.clock()),
            rows=sum(value["copies"] for value in expected.values()),
            event_records=sum(
                value["records"] * value["copies"] for value in expected.values()
            ),
            expected_fingerprint=fingerprint(expected),
        )
        self._write_journal(journal)

    def backfill(self) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        self._assert_origin_unchanged(journal)
        for slice_record in journal["slices"]:
            for stream in STREAMS:
                self._stage_stream(journal, slice_record, stream)
            self._stage_history_slice(journal, slice_record)
        journal["phase"] = "backfilled"
        self._write_journal(journal)
        return {"status": "backfilled", "slices": len(journal["slices"])}
