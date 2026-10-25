"""Migration responsibility methods for history."""

from __future__ import annotations

from decimal import InvalidOperation
from decimal import Decimal
from typing import Any
import uuid
from .common import (
    MAX_CANDIDATE_BYTES,
    ROLLUP_ID_RE,
    Refused,
    STREAMS,
    SUMMARY_INDEX_WAIT_ATTEMPTS,
    Uncertain,
    V2_ROW_FIELDS,
    _add_record_maps,
    _integer,
    _number,
    canonical,
    fingerprint,
)


class MigrationHistory:
    @staticmethod
    def _history_stable_fields(contract: dict[str, Any]) -> list[str]:
        receipt_fields = {"received_time", "latest_received_time"}
        return [
            field
            for field in contract.get("expected_row_fields", [])
            if field not in receipt_fields
        ]

    def _history_expected(
        self,
        journal,
        contract,
        start,
        end,
        *,
        event_bounds: dict[str, str] | None = None,
    ):
        time_bounds = event_bounds or {
            "earliest_time": str(journal["event_earliest"]),
            "latest_time": str(journal["event_latest"]),
        }
        rows = self._query(
            journal,
            contract["expected_row_query"],
            start,
            end,
            label=f"network client history expected keys {start}",
            persist_result_rows=False,
            earliest_time=time_bounds["earliest_time"],
            latest_time=time_bounds["latest_time"],
        )
        allowed_status = set(contract["validation"].get("allowed_mapping_statuses", []))
        fields = self._history_stable_fields(contract)
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            key = str(row.get("_key", ""))
            status = str(row.get("mapping_status", ""))
            version = str(row.get("contract_version", ""))
            if (
                not ROLLUP_ID_RE.fullmatch(key)
                or version != str(contract["contract_version"])
                or status not in allowed_status
                or not row.get("source")
                or not row.get("source_authority")
                or not row.get("native_id")
                or not row.get("event_fingerprint")
            ):
                raise Refused(
                    "network client history source rows failed key/schema checks"
                )
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in fields
            }
            previous = grouped.get(key)
            if previous is None:
                received_min = _number(row.get("received_time"))
                received_max = _number(row.get("latest_received_time"))
                if received_max is None:
                    received_max = received_min
                grouped[key] = {
                    "stable": stable,
                    "received_min": received_min,
                    "received_max": received_max,
                    "fingerprint": fingerprint(stable),
                    "mapping_status": status,
                }
            else:
                if previous["stable"] != stable:
                    raise Refused(
                        "history replay key has conflicting normalized fields"
                    )
                receipt = _number(row.get("received_time"))
                latest = _number(row.get("latest_received_time"))
                if latest is None:
                    latest = receipt
                if receipt is not None:
                    previous["received_min"] = min(
                        receipt
                        if previous["received_min"] is None
                        else previous["received_min"],
                        receipt,
                    )
                if latest is not None:
                    previous["received_max"] = max(
                        latest
                        if previous["received_max"] is None
                        else previous["received_max"],
                        latest,
                    )
        return grouped

    def _history_baseline_snapshot(self, interface):
        contract = interface["staged_collections"]["network_client_history"]
        baseline = {}
        for row in self._collection_rows(contract["collection"]):
            key = str(row.get("_key", ""))
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in self._history_stable_fields(contract)
            }
            received = _number(row.get("received_time"))
            latest = _number(row.get("latest_received_time"))
            if latest is None:
                latest = received
            if not key or received is None or latest is None:
                raise Refused("preexisting network client history row is incomplete")
            key_hash = fingerprint(key)
            if key_hash in baseline:
                raise Refused("preexisting network client history has duplicate keys")
            baseline[key_hash] = {
                "stable_fingerprint": fingerprint(stable),
                "received_min": received,
                "received_max": latest,
            }
        return baseline

    @staticmethod
    def _history_receipt_manifest(expected):
        return {
            fingerprint(key): {
                "stable_fingerprint": value["fingerprint"],
                "received_min": value["received_min"],
                "received_max": value["received_max"],
            }
            for key, value in expected.items()
        }

    def _cumulative_history_expected(self, journal, contract, through_end):
        combined = {}
        auxiliary = (journal.get("cutover") or {}).get("history_bridge_slices", [])
        for item in [*journal["slices"], *auxiliary]:
            # A one-minute history-only bridge may intentionally be staged
            # just ahead of the current five-minute summary slice. Keep its
            # already-retained receipts in the cumulative equality check.
            if (
                item["end"] > through_end
                and item.get("history", {}).get("state") != "verified"
            ):
                continue
            receipts = item.get("history", {}).get("expected_receipts")
            if receipts is None:
                expected = self._history_expected(
                    journal, contract, item["start"], item["end"]
                )
                receipts = {
                    fingerprint(key): {
                        "stable_fingerprint": value["fingerprint"],
                        "received_min": value["received_min"],
                        "received_max": value["received_max"],
                    }
                    for key, value in expected.items()
                }
            for key_hash, value in receipts.items():
                previous = combined.get(key_hash)
                if previous is None:
                    combined[key_hash] = dict(value)
                    continue
                if previous["stable_fingerprint"] != value["stable_fingerprint"]:
                    raise Refused("history replay key conflicts across staged slices")
                for receipt_field, reducer in (
                    ("received_min", min),
                    ("received_max", max),
                ):
                    left, right = previous[receipt_field], value[receipt_field]
                    if left is None:
                        previous[receipt_field] = right
                    elif right is not None:
                        previous[receipt_field] = reducer(left, right)
        for cycle in (
            (journal.get("cutover") or {})
            .get("scheduled_history", {})
            .get("cycles", [])
        ):
            for key_hash, value in cycle.get("expected_receipts", {}).items():
                previous = combined.get(key_hash)
                if previous is None:
                    combined[key_hash] = dict(value)
                    continue
                if previous["stable_fingerprint"] != value["stable_fingerprint"]:
                    raise Refused("history key conflicts across scheduled windows")
                for receipt_field, reducer in (
                    ("received_min", min),
                    ("received_max", max),
                ):
                    left, right = previous[receipt_field], value[receipt_field]
                    if left is None:
                        previous[receipt_field] = right
                    elif right is not None:
                        previous[receipt_field] = reducer(left, right)
        return combined

    def _validate_history_rows(self, contract, expected, actual_rows, baseline=None):
        fields = set(contract["fields"])
        actual = {}
        actual_by_hash = {}
        for row in actual_rows:
            key = str(row.get("_key", ""))
            if key in actual:
                raise Refused("network client history collection has duplicate keys")
            # KV Store REST adds ownership metadata to outputlookup rows.
            # It is not a source field or part of the normalized history hash.
            if "_user" in row and not isinstance(row["_user"], str):
                raise Refused("network client history ownership metadata is malformed")
            if not (fields | {"_user"}).issuperset(row):
                raise Refused(
                    "network client history row has fields outside its contract"
                )
            actual[key] = row
            actual_by_hash[fingerprint(key)] = row
        baseline = baseline or {}
        expected_by_hash = {
            (key if "stable_fingerprint" in value else fingerprint(key)): value
            for key, value in expected.items()
        }
        for key_hash in set(expected_by_hash) & set(baseline):
            expected_row = expected_by_hash[key_hash]
            baseline_row = baseline[key_hash]
            stable_fp = expected_row.get("stable_fingerprint") or fingerprint(
                expected_row["stable"]
            )
            if stable_fp != baseline_row["stable_fingerprint"]:
                raise Refused("preexisting history key conflicts with source evidence")
            expected_row["received_min"] = min(
                expected_row["received_min"], baseline_row["received_min"]
            )
            expected_row["received_max"] = max(
                expected_row["received_max"], baseline_row["received_max"]
            )
        expected_hashes = set(expected_by_hash)
        if set(actual_by_hash) != expected_hashes | set(baseline):
            return None
        stable_fields = self._history_stable_fields(contract)
        for key_hash, expected_row in expected_by_hash.items():
            row = actual_by_hash[key_hash]
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in stable_fields
            }
            expected_stable_fingerprint = expected_row.get("stable_fingerprint")
            if expected_stable_fingerprint is not None:
                stable_matches = fingerprint(stable) == expected_stable_fingerprint
            else:
                stable_matches = stable == expected_row["stable"]
            if not stable_matches:
                raise Refused(
                    "network client history row differs from normalized source evidence"
                )
            got_min = _number(row.get("received_time"))
            got_max = _number(row.get("latest_received_time"))
            if (
                got_min is None
                or got_max is None
                or got_min != expected_row["received_min"]
                or got_max != expected_row["received_max"]
            ):
                raise Refused("network client history receipt merge is incomplete")
        for key_hash, expected_row in baseline.items():
            row = actual_by_hash[key_hash]
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in stable_fields
            }
            if fingerprint(stable) != expected_row["stable_fingerprint"]:
                raise Refused("preexisting network client history row was changed")
            # A source replay may legitimately extend a preexisting receipt
            # range. The cumulative source expectation above validates the
            # exact merged extrema in that case.
            if key_hash in expected_hashes:
                continue
            if (
                _number(row.get("received_time")) != expected_row["received_min"]
                or _number(row.get("latest_received_time"))
                != expected_row["received_max"]
            ):
                raise Refused("preexisting network client history receipt changed")
        return actual

    @staticmethod
    def _normalize_history_field(field: str, value: Any) -> Any:
        if value is None:
            return None
        if field in {"contract_version", "source_time", "collected_time"}:
            number = _number(value)
            if number is not None:
                return number
        if isinstance(value, (dict, list)):
            return canonical(value).decode("utf-8")
        return str(value)

    def _stage_history_slice(self, journal, slice_record):
        self._assert_origin_unchanged(journal)
        state = slice_record["history"]
        if state.get("state") == "verified":
            return
        if state.get("state") in {"dispatch_pending", "dispatch_unknown"}:
            raise Uncertain(
                "network client history dispatch requires SID reconciliation"
            )
        interface, _ = self._interface()
        contract = interface["staged_collections"]["network_client_history"]
        if "history_baseline" not in journal:
            journal["history_baseline"] = self._history_baseline_snapshot(interface)
            self._write_journal(journal)
        start, end = slice_record["start"], slice_record["end"]
        request_bounds = state.get("request_bounds")
        if request_bounds is None:
            request_bounds = {
                "earliest_time": str(journal["event_earliest"]),
                "latest_time": str(journal["event_latest"]),
                "index_earliest": str(start),
                "index_latest": str(end),
            }
        elif request_bounds != {
            "earliest_time": str(request_bounds.get("earliest_time", "")),
            "latest_time": str(request_bounds.get("latest_time", "")),
            "index_earliest": str(start),
            "index_latest": str(end),
        }:
            raise Refused("history slice request bounds changed on resume")
        event_bounds = {
            "earliest_time": request_bounds["earliest_time"],
            "latest_time": request_bounds["latest_time"],
        }
        expected = self._history_expected(
            journal, contract, start, end, event_bounds=event_bounds
        )
        expected_fingerprint = fingerprint(
            {key: value["fingerprint"] for key, value in expected.items()}
        )
        if (
            state.get("expected_fingerprint") is not None
            and state.get("expected_fingerprint") != expected_fingerprint
        ):
            raise Refused("history slice source changed after its durable expectation")
        intent_fingerprint = fingerprint(
            {
                "migration_id": journal["migration_id"],
                "slice": [start, end],
                "request_bounds": request_bounds,
                "expected": expected_fingerprint,
            }
        )
        if (
            state.get("intent_fingerprint") is not None
            and state.get("intent_fingerprint") != intent_fingerprint
        ):
            raise Refused("history slice writer intent changed on resume")
        state["expected_receipts"] = {
            fingerprint(key): {
                "stable_fingerprint": value["fingerprint"],
                "received_min": value["received_min"],
                "received_max": value["received_max"],
            }
            for key, value in expected.items()
        }
        self._write_journal(journal)
        cumulative = self._cumulative_history_expected(journal, contract, end)
        state.update(
            state="expected",
            request_bounds=request_bounds,
            intent_fingerprint=intent_fingerprint,
            expected_keys=sorted(expected),
            expected_fingerprint=expected_fingerprint,
        )
        self._write_journal(journal)
        if expected:
            self._dispatch_writer(
                journal,
                contract["builder_search"],
                request_bounds,
                label=f"network client history slice {start}",
                intent_fingerprint=intent_fingerprint,
            )
        for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
            self._assert_origin_unchanged(journal)
            actual_rows = self._collection_rows(contract["collection"])
            actual = self._validate_history_rows(
                contract, cumulative, actual_rows, journal["history_baseline"]
            )
            if actual is not None:
                state.update(
                    state="verified",
                    verified_at=int(self.clock()),
                    row_count=len(expected),
                    actual_fingerprint=fingerprint(
                        {
                            key: fingerprint(
                                {
                                    field: actual[key].get(field)
                                    for field in self._history_stable_fields(contract)
                                }
                            )
                            for key in sorted(expected)
                        }
                    ),
                )
                self._write_journal(journal)
                return
            self._wait_before_summary_retry(attempt)
        raise Refused(
            "network client history rows did not become visible in the collection"
        )

    def _stage_catalog(self, journal):
        """Build and verify the separate V2 catalog before any public switch."""
        self._assert_origin_unchanged(journal)
        interface, _ = self._interface()
        contract = interface["staged_collections"]["application_catalog_v2"]
        bounds = contract.get("dispatch_bounds")
        if (
            not isinstance(bounds, dict)
            or bounds.get("earliest_time") != "-1h@h"
            or bounds.get("latest_time") != "@h"
        ):
            raise Refused("catalog dispatch bounds are not the shipped bounded window")
        state = journal.setdefault("catalog", {})
        input_fingerprint = fingerprint(
            {
                "slices": [
                    {
                        "start": item["start"],
                        "end": item["end"],
                        "streams": {
                            stream: item["streams"][stream].get("expected_fingerprint")
                            or fingerprint(item["streams"][stream].get("expected", {}))
                            for stream in STREAMS
                        },
                    }
                    for item in journal["slices"]
                ],
                "scheduled_cycles": {
                    stream: [
                        {
                            "index_bounds": cycle["index_bounds"],
                            "expected_fingerprint": cycle["expected_fingerprint"],
                        }
                        for cycle in stream_state.get("cycles", [])
                    ]
                    for stream, stream_state in (
                        (journal.get("cutover") or {}).get("scheduled_streams") or {}
                    ).items()
                },
            }
        )
        same_generation = state.get("input_fingerprint") == input_fingerprint
        prior_bounds = state.get("dispatch_bounds") if same_generation else None
        if isinstance(prior_bounds, dict) and all(
            _integer(prior_bounds.get(key)) is not None
            for key in ("earliest_time", "latest_time")
        ):
            event_earliest = str(_integer(prior_bounds["earliest_time"]))
            event_latest = str(_integer(prior_bounds["latest_time"]))
        else:
            window_end = int(self.clock()) // 3600 * 3600
            event_earliest = str(window_end - 3600)
            event_latest = str(window_end)
        status_rows = self._query(
            journal,
            contract["status_query"],
            None,
            None,
            label="v2 catalog status and expected rows",
            earliest_time=event_earliest,
            latest_time=event_latest,
            persist_result_rows=False,
        )
        status = [row for row in status_rows if row.get("adm_kind") == "status"]
        results = [row for row in status_rows if row.get("adm_kind") == "result"]
        if (
            len(status) != 1
            or _integer(status[0].get("adm_catalog_invalid")) != 0
            or any(
                row.get("adm_kind") not in {"status", "result"} for row in status_rows
            )
        ):
            raise Refused("v2 catalog build status is missing, invalid, or ambiguous")
        fields = contract["fields"]
        empty_key = contract["validation"].get("empty_snapshot_key")
        stable_fields = [field for field in fields if field != "updated"]

        numeric_fields = {
            "pods",
            "first_seen",
            "last_seen",
            "peers",
            "conversations_1h",
            "blocked_1h",
            "unknown_peers_1h",
            "window_start",
            "window_end",
        }
        count_fields = {
            "pods",
            "peers",
            "conversations_1h",
            "blocked_1h",
            "unknown_peers_1h",
        }

        def stable(rows):
            normalized = {}
            for key, value in rows.items():
                item = {}
                for field in stable_fields:
                    raw = value.get(field)
                    if field in numeric_fields and not (
                        key == empty_key and raw is None
                    ):
                        if isinstance(raw, bool) or not isinstance(
                            raw, (str, int, float)
                        ):
                            raise Refused("catalog numeric field is malformed")
                        try:
                            number = Decimal(str(raw))
                        except InvalidOperation:
                            raise Refused(
                                "catalog numeric field is malformed"
                            ) from None
                        if (
                            not number.is_finite()
                            or number < 0
                            or abs(number.as_tuple().exponent) > 128
                            or number.adjusted() > 128
                            or (
                                field in count_fields
                                and number != number.to_integral_value()
                            )
                        ):
                            raise Refused("catalog numeric field is malformed")
                        # Exact decimal comparison avoids rounding large counters.
                        raw = format(number, "f")
                        if "." in raw:
                            raw = raw.rstrip("0").rstrip(".")
                        if number == 0:
                            raw = "0"
                    item[field] = raw
                normalized[key] = item
            return normalized

        expected = {}
        for row in results:
            key = str(row.get("_key", ""))
            if not key or key in expected or any(field not in row for field in fields):
                raise Refused("v2 catalog builder returned invalid or duplicate rows")
            expected[key] = {field: row.get(field) for field in fields}
        expected_stable_fingerprint = fingerprint(stable(expected))
        legacy_expected_fingerprint = fingerprint(
            {
                key: {field: value.get(field) for field in stable_fields}
                for key, value in expected.items()
            }
        )
        prior_fingerprint = state.get("expected_fingerprint")
        if same_generation and prior_fingerprint not in (
            None,
            expected_stable_fingerprint,
            legacy_expected_fingerprint,
        ):
            # The catalog is a rewritable derived collection built from live
            # workload and identity state, so unchanged staged input with a new
            # output is a new build. Refuse only while the prior generation's
            # writer could still be running or its outcome is unknown; a job
            # with a recorded SID is settled here by reading it to completion.
            self._settle_prior_catalog_writer_jobs(journal, contract["writer_search"])
            state.setdefault("superseded_generations", []).append(
                {
                    "build_generation": state.get("build_generation"),
                    "expected_fingerprint": prior_fingerprint,
                }
            )
            same_generation = False
        if (
            same_generation
            and prior_fingerprint == legacy_expected_fingerprint
            and prior_fingerprint != expected_stable_fingerprint
        ):
            state["legacy_expected_fingerprint"] = prior_fingerprint
        state["numeric_canonicalizer"] = "exact-decimal-v1"
        skip_dispatch = same_generation and state.get("state") == "verified"
        build_generation = int(state.get("build_generation", 0)) + (
            0 if same_generation else 1
        )
        state.update(
            state="expected",
            input_fingerprint=input_fingerprint,
            build_generation=build_generation,
            expected_keys=sorted(expected),
            expected_fingerprint=expected_stable_fingerprint,
            status_fingerprint=fingerprint(status[0]),
            dispatch_bounds={
                "earliest_time": event_earliest,
                "latest_time": event_latest,
            },
        )
        self._write_journal(journal)

        if not skip_dispatch:
            self._dispatch_writer(
                journal,
                contract["writer_search"],
                {"earliest_time": event_earliest, "latest_time": event_latest},
                label=f"v2 application catalog generation {state['build_generation']}",
                intent_fingerprint=fingerprint(
                    {
                        "build_generation": build_generation,
                        "input_fingerprint": input_fingerprint,
                    }
                ),
            )
        read_rows = self._query(
            journal,
            contract["read_query"],
            None,
            None,
            label="v2 catalog complete readback query",
            earliest_time=event_earliest,
            latest_time=event_latest,
            persist_result_rows=False,
        )
        actual = {}
        for row in read_rows:
            key = str(row.get("_key", ""))
            is_empty_marker = key == empty_key
            if (
                not key
                or key in actual
                or (not is_empty_marker and any(field not in row for field in fields))
            ):
                raise Refused(
                    "v2 catalog read query has missing fields or duplicate keys"
                )
            actual[key] = {field: row.get(field) for field in fields}
        collection_rows = self._collection_rows(contract["collection"])
        collection = {}
        for row in collection_rows:
            key = str(row.get("_key", ""))
            is_empty_marker = key == empty_key
            if (
                not key
                or key in collection
                or (not is_empty_marker and any(field not in row for field in fields))
            ):
                raise Refused(
                    "v2 catalog collection has missing fields or duplicate keys"
                )
            collection[key] = {field: row.get(field) for field in fields}
        if stable(actual) != stable(collection):
            raise Refused("v2 catalog REST and complete query reads disagree")
        expected_collection_keys = {empty_key} if not expected else set(expected)
        if set(collection) != expected_collection_keys:
            raise Refused("v2 catalog collection contains missing or stale keys")
        if any(
            stable({key: collection.get(key, {})}).get(key)
            != stable({key: value}).get(key)
            for key, value in expected.items()
        ):
            raise Refused("v2 catalog collection does not contain every computed row")
        if not expected:
            marker = collection.get(empty_key, {})
            if (
                set(collection) != {empty_key}
                or _number(marker.get("updated")) is None
                or _number(marker.get("updated")) <= 0
            ):
                raise Refused(
                    "complete empty v2 catalog did not write its sole reserved marker"
                )
        elif empty_key in collection:
            raise Refused("non-empty v2 catalog contains the reserved empty marker")
        for row in collection.values():
            if _number(row.get("updated")) is None or _number(row.get("updated")) <= 0:
                raise Refused("v2 catalog row has no valid update timestamp")
        state.update(
            state="verified",
            verified_at=int(self.clock()),
            rows=len(expected),
            collection_rows=len(collection),
            actual_fingerprint=fingerprint(stable(actual)),
            complete_paged_read=True,
        )
        self._write_journal(journal)

    def _validate_history_coverage(self, journal, interface) -> dict[str, Any]:
        """Re-read source history and the full KV collection before cutover."""
        contract = interface["staged_collections"]["network_client_history"]
        expected_by_slice = {}
        combined = {}
        all_history_slices = [
            *journal["slices"],
            *((journal.get("cutover") or {}).get("history_bridge_slices") or []),
        ]
        for item in all_history_slices:
            start, end = item["start"], item["end"]
            history_state = item.get("history") or {}
            request_bounds = history_state.get("request_bounds")
            if request_bounds is None:
                request_bounds = {
                    "earliest_time": str(journal["event_earliest"]),
                    "latest_time": str(journal["event_latest"]),
                    "index_earliest": str(start),
                    "index_latest": str(end),
                }
            if (
                not isinstance(request_bounds, dict)
                or str(request_bounds.get("index_earliest")) != str(start)
                or str(request_bounds.get("index_latest")) != str(end)
                or not request_bounds.get("earliest_time")
                or not request_bounds.get("latest_time")
            ):
                raise Refused("history slice has invalid pinned source request bounds")
            event_bounds = {
                "earliest_time": str(request_bounds["earliest_time"]),
                "latest_time": str(request_bounds["latest_time"]),
            }
            expected = self._history_expected(
                journal, contract, start, end, event_bounds=event_bounds
            )
            for key, value in expected.items():
                previous = combined.get(key)
                if previous is None:
                    combined[key] = dict(value)
                else:
                    if previous["stable"] != value["stable"]:
                        raise Refused(
                            "history replay key conflicts across staged slices"
                        )
                    for receipt_field, reducer in (
                        ("received_min", min),
                        ("received_max", max),
                    ):
                        left, right = previous[receipt_field], value[receipt_field]
                        if left is None:
                            previous[receipt_field] = right
                        elif right is not None:
                            previous[receipt_field] = reducer(left, right)
            expected_by_slice[id(item)] = expected
        scheduled_history = (journal.get("cutover") or {}).get("scheduled_history", {})
        for cycle in scheduled_history.get("cycles", []):
            bounds = cycle.get("index_bounds") or []
            if len(bounds) != 2:
                raise Refused("scheduled history evidence has invalid index bounds")
            expected = self._history_expected(
                journal,
                contract,
                int(bounds[0]),
                int(bounds[1]),
                event_bounds=cycle["event_bounds"],
            )
            if fingerprint(expected) != cycle.get("expected_fingerprint"):
                raise Refused("scheduled history source changed after its audit")
            for key, value in expected.items():
                previous = combined.get(key)
                if previous is None:
                    combined[key] = dict(value)
                    continue
                if previous["stable"] != value["stable"]:
                    raise Refused(
                        "history replay key conflicts across scheduled windows"
                    )
                for receipt_field, reducer in (
                    ("received_min", min),
                    ("received_max", max),
                ):
                    left, right = previous[receipt_field], value[receipt_field]
                    if left is None:
                        previous[receipt_field] = right
                    elif right is not None:
                        previous[receipt_field] = reducer(left, right)
            cycle["final_validated_at"] = int(self.clock())
            cycle["final_rows"] = len(expected)
        if (
            scheduled_history.get("cycles")
            and _integer(scheduled_history.get("observation_epoch")) is None
        ):
            raise Refused("scheduled history audit boundary is not journaled")
        rows = self._collection_rows(contract["collection"])
        if "history_baseline" not in journal:
            raise Refused("immutable pre-migration history baseline is missing")
        actual = None
        for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
            actual = self._validate_history_rows(
                contract, combined, rows, journal["history_baseline"]
            )
            if actual is not None:
                break
            if attempt < SUMMARY_INDEX_WAIT_ATTEMPTS:
                self._wait_before_summary_retry(attempt)
                rows = self._collection_rows(contract["collection"])
        if actual is None:
            raise Refused(
                "final history collection has missing or unexpected source keys"
            )
        for item in all_history_slices:
            if id(item) not in expected_by_slice:
                continue
            expected = expected_by_slice[id(item)]
            stable_expected = {
                key: value["fingerprint"] for key, value in sorted(expected.items())
            }
            stable_actual = {
                key: fingerprint(
                    {
                        field: self._normalize_history_field(
                            field, actual[key].get(field)
                        )
                        for field in self._history_stable_fields(contract)
                    }
                )
                for key in sorted(expected)
            }
            if stable_actual != stable_expected:
                raise Refused(
                    "final history rows differ from their staged source evidence"
                )
            item["history"]["final_validation"] = {
                "validated_at": int(self.clock()),
                "rows": len(expected),
                "fingerprint": fingerprint(stable_actual),
            }
            item["history"]["actual_fingerprint"] = fingerprint(stable_actual)
        self._write_journal(journal)
        return {
            "keys": len(combined),
            "fingerprint": fingerprint(
                {key: value["fingerprint"] for key, value in sorted(combined.items())}
            ),
            "validated_at": int(self.clock()),
        }

    def validate(self, scenario: dict[str, Any] | None = None) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        interface, interface_hash = self._interface()
        self._assert_origin_unchanged(journal)
        incomplete = [
            (slice_record["start"], stream)
            for slice_record in journal["slices"]
            for stream, state in [
                *slice_record["streams"].items(),
                ("network_client_history", slice_record["history"]),
            ]
            if state.get("state") != "verified"
        ]
        if incomplete:
            raise Refused(
                "every conversation and traffic slice must validate before cutover"
            )
        validation_id = uuid.uuid4().hex
        self._verify_preexisting_index(journal, final_pass=True)
        for stream, spec in STREAMS.items():
            expected_all = {}
            for (source, rollup_id), value in self._preexisting_v2_map(journal).items():
                if source == spec["source"]:
                    expected_all = _add_record_maps(
                        expected_all,
                        {rollup_id: value},
                        label=f"final {stream} baseline",
                    )
            for slice_record in journal["slices"]:
                self._assert_origin_unchanged(journal)
                start, end = slice_record["start"], slice_record["end"]
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
                    label=f"final {stream} expected output {start} {validation_id}",
                )
                expected = self._record_map(expected_rows, stream)
                expected_all = _add_record_maps(
                    expected_all, expected, label=f"final {stream} source slices"
                )
            scheduled_state = (
                (journal.get("cutover") or {}).get("scheduled_streams") or {}
            ).get(stream) or {}
            for cycle in scheduled_state.get("cycles", []):
                if cycle.get("state") == "verified":
                    expected_all = _add_record_maps(
                        expected_all,
                        cycle.get("expected") or {},
                        label=f"final {stream} scheduled cycles",
                    )
            self._assert_origin_unchanged(journal)
            actual = self._poll_persisted_rows(
                journal,
                expected_all,
                stream,
                label=f"final {stream} staged records {validation_id}",
            )
            if expected_all != actual:
                raise Refused(
                    f"final {stream} staged coverage does not match source data"
                )
            for slice_record in journal["slices"]:
                slice_record["streams"][stream]["final_validation"] = {
                    "expected_fingerprint": fingerprint(expected_all),
                    "actual_fingerprint": fingerprint(actual),
                    "validated_at": int(self.clock()),
                }
        history_final = self._validate_history_coverage(journal, interface)
        scheduled_cycles = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        audit_upper = (
            self._scheduled_output_watermark(journal)
            if any(state.get("cycles") for state in scheduled_cycles.values())
            else None
        )
        journal["staged_ingestion_window"] = self._validate_migration_ingestion_window(
            journal, upper_bound=audit_upper
        )
        self._stage_catalog(journal)
        journal = self._load()
        journal["coverage"] = {
            stream: {
                "slices": len(journal["slices"]),
                "rows": sum(
                    item["streams"][stream].get("rows", 0) for item in journal["slices"]
                ),
                "event_records": sum(
                    item["streams"][stream].get("event_records", 0)
                    for item in journal["slices"]
                ),
                "from_index_time": journal["range"]["start"],
                "through_index_time": journal["range"]["end"],
            }
            for stream in STREAMS
        }
        journal["coverage"]["network_client_history"] = {
            "slices": len(journal["slices"]),
            "rows": sum(
                item["history"].get("row_count", 0) for item in journal["slices"]
            ),
            "fingerprint": fingerprint(
                [
                    item["history"].get("actual_fingerprint")
                    for item in journal["slices"]
                ]
            ),
            "final_validation": history_final,
        }
        journal["coverage"]["application_catalog_v2"] = {
            "rows": journal["catalog"].get("rows", 0),
            "collection_rows": journal["catalog"].get("collection_rows", 0),
            "fingerprint": journal["catalog"].get("actual_fingerprint"),
        }
        surfaces = []
        public_surface_error = None
        if scenario is not None:
            schema = interface.get("scenario_schema") or {}
            required_scenario = schema.get("required_fields")
            if not isinstance(required_scenario, list) or set(required_scenario) != set(
                scenario
            ):
                raise Refused(
                    "validation scenario fields do not match the authoritative schema"
                )
            surfaces = self._public_surface_evidence(journal, interface, scenario)
        else:
            public_surface_error = (
                "deployment-specific validation scenario was not supplied"
            )
        candidate = {
            "schema": 1,
            "migration_id": journal["migration_id"],
            "interface_sha256": interface_hash,
            "origin_fingerprint": journal["origin_fingerprint"],
            "coverage": journal["coverage"],
            "history": journal["coverage"]["network_client_history"],
            "catalog": journal["coverage"]["application_catalog_v2"],
            "slice_fingerprints": [
                {
                    "start": item["start"],
                    "end": item["end"],
                    "streams": {
                        name: item["streams"][name]["final_validation"]
                        for name in STREAMS
                    },
                }
                for item in journal["slices"]
            ],
            "scenario_sha256": fingerprint(scenario) if scenario is not None else None,
            "scenario": scenario,
            "public_surfaces": surfaces,
            "cutover_eligible": bool(surfaces) and scenario is not None,
            "reason": public_surface_error,
        }
        if len(canonical(candidate)) > MAX_CANDIDATE_BYTES:
            raise Refused(
                "validated candidate evidence exceeds its bound; validate a shorter range"
            )
        candidate_path = self.journal.path.with_suffix(".candidate.json")
        candidate_hash = self.journal.write_artifact(candidate_path, candidate)
        if journal.get("phase") != "cutover_in_progress":
            journal["phase"] = "coverage_validated"
        journal["candidate_sha256"] = candidate_hash
        journal["candidate_cutover_eligible"] = candidate["cutover_eligible"]
        self._write_journal(journal)
        return {
            "status": "coverage_validated",
            "coverage": journal["coverage"],
            "candidate_sha256": candidate_hash,
            "cutover_eligible": candidate["cutover_eligible"],
        }
