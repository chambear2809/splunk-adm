"""Migration responsibility methods for core."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import time
from typing import Any
from urllib.parse import quote
import uuid
from .common import (
    ADMIN_ROLES,
    APP,
    COLLECTION_PAGE_SIZE,
    INTERFACE_PATH,
    JOURNAL_SCHEMA,
    LIVE_BUILDER_COLLECTIONS,
    MACROS,
    MAX_COLLECTION_ROWS,
    MAX_RESULTS,
    MigrationError,
    REQUIRED_MACROS,
    REQUIRED_SEARCHES,
    Refused,
    SEARCHES,
    STREAMS,
    SUMMARY_CANONICALIZER_VERSION,
    V1_INDEX,
    V2_INDEX,
    VOLATILE_SAVED_SEARCH_FIELDS,
    _config_equal,
    _contract_marker,
    _integer,
    _macro_definition_equal,
    _strict_bool,
    _verify_created_directory,
    canonical,
    ensure_state_directory,
    fingerprint,
    plan_slices,
)
from .journal import Journal


class MigrationCore:
    def __init__(
        self,
        api,
        journal: Journal,
        *,
        clock=time.time,
        sleep=time.sleep,
        qualifier=None,
    ):
        self.api = api
        self.journal = journal
        self.clock = clock
        self.sleep = sleep
        self.qualifier = qualifier

    @contextmanager
    def operation_locked(self, *, lock_directory: Path | None = None):
        """Serialize one OS user's local controller by verified target GUID.

        This is an extra local guard, not a remote/distributed run fence. The
        operator still owns an exclusive lifecycle across other users/hosts.
        Acquire target before journal in every mutating CLI/harness path.
        """
        self.qualify()
        server = self._single_entry("/services/server/info").get("content") or {}
        guid = server.get("guid")
        if not isinstance(guid, str) or not guid.strip():
            raise Refused("target GUID is unavailable for local operation fencing")
        directory = lock_directory or Path.home() / ".splunk-adm/cisco-target-locks"
        ensure_state_directory(directory)
        _verify_created_directory(directory)
        identity = hashlib.sha256(canonical([guid, "splunk_adm"])).hexdigest()
        target = Journal(directory / (identity + ".operation"))
        with target.locked(blocking=False), self.journal.locked(blocking=False):
            yield

    def _request(self, method: str, path: str, data=None):
        try:
            return self.api.request(method, path, data=data, json_body=False)
        except Exception as exc:
            status = getattr(exc, "status", None)
            if isinstance(status, int) and 400 <= status < 500:
                raise Refused(
                    f"Splunk REST rejected the request (HTTP {status})"
                ) from None
            # Never propagate client exception text; it may contain server or auth details.
            raise MigrationError(
                f"Splunk REST request failed ({type(exc).__name__})"
            ) from None

    @staticmethod
    def _interface() -> tuple[dict[str, Any], str]:
        try:
            raw = INTERFACE_PATH.read_bytes()
            interface = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise Refused(
                "authoritative pipeline interface manifest is unavailable"
            ) from None
        if not isinstance(interface, dict) or interface.get("contract_version") != 1:
            raise Refused("pipeline interface manifest version is unsupported")
        activation = interface.get("activation", {})
        flow = interface.get("flow_v2", {})
        expected = {
            "default": "adm_data_contract_version=1",
            "summary_v1_index_macro": "adm_index_summary -> index=adm_summary",
            "summary_v1_writer_index_macro": "adm_summary_index_name -> adm_summary",
            "summary_v2_index_macro": "adm_index_summary_v2 -> index=adm_summary_v2",
            "summary_v2_writer_index_macro": "adm_summary_index_v2_name -> adm_summary_v2",
            "v1_reader": "adm_graph(4)",
            "v2_reader": "adm_graph_v2(4)",
        }
        if any(activation.get(key) != value for key, value in expected.items()):
            raise Refused(
                "pipeline interface manifest conflicts with the supported v1/v2 contract"
            )
        if flow.get("searches") != [item["saved_search"] for item in STREAMS.values()]:
            raise Refused(
                "pipeline interface manifest has unexpected staged writer names"
            )
        if (
            flow.get("conversation_rollup") != "adm_conversation_rollup_v2"
            or flow.get("traffic_observation_rollup") != "adm_traffic_observations_v2"
        ):
            raise Refused(
                "pipeline interface manifest has unexpected v2 writer definitions"
            )
        if (
            flow.get("records")
            != "Version-2 conversations retain the base v1 fields plus contract_version=2 and use rollup IDs with a v2 prefix. Stream flow records are kept in separate source=adm:traffic_observation records and excluded from conversation totals."
        ):
            raise Refused("pipeline interface manifest v2 record contract changed")
        activation_writers = activation.get("writer_contracts")
        if not isinstance(activation_writers, list):
            raise Refused("pipeline interface has no exact writer contract allowlist")
        writer_names = {
            item.get("name") for item in activation_writers if isinstance(item, dict)
        }
        if writer_names != set(REQUIRED_SEARCHES):
            raise Refused(
                "pipeline interface writer allowlist is incomplete or unexpected"
            )
        staged = interface.get("staged_collections")
        history = (staged or {}).get("network_client_history")
        catalog = (staged or {}).get("application_catalog_v2")
        if (
            not isinstance(history, dict)
            or history.get("collection") != "adm_network_client_history"
            or history.get("builder_search") != "ADM - Network client history builder"
            or history.get("builder_source_query")
            != "| `adm_network_client_history_build`"
            or not isinstance(history.get("expected_row_query"), str)
            or not isinstance(history.get("expected_row_fields"), list)
            or history.get("expected_row_fields") != history.get("fields")
            or set(history.get("validation", {}).get("allowed_mapping_statuses", []))
            != {"mapped", "unmapped", "ambiguous"}
            or not isinstance(catalog, dict)
            or catalog.get("collection") != "adm_app_catalog_v2"
            or catalog.get("writer_search") != "ADM - Application catalog v2"
            or catalog.get("writer_source_query") != "| `adm_catalog_writer_v2`"
            or catalog.get("status_query") != "| `adm_catalog_build_status_v2`"
            or catalog.get("read_query")
            != "| inputlookup strict=true adm_app_catalog_v2"
            or not isinstance(catalog.get("dispatch_bounds"), dict)
            or catalog["dispatch_bounds"].get("earliest_time") != "-1h@h"
            or catalog["dispatch_bounds"].get("latest_time") != "@h"
        ):
            raise Refused("staged history/catalog collection contract is incomplete")
        for item in activation_writers:
            if not isinstance(item, dict) or item.get("kind") != "saved_search":
                raise Refused(
                    "pipeline interface contains an unsupported writer target"
                )
            name = item["name"]
            expected_target = SEARCHES + quote(name, safe="")
            if item.get("rest_target") != expected_target:
                raise Refused(
                    "pipeline interface writer REST target is not allowlisted"
                )
            fields = item.get("fields")
            transition = item.get("state_transition")
            if (
                not isinstance(fields, dict)
                or not isinstance(fields.get("search"), str)
                or not isinstance(item.get("source_query"), str)
                or item.get("bounded_source_query_only") is not True
                or not isinstance(transition, dict)
            ):
                raise Refused("pipeline interface writer contract is incomplete")
            if name in {spec["saved_search"] for spec in STREAMS.values()}:
                stream = next(
                    key for key, spec in STREAMS.items() if spec["saved_search"] == name
                )
                suffix = f' | collect index=`adm_summary_index_v2_name` source="{STREAMS[stream]["source"]}"'
                if fields["search"] != item["source_query"].strip() + suffix:
                    raise Refused("pipeline interface staged writer SPL is not exact")
                if str(fields.get("disabled")) not in {"1", "true", "True"}:
                    raise Refused("pipeline interface staged writer must ship disabled")
            elif name == "ADM - Conversation rollup":
                suffix = ' | collect index=`adm_summary_index_name` source="adm:conversation"'
                if fields["search"] != item["source_query"].strip() + suffix:
                    raise Refused(
                        "pipeline interface legacy writer does not preserve the v1 index"
                    )
        selectors = activation.get("cutover_selectors")
        expected_selector_names = {
            "adm_data_contract_version",
            "adm_graph(4)",
            "adm_catalog_build",
            "adm_find(1)",
            "adm_health_sources",
            "adm_flow_evidence(4)",
            "adm_topology",
            "adm_health_quality",
        }
        if (
            not isinstance(selectors, list)
            or {item.get("name") for item in selectors if isinstance(item, dict)}
            != expected_selector_names
        ):
            raise Refused(
                "pipeline interface selector allowlist is incomplete or unexpected"
            )
        for selector in selectors:
            if (
                not isinstance(selector, dict)
                or selector.get("kind") != "macro_definition"
                or selector.get("field") != "definition"
                or selector.get("rest_target")
                != MACROS + quote(str(selector.get("name", "")), safe="()")
                or not isinstance(selector.get("before"), str)
                or not isinstance(selector.get("after"), str)
            ):
                raise Refused("pipeline interface selector target is not allowlisted")
        return interface, hashlib.sha256(raw).hexdigest()

    def _single_entry(self, path: str) -> dict[str, Any]:
        response = self._request("GET", path)
        entries = response.get("entry")
        if (
            not isinstance(entries, list)
            or len(entries) != 1
            or not isinstance(entries[0], dict)
        ):
            raise Refused("target configuration evidence is incomplete")
        return entries[0]

    @staticmethod
    def _stable_saved_search_content(content: dict[str, Any]) -> dict[str, Any]:
        """Drop REST runtime counters while retaining effective search settings."""
        return {
            key: value
            for key, value in content.items()
            if key not in VOLATILE_SAVED_SEARCH_FIELDS and not key.startswith("eai:")
        }

    @staticmethod
    def _normalize_saved_search_schedule(
        content: dict[str, Any], expected_fields: dict[str, Any]
    ) -> dict[str, Any]:
        """Canonicalize Splunk REST schedule aliases for one writer contract.

        Splunk may expose ``is_scheduled`` even when the saved-search
        configuration contract names the source field ``enableSched``. Keep
        the contract's spelling in snapshots, but only when the REST evidence
        is present and unambiguous.
        """
        schedule_fields = [
            field
            for field in ("enableSched", "is_scheduled")
            if field in expected_fields
        ]
        if len(schedule_fields) != 1:
            raise Refused("writer schedule contract is missing an exact schedule field")
        canonical_field = schedule_fields[0]
        alias_field = (
            "is_scheduled" if canonical_field == "enableSched" else "enableSched"
        )
        has_canonical = canonical_field in content
        has_alias = alias_field in content
        if not has_canonical and not has_alias:
            raise Refused("saved search schedule evidence is missing")
        if has_canonical and _strict_bool(content[canonical_field]) is None:
            raise Refused("saved search schedule evidence is invalid")
        if has_alias and _strict_bool(content[alias_field]) is None:
            raise Refused("saved search schedule alias evidence is invalid")
        if (
            has_canonical
            and has_alias
            and not _config_equal(
                canonical_field, content[canonical_field], content[alias_field]
            )
        ):
            raise Refused("saved search schedule aliases conflict")
        normalized = dict(content)
        if not has_canonical:
            normalized[canonical_field] = content[alias_field]
        normalized.pop(alias_field, None)
        return normalized

    def _entries(
        self, path: str, *, max_count: int = MAX_RESULTS
    ) -> list[dict[str, Any]]:
        response = self._request("GET", path)
        entries = response.get("entry")
        paging = response.get("paging") or {}
        total = _integer(paging.get("total"))
        if not isinstance(entries, list) or total is None or total != len(entries):
            raise Refused("target REST listing is incomplete")
        if total > max_count or any(not isinstance(row, dict) for row in entries):
            raise Refused("target REST listing exceeds the qualified bound")
        return entries

    def _collection_rows(self, name: str) -> list[dict[str, Any]]:
        base = APP + "/storage/collections/data/" + quote(name, safe="")
        records = []
        offset = 0
        while True:
            page = self._request(
                "GET",
                base + f"?limit={COLLECTION_PAGE_SIZE}&skip={offset}&sort=_key:1",
            )
            if not isinstance(page, list) or len(page) > COLLECTION_PAGE_SIZE:
                raise Refused(f"{name} paged read is malformed")
            records.extend(page)
            if len(records) > MAX_COLLECTION_ROWS:
                raise Refused(f"{name} collection exceeds the qualified row bound")
            if len(page) < COLLECTION_PAGE_SIZE:
                # A reduced server query cap can masquerade as a short final
                # page. Sorted overlap proves there is no extra hidden row.
                probe = self._request(
                    "GET",
                    base
                    + f"?limit={COLLECTION_PAGE_SIZE}&skip={offset + 1}&sort=_key:1",
                )
                if probe != page[1:]:
                    raise Refused(
                        f"{name} collection read is capped or changed during completion proof"
                    )
                break
            offset += len(page)
        return records

    def _collection_snapshot(self, name: str) -> dict[str, Any]:
        records = self._collection_rows(name)
        if any(not isinstance(row, dict) or not row.get("_key") for row in records):
            raise Refused(f"{name} snapshot contains malformed rows")
        records = sorted(records, key=lambda row: str(row["_key"]))
        if len({row["_key"] for row in records}) != len(records):
            raise Refused(f"{name} snapshot contains duplicate keys")
        return {
            "count": len(records),
            "sha256": fingerprint(records),
            "complete_paged_read": True,
        }

    def _live_collection_presence(self, name: str) -> dict[str, Any]:
        base = APP + "/storage/collections/data/" + quote(name, safe="")
        page = self._request("GET", base + "?limit=1")
        if (
            not isinstance(page, list)
            or len(page) > 1
            or any(not isinstance(row, dict) or not row.get("_key") for row in page)
        ):
            raise Refused(f"{name} collection read is malformed")
        return {"live_builder_collection": True, "readable": True}

    def _macro(self, name: str) -> dict[str, Any]:
        return self._single_entry(MACROS + quote(name, safe=""))

    def _saved_search(self, name: str) -> dict[str, Any]:
        return self._single_entry(SEARCHES + quote(name, safe=""))

    @staticmethod
    def _acl(entry: dict[str, Any]) -> dict[str, tuple[str, ...]]:
        perms = (entry.get("acl") or {}).get("perms") or {}
        result = {}
        for action in ("read", "write"):
            roles = perms.get(action)
            if not isinstance(roles, list) or not roles or set(roles) - ADMIN_ROLES:
                raise Refused("saved-search ACL is not administrator-only")
            result[action] = tuple(sorted(set(roles)))
        return result

    def qualify(self) -> None:
        try:
            # The packaged recovery qualifier fails closed on version, role,
            # Cloud, SHC, indexer-cluster and peer evidence.
            if self.qualifier:
                self.qualifier()
            else:
                from adm_recovery_lib.core import Recovery

                Recovery(self.api).qualify_deployment()
        except MigrationError:
            raise
        except Exception as exc:
            raise Refused(
                f"standalone deployment qualification failed ({type(exc).__name__})"
            ) from None

    def snapshot(self, *, allow_activation: bool = False) -> dict[str, Any]:
        interface, _ = self._interface()
        server = self._single_entry("/services/server/info").get("content") or {}
        if not server.get("guid") or not server.get("version"):
            raise Refused("target instance identity is incomplete")
        context = (
            self._single_entry("/services/authentication/current-context").get(
                "content"
            )
            or {}
        )
        if not set(context.get("roles", [])) & ADMIN_ROLES:
            raise Refused("administrator session is required")
        required_capabilities = {
            "search",
            "schedule_search",
            "run_collect",
            "output_file",
        }
        if not required_capabilities.issubset(set(context.get("capabilities", []))):
            raise Refused(
                "administrator session lacks required search/write capabilities"
            )
        macros = {}
        for name in REQUIRED_MACROS:
            entry = self._macro(name)
            content = entry.get("content") or {}
            args = content.get("args", "")
            self._macro_args_parts(name, args)
            macros[name] = {
                "definition": content.get("definition"),
                "args": args,
                "acl": entry.get("acl", {}),
            }
        all_macros = self._entries(
            APP + "/configs/conf-macros?count=10000", max_count=MAX_RESULTS
        )
        macro_inventory = [
            {
                "name": entry.get("name"),
                "content": entry.get("content") or {},
                "acl": entry.get("acl") or {},
            }
            for entry in all_macros
            if entry.get("name")
            not in {
                selector.get("name")
                for selector in interface["activation"]["cutover_selectors"]
            }
        ]
        macro_inventory.sort(key=lambda item: str(item.get("name", "")))
        all_transforms = self._entries(
            APP + "/configs/conf-transforms?count=10000", max_count=MAX_RESULTS
        )
        transform_inventory = [
            {
                "name": entry.get("name"),
                "content": entry.get("content") or {},
                "acl": entry.get("acl") or {},
            }
            for entry in all_transforms
        ]
        transform_inventory.sort(key=lambda item: str(item.get("name", "")))
        searches = {}
        for name in REQUIRED_SEARCHES:
            entry = self._saved_search(name)
            searches[name] = {
                "content": self._stable_saved_search_content(entry.get("content", {})),
                "acl": entry.get("acl", {}),
            }
            self._acl(entry)
        writer_contracts = {
            item["name"]: item for item in interface["activation"]["writer_contracts"]
        }
        for name, item in searches.items():
            searches[name]["content"] = self._normalize_saved_search_schedule(
                item["content"], writer_contracts[name]["fields"]
            )
        for writer in interface["activation"]["writer_contracts"]:
            actual = searches[writer["name"]]["content"]
            for field, expected in writer["fields"].items():
                if field == "disabled":
                    continue
                if not _config_equal(field, actual.get(field), expected):
                    raise Refused(
                        "writer schedule or definition differs from the shipped contract"
                    )
        v1_index = macros["adm_index_summary"]["definition"]
        v1_write = macros["adm_summary_index_name"]["definition"]
        v2_index = macros["adm_index_summary_v2"]["definition"]
        v2_write = macros["adm_summary_index_v2_name"]["definition"]
        if v1_index != f"index={V1_INDEX}" or v1_write != V1_INDEX:
            raise Refused("legacy summary reader/writer contract differs from v1")
        if v2_index != f"index={V2_INDEX}" or v2_write != V2_INDEX:
            raise Refused("staged summary reader/writer contract differs from v2")
        if V1_INDEX == V2_INDEX:
            raise Refused("v1 and v2 summary indexes must be distinct")
        active_version = _contract_marker(
            macros["adm_data_contract_version"]["definition"]
        )
        if active_version != "1" and not (allow_activation and active_version == "2"):
            raise Refused(
                "active data contract is not v1; inspect current cutover state"
            )
        selectors = {
            selector["name"]: selector
            for selector in interface["activation"]["cutover_selectors"]
        }
        for name, selector in selectors.items():
            current = macros[name]["definition"]
            if not _macro_definition_equal(current, selector["before"]) and not (
                allow_activation and _macro_definition_equal(current, selector["after"])
            ):
                raise Refused(
                    "a public selector differs from both journal origin and cutover target"
                )
        for key, spec in STREAMS.items():
            item = searches[spec["saved_search"]]
            content = item["content"]
            expected = writer_contracts[spec["saved_search"]]["fields"]
            mismatches = [
                field
                for field, value in expected.items()
                if field != "disabled"
                and not _config_equal(field, content.get(field), value)
            ]
            disabled = str(content.get("disabled", "")).lower()
            if disabled not in {"1", "true"} and not (
                allow_activation and disabled in {"0", "false"}
            ):
                mismatches.append("disabled")
            if mismatches:
                raise Refused(
                    f"{key} staged writer differs from the shipped v2 contract"
                )
            if content.get("dispatchAs") != "owner":
                raise Refused(f"{key} staged writer is not owner-dispatched")
            if str(content.get("disabled", "")).lower() not in {"1", "true"} and not (
                allow_activation
                and str(content.get("disabled", "")).lower() in {"0", "false"}
            ):
                raise Refused(f"{key} staged writer schedule must remain disabled")
        data_snapshots = {
            name: self._collection_snapshot(name)
            for name in (
                "adm_observer_scope",
                "adm_network_source_scope",
                "adm_cilium_cluster_settings",
            )
        }
        data_snapshots.update(
            {
                name: self._live_collection_presence(name)
                for name in LIVE_BUILDER_COLLECTIONS
            }
        )
        return {
            "target": {
                "guid": server["guid"],
                "version": server["version"],
                "app": "splunk_adm",
            },
            "principal": {
                "username": context.get("username"),
                "roles": sorted(set(context.get("roles", []))),
                "capabilities": sorted(required_capabilities),
            },
            "macros": macros,
            "macro_inventory": fingerprint(macro_inventory),
            "transform_inventory": fingerprint(transform_inventory),
            "effective_lookup_data": data_snapshots,
            "saved_searches": searches,
        }

    def prepare(self, start: int, end: int) -> dict[str, Any]:
        self.qualify()
        interface, interface_hash = self._interface()
        slices = plan_slices(start, end, int(self.clock()))
        snapshot = self.snapshot()
        journal = self.journal.read()
        if journal:
            if journal.get("origin_fingerprint") != fingerprint(snapshot):
                raise Refused("effective configuration differs from the journal origin")
            if journal.get("interface_sha256") != interface_hash:
                raise Refused("pipeline interface manifest changed after preparation")
            self._assert_canonicalizer_current(journal)
            if journal.get("range") != {"start": start, "end": end}:
                raise Refused("journal already belongs to a different backfill range")
            if "preexisting_v2_rows" not in journal:
                self._verify_preexisting_index(journal)
            return journal
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": uuid.uuid4().hex,
            "created_at": int(self.clock()),
            "interface_sha256": interface_hash,
            "interface_contract_version": interface.get("contract_version"),
            "phase": "prepared",
            "range": {"start": start, "end": end},
            # Absolute and durable so a resumed job has identical REST bounds.
            "event_earliest": "0",
            "event_latest": str(int(self.clock()) + 15 * 60),
            "origin": snapshot,
            "origin_fingerprint": fingerprint(snapshot),
            "slices": [
                {
                    **time_slice,
                    "streams": {name: {"state": "pending"} for name in STREAMS},
                    "history": {"state": "pending"},
                }
                for time_slice in slices
            ],
            # Keep only hashes and receipt extents for rows that existed
            # before this migration. The collection may contain a valid
            # baseline from an earlier attempt; it must survive every staged
            # replay without copying client fields into the journal.
            "history_baseline": self._history_baseline_snapshot(interface),
            "catalog": {"state": "pending"},
            "jobs": [],
            "cutover": None,
            "rollback": None,
        }
        self._write_journal(journal)
        self._verify_preexisting_index(journal)
        return journal
