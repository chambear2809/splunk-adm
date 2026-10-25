"""Migration responsibility methods for evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import quote
import uuid
from .common import (
    ALLOWED_PREDICATES,
    JOBS,
    MAX_RECOVERY_EVIDENCE_BYTES,
    MAX_RESULT_ARTIFACT_BYTES,
    MAX_RESULT_EVIDENCE_BYTES,
    MigrationError,
    REQUIRED_SURFACES,
    Refused,
    SEARCHES,
    STREAMS,
    SUMMARY_CANONICALIZER_VERSION,
    Uncertain,
    _config_equal,
    _job_active,
    _job_sid,
    _macro_definition_equal,
    _strict_bool,
    canonical,
    fingerprint,
)


class MigrationEvidence:
    def _result_artifact_path(self, journal, record) -> Path:
        identity = [journal.get("migration_id"), record.get("id")]
        if any(
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
            for value in identity
        ):
            raise Refused("result artifact identity is invalid")
        return self.journal.path.with_name(
            self.journal.path.name
            + ".result-"
            + ("recovery-" if record.get("recovery_evidence") else "")
            + fingerprint(identity)
            + ".json"
        )

    @staticmethod
    def _read_result_artifact_file(
        path: Path, limit: int = MAX_RESULT_ARTIFACT_BYTES
    ) -> bytes:
        try:
            fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_size > limit
                ):
                    raise Refused(
                        "result artifact ownership, permissions, type or size is invalid"
                    )
                payload = stream.read(limit + 1)
                if len(payload) != info.st_size or len(payload) > limit:
                    raise Refused("result artifact changed or exceeds its bound")
                return payload
        except OSError:
            raise Refused("result artifact is unavailable or unsafe") from None

    @staticmethod
    def _result_artifact_identity(journal, record):
        return {
            "schema": 1,
            "migration_id": journal.get("migration_id"),
            "job_id": record.get("id"),
            "kind": record.get("kind"),
            "label": record.get("label"),
            "query_fingerprint": record.get("query_fingerprint"),
            "request_bounds": record.get("request_bounds"),
            "result_count": record.get("result_count"),
        }

    def _persist_result_artifact(self, journal, record):
        rows = record["result_rows"]
        if not isinstance(rows, list) or len(rows) != record.get("result_count"):
            raise Refused("cached result count does not match the job")
        path = self._result_artifact_path(journal, record)
        value = {**self._result_artifact_identity(journal, record), "rows": rows}
        payload = canonical(value)
        if len(payload) > MAX_RESULT_ARTIFACT_BYTES:
            raise Refused("result artifact exceeds the 16 MiB limit")
        prefix = self.journal.path.name + ".result-"
        recovery_prefix = prefix + "recovery-"
        recovery = bool(record.get("recovery_evidence"))
        limit = MAX_RECOVERY_EVIDENCE_BYTES if recovery else MAX_RESULT_EVIDENCE_BYTES
        total = 0
        for candidate in path.parent.iterdir():
            if candidate.name.startswith(prefix) and candidate.name.endswith(".json"):
                info = candidate.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_size > MAX_RESULT_ARTIFACT_BYTES
                ):
                    raise Refused("existing result evidence is unsafe")
                if candidate.name.startswith(recovery_prefix) == recovery:
                    total += info.st_size
        if path.exists() or path.is_symlink():
            if self._read_result_artifact_file(path) != payload:
                raise Refused("immutable result artifact differs from this job")
        else:
            if total + len(payload) > limit:
                raise Refused("result evidence exceeds the 256 MiB budget")
            try:
                self.journal.write_artifact(path, value)
            except (OSError, Refused) as error:
                raise Refused(
                    f"result evidence could not be persisted ({error}); "
                    "resume the recorded SID"
                ) from error
        if total > limit:
            raise Refused("existing result evidence exceeds the 256 MiB budget")
        record["result_artifact"] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
        del record["result_rows"]

    def _cached_result_rows(self, journal, record):
        reference = record.get("result_artifact")
        if reference is not None:
            if not isinstance(reference, dict):
                raise Refused("result artifact reference is malformed")
            payload = self._read_result_artifact_file(
                self._result_artifact_path(journal, record)
            )
            if len(payload) != reference.get("bytes") or hashlib.sha256(
                payload
            ).hexdigest() != reference.get("sha256"):
                raise Refused("result artifact digest or size differs from the journal")
            try:
                value = json.loads(payload)
            except (UnicodeError, json.JSONDecodeError):
                raise Refused("result artifact is corrupt") from None
            identity = self._result_artifact_identity(journal, record)
            if not isinstance(value, dict) or any(
                value.get(key) != expected for key, expected in identity.items()
            ):
                raise Refused("result artifact belongs to another job or query")
            rows = value.get("rows")
            if not isinstance(rows, list) or len(rows) != record.get("result_count"):
                raise Refused("result artifact row count differs from the job")
            return rows
        rows = record.get("result_rows")
        return rows if isinstance(rows, list) else None

    def _write_journal(self, journal: dict[str, Any]) -> None:
        # Prepared migration journals externalize complete query evidence before
        # the atomic journal replacement. Probe-only journals retain the original
        # inline format; they have no migration identity or durable recovery claim.
        if journal.get("migration_id"):
            for record in journal.get("jobs", []):
                if (
                    record.get("kind") in {"search", "saved_search"}
                    and record.get("state") == "complete"
                    and "result_rows" in record
                ):
                    self._persist_result_artifact(journal, record)
        journal["updated_at"] = int(self.clock())
        self.journal.write(journal)

    def _assert_origin_unchanged(self, journal: dict[str, Any]) -> None:
        for execution in reversed(journal.get("temporary_manual_executions", [])):
            if execution.get("state") != "restored":
                self._recover_temporary_manual_writer(journal, execution["name"])
        if journal.get("phase") in {"cutover_in_progress", "rollback_in_progress"}:
            self._assert_cutover_origin_compatible(journal)
            return
        if fingerprint(self.snapshot()) != journal.get("origin_fingerprint"):
            raise Refused("effective pipeline, mappings, or target changed")
        self._assert_no_competing_staged_jobs(journal)

    def _assert_no_competing_staged_jobs(self, journal: dict[str, Any]) -> None:
        entries = self._entries(JOBS + "?count=0")
        known_sids = {
            job.get("sid") for job in journal.get("jobs", []) if job.get("sid")
        }
        writer_names = {spec["saved_search"] for spec in STREAMS.values()}
        writer_names.update(
            {
                "ADM - Network client history builder",
                "ADM - Application catalog v2",
            }
        )
        writer_macros = {spec["macro"] for spec in STREAMS.values()}
        writer_macros.update(
            {"adm_network_client_history_build", "adm_catalog_writer_v2"}
        )
        for entry in entries:
            content = entry.get("content") or {}
            search = str(content.get("search", ""))
            label = content.get("label") or content.get("savedsearch_name")
            if (
                label in writer_names
                or any(f"`{macro}`" in search for macro in writer_macros)
                or re.search(
                    r"(?i)\bcollect\s+index\s*=\s*(?:`?adm_summary_index_v2_name`?|adm_summary_v2)\b",
                    search,
                )
            ) and _job_active(content):
                sid = _job_sid(entry)
                if sid not in known_sids:
                    raise Refused("a competing staged v2 writer job is active")

    @staticmethod
    def _scenario_query(surface: dict[str, Any], scenario: dict[str, Any]) -> str:
        invoke = surface.get("invoke")
        if not isinstance(invoke, str) or not invoke.strip():
            raise Refused("public-surface manifest has no executable query")
        query = invoke
        fields = set(re.findall(r"\{\{([a-z][a-z0-9_]*)\}\}", query))
        for field in fields:
            if (
                field not in scenario
                or not isinstance(scenario[field], str)
                or not scenario[field]
            ):
                raise Refused(f"validation scenario is missing {field}")
            if field == "server_port":
                if (
                    not re.fullmatch(r"[0-9]{1,5}", scenario[field])
                    or not 1 <= int(scenario[field]) <= 65535
                ):
                    raise Refused(
                        "validation scenario server_port must be a TCP/UDP port"
                    )
            elif not re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,128}", scenario[field]):
                raise Refused(
                    f"validation scenario {field} contains unsafe macro characters"
                )
            query = query.replace(
                "{{" + field + "}}", json.dumps(scenario[field])[1:-1]
            )
        if "{{" in query or "}}" in query:
            raise Refused("public-surface query contains an unresolved scenario value")
        if surface.get("read_only") is not True or not query.lstrip().startswith("|"):
            raise Refused(
                "public-surface query is not an allowlisted read-only macro call"
            )
        if "|" in query[1:] or ";" in query or "\n" in query or "\r" in query:
            raise Refused(
                "public-surface query contains commands outside its exact macro invocation"
            )
        return query

    @staticmethod
    def _validate_surface_predicates(
        rows: list[dict[str, Any]], surface: dict[str, Any], scenario: dict[str, Any]
    ) -> None:
        required = surface.get("required_fields")
        predicates = surface.get("predicates")
        if (
            not isinstance(required, list)
            or not required
            or any(not isinstance(field, str) or not field for field in required)
            or not isinstance(predicates, list)
        ):
            raise Refused("public-surface result contract is malformed")
        by_type = surface.get("required_fields_by_row_type")
        if by_type is not None and (
            not isinstance(by_type, dict)
            or not by_type
            or any(
                not isinstance(kind, str)
                or not kind
                or not isinstance(fields, list)
                or any(not isinstance(field, str) or not field for field in fields)
                for kind, fields in by_type.items()
            )
        ):
            raise Refused("public-surface row-type contract is malformed")
        for row in rows:
            if by_type is not None and row.get("row_type") not in by_type:
                raise Refused("public-surface row type is outside its contract")
            fields = required + (
                by_type[row["row_type"]] if by_type is not None else []
            )
            missing = [field for field in fields if field not in row]
            if missing:
                raise Refused(
                    "public-surface result is missing required fields: "
                    + ", ".join(missing)
                )
        for predicate in predicates:
            if not isinstance(predicate, dict):
                raise Refused("public-surface predicate is malformed")
            field = predicate.get("field")
            operator = predicate.get("operator")
            value = predicate.get("value")
            if (
                isinstance(value, str)
                and value.startswith("{{")
                and value.endswith("}}")
            ):
                scenario_key = value[2:-2]
                if scenario_key not in scenario:
                    raise Refused(f"validation scenario is missing {scenario_key}")
                value = scenario[scenario_key]
            if not isinstance(field, str) or operator not in ALLOWED_PREDICATES:
                raise Refused("public-surface predicate uses an unsupported rule")
            values = [row.get(field) for row in rows if field in row]
            if operator in {"contains", "contains_all"}:
                expected = value if isinstance(value, list) else [value]
                if not all(
                    any(str(item) in str(actual) for actual in values)
                    for item in expected
                ):
                    raise Refused("public-surface content predicate failed")
            elif operator == "allowed_values":
                allowed = {str(item) for item in value}
                if any(str(actual) not in allowed for actual in values):
                    raise Refused("public-surface value is outside its allowlist")
            elif operator == "equals":
                if not values or any(str(actual) != str(value) for actual in values):
                    raise Refused("public-surface equality predicate failed")
            elif operator == "equals_or_missing":
                if any(str(actual) != str(value) for actual in values):
                    raise Refused("public-surface version predicate failed")
            elif operator in {"not_null", "is_not_null"}:
                if not values or any(actual in (None, "", "null") for actual in values):
                    raise Refused("public-surface non-null predicate failed")
            elif operator == "distinct_from":
                if not rows or any(
                    str(row.get(field, "")) == str(row.get(value, "")) for row in rows
                ):
                    raise Refused("public-surface distinct-field predicate failed")
            elif operator == "traffic_observation_contract":
                for actual in values:
                    if actual in (None, ""):
                        continue
                    try:
                        observations = (
                            json.loads(actual) if isinstance(actual, str) else actual
                        )
                    except (TypeError, json.JSONDecodeError):
                        raise Refused("traffic evidence is not valid JSON") from None
                    if not isinstance(observations, list) or not observations:
                        raise Refused(
                            "traffic evidence must be a nonempty object array"
                        )
                    for observation in observations:
                        if not isinstance(observation, dict):
                            raise Refused(
                                "traffic evidence contains a non-object record"
                            )
                        status = observation.get("mapping_status")
                        if status not in {"mapped", "unmapped", "ambiguous"}:
                            raise Refused("traffic evidence mapping status is invalid")
                        if status == "mapped" and any(
                            observation.get(key) in (None, "")
                            for key in (
                                "source",
                                "source_authority",
                                "scope",
                                "cluster",
                                "domain_kind",
                            )
                        ):
                            raise Refused(
                                "mapped traffic evidence lacks qualified identity"
                            )
                        if status != "mapped" and any(
                            observation.get(key) not in (None, "", "null")
                            for key in ("scope", "cluster")
                        ):
                            raise Refused("unresolved traffic evidence carries a scope")
                        if "routing_domain" not in observation:
                            raise Refused(
                                "traffic evidence lost routing-domain context"
                            )
                        if (
                            observation.get("counter_semantics") != "unknown"
                            or str(observation.get("metrics_authoritative")) != "0"
                        ):
                            raise Refused(
                                "traffic counter semantics differ from the qualified unknown/0 contract"
                            )
            elif operator == "flat_json_array_if_present":
                for actual in values:
                    if actual in (None, ""):
                        continue
                    try:
                        decoded = (
                            json.loads(actual) if isinstance(actual, str) else actual
                        )
                    except (TypeError, json.JSONDecodeError):
                        raise Refused(
                            "public-surface JSON array predicate failed"
                        ) from None
                    if not isinstance(decoded, list) or any(
                        isinstance(item, (list, dict)) for item in decoded
                    ):
                        raise Refused("public-surface JSON array predicate failed")
            elif operator == "must_exist_in_node_ids":
                node_ids = {
                    str(row.get("id")) for row in rows if row.get("row_type") == "node"
                }
                targets = [
                    str(row.get("target"))
                    for row in rows
                    if row.get("context_edge_target")
                ]
                if any(target not in node_ids for target in targets):
                    raise Refused("public-surface graph reference predicate failed")
            elif operator == "unique_for_source_authority_native":
                entities = [
                    row
                    for row in rows
                    if row.get("endpoint_kind") == "network_client"
                    or row.get("row_type") == "device"
                ]
                identities = []
                ids = []
                for row in entities:
                    source = row.get("attr_source") or row.get("source")
                    authority = row.get("attr_source_authority") or row.get(
                        "source_authority"
                    )
                    native = row.get("attr_native_id") or row.get("native_id")
                    entity_id = (
                        row.get("node_id") or row.get("id") or row.get("device_id")
                    )
                    if not all(
                        isinstance(part, str) and part.strip()
                        for part in (source, authority, native, entity_id)
                    ):
                        raise Refused("public-surface identity is not source-qualified")
                    identities.append((source, authority, native))
                    ids.append(entity_id)
                if len(identities) != len(set(identities)) or len(ids) != len(set(ids)):
                    raise Refused("public-surface source identity is not unique")
            elif operator == "null_when_mapping_unmapped_or_ambiguous":
                ambiguous = {"unmapped", "ambiguous", "ambiguous_or_unmapped"}
                if any(
                    str(row.get("mapping_status", "")).lower() in ambiguous
                    and row.get(field) not in (None, "", "null")
                    for row in rows
                ):
                    raise Refused("public-surface unmapped observation carries a scope")
            elif operator == "source_qualified_before_aggregation":
                devices = [row for row in rows if row.get("row_type") == "device"]
                if not devices:
                    raise Refused("topology has no device evidence")
                identities = []
                device_ids = []
                for row in devices:
                    if not all(
                        isinstance(row.get(key), str) and row[key].strip()
                        for key in ("device_id", "device_authority")
                    ):
                        raise Refused("topology device authority or ID is missing")
                    device_ids.append(row["device_id"])
                    native = row.get("native_device_id")
                    if row.get("mapping_status") == "incomplete_identity":
                        if native not in (None, "", "null") or any(
                            row.get(key) not in (None, "", "null")
                            for key in ("scope", "cluster")
                        ):
                            raise Refused(
                                "incomplete topology device claims a native or scoped identity"
                            )
                    elif not isinstance(native, str) or not native.strip():
                        raise Refused("topology device native identity is missing")
                    else:
                        identities.append((row["device_authority"], native))
                if len(identities) != len(set(identities)) or len(device_ids) != len(
                    set(device_ids)
                ):
                    raise Refused("topology source-qualified device IDs are not unique")
            elif operator == "must_resolve_to_device_ids":
                device_ids = {
                    str(row.get("device_id"))
                    for row in rows
                    if row.get("row_type") == "device" and row.get("device_id")
                }
                links = [row for row in rows if row.get("row_type") == "link"]
                if any(
                    not row.get("a_device")
                    or not row.get("b_device")
                    or str(row.get("a_device")) not in device_ids
                    or str(row.get("b_device")) not in device_ids
                    for row in links
                ):
                    raise Refused("topology link endpoint does not resolve to a device")
            elif operator == "legacy_explicit_physical_links":
                if value != ["aci", "lldp", "cdp"]:
                    raise Refused("legacy topology link contract is unsupported")
                if any(
                    row.get("link_source") not in value
                    or not row.get("a_device")
                    or not row.get("b_device")
                    or row.get("a_device") == row.get("b_device")
                    for row in rows
                    if row.get("row_type") == "link"
                ):
                    raise Refused("legacy topology link lacks explicit source evidence")
            elif operator == "only_explicit_physical_links":
                links = [row for row in rows if row.get("row_type") == "link"]
                allowed_kinds = {"physical", "wireless_association"}
                if any(
                    row.get("link_kind") not in allowed_kinds
                    or not isinstance(row.get("link_source"), str)
                    or not row.get("link_source")
                    or not (
                        (row.get("a_device") and row.get("b_device"))
                        or (row.get("physical_adjacency") in (1, "1", True))
                    )
                    for row in links
                ):
                    raise Refused("topology contains an unsupported inferred link")
            elif operator == "topology_mapping_scope_consistency":
                expected_contract = {
                    "device_allowed_statuses": [
                        "mapped",
                        "unmapped",
                        "ambiguous",
                        "incomplete_identity",
                    ],
                    "mapped_device_requires_one_scope_and_cluster": True,
                    "unmapped_or_ambiguous_device_requires_null_scope_and_cluster": True,
                    "link_requires_mapping_status": "mapped",
                    "link_requires_existing_device_endpoints": True,
                }
                if value != expected_contract:
                    raise Refused("topology mapping predicate contract is unknown")
                for row in rows:
                    status = str(row.get("mapping_status", "")).lower()
                    if row.get("row_type") == "device":
                        if status not in {
                            "mapped",
                            "unmapped",
                            "ambiguous",
                            "incomplete_identity",
                        }:
                            raise Refused("topology device mapping state is invalid")
                        if status == "mapped" and not all(
                            isinstance(row.get(key), str) and row[key].strip()
                            for key in ("scope", "cluster")
                        ):
                            raise Refused("mapped topology device lacks scope/cluster")
                        if status != "mapped" and (
                            row.get("scope") not in (None, "", "null")
                            or row.get("cluster") not in (None, "", "null")
                        ):
                            raise Refused(
                                "unmapped topology device carries scope/cluster"
                            )
                    elif row.get("row_type") == "link" and status != "mapped":
                        raise Refused(
                            "topology link is not mapped to an explicit scope"
                        )
            elif operator == "required_for_kubernetes_nodes":
                if any(
                    str(row.get("device_kind", row.get("kind", ""))).lower()
                    in {"kubernetes_node", "k8s_node", "node"}
                    and not row.get(field)
                    for row in rows
                ):
                    raise Refused("Kubernetes topology node is missing its cluster")
            elif operator == "exactly_one_mapped_row_for_cross_domain_join":
                # Current pipeline manifest does not use this rule. Its contract
                # requires an explicit join key, so refuse ambiguous definitions.
                key = predicate.get("key_field")
                if not isinstance(key, str) or not key:
                    raise Refused("cross-domain join predicate has no key field")
                grouped: dict[str, list[dict[str, Any]]] = {}
                for row in rows:
                    if row.get(key) not in (None, ""):
                        grouped.setdefault(str(row[key]), []).append(row)
                if any(
                    sum(row.get("mapping_status") == "mapped" for row in group) != 1
                    for group in grouped.values()
                ):
                    raise Refused("cross-domain join did not resolve exactly once")
            else:
                # Structural semantics need a dedicated rule implementation; do not
                # claim a smoke test based on a rule this version cannot evaluate.
                raise Refused(f"public-surface predicate {operator} is not implemented")

    def _public_surface_evidence(
        self,
        journal: dict[str, Any],
        interface: dict[str, Any],
        scenario: dict[str, Any],
    ) -> list[dict[str, Any]]:
        surfaces = interface.get("public_surfaces")
        if not isinstance(surfaces, list):
            raise Refused("authoritative public-surface manifest is incomplete")
        by_name = {
            item.get("surface"): item for item in surfaces if isinstance(item, dict)
        }
        if set(by_name) != REQUIRED_SURFACES | {"writers"}:
            raise Refused(
                "public-surface manifest is incomplete or has unknown entries"
            )
        for name in REQUIRED_SURFACES:
            versions = by_name[name].get("v2") or {}
            if (
                not isinstance(versions, dict)
                or versions.get("status", "ready") != "ready"
                or not isinstance(versions.get("invoke"), str)
                or not versions.get("invoke")
                or not isinstance(versions.get("definition"), str)
                or not isinstance(versions.get("definition_sha256"), str)
            ):
                raise Refused(f"{name} v2 surface is blocked or incomplete")
        evidence = []
        for name in sorted(REQUIRED_SURFACES):
            item = by_name[name]
            versions = item.get("v2")
            if (
                not isinstance(versions, dict)
                or versions.get("status", "ready") != "ready"
            ):
                raise Refused(f"{name} v2 surface is blocked or incomplete")
            macro_name = versions.get("macro")
            expected_definition = versions.get("definition")
            expected_hash = versions.get("definition_sha256")
            if not isinstance(macro_name, str) or not isinstance(
                expected_definition, str
            ):
                raise Refused(f"{name} has no exact allowlisted v2 macro definition")
            if (
                hashlib.sha256(expected_definition.encode()).hexdigest()
                != expected_hash
            ):
                raise Refused(f"{name} v2 macro definition hash is invalid")
            live_definition = (self._macro(macro_name).get("content") or {}).get(
                "definition"
            )
            if not _macro_definition_equal(live_definition, expected_definition):
                raise Refused(
                    f"{name} v2 macro definition differs from the shipped interface"
                )
            query = self._scenario_query(versions, scenario)
            rows = self._query(
                journal, query, None, None, label=f"public surface smoke {name}"
            )
            self._validate_surface_predicates(rows, versions, scenario)
            evidence.append(
                {
                    "surface": name,
                    "query_sha256": fingerprint(query),
                    "row_count": len(rows),
                    "rows_sha256": fingerprint(rows),
                    "validated_at": int(self.clock()),
                }
            )
            if name == "evidence_drilldown":
                traffic = item.get("traffic_v2")
                if not isinstance(traffic, dict):
                    raise Refused("traffic evidence surface is missing")
                definition = traffic.get("definition")
                macro = traffic.get("macro")
                if (
                    not isinstance(definition, str)
                    or not isinstance(macro, str)
                    or hashlib.sha256(definition.encode()).hexdigest()
                    != traffic.get("definition_sha256")
                    or not _macro_definition_equal(
                        (self._macro(macro).get("content") or {}).get("definition"),
                        definition,
                    )
                ):
                    raise Refused("traffic evidence macro differs from its contract")
                traffic_query = self._scenario_query(traffic, scenario)
                traffic_rows = self._query(
                    journal,
                    traffic_query,
                    None,
                    None,
                    label="public surface smoke traffic evidence",
                )
                self._validate_surface_predicates(traffic_rows, traffic, scenario)
                evidence.append(
                    {
                        "surface": "traffic_evidence",
                        "query_sha256": fingerprint(traffic_query),
                        "row_count": len(traffic_rows),
                        "rows_sha256": fingerprint(traffic_rows),
                        "validated_at": int(self.clock()),
                    }
                )
            if name == "find":
                client_surface = item.get("network_client_v2")
                if not isinstance(client_surface, dict):
                    raise Refused("Find network-client history surface is missing")
                client_query = self._scenario_query(client_surface, scenario)
                client_rows = self._query(
                    journal,
                    client_query,
                    None,
                    None,
                    label="public surface smoke network client history",
                )
                self._validate_surface_predicates(client_rows, client_surface, scenario)
                evidence.append(
                    {
                        "surface": "network_client_history",
                        "query_sha256": fingerprint(client_query),
                        "row_count": len(client_rows),
                        "rows_sha256": fingerprint(client_rows),
                        "validated_at": int(self.clock()),
                    }
                )
        return evidence

    def _public_selector_smoke(
        self,
        journal: dict[str, Any],
        interface: dict[str, Any],
        scenario: dict[str, Any],
        *,
        phase: str,
    ) -> list[dict[str, Any]]:
        """Exercise the public macro entrypoints after selector mutation/restoration."""
        if phase not in {"public_after_invoke", "rollback_before_invoke"}:
            raise Refused("unsupported public selector smoke phase")
        surfaces = interface.get("public_surfaces")
        if not isinstance(surfaces, list):
            raise Refused("authoritative public-surface manifest is incomplete")
        evidence = []
        for item in surfaces:
            if not isinstance(item, dict) or item.get("surface") == "writers":
                continue
            for version_name in ("v2", "network_client_v2", "traffic_v2"):
                version = item.get(version_name)
                if not isinstance(version, dict):
                    continue
                invoke = version.get(phase)
                if not isinstance(invoke, str) or not invoke:
                    if version_name in {"network_client_v2", "traffic_v2"}:
                        invoke = version.get("invoke")
                    if not isinstance(invoke, str) or not invoke:
                        if version_name == "network_client_v2":
                            continue
                        raise Refused(
                            f"{item.get('surface')} has no {phase} public query"
                        )
                contract = version
                if phase == "rollback_before_invoke" and version_name not in {
                    "network_client_v2",
                    "traffic_v2",
                }:
                    contract = item.get("v1")
                    if not isinstance(contract, dict):
                        raise Refused(
                            f"{item.get('surface')} has no V1 rollback result contract"
                        )
                query_contract = {**contract, "invoke": invoke}
                query = self._scenario_query(query_contract, scenario)
                rows = self._query(
                    journal,
                    query,
                    None,
                    None,
                    label=f"{phase} selector smoke {item.get('surface')}:{version_name}",
                )
                self._validate_surface_predicates(rows, contract, scenario)
                evidence.append(
                    {
                        "surface": item.get("surface"),
                        "version": version_name,
                        "phase": phase,
                        "query_sha256": fingerprint(query),
                        "row_count": len(rows),
                        "rows_sha256": fingerprint(rows),
                        "validated_at": int(self.clock()),
                    }
                )
        required = {item for item in REQUIRED_SURFACES}
        observed = {item["surface"] for item in evidence}
        if observed != required:
            raise Refused("public selector smoke did not cover every required surface")
        return evidence

    def _load(self) -> dict[str, Any]:
        journal = self.journal.read()
        if not journal:
            raise Refused("migration journal does not exist; run prepare first")
        _, current_interface_hash = self._interface()
        if journal.get("interface_sha256") != current_interface_hash:
            raise Refused("pipeline interface manifest changed after preparation")
        self._assert_canonicalizer_current(journal)
        return journal

    @staticmethod
    def _assert_canonicalizer_current(journal: dict[str, Any]) -> None:
        # Digests recorded under another canonicalizer cannot be compared; fail
        # here instead of surfacing as misleading "content changed" refusals.
        recorded = journal.get("canonicalizer_version", 1)
        if recorded != SUMMARY_CANONICALIZER_VERSION:
            raise Refused(
                f"journal was written with summary canonicalizer version {recorded} "
                f"but this helper uses version {SUMMARY_CANONICALIZER_VERSION}; "
                "finish or roll it back with the helper that created it"
            )

    def _save_job(self, journal, job):
        journal.setdefault("jobs", []).append(job)
        self._write_journal(journal)

    @staticmethod
    def _evidence_class(journal) -> dict[str, Any]:
        if journal.get("phase") == "rollback_in_progress":
            return {"recovery_evidence": True}
        return {}

    def _manual_writer_entry(self, name: str) -> dict[str, Any]:
        return self._saved_search(name)

    def _manual_writer_check(self, execution: dict[str, Any]) -> dict[str, Any]:
        """Check the complete saved-search definition and ACL around a temporary run."""
        entry = self._manual_writer_entry(execution["name"])
        content = entry.get("content") or {}
        stable = self._stable_saved_search_content(content)
        for field in ("disabled", "enableSched", "is_scheduled"):
            stable.pop(field, None)
        if fingerprint(stable) != execution["search_fingerprint"]:
            raise Refused("saved-search definition drifted during temporary execution")
        acl = entry.get("acl") or (content.get("eai:acl") or {})
        if fingerprint(acl) != execution["acl_fingerprint"]:
            raise Refused("saved-search ACL drifted during temporary execution")
        return content

    @staticmethod
    def _manual_field_value(content: dict[str, Any], field: str) -> Any:
        if field == "is_scheduled":
            return content.get("is_scheduled", content.get("enableSched"))
        return content.get(field)

    def _manual_writer_field(
        self,
        journal: dict[str, Any],
        execution: dict[str, Any],
        field: str,
        value: Any,
        *,
        allowed_current: set[str],
    ) -> None:
        """Durably mutate and read back one temporary saved-search field."""
        content = self._manual_writer_check(execution)
        current = self._manual_field_value(content, field)
        pending_key = "pending_" + field
        prior_state = execution.get(pending_key)
        if prior_state in {"request_pending", "request_unknown"}:
            prior_target = execution.get("requested_" + field)
            prior_before = execution.get("before_" + field)
            if _config_equal(field, current, prior_target):
                execution[pending_key] = "applied"
                execution["observed_" + field] = current
                self._write_journal(journal)
            elif _config_equal(field, current, prior_before):
                execution[pending_key] = "request_unknown"
                self._write_journal(journal)
                raise Uncertain(
                    "temporary writer configuration outcome remains ambiguous"
                )
            else:
                raise Refused(
                    "temporary writer field drifted from both journaled states"
                )
        if _config_equal(field, current, value):
            execution["observed_" + field] = current
            self._write_journal(journal)
            return
        if not any(
            _config_equal(field, current, allowed) for allowed in allowed_current
        ):
            raise Refused("temporary writer field is outside the journaled transition")
        execution[pending_key] = "request_pending"
        execution["before_" + field] = current
        execution["requested_" + field] = value
        self._write_journal(journal)
        try:
            self._request(
                "POST",
                SEARCHES + quote(execution["name"], safe=""),
                {field: value},
            )
        except Refused:
            observed = self._manual_field_value(
                self._manual_writer_check(execution), field
            )
            if not _config_equal(field, observed, value):
                execution[pending_key] = "rejected"
                self._write_journal(journal)
                raise
        except MigrationError:
            observed = self._manual_field_value(
                self._manual_writer_check(execution), field
            )
            if not _config_equal(field, observed, value):
                execution[pending_key] = "request_unknown"
                self._write_journal(journal)
                raise Uncertain(
                    "temporary writer configuration outcome is unknown"
                ) from None
        observed = self._manual_field_value(self._manual_writer_check(execution), field)
        if not _config_equal(field, observed, value):
            execution[pending_key] = "readback_failed"
            self._write_journal(journal)
            raise Refused("temporary writer configuration readback failed")
        execution[pending_key] = "applied"
        execution["observed_" + field] = observed
        self._write_journal(journal)

    def _restore_manual_writer(
        self, journal: dict[str, Any], execution: dict[str, Any]
    ) -> None:
        # Disable first so the scheduler can never see an enabled writer.
        content = self._manual_writer_check(execution)
        schedule_value = self._manual_field_value(content, "is_scheduled")
        disabled_value = self._manual_field_value(content, "disabled")
        schedule_safe = _config_equal("is_scheduled", schedule_value, "0") or (
            _strict_bool(disabled_value) is True
            and _config_equal(
                "is_scheduled", schedule_value, execution["original_schedule"]
            )
        )
        if not schedule_safe:
            raise Refused("temporary writer must be unscheduled until disabled")
        self._manual_writer_field(
            journal,
            execution,
            "disabled",
            execution["original_disabled"],
            allowed_current={"0", execution["original_disabled"]},
        )
        content = self._manual_writer_check(execution)
        if _strict_bool(self._manual_field_value(content, "disabled")) is not True:
            raise Refused(
                "writer disablement did not read back before schedule restoration"
            )
        self._manual_writer_field(
            journal,
            execution,
            "is_scheduled",
            execution["original_schedule"],
            allowed_current={"0", execution["original_schedule"]},
        )
        execution["state"] = "restored"
        execution["restored_at"] = int(self.clock())
        self._write_journal(journal)

    def _recover_temporary_manual_writer(
        self, journal: dict[str, Any], name: str
    ) -> None:
        """Restore interrupted temporary config before snapshot guards run."""
        for execution in reversed(journal.get("temporary_manual_executions", [])):
            if execution.get("name") != name or execution.get("state") == "restored":
                continue
            self._restore_manual_writer(journal, execution)
            job = next(
                (
                    item
                    for item in journal.get("jobs", [])
                    if item.get("id") == execution.get("job_id")
                ),
                None,
            )
            if job and job.get("state") == "configuration_pending":
                job["state"] = "preparation_aborted"
                job["preparation_aborted_at"] = int(self.clock())
                self._write_journal(journal)
            elif job and job.get("state") in {"dispatch_pending", "dispatch_unknown"}:
                raise Uncertain(
                    "interrupted writer operation was restored; reconcile dispatch before retry"
                )

    def _temporary_manual_writer(
        self,
        journal: dict[str, Any],
        name: str,
        bounds: dict[str, str],
        job: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Prepare one disabled writer for a single manual dispatch, or resume safely.

        Returns None for already-authorized cutover writers. Disabled writers get
        a durable intent before either configuration field is changed.
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
        content = self._normalize_saved_search_schedule(
            (self._saved_search(name).get("content") or {}), writer["fields"]
        )
        disabled = _strict_bool(content.get("disabled"))
        if disabled is False and self._writer_enabled_by_journal(journal, name):
            return None
        if disabled is not True:
            raise Refused("writer must be disabled or enabled by journaled cutover")
        contract_schedule_field = next(
            field
            for field in ("enableSched", "is_scheduled")
            if field in writer["fields"]
        )
        schedule_field = "is_scheduled"
        entry = self._saved_search(name)
        acl = entry.get("acl") or {}
        stable = self._stable_saved_search_content(content)
        for field in ("disabled", "enableSched", "is_scheduled"):
            stable.pop(field, None)
        executions = journal.setdefault("temporary_manual_executions", [])
        linked = next(
            (item for item in reversed(executions) if item.get("job_id") == job["id"]),
            None,
        )
        if linked and linked.get("state") != "restored":
            # Pending means the POST may already have reached Splunk. Restore
            # configuration, but never send the same operation again.
            self._restore_manual_writer(journal, linked)
            if job.get("state") in {
                "configuration_pending",
                "dispatch_pending",
                "dispatch_unknown",
            }:
                raise Uncertain(
                    "writer dispatch remains ambiguous after safe configuration restore"
                )
            return linked
        if linked and job.get("state") in {
            "dispatch_pending",
            "dispatch_unknown",
            "running",
        }:
            return linked
        execution = {
            "id": uuid.uuid4().hex,
            "job_id": job["id"],
            "operation_id": uuid.uuid4().hex,
            "name": name,
            "request_bounds": dict(bounds),
            "state": "configuration_preparing",
            "original_disabled": content["disabled"],
            "original_schedule": content[contract_schedule_field],
            "schedule_field": schedule_field,
            "acl": acl,
            "acl_fingerprint": fingerprint(acl),
            "search_fingerprint": fingerprint(stable),
            "created_at": int(self.clock()),
        }
        executions.append(execution)
        self._write_journal(journal)
        # Ordered to avoid an enabled-and-scheduled intermediate state.
        self._manual_writer_field(
            journal,
            execution,
            schedule_field,
            "0",
            allowed_current={execution["original_schedule"]},
        )
        content = self._manual_writer_check(execution)
        if (
            not _config_equal(
                "is_scheduled", self._manual_field_value(content, "is_scheduled"), "0"
            )
            or _strict_bool(self._manual_field_value(content, "disabled")) is not True
        ):
            raise Refused(
                "writer must be disabled and unscheduled before manual enablement"
            )
        self._manual_writer_field(
            journal,
            execution,
            "disabled",
            "0",
            allowed_current={execution["original_disabled"]},
        )
        execution["state"] = "configuration_prepared"
        execution["prepared_at"] = int(self.clock())
        content = self._manual_writer_check(execution)
        if _strict_bool(
            self._manual_field_value(content, "disabled")
        ) is not False or not _config_equal(
            "is_scheduled", self._manual_field_value(content, "is_scheduled"), "0"
        ):
            raise Refused("temporary writer did not reach the exact manual-only state")
        self._write_journal(journal)
        return execution
