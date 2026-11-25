"""Pure deterministic history derivation from immutable collection receipts."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .contracts import (
    MAX_COMPARISON_SECONDS,
    MAX_COLLECTIONS,
    MAX_INPUT_BYTES,
    MAX_OBJECTS,
    MAX_RECORD_BYTES,
    ContractError,
    canonical_json,
    normalize_collection,
    sha256_hex,
)
from .projections import projection_definition
from .relationships import (
    RelationshipError,
    administrator_relationship_collections,
)

ALGORITHM_VERSION = "configuration-history-v1"
CANONICALIZATION = "bounded-decimal-json-v1"
ROW_ORDER = "record_id-asc-v1"
ROW_HASH_EXCLUDES = ["generation_id"]
RECORD_ID_EXCLUDES = {"record_id", "generation_id"}
PARTITION_FIELDS = ("product", "authority", "family", "partition", "scope")
MAX_GENERATION_ROWS = 10_000


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _receipt_hash(collection: dict[str, Any]) -> str:
    return sha256_hex(collection)


def _stream_key(collection: dict[str, Any]) -> tuple[str, ...]:
    return tuple(collection[field] for field in PARTITION_FIELDS)


def _capture_key(collection: dict[str, Any]) -> tuple[str, ...]:
    return (*_stream_key(collection), collection["capture_id"])


def _receipt_sort_key(collection: dict[str, Any]) -> tuple[Any, ...]:
    return (
        collection["started_at"],
        collection["completed_at"]
        if collection["completed_at"] is not None
        else float("inf"),
        collection["capture_id"],
        _receipt_hash(collection),
    )


def _capture_reference(collection: dict[str, Any]) -> list[str]:
    references = [f"capture:{collection['capture_id']}"]
    if collection["source_reference"] is not None:
        references.append(collection["source_reference"])
    return sorted(set(references))


def _row_record_id(row_body: dict[str, Any]) -> str:
    payload = {
        key: value for key, value in row_body.items() if key not in RECORD_ID_EXCLUDES
    }
    return sha256_hex(payload)


def row_record_id(row_body: dict[str, Any]) -> str:
    """Return the plain lowercase SHA-256 identity of a generation row body."""

    return _row_record_id(row_body)


def _make_row(row_body: dict[str, Any]) -> dict[str, Any]:
    row = dict(row_body)
    row["record_id"] = _row_record_id(row_body)
    if len(canonical_json(row)) > MAX_RECORD_BYTES:
        _fail("row_size_limit", "A generated row exceeds the 64 KiB limit.")
    return row


def _common_row(
    collection: dict[str, Any],
    *,
    record_type: str,
    change_type: str,
    object_observation: dict[str, Any] | None = None,
    earliest_at: int | float | None = None,
    latest_at: int | float | None = None,
    source_refs: list[str] | None = None,
    coverage_complete: bool,
    gap: bool,
    qualification: str,
    field_diffs: list[dict[str, Any]] | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    obj = object_observation or {}
    definition = projection_definition(collection["product"], collection["family"])
    if record_type == "observation":
        time_qualification = (
            "source_event_time_reported"
            if obj.get("event_at") is not None
            else "unknown_source_time"
        )
        clock_uncertainty_unknown = True
    elif record_type == "change":
        time_qualification = "snapshot_interval"
        clock_uncertainty_unknown = False
    elif record_type == "baseline":
        time_qualification = "collection_interval"
        clock_uncertainty_unknown = False
    else:
        time_qualification = "coverage_interval"
        clock_uncertainty_unknown = False
    return {
        "schema_version": 1,
        "record_type": record_type,
        "change_type": change_type,
        "product": collection["product"],
        "authority": collection["authority"],
        "source_version": collection["source_version"],
        "family": collection["family"],
        "partition": collection["partition"],
        "scope": collection["scope"],
        "permissions_fingerprint": collection["permissions_fingerprint"],
        "object_id": obj.get("object_id"),
        "revision": obj.get("revision"),
        "kind": obj.get("kind"),
        "actor": obj.get("actor"),
        "event_at": obj.get("event_at"),
        "effective_at": obj.get("effective_at"),
        "observed_at": obj.get("observed_at"),
        "received_at": collection["received_at"],
        "earliest_at": earliest_at,
        "latest_at": latest_at,
        "source_refs": source_refs
        if source_refs is not None
        else _capture_reference(collection),
        "field_diffs": field_diffs if field_diffs is not None else [],
        "attributes": attributes if attributes is not None else {},
        "coverage_complete": coverage_complete,
        "gap": gap,
        "qualification": qualification,
        "time_qualification": time_qualification,
        "clock_uncertainty_unknown": clock_uncertainty_unknown,
        "projection_qualification": (
            definition.qualification if definition is not None else "unsupported"
        ),
        "native_sample_unqualified": (
            definition.native_sample_unqualified if definition is not None else True
        ),
        "context_only": definition.context_only if definition is not None else True,
    }


def _coverage_row(
    collection: dict[str, Any],
    change_type: str,
    *,
    qualification: str,
    gap: bool = True,
    earliest_at: int | float | None = None,
    latest_at: int | float | None = None,
) -> dict[str, Any]:
    return _make_row(
        _common_row(
            collection,
            record_type="coverage",
            change_type=change_type,
            earliest_at=collection["started_at"]
            if earliest_at is None
            else earliest_at,
            latest_at=collection["completed_at"] if latest_at is None else latest_at,
            coverage_complete=collection["status"] == "complete",
            gap=gap,
            qualification=qualification,
        )
    )


def _baseline_row(collection: dict[str, Any], reason: str) -> dict[str, Any]:
    return _make_row(
        _common_row(
            collection,
            record_type="baseline",
            change_type="baseline" if reason == "initial" else "baseline_after_gap",
            earliest_at=collection["started_at"],
            latest_at=collection["completed_at"],
            coverage_complete=True,
            gap=reason != "initial",
            qualification=f"complete_baseline:{reason}",
        )
    )


def _semantic_fields(obj: dict[str, Any]) -> dict[str, Any]:
    return obj["fields"]


def _field_diffs(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for field in sorted(set(before) | set(after)):
        before_present = field in before
        after_present = field in after
        before_value = before.get(field)
        after_value = after.get(field)
        if before_present == after_present and canonical_json(
            before_value
        ) == canonical_json(after_value):
            continue
        differences.append(
            {
                "field": field,
                "before": before_value,
                "after": after_value,
                "before_present": before_present,
                "after_present": after_present,
            }
        )
    return differences


def _change_row(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    change_type: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    earliest_at: int | float,
    latest_at: int | float,
    qualification: str,
) -> dict[str, Any]:
    obj = after or before or {}
    if before is not None and after is not None:
        diffs = _field_diffs(_semantic_fields(before), _semantic_fields(after))
    elif after is not None:
        diffs = _field_diffs({}, _semantic_fields(after))
    else:
        diffs = _field_diffs(_semantic_fields(before or {}), {})
    return _make_row(
        _common_row(
            current,
            record_type="change",
            change_type=change_type,
            object_observation=obj,
            earliest_at=earliest_at,
            latest_at=latest_at,
            source_refs=sorted(
                set(_capture_reference(previous) + _capture_reference(current))
            ),
            coverage_complete=True,
            gap=False,
            qualification=qualification,
            field_diffs=diffs,
        )
    )


def _is_complete_state(collection: dict[str, Any]) -> bool:
    return collection["status"] == "complete" and collection["completed_at"] is not None


def _is_snapshot_observation(
    collection: dict[str, Any], observation: dict[str, Any]
) -> bool:
    definition = projection_definition(collection["product"], collection["family"])
    return observation["kind"] == "configuration" or (
        observation["kind"] == "operational"
        and definition is not None
        and definition.operational_snapshot
    )


def _snapshot_state(collection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        obj["object_id"]: obj
        for obj in collection["objects"]
        if _is_snapshot_observation(collection, obj)
    }


def _compare_snapshots(
    previous: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    previous_state = _snapshot_state(previous)
    current_state = _snapshot_state(current)
    earliest = previous["started_at"]
    latest = current["completed_at"]
    if latest is None:
        return []

    rows: list[dict[str, Any]] = []
    definition = projection_definition(current["product"], current["family"])
    operational_snapshot = definition is not None and definition.operational_snapshot
    can_infer_additions = previous["enumeration"] == "full" and not operational_snapshot
    can_infer_removals = (
        previous["enumeration"] == "full"
        and current["enumeration"] == "full"
        and previous["deletions_authoritative"]
        and current["deletions_authoritative"]
        and not operational_snapshot
    )
    for object_id in sorted(set(previous_state) & set(current_state)):
        before = previous_state[object_id]
        after = current_state[object_id]
        if canonical_json(_semantic_fields(before)) == canonical_json(
            _semantic_fields(after)
        ):
            continue
        rows.append(
            _change_row(
                previous,
                current,
                change_type="modified",
                before=before,
                after=after,
                earliest_at=earliest,
                latest_at=latest,
                qualification="snapshot_interval",
            )
        )
    if can_infer_additions:
        for object_id in sorted(set(current_state) - set(previous_state)):
            rows.append(
                _change_row(
                    previous,
                    current,
                    change_type="added",
                    before=None,
                    after=current_state[object_id],
                    earliest_at=earliest,
                    latest_at=latest,
                    qualification="complete_enumeration_interval",
                )
            )
    if can_infer_removals:
        for object_id in sorted(set(previous_state) - set(current_state)):
            rows.append(
                _change_row(
                    previous,
                    current,
                    change_type="removed",
                    before=previous_state[object_id],
                    after=None,
                    earliest_at=earliest,
                    latest_at=latest,
                    qualification="authoritative_full_enumeration_interval",
                )
            )
    return rows


def _receipt_record(collection: dict[str, Any], receipt_hash: str) -> dict[str, Any]:
    result = {key: value for key, value in collection.items() if key != "objects"}
    definition = projection_definition(collection["product"], collection["family"])
    result.update(
        {
            "record_type": "receipt",
            "receipt_hash": receipt_hash,
            "object_count": len(collection["objects"]),
            "projection_qualification": (
                definition.qualification if definition is not None else "unsupported"
            ),
            "native_sample_unqualified": (
                definition.native_sample_unqualified if definition is not None else True
            ),
            "context_only": definition.context_only if definition is not None else True,
        }
    )
    result["evidence_id"] = sha256_hex(result)
    if len(canonical_json(result)) > MAX_RECORD_BYTES:
        _fail("row_size_limit", "A receipt evidence row exceeds the 64 KiB limit.")
    return result


def _object_record(
    collection: dict[str, Any], receipt_hash: str, observation: dict[str, Any]
) -> dict[str, Any]:
    definition = projection_definition(collection["product"], collection["family"])
    result = {
        "schema_version": 1,
        "record_type": "object_observation",
        "receipt_hash": receipt_hash,
        "capture_id": collection["capture_id"],
        "product": collection["product"],
        "authority": collection["authority"],
        "source_version": collection["source_version"],
        "family": collection["family"],
        "partition": collection["partition"],
        "scope": collection["scope"],
        "permissions_fingerprint": collection["permissions_fingerprint"],
        "source_reference": collection["source_reference"],
        **observation,
        "attributes": observation["fields"],
        "projection_qualification": (
            definition.qualification if definition is not None else "unsupported"
        ),
        "native_sample_unqualified": (
            definition.native_sample_unqualified if definition is not None else True
        ),
        "context_only": definition.context_only if definition is not None else True,
    }
    del result["fields"]
    result["evidence_id"] = sha256_hex(result)
    if len(canonical_json(result)) > MAX_RECORD_BYTES:
        _fail("row_size_limit", "An object evidence row exceeds the 64 KiB limit.")
    return result


def _event_signature(observation: dict[str, Any]) -> bytes:
    return canonical_json(
        {
            "kind": observation["kind"],
            "revision": observation["revision"],
            "actor": observation["actor"],
            "event_at": observation["event_at"],
            "effective_at": observation["effective_at"],
            "fields": observation["fields"],
        }
    )


def _observation_row(
    collection: dict[str, Any], observation: dict[str, Any]
) -> dict[str, Any]:
    return _make_row(
        _common_row(
            collection,
            record_type="observation",
            change_type="observation",
            object_observation=observation,
            earliest_at=None,
            latest_at=None,
            coverage_complete=collection["status"] == "complete",
            gap=collection["status"] != "complete",
            qualification="native_observation",
            attributes=observation["fields"],
        )
    )


def _derive_partition_rows(collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    last_permissions: str | None = None
    last_source_version: str | None = None
    max_prior_end: int | float | None = None
    reset_reason = "initial"

    for collection in collections:
        definition = projection_definition(collection["product"], collection["family"])
        supports_snapshot_history = definition is not None and (
            "configuration" in definition.allowed_kinds
            or definition.operational_snapshot
        )
        permissions = collection["permissions_fingerprint"]
        permission_changed = (
            last_permissions is not None and permissions != last_permissions
        )
        permission_unknown = permissions is None
        if permission_changed:
            rows.append(
                _coverage_row(
                    collection,
                    "permissions_changed",
                    qualification="permission_attestation_reset",
                )
            )
            previous = None
            reset_reason = "permissions_changed"
        elif permission_unknown:
            previous = None
            reset_reason = "permissions_unknown"

        if (
            last_source_version is not None
            and collection["source_version"] != last_source_version
        ):
            rows.append(
                _coverage_row(
                    collection,
                    "source_version_changed",
                    qualification="source_version_reset",
                )
            )
            previous = None
            reset_reason = "source_version_changed"

        if not supports_snapshot_history:
            if collection["status"] != "complete":
                change_type = (
                    "partial_collection"
                    if collection["status"] == "partial"
                    else "failed_collection"
                )
                rows.append(
                    _coverage_row(
                        collection,
                        change_type,
                        qualification="incomplete_collection",
                    )
                )
            last_permissions = permissions
            last_source_version = collection["source_version"]
            continue

        if collection["status"] != "complete":
            change_type = (
                "partial_collection"
                if collection["status"] == "partial"
                else "failed_collection"
            )
            rows.append(
                _coverage_row(
                    collection,
                    change_type,
                    qualification="incomplete_collection",
                )
            )
            previous = None
            reset_reason = "incomplete_collection"
            if collection["completed_at"] is not None:
                max_prior_end = max(
                    max_prior_end
                    if max_prior_end is not None
                    else collection["completed_at"],
                    collection["completed_at"],
                )
            last_permissions = permissions
            last_source_version = collection["source_version"]
            continue

        if max_prior_end is not None and collection["started_at"] < max_prior_end:
            rows.append(
                _coverage_row(
                    collection,
                    "overlapping_collection",
                    qualification="overlapping_collection_reset",
                )
            )
            previous = None
            reset_reason = "overlap"

        if previous is not None:
            width = collection["completed_at"] - previous["started_at"]
            if width > MAX_COMPARISON_SECONDS:
                rows.append(
                    _coverage_row(
                        collection,
                        "comparison_gap",
                        qualification="comparison_gap_exceeded",
                        earliest_at=previous["started_at"],
                        latest_at=collection["completed_at"],
                    )
                )
                previous = None
                reset_reason = "comparison_gap"

        if previous is None:
            rows.append(_baseline_row(collection, reset_reason))
        else:
            rows.extend(_compare_snapshots(previous, collection))

        previous = collection
        max_prior_end = max(
            max_prior_end if max_prior_end is not None else collection["completed_at"],
            collection["completed_at"],
        )
        last_permissions = permissions
        last_source_version = collection["source_version"]
    return rows


def _derive_observation_rows(collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    partial_snapshot_rows: list[dict[str, Any]] = []
    occurrences: dict[
        tuple[tuple[str, ...], str, str, str | None],
        list[tuple[dict[str, Any], dict[str, Any]]],
    ] = {}
    signatures: dict[tuple[tuple[str, ...], str, str, str | None], bytes] = {}
    for collection in collections:
        for observation in collection["objects"]:
            if _is_snapshot_observation(collection, observation):
                if (
                    observation["kind"] == "operational"
                    and collection["status"] != "complete"
                ):
                    # Retain the received partial fact with its gap. It is not
                    # a native revision/event or a baseline for comparison.
                    partial_snapshot_rows.append(
                        _observation_row(collection, observation)
                    )
                continue
            key = (
                _stream_key(collection),
                observation["kind"],
                observation["object_id"],
                observation["revision"],
            )
            signature = _event_signature(observation)
            previous_signature = signatures.get(key)
            if previous_signature is not None and previous_signature != signature:
                _fail(
                    "conflicting_native_revision",
                    "Conflicting content uses the same native revision.",
                )
            signatures[key] = signature
            occurrences.setdefault(key, []).append((collection, observation))
    rows: list[dict[str, Any]] = partial_snapshot_rows
    for key in sorted(
        occurrences, key=lambda item: (item[0], item[1], item[2], item[3] or "")
    ):
        candidates = occurrences[key]
        collection, observation = min(
            candidates,
            key=lambda item: (
                item[0]["started_at"],
                item[0]["capture_id"],
                _receipt_hash(item[0]),
            ),
        )
        rows.append(_observation_row(collection, observation))
    return rows


def _dedupe_collections(
    collections: Iterable[dict[str, Any]],
    *,
    administrator_ingress: bool = False,
    allow_empty: bool = False,
) -> tuple[list[dict[str, Any]], dict[tuple[str, ...], str]]:
    by_capture: dict[tuple[str, ...], tuple[str, dict[str, Any]]] = {}
    input_count = 0
    object_count = 0
    input_bytes = 0
    for raw in collections:
        input_count += 1
        if input_count > MAX_COLLECTIONS:
            _fail("collection_limit", "Input exceeds the 10,000-collection limit.")
        collection = normalize_collection(
            raw, _administrator_ingress=administrator_ingress
        )
        object_count += len(collection["objects"])
        input_bytes += len(canonical_json(collection))
        if object_count > MAX_OBJECTS:
            _fail("object_limit", "Input exceeds the 10,000-object limit.")
        if input_bytes > MAX_INPUT_BYTES:
            _fail("input_limit", "Normalized input exceeds the 50 MiB limit.")
        receipt_hash = _receipt_hash(collection)
        capture_key = _capture_key(collection)
        previous = by_capture.get(capture_key)
        if previous is not None:
            if previous[0] != receipt_hash:
                _fail(
                    "conflicting_capture",
                    "A capture_id has conflicting receipt content.",
                )
            continue
        by_capture[capture_key] = (receipt_hash, collection)
    if not by_capture and not allow_empty:
        _fail("empty_history", "At least one collection receipt is required.")

    revision_content: dict[tuple[tuple[str, ...], str, str], bytes] = {}
    for receipt_hash, collection in by_capture.values():
        for observation in collection["objects"]:
            if (
                not _is_snapshot_observation(collection, observation)
                or observation["revision"] is None
            ):
                continue
            key = (
                _stream_key(collection),
                observation["object_id"],
                observation["revision"],
            )
            content = canonical_json(
                {
                    "kind": observation["kind"],
                    "actor": observation["actor"],
                    "event_at": observation["event_at"],
                    "effective_at": observation["effective_at"],
                    "fields": observation["fields"],
                }
            )
            previous = revision_content.get(key)
            if previous is not None and previous != content:
                _fail(
                    "conflicting_native_revision",
                    "Conflicting content uses the same native revision.",
                )
            revision_content[key] = content

    result = [collection for _, collection in by_capture.values()]
    result.sort(key=_receipt_sort_key)
    hashes = {
        _capture_key(collection): receipt_hash
        for receipt_hash, collection in by_capture.values()
    }
    return result, hashes


def _evidence_records(
    collections: list[dict[str, Any]], receipt_hashes: dict[tuple[str, ...], str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    receipts: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for collection in collections:
        receipt_hash = receipt_hashes[_capture_key(collection)]
        receipts.append(_receipt_record(collection, receipt_hash))
        for observation in collection["objects"]:
            observations.append(_object_record(collection, receipt_hash, observation))
    observations.sort(
        key=lambda row: (
            row["capture_id"],
            row["object_id"],
            row["revision"] or "",
            row["evidence_id"],
        )
    )
    return receipts, observations


def _manifest_body(
    rows: list[dict[str, Any]], receipt_hashes: dict[tuple[str, ...], str]
) -> dict[str, Any]:
    row_hashes = [
        canonical_json(
            {key: value for key, value in row.items() if key != "generation_id"}
        )
        for row in rows
    ]
    row_hash = sha256_hex(b"\n".join(row_hashes))
    source_times = [
        row["latest_at"]
        if row["latest_at"] is not None
        else row["event_at"]
        if row["event_at"] is not None
        else row["observed_at"]
        if row["observed_at"] is not None
        else row["received_at"]
        for row in rows
    ]
    return {
        "schema_version": 1,
        "record_type": "generation_manifest",
        "algorithm_version": ALGORITHM_VERSION,
        "canonicalization": CANONICALIZATION,
        "row_order": ROW_ORDER,
        "record_id_hash_excludes": ["record_id", "generation_id"],
        "row_hash_excludes": ROW_HASH_EXCLUDES,
        "source_receipt_hashes": sorted(set(receipt_hashes.values())),
        "row_count": len(rows),
        "rows_sha256": row_hash,
        "source_earliest": min(source_times) if source_times else None,
        "source_latest": max(source_times) if source_times else None,
    }


def build_generation(
    collections: Iterable[dict[str, Any]],
    *,
    administrator_relationships: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build immutable evidence and one deterministic derived generation.

    This function performs no I/O. Duplicate captures with identical content are
    idempotent; conflicting capture IDs or native revisions fail closed. The
    reserved Atlas relationship family can only be supplied through the explicit
    trusted keyword-only ``administrator_relationships`` input. This local code
    path preserves admin attestations; it does not cryptographically authenticate
    the issuer or qualify production administration.
    """

    normalized_sources, source_receipt_hashes = _dedupe_collections(
        collections, allow_empty=True
    )
    try:
        admin_input = administrator_relationship_collections(
            administrator_relationships
        )
    except RelationshipError as exc:
        _fail(exc.code, str(exc))
    normalized_admin, admin_receipt_hashes = _dedupe_collections(
        admin_input,
        administrator_ingress=True,
        allow_empty=True,
    )
    normalized = normalized_sources + normalized_admin
    if not normalized:
        _fail("empty_history", "At least one collection receipt is required.")
    if len(normalized) > MAX_COLLECTIONS:
        _fail("collection_limit", "Input exceeds the 10,000-collection limit.")
    if sum(len(collection["objects"]) for collection in normalized) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if (
        sum(len(canonical_json(collection)) for collection in normalized)
        > MAX_INPUT_BYTES
    ):
        _fail("input_limit", "Normalized input exceeds the 50 MiB limit.")
    receipt_hashes = {**source_receipt_hashes, **admin_receipt_hashes}
    normalized.sort(key=_receipt_sort_key)
    by_stream: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for collection in normalized:
        by_stream.setdefault(_stream_key(collection), []).append(collection)

    rows: list[dict[str, Any]] = []
    for stream_key in sorted(by_stream):
        stream = sorted(by_stream[stream_key], key=_receipt_sort_key)
        rows.extend(_derive_partition_rows(stream))
    rows.extend(_derive_observation_rows(normalized))
    rows.sort(key=lambda row: row["record_id"])
    # Content-identical rows can arise from exact duplicate native events in
    # separate source partitions. Keep one immutable timeline row.
    unique_rows: dict[str, dict[str, Any]] = {}
    for row in rows:
        existing = unique_rows.get(row["record_id"])
        if existing is not None and canonical_json(existing) != canonical_json(row):
            _fail(
                "record_id_collision", "Generated row identity has conflicting content."
            )
        unique_rows[row["record_id"]] = row
    rows = [unique_rows[key] for key in sorted(unique_rows)]
    if len(rows) > MAX_GENERATION_ROWS:
        _fail("row_limit", "Generation exceeds the 10,000-row limit.")

    manifest = _manifest_body(rows, receipt_hashes)
    generation_id = sha256_hex(manifest)
    manifest["generation_id"] = generation_id
    for row in rows:
        row["generation_id"] = generation_id
        if len(canonical_json(row)) > MAX_RECORD_BYTES:
            _fail("row_size_limit", "A generated row exceeds the 64 KiB limit.")
    if len(canonical_json(manifest)) > 512 * 1024:
        _fail("manifest_size_limit", "Generation manifest exceeds the 512 KiB limit.")
    receipts, observations = _evidence_records(normalized, receipt_hashes)
    return {
        "receipts": receipts,
        "observations": observations,
        "rows": rows,
        "manifest": manifest,
    }
