"""Strict, offline ThousandEyes activity adapters.

The adapters project only the frozen ``activity_log`` fields.  Activity
records remain context-only: an account ID, resource name, or event label is
not a test, agent, application, or infrastructure binding.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..contracts import (
    ContractError,
    MAX_EPOCH,
    MAX_FIELDS,
    MAX_OBJECTS,
    MAX_TEXT,
    _iso_to_epoch,
    canonical_json,
    normalize_collection,
    sha256_hex,
)

PRODUCT = "thousandeyes"
ACTIVITY_FAMILY = "activity_log"

# These are dispositions keyed exactly to the shared W10 feature inventory.
# They are not live-qualification claims; the source note records evidence
# stages. Generic activity-log context is described separately in that note.
FEATURE_DISPOSITIONS = {
    "thousandeyes.test_crud": "adapter_tested_context_only_resource_names_not_ids",
    "thousandeyes.target_interval": "blocked_no_frozen_test_configuration_projection",
    "thousandeyes.agent_assignment": "blocked_no_versioned_test_agent_binding_projection",
    "thousandeyes.alert_rule": "blocked_no_alert_rule_configuration_projection",
    "thousandeyes.stream_configuration": "blocked_no_stream_configuration_revision_projection",
    "thousandeyes.account_resource_mapping": "blocked_account_crosswalk_and_native_resource_ids_unqualified",
    "thousandeyes.metric_units_config": "blocked_no_compatible_configuration_revision_projection",
    "thousandeyes.path_events": "unsupported_as_configuration_history_measurement_and_event_context_only",
    "thousandeyes.cea_endpoint_identity": "blocked_no_qualified_domain_binding",
    "thousandeyes.api_trace_support": "blocked_no_received_trace_readback_for_disputed_support",
}

_NANOSECONDS = re.compile(r"^[0-9]+$")
_MAX_INT64 = 9_223_372_036_854_775_807
_API_SOURCE_REFERENCE = "thousandeyes:api:v7:audit-user-events"
_OTEL_SOURCE_REFERENCE = "thousandeyes:otel:v2:activity-log"


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _records(value: Any, label: str) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _fail("invalid_native_records", f"ThousandEyes {label} records must be a list.")
    if len(value) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if any(not isinstance(record, Mapping) for record in value):
        _fail(
            "invalid_native_record",
            "Every ThousandEyes native record must be an object.",
        )
    return value


def _native_text(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None or value == "":
        if required:
            _fail("missing_native_field", f"Native {field} is required.")
        return None
    if not isinstance(value, str):
        _fail("invalid_native_field", f"Native {field} must be text.")
    result = value.strip()
    if not result:
        if required:
            _fail("missing_native_field", f"Native {field} is required.")
        return None
    if len(result) > MAX_TEXT:
        _fail("invalid_native_field", f"Native {field} exceeds the bounded text limit.")
    return result


def _metadata(
    value: Any,
    *,
    source_reference: str,
    force_partial: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    metadata = dict(value)
    if "objects" in metadata:
        _fail("invalid_collection", "Collection metadata must not supply objects.")
    if metadata.get("product", PRODUCT) != PRODUCT:
        _fail("wrong_product", "Collection metadata product must be thousandeyes.")
    if metadata.get("family", ACTIVITY_FAMILY) != ACTIVITY_FAMILY:
        _fail("wrong_family", "Collection metadata family must be activity_log.")
    if metadata.get("deletions_authoritative", False) is not False:
        _fail(
            "invalid_deletion_authority",
            "ThousandEyes activity records cannot establish authoritative deletions.",
        )
    if metadata.get("enumeration", "incremental") != "incremental":
        _fail(
            "invalid_enumeration",
            "ThousandEyes activity collections must use incremental enumeration.",
        )
    if force_partial:
        if metadata.get("status", "partial") == "complete":
            _fail(
                "unqualified_completeness",
                "The OTel activity stream has no reviewed checkpoint or delivery-completeness evidence.",
            )
        metadata.update(
            status=metadata.get("status", "partial"),
            pages_expected=0,
            pages_received=0,
        )
    return {
        **metadata,
        "schema_version": metadata.get("schema_version", 1),
        "product": PRODUCT,
        "family": ACTIVITY_FAMILY,
        "enumeration": "incremental",
        "deletions_authoritative": False,
        "source_reference": metadata.get("source_reference", source_reference),
    }


def _event_identity(
    metadata: Mapping[str, Any],
    *,
    event_at: float | int,
    observed_at: float | int,
    actor: str | None,
    fields: Mapping[str, str],
) -> dict[str, Any]:
    identity = {
        "authority": metadata.get("authority"),
        "partition": metadata.get("partition"),
        "event_at": event_at,
        "actor": actor,
        "fields": dict(fields),
    }
    return {
        "object_id": sha256_hex(canonical_json(identity)),
        "revision": None,
        "observed_at": observed_at,
        "event_at": event_at,
        "effective_at": None,
        "kind": "audit",
        "actor": actor,
        "fields": dict(fields),
    }


def _deduplicate(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for obj in objects:
        encoded = canonical_json(obj)
        prior = by_id.get(obj["object_id"])
        if prior is not None:
            if prior[0] != encoded:
                _fail(
                    "native_identity_collision",
                    "Different projected content uses the same ThousandEyes activity identity.",
                )
            continue
        by_id[obj["object_id"]] = (encoded, obj)
    return [by_id[object_id][1] for object_id in sorted(by_id)]


def adapt_thousandeyes_activity_events(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Project documented API v7 ``UserEvent`` rows as audit context.

    The caller supplies page counts, a permission fingerprint, source version,
    account-group partition, authority, scope, collection times, receipt time,
    and the requested ``query_start``/``query_end`` ISO-8601 bounds. Complete
    API receipts require both query bounds and retain them in the safe source
    reference because the frozen collection contract has no separate window
    fields. Native ``aid`` is required to match the partition. The API does not
    expose an event ID, so the repeatable object ID hashes only retained fields.
    The ``user`` (name/email) and ``ipAddress`` properties are discarded. The
    API's resource names are context strings, never native test/application IDs.
    Multiple resource entries are refused because the frozen projection has
    scalar resource fields and must not silently drop or concatenate entries.
    """

    records = _records(native_records, "activity API")
    if not isinstance(collection_metadata, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    source_metadata = dict(collection_metadata)
    query_start = source_metadata.pop("query_start", None)
    query_end = source_metadata.pop("query_end", None)
    if source_metadata.get("status") == "complete" and (
        query_start is None or query_end is None
    ):
        _fail(
            "missing_collection_window",
            "A complete activity API receipt requires explicit query_start and query_end.",
        )
    if (query_start is None) != (query_end is None):
        _fail(
            "invalid_collection_window",
            "Activity API query_start and query_end must be supplied together.",
        )
    source_reference = _native_text(
        source_metadata.get("source_reference", _API_SOURCE_REFERENCE),
        "source_reference",
        required=True,
    )
    if query_start is not None and query_end is not None:
        start_text = _native_text(query_start, "query_start", required=True)
        end_text = _native_text(query_end, "query_end", required=True)
        try:
            start_at = _iso_to_epoch(start_text)
            end_at = _iso_to_epoch(end_text)
        except ContractError as exc:
            if exc.code == "invalid_number":
                _fail(
                    "invalid_time_precision",
                    "API query window exceeds millisecond precision.",
                )
            raise
        if end_at <= start_at:
            _fail(
                "invalid_collection_window",
                "API query_end must be later than query_start.",
            )
        source_reference = (
            f"{source_reference};window_start={start_text};window_end={end_text}"
        )
    source_metadata["source_reference"] = source_reference
    metadata = _metadata(source_metadata, source_reference=_API_SOURCE_REFERENCE)
    partition = metadata.get("partition")
    if not isinstance(partition, str) or not partition.strip():
        _fail(
            "missing_native_partition",
            "ThousandEyes activity API receipts require one account-group partition.",
        )

    objects: list[dict[str, Any]] = []
    for record in records:
        aid = _native_text(record.get("aid"), "aid", required=True)
        if aid != partition:
            _fail(
                "wrong_native_partition",
                "Native aid does not match the receipt account-group partition.",
            )
        try:
            event_at = _iso_to_epoch(
                _native_text(record.get("date"), "date", required=True)
            )
        except ContractError as exc:
            if exc.code == "invalid_number":
                _fail(
                    "invalid_time_precision",
                    "Native date exceeds millisecond precision.",
                )
            raise
        event_name = _native_text(record.get("event"), "event", required=True)
        uid = _native_text(record.get("uid"), "uid")
        actor = None if uid is None else f"uid:{uid}"

        fields = {"account_id": aid, "event_name": event_name}
        resources = record.get("resources")
        if resources is not None:
            if not isinstance(resources, Sequence) or isinstance(
                resources, (str, bytes, bytearray)
            ):
                _fail("invalid_native_field", "Native resources must be a list.")
            if len(resources) > 1:
                _fail(
                    "unsupported_resource_cardinality",
                    "The frozen projection cannot represent multiple native activity resources.",
                )
            if resources:
                resource = resources[0]
                if not isinstance(resource, Mapping):
                    _fail(
                        "invalid_native_field",
                        "Every native activity resource must be an object.",
                    )
                resource_type = _native_text(
                    resource.get("type"), "resources.type", required=True
                )
                resource_name = _native_text(
                    resource.get("name"), "resources.name", required=True
                )
                fields["resource_type"] = resource_type
                fields["resource_name"] = resource_name

        objects.append(
            _event_identity(
                metadata,
                event_at=event_at,
                observed_at=metadata.get("received_at"),
                actor=actor,
                fields=fields,
            )
        )

    return normalize_collection({**metadata, "objects": _deduplicate(objects)})


def _attribute_map(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > MAX_FIELDS:
        _fail(
            "invalid_native_field",
            f"Native {label} must be a bounded OTel attribute list.",
        )
    result: dict[str, str] = {}
    for item in value:
        if not isinstance(item, Mapping):
            _fail(
                "invalid_native_field",
                f"Every native {label} attribute must be an object.",
            )
        key = item.get("key")
        if not isinstance(key, str):
            _fail("invalid_native_field", f"Native {label} attribute key must be text.")
        if key not in {
            "thousandeyes.account.id",
            "thousandeyes.data.version",
            "thousandeyes.stream.id",
            "thousandeyes.user.id",
        }:
            continue
        native_value = item.get("value")
        if not isinstance(native_value, Mapping):
            _fail(
                "invalid_native_field",
                f"Native {label} attribute value must be an object.",
            )
        text_value = native_value.get("stringValue")
        if not isinstance(text_value, str):
            _fail("invalid_native_field", f"Native {key} must use stringValue.")
        text_value = _native_text(text_value, key)
        if text_value is None:
            result[key] = ""
            continue
        previous = result.get(key)
        if previous is not None and previous != text_value:
            _fail(
                "conflicting_native_field",
                f"Native {label} contains conflicting {key} values.",
            )
        result[key] = text_value.strip()
    return result


def _otel_timestamp_nanos(value: Any, field: str) -> float | int:
    if (
        not isinstance(value, str)
        or len(value) > 19
        or not _NANOSECONDS.fullmatch(value)
    ):
        _fail(
            "invalid_time",
            f"Native {field} must be an unsigned epoch nanosecond string.",
        )
    nanoseconds = int(value)
    if nanoseconds > _MAX_INT64:
        _fail("invalid_time", f"Native {field} exceeds the OTel int64 range.")
    if nanoseconds % 1_000_000:
        _fail(
            "invalid_time_precision", f"Native {field} exceeds millisecond precision."
        )
    milliseconds = nanoseconds // 1_000_000
    if milliseconds > MAX_EPOCH * 1000:
        _fail("invalid_time", f"Native {field} is outside the supported epoch range.")
    seconds, remainder = divmod(milliseconds, 1000)
    return seconds if remainder == 0 else seconds + remainder / 1000


def adapt_thousandeyes_otel_activity(
    native_payload: Mapping[str, Any],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Project official OTel v2 ``resourceLogs`` activity records.

    The account and stream IDs stay source attributes. ``account.id`` is not
    assumed to equal the API's account-group ``aid``. One payload must contain
    a single stream/account pair matching the explicit ``stream:<id>`` receipt
    partition. OTel activity delivery has no reviewed checkpoint or completeness
    acknowledgment, so this adapter always retains a partial receipt. The
    documented comma-separated ``activitylog.resources`` value is not parsed;
    its resource-type/name grammar is not documented.
    """

    if not isinstance(native_payload, Mapping):
        _fail(
            "invalid_native_record",
            "ThousandEyes OTel activity payload must be an object.",
        )
    resource_logs = native_payload.get("resourceLogs")
    if not isinstance(resource_logs, list) or len(resource_logs) > MAX_OBJECTS:
        _fail("invalid_native_records", "Native resourceLogs must be a bounded list.")

    if not isinstance(collection_metadata, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    source_metadata = dict(collection_metadata)
    expected_stream_id = source_metadata.pop("stream_id", None)
    metadata = _metadata(
        source_metadata,
        source_reference=_OTEL_SOURCE_REFERENCE,
        force_partial=True,
    )
    objects: list[dict[str, Any]] = []
    payload_streams: set[str] = set()
    payload_accounts: set[str] = set()
    native_items_seen = 0
    for resource_log in resource_logs:
        native_items_seen += 1
        if native_items_seen > MAX_OBJECTS:
            _fail("object_limit", "OTel input exceeds the 10,000-item limit.")
        if not isinstance(resource_log, Mapping):
            _fail(
                "invalid_native_record", "Every native resource log must be an object."
            )
        resource = resource_log.get("resource")
        if not isinstance(resource, Mapping):
            _fail(
                "invalid_native_field",
                "Native resource log must contain resource attributes.",
            )
        resource_attributes = _attribute_map(
            resource.get("attributes"), "resource attributes"
        )
        if resource_attributes.get("thousandeyes.data.version") != "v2":
            _fail(
                "unsupported_native_schema",
                "Only documented ThousandEyes OTel data model v2 is supported.",
            )
        stream_id = resource_attributes.get("thousandeyes.stream.id")
        account_id = resource_attributes.get("thousandeyes.account.id")
        if not stream_id or not account_id:
            _fail("missing_native_field", "Native stream and account IDs are required.")
        payload_streams.add(stream_id)
        payload_accounts.add(account_id)

        scope_logs = resource_log.get("scopeLogs")
        if not isinstance(scope_logs, list) or len(scope_logs) > MAX_OBJECTS:
            _fail("invalid_native_field", "Native scopeLogs must be a bounded list.")
        for scope_log in scope_logs:
            native_items_seen += 1
            if native_items_seen > MAX_OBJECTS:
                _fail("object_limit", "OTel input exceeds the 10,000-item limit.")
            if not isinstance(scope_log, Mapping):
                _fail(
                    "invalid_native_record", "Every native scope log must be an object."
                )
            log_records = scope_log.get("logRecords")
            if not isinstance(log_records, list) or len(log_records) > MAX_OBJECTS:
                _fail(
                    "invalid_native_field", "Native logRecords must be a bounded list."
                )
            for log_record in log_records:
                native_items_seen += 1
                if native_items_seen > MAX_OBJECTS:
                    _fail("object_limit", "OTel input exceeds the 10,000-item limit.")
                if not isinstance(log_record, Mapping):
                    _fail(
                        "invalid_native_record",
                        "Every native log record must be an object.",
                    )
                body = log_record.get("body")
                if not isinstance(body, Mapping):
                    _fail(
                        "invalid_native_field",
                        "Native activity body must be an OTel AnyValue object.",
                    )
                event_name = _native_text(
                    body.get("stringValue"), "body.stringValue", required=True
                )
                log_attributes = _attribute_map(
                    log_record.get("attributes", []), "log attributes"
                )
                uid = log_attributes.get("thousandeyes.user.id")
                actor = None if not uid else f"user_id:{uid}"
                event_at = _otel_timestamp_nanos(
                    log_record.get("timeUnixNano"), "timeUnixNano"
                )
                observed_time = log_record.get("observedTimeUnixNano")
                observed_at = (
                    metadata.get("received_at")
                    if observed_time is None
                    else _otel_timestamp_nanos(observed_time, "observedTimeUnixNano")
                )
                fields = {"account_id": account_id, "event_name": event_name}
                if len(objects) >= MAX_OBJECTS:
                    _fail("object_limit", "Input exceeds the 10,000-object limit.")
                objects.append(
                    _event_identity(
                        metadata,
                        event_at=event_at,
                        observed_at=observed_at,
                        actor=actor,
                        fields=fields,
                    )
                )

    if len(payload_streams) > 1 or len(payload_accounts) > 1:
        _fail(
            "mixed_native_partition",
            "One OTel activity receipt must contain exactly one stream and account identity.",
        )
    if (
        expected_stream_id is not None
        and payload_streams
        and payload_streams != {expected_stream_id}
    ):
        _fail(
            "wrong_native_partition",
            "Native stream.id does not match configured stream_id.",
        )
    if payload_streams:
        expected_partition = f"stream:{next(iter(payload_streams))}"
        if metadata.get("partition") != expected_partition:
            _fail(
                "wrong_native_partition",
                "OTel receipt partition must be the explicit stream:<stream.id> identity.",
            )
    elif metadata.get("status") == "complete":
        _fail(
            "unqualified_completeness",
            "An empty OTel payload cannot establish complete activity coverage.",
        )

    return normalize_collection({**metadata, "objects": _deduplicate(objects)})


def refuse_thousandeyes_test_configuration(
    native_records: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Refuse test snapshots until the frozen contract has a TE config projection."""

    del native_records, collection_metadata
    _fail(
        "unsupported_projection",
        "ThousandEyes test configuration requires a reviewed native snapshot projection and revision contract.",
    )
