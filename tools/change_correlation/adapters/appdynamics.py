"""Allowlisted, offline adapter for AppDynamics Controller audit records.

The source has no reviewed durable audit-row identity, so this adapter derives
an opaque repeatable identity from only its safe projected fields. Exact rows
that differ only in omitted data collapse; audit volume and event uniqueness
must not be inferred from that derived identity.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..contracts import (
    ContractError,
    MAX_EPOCH,
    MAX_OBJECTS,
    _iso_to_epoch,
    canonical_json,
    normalize_collection,
    sha256_hex,
)

PRODUCT = "appdynamics"
AUDIT_FAMILY = "audit_log"

# These are source-path dispositions, not live qualification claims. The
# shared capability register remains the authority for its stage statuses.
FEATURE_DISPOSITIONS = {
    "appdynamics.app_agent_audit": "adapter_tested_generic_audit_observation",
    "appdynamics.instrumentation_discovery": "blocked_event_subtype_and_binding_unqualified",
    "appdynamics.backend_discovery_rules": "blocked_no_rules_history_schema",
    "appdynamics.tier_node_model": "blocked_existing_inventory_is_current_only",
    "appdynamics.health_rule_alert": "blocked_monitoring_change_invalidation_missing",
    "appdynamics.release_deployment": "blocked_no_deployment_receipt_feed",
    "appdynamics.performance_call_coverage": "unsupported_as_change_history",
    "appdynamics.controller_stable_ids": "documented_current_ids_history_unqualified",
}

_FIELD_MAP = (
    ("accountName", "account_name"),
    ("securityProviderType", "security_provider_type"),
    ("action", "action"),
    ("objectType", "object_type"),
    ("objectName", "object_name"),
)


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _records(value: Any) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _fail("invalid_native_records", "AppDynamics audit records must be a list.")
    if len(value) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if any(not isinstance(record, Mapping) for record in value):
        _fail(
            "invalid_native_record", "Every AppDynamics audit record must be an object."
        )
    return value


def _native_text(record: Mapping[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        _fail("invalid_native_field", f"Native {field} must be text.")
    return value.strip() or None


def _epoch_milliseconds(value: Any) -> float | int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("invalid_time", "Native timeStamp must be integer epoch milliseconds.")
    if value < 0 or value > MAX_EPOCH * 1000:
        _fail("invalid_time", "Native timeStamp is outside the supported epoch range.")
    seconds, milliseconds = divmod(value, 1000)
    return seconds if milliseconds == 0 else seconds + milliseconds / 1000


def _event_time(record: Mapping[str, Any]) -> float | int | None:
    timestamp = record.get("timeStamp")
    audit_datetime = record.get("auditDateTime")
    from_milliseconds = None if timestamp is None else _epoch_milliseconds(timestamp)
    from_datetime = None
    if audit_datetime is not None and audit_datetime != "":
        if not isinstance(audit_datetime, str):
            _fail("invalid_time", "Native auditDateTime must be offset-qualified text.")
        from_datetime = _iso_to_epoch(audit_datetime)

    if from_milliseconds is not None and from_datetime is not None:
        if round(from_datetime * 1000) != round(from_milliseconds * 1000):
            _fail(
                "conflicting_native_time",
                "Native timeStamp and auditDateTime disagree.",
            )
    if from_milliseconds is not None:
        return from_milliseconds
    return from_datetime


def _metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    metadata = dict(value)
    if "objects" in metadata:
        _fail("invalid_collection", "Collection metadata must not supply objects.")
    if metadata.get("product", PRODUCT) != PRODUCT:
        _fail("wrong_product", "Collection metadata product must be appdynamics.")
    if metadata.get("family", AUDIT_FAMILY) != AUDIT_FAMILY:
        _fail("wrong_family", "Collection metadata family must be audit_log.")
    if metadata.get("deletions_authoritative", False) is not False:
        _fail(
            "invalid_deletion_authority",
            "AppDynamics audit collections cannot establish authoritative deletions.",
        )
    if metadata.get("enumeration", "incremental") != "incremental":
        _fail(
            "invalid_enumeration",
            "AppDynamics audit collections must use incremental enumeration.",
        )
    return {
        **metadata,
        "schema_version": metadata.get("schema_version", 1),
        "product": PRODUCT,
        "family": AUDIT_FAMILY,
        "enumeration": "incremental",
        "deletions_authoritative": False,
    }


def adapt_appdynamics_audits(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Project ControllerAuditHistory JSON rows into safe audit observations.

    The caller supplies an authority-qualified Controller tenant identity,
    partition, scope, source version, query interval, request/page outcome,
    permissions fingerprint, and receipt time. ``timeStamp`` (epoch ms) is
    preferred; ``auditDateTime`` is an offset-qualified fallback, and both
    must agree when present. The event actor is ``userName``. Raw diffs,
    Controller URLs, application names, API key fields, object IDs and all
    unreviewed fields are discarded. No effective transition or managed-object
    relationship is asserted.

    Because no durable native row identity was qualified, ``object_id`` is a
    local SHA-256 over authority, partition, event time, actor, and projected
    fields. This supports replay stability only for the projected record; two
    native actions identical after projection are indistinguishable.
    """

    records = _records(native_records)
    metadata = _metadata(collection_metadata)
    authority = metadata.get("authority")
    partition = metadata.get("partition")
    if not isinstance(authority, str) or not authority:
        _fail(
            "missing_native_authority",
            "AppDynamics receipts require a Controller authority.",
        )
    if not isinstance(partition, str) or not partition:
        _fail(
            "missing_native_partition",
            "AppDynamics receipts require an explicit partition.",
        )

    normalized_by_id: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for record in records:
        event_at = _event_time(record)
        actor = _native_text(record, "userName")
        fields: dict[str, str] = {}
        for native_name, projected_name in _FIELD_MAP:
            text = _native_text(record, native_name)
            if text is not None:
                fields[projected_name] = text

        identity = {
            "authority": authority,
            "partition": partition,
            "event_at": event_at,
            "actor": actor,
            "fields": fields,
        }
        identity_bytes = canonical_json(identity)
        object_id = sha256_hex(identity_bytes)
        observation = {
            "object_id": object_id,
            "revision": None,
            "observed_at": metadata.get("received_at"),
            "event_at": event_at,
            "effective_at": None,
            "kind": "audit",
            "actor": actor,
            "fields": fields,
        }
        previous = normalized_by_id.get(object_id)
        if previous is not None:
            if previous[0] != identity_bytes:
                _fail(
                    "native_identity_collision",
                    "Different projected content uses the same AppDynamics audit identity.",
                )
            continue
        normalized_by_id[object_id] = (identity_bytes, observation)

    objects = [normalized_by_id[key][1] for key in sorted(normalized_by_id)]
    return normalize_collection({**metadata, "objects": objects})
