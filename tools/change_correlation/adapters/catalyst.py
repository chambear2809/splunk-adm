"""Allowlisted Catalyst Center audit adaptation and explicit ISE blocks.

The Catalyst Center mapping follows the published 2.3.7.5 response schema and
the Cisco Enterprise Networking TA 4.0.60 emitter. It is documentation-shaped
offline support only; it does not attest a live controller release, collection
permissions, or complete native history. ISE has documented source catalogs,
but no frozen Atlas family/projection or sanitized, version-matched row sample
for this workstream, so its native paths fail closed.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from ..contracts import (
    MAX_EPOCH,
    MAX_OBJECTS,
    MAX_SAFE_INTEGER,
    ContractError,
    normalize_collection,
)

PRODUCT = "catalyst_center"
AUDIT_FAMILY = "audit_log"

# These are source workstream dispositions, not live qualification statuses.
# They make explicit which of the shared register's product features the audit
# family can and cannot establish. Only the generic audit row is normalized.
FEATURE_DISPOSITIONS = {
    "catalyst_center.audit_task_status": "adapter_tested_generic_audit_only",
    "catalyst_center.provisioning_templates": "blocked_target_and_completion_missing",
    "catalyst_center.device_site_profile": "blocked_event_target_binding_missing",
    "catalyst_center.software_activation": "blocked_swim_application_binding_missing",
    "catalyst_center.interface_client_vlan": "blocked_historical_binding_missing",
    "catalyst_center.network_device_identity": "blocked_event_device_identity_missing",
    "catalyst_center.compliance_actual_diff": "unsupported_audit_is_not_config_diff",
    "catalyst_center.wireless_config": "blocked_wireless_object_schema_missing",
    "catalyst_center.historical_bindings": "blocked_snapshot_has_no_validity_interval",
}

ISE_FEATURE_DISPOSITIONS = {
    "ise_trustsec.configuration_audit": "blocked_frozen_projection_and_sample_missing",
    "ise_trustsec.sgt_definitions": "blocked_snapshot_projection_and_change_semantics_missing",
    "ise_trustsec.sxp_bindings": "blocked_binding_lineage_expiry_and_delete_semantics_missing",
    "ise_trustsec.session_context": "unsupported_operational_context_not_config_history",
}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _records(value: Any) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _fail("invalid_native_records", "Catalyst Center audit records must be a list.")
    if len(value) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if any(not isinstance(record, Mapping) for record in value):
        _fail(
            "invalid_native_record",
            "Every Catalyst Center audit record must be an object.",
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
    if len(result) > 512 or any(ord(char) < 32 or ord(char) == 127 for char in result):
        _fail("invalid_native_field", f"Native {field} is outside the supported range.")
    return result


def _native_integer(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("invalid_native_field", f"Native {field} must be an integer.")
    if value < 0 or value > MAX_SAFE_INTEGER:
        _fail("invalid_native_field", f"Native {field} is outside the supported range.")
    return value


def _native_count(value: Any, field: str) -> int | None:
    """Accept the API's JSON ``number`` only when it is an exact count."""

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail("invalid_native_field", f"Native {field} must be a non-negative count.")
    # Bound before converting to float: an untrusted, enormous Python integer
    # can overflow in ``float(value)`` before it is rejected.
    if value < 0 or value > MAX_SAFE_INTEGER:
        _fail("invalid_native_field", f"Native {field} is outside the supported range.")
    if not math.isfinite(float(value)):
        _fail("invalid_native_field", f"Native {field} is outside the supported range.")
    if int(value) != value:
        _fail("invalid_native_field", f"Native {field} must be an exact count.")
    return int(value)


def _event_time(value: Any) -> int | float | None:
    """Convert the documented integer Unix epoch milliseconds exactly."""

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(
            "invalid_time", "Native timestamp must be an integer in epoch milliseconds."
        )
    if value < 0 or value > MAX_EPOCH * 1000:
        _fail("invalid_time", "Native timestamp is outside the supported epoch range.")
    seconds, milliseconds = divmod(value, 1000)
    if milliseconds == 0:
        return seconds
    return seconds + milliseconds / 1000


def _metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    metadata = dict(value)
    if "objects" in metadata:
        _fail("invalid_collection", "Collection metadata must not supply objects.")
    if metadata.get("product", PRODUCT) != PRODUCT:
        _fail("wrong_product", "Collection metadata product must be catalyst_center.")
    if metadata.get("family", AUDIT_FAMILY) != AUDIT_FAMILY:
        _fail("wrong_family", "Collection metadata family must be audit_log.")
    if metadata.get("enumeration", "incremental") != "incremental":
        _fail(
            "invalid_enumeration",
            "Catalyst Center audit collections must be incremental.",
        )
    if metadata.get("deletions_authoritative", False) is not False:
        _fail(
            "invalid_deletion_authority",
            "Catalyst Center audit collections cannot establish authoritative deletions.",
        )
    return {
        **metadata,
        "schema_version": metadata.get("schema_version", 1),
        "product": PRODUCT,
        "family": AUDIT_FAMILY,
        "enumeration": "incremental",
        "deletions_authoritative": False,
    }


def adapt_catalyst_audits(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Project Catalyst Center audit records into an immutable audit receipt.

    Native ``instanceId`` identifies the audit record only; it is not the ID of
    an affected device, policy, task, or configuration object. Native
    ``timestamp`` is reported audit time in epoch milliseconds. ``userId`` is
    retained as the reported actor, but neither it nor event names prove a
    successful task or applied network change. TA 4.0.60 renames native
    ``source`` to ``src``; either spelling is accepted, but ambiguous dual
    presence fails closed. The native ``network`` value is deliberately omitted
    because the reviewed API schema does not define it as a stable network ID.

    Collection metadata is supplied by an external, trusted export boundary.
    This function does not call Catalyst Center, fetch pages, or prove the
    collector's completion or permission attestations.
    """

    records = _records(native_records)
    metadata = _metadata(collection_metadata)
    observations: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    text_fields = (
        ("parentInstanceId", "parent_event_id"),
        ("name", "event_name"),
        ("type", "event_type"),
        ("category", "category"),
        ("domain", "domain"),
        ("subDomain", "subdomain"),
        ("eventHierarchy", "event_hierarchy"),
    )

    for record in records:
        native_id = _native_text(record.get("instanceId"), "instanceId", required=True)
        assert native_id is not None
        if native_id in seen_ids:
            _fail(
                "duplicate_native_id", "Catalyst Center audit instanceId is duplicated."
            )
        seen_ids.add(native_id)

        if "source" in record and "src" in record:
            _fail(
                "ambiguous_native_field",
                "Catalyst Center audit row cannot contain both source and TA src.",
            )

        fields: dict[str, Any] = {}
        for source_name, projected_name in text_fields:
            value = _native_text(record.get(source_name), source_name)
            if value is not None:
                fields[projected_name] = value

        source_name = "source" if "source" in record else "src"
        source = _native_text(record.get(source_name), source_name)
        if source is not None:
            fields["source"] = source

        severity = _native_integer(record.get("severity"), "severity")
        if severity is not None:
            fields["severity"] = severity
        child_count = _native_count(record.get("childCount"), "childCount")
        if child_count is not None:
            fields["child_count"] = child_count

        observations.append(
            {
                "object_id": native_id,
                "revision": None,
                "observed_at": metadata.get("received_at"),
                "event_at": _event_time(record.get("timestamp")),
                "effective_at": None,
                "kind": "audit",
                "actor": _native_text(record.get("userId"), "userId"),
                "fields": fields,
            }
        )

    return normalize_collection(
        {
            **metadata,
            "schema_version": metadata.get("schema_version", 1),
            "product": PRODUCT,
            "family": AUDIT_FAMILY,
            "enumeration": "incremental",
            "deletions_authoritative": False,
            "objects": observations,
        }
    )


def _refuse_ise_native_schema() -> None:
    _fail(
        "unsupported_source_schema",
        "ISE and TrustSec have no approved native projection for this change-history contract; "
        "a version-matched sanitized source sample and frozen family schema are required.",
    )


def adapt_ise_configuration_audits(native_records: Any, collection_metadata: Any):
    """Fail closed until the ISE audit family and safe projection are frozen."""

    _refuse_ise_native_schema()


def adapt_ise_sgt_snapshots(native_records: Any, collection_metadata: Any):
    """Fail closed until ISE security-group snapshot semantics are qualified."""

    _refuse_ise_native_schema()


def adapt_ise_sxp_bindings(native_records: Any, collection_metadata: Any):
    """Fail closed until binding identity, expiry, and removal semantics are qualified."""

    _refuse_ise_native_schema()


def adapt_ise_session_context(native_records: Any, collection_metadata: Any):
    """Fail closed: current session context is not configuration history."""

    _refuse_ise_native_schema()
