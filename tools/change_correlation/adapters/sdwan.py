"""Allowlisted, offline adapter for Cisco Catalyst SD-WAN Manager audit rows.

The mapping follows the published 26.1 ``AuditLogEntry`` schema and the
``/auditlog/severity`` response. It preserves audit identity and time, plus a
small set of scalar context fields. Audit details and message/configuration
payloads are deliberately discarded; an audit record does not identify the
changed policy or prove that a configuration reached a device.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from ..contracts import ContractError, MAX_EPOCH, MAX_OBJECTS, normalize_collection

PRODUCT = "sdwan"
AUDIT_FAMILY = "audit_log"

# These describe what this one audit family can say about the nine SD-WAN
# capabilities in the frozen source register. They are not live qualifications.
FEATURE_DISPOSITIONS = {
    "sdwan.template_changes": "adapter_tested_context_only",
    "sdwan.policy_changes": "adapter_tested_context_only",
    "sdwan.device_template_revisions": "blocked_native_object_revision_missing",
    "sdwan.deployment_action_status": "unsupported_in_audit_family",
    "sdwan.site_vpn_device": "blocked_native_site_vpn_binding_missing",
    "sdwan.routing_transport_aar_qos": "blocked_native_semantics_missing",
    "sdwan.tunnel_health": "unsupported_operational_family",
    "sdwan.exporter_sampling": "unsupported_history_not_verified",
    "sdwan.detail_completeness_retention": "blocked_source_sample_and_retention_missing",
}

_REQUIRED_FIELDS = {
    "auditdetails",
    "entry_time",
    "logdeviceid",
    "logfeature",
    "logid",
    "logmessage",
    "logmodule",
    "loguser",
    "logusersrcip",
    "statcycletime",
    "tenant",
}
_TEXT_FIELDS = {
    "logdeviceid",
    "logfeature",
    "logmessage",
    "logmodule",
    "loguser",
    "logusersrcip",
    "tenant",
}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _records(value: Any) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _fail("invalid_native_records", "SD-WAN audit records must be a list.")
    if len(value) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if any(not isinstance(record, Mapping) for record in value):
        _fail("invalid_native_record", "Every SD-WAN audit record must be an object.")
    return value


def _native_string(record: Mapping[str, Any], field: str) -> str:
    if field not in record:
        _fail("missing_native_field", f"Native {field} is required.")
    value = record[field]
    if not isinstance(value, str):
        _fail("invalid_native_field", f"Native {field} must be text.")
    return value


def _native_uuid(value: str, field: str) -> str:
    if not value:
        _fail("missing_native_id", f"Native {field} is required.")
    try:
        parsed = str(UUID(value))
    except (ValueError, AttributeError):
        _fail("invalid_native_id", f"Native {field} must be a UUID.")
    if parsed != value.lower():
        _fail("invalid_native_id", f"Native {field} must use UUID text form.")
    return parsed


def _validate_discarded_schema(record: Mapping[str, Any]) -> None:
    """Validate documented required shapes without retaining their contents."""

    missing = _REQUIRED_FIELDS - set(record)
    if missing:
        _fail("missing_native_field", "SD-WAN audit row is missing required fields.")

    # The 26.1 API model documents auditdetails as string[]. The packaged TA's
    # helper also accepts the JSON-string form from its API strategies. Neither
    # form is decoded or retained here.
    details = record["auditdetails"]
    if isinstance(details, str):
        pass
    elif isinstance(details, list) and all(isinstance(item, str) for item in details):
        pass
    else:
        _fail("invalid_native_field", "Native auditdetails has an unsupported shape.")

    for field in sorted(_TEXT_FIELDS):
        if not isinstance(record[field], str):
            _fail("invalid_native_field", f"Native {field} must be text.")

    stat_cycle_time = record["statcycletime"]
    if isinstance(stat_cycle_time, bool) or not isinstance(stat_cycle_time, int):
        _fail("invalid_native_field", "Native statcycletime must be an integer.")


def _event_time(value: Any) -> float | int:
    """Convert documented Unix epoch milliseconds to exact contract seconds."""

    if isinstance(value, bool) or not isinstance(value, int):
        _fail(
            "invalid_time",
            "Native entry_time must be an integer in epoch milliseconds.",
        )
    if value < 0 or value > MAX_EPOCH * 1000:
        _fail("invalid_time", "Native entry_time is outside the supported epoch range.")
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
        _fail("wrong_product", "Collection metadata product must be sdwan.")
    if metadata.get("family", AUDIT_FAMILY) != AUDIT_FAMILY:
        _fail("wrong_family", "Collection metadata family must be audit_log.")
    if metadata.get("deletions_authoritative", False) is not False:
        _fail(
            "invalid_deletion_authority",
            "SD-WAN audit collections cannot establish authoritative deletions.",
        )
    if metadata.get("enumeration", "incremental") != "incremental":
        _fail(
            "invalid_enumeration",
            "SD-WAN audit collections must use incremental enumeration.",
        )
    return {
        **metadata,
        "schema_version": metadata.get("schema_version", 1),
        "product": PRODUCT,
        "family": AUDIT_FAMILY,
        "enumeration": "incremental",
        "deletions_authoritative": False,
    }


def adapt_sdwan_audits(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize API-shaped SD-WAN audit rows into a bounded receipt.

    ``collection_metadata`` carries Manager authority, the collector's native
    partition, and the shared routing ``scope`` independently. The adapter
    maps ``logid`` to native event identity, ``entry_time`` to reported audit
    time, and ``loguser`` to actor. ``effective_at`` is always unknown. The
    ``logdeviceid`` field is preserved only as context; this adapter creates no
    device, site, VPN, policy, template, or traffic relationship.

    A complete receipt's page and permission metadata is an upstream collector
    attestation. This offline adapter does not fetch, paginate, or prove that
    attestation.
    """

    records = _records(native_records)
    metadata = _metadata(collection_metadata)
    observations: list[dict[str, Any]] = []

    for record in records:
        _validate_discarded_schema(record)

        native_id = _native_uuid(_native_string(record, "logid"), "logid")
        actor_text = _native_string(record, "loguser")
        actor = _native_uuid(actor_text, "loguser") if actor_text else None

        fields: dict[str, str] = {}
        for source_name, projected_name in (
            ("logdeviceid", "device_id"),
            ("logfeature", "feature"),
            ("logmodule", "module"),
            ("tenant", "tenant"),
        ):
            value = record[source_name]
            if value:
                fields[projected_name] = value

        observations.append(
            {
                "object_id": native_id,
                "revision": None,
                "observed_at": metadata.get("received_at"),
                "event_at": _event_time(record["entry_time"]),
                "effective_at": None,
                "kind": "audit",
                "actor": actor,
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
