"""Bounded Cisco FTD eStreamer connection observations."""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any

from ..contracts import MAX_EPOCH, MAX_OBJECTS, ContractError, normalize_collection

_RECORD_KEYS = {"event_fingerprint", "_indextime", "native_event"}
_METADATA_KEYS = {
    "schema_version",
    "capture_id",
    "product",
    "authority",
    "source_version",
    "family",
    "partition",
    "scope",
    "started_at",
    "completed_at",
    "received_at",
    "status",
    "permissions_fingerprint",
    "pages_expected",
    "pages_received",
    "source_reference",
    "enumeration",
    "deletions_authoritative",
}
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_ACTION_OUTCOMES = {
    "Allow": "reported_allow_trust",
    "Trust": "reported_allow_trust",
    "Block": "reported_block",
    "Block with reset": "reported_block",
    "Interactive Block": "interactive_initial_block",
    "Interactive Block with reset": "interactive_initial_block",
    "Fastpath": "fastpath",
    "Default Action": "unknown",
}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _source_text(
    value: Any, field: str, *, required: bool = False, allow_integer: bool = False
) -> str | None:
    if value is None or value == "":
        if required:
            _fail("invalid_source_field", f"{field} is required.")
        return None
    if isinstance(value, int) and not isinstance(value, bool) and allow_integer:
        value = str(value)
    if not isinstance(value, str):
        _fail("invalid_source_field", f"{field} must be a single text value.")
    if not value.strip():
        if required:
            _fail("invalid_source_field", f"{field} is required.")
        return None
    if len(value) > 512 or _CONTROL_RE.search(value):
        _fail("invalid_source_field", f"{field} is outside the supported bounds.")
    return value


def _source_epoch(
    value: Any, field: str, *, required: bool = False, allow_fraction: bool = False
) -> int | float | None:
    if value is None:
        if required:
            _fail("invalid_source_time", f"{field} is required.")
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail("invalid_source_time", f"{field} must be a UTC epoch number.")
    if not math.isfinite(float(value)) or value < 0 or value > MAX_EPOCH:
        _fail("invalid_source_time", f"{field} is outside the supported range.")
    if not allow_fraction and (not isinstance(value, int)):
        _fail("invalid_source_time", f"{field} must be whole epoch seconds.")
    return value


def _source_ip(value: Any, field: str, *, required: bool = False) -> str | None:
    result = _source_text(value, field, required=required)
    if result is None:
        return None
    try:
        ipaddress.ip_address(result)
    except ValueError as exc:
        raise ContractError(
            "invalid_source_field", f"{field} must be a single IP address."
        ) from exc
    return result


def _source_port(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("invalid_source_field", f"{field} must be an integer port.")
    if not 0 <= value <= 65535:
        _fail("invalid_source_field", f"{field} is outside the port range.")
    return value


def _source_id(value: Any, field: str, *, allow_integer: bool = False) -> str | None:
    result = _source_text(value, field, allow_integer=allow_integer)
    if result is None:
        return None
    if allow_integer and not result.isdecimal():
        _fail("invalid_source_field", f"{field} must be a numeric identifier.")
    return result


def _native_action(value: Any) -> tuple[str | None, str]:
    if value is None or value == "":
        return None, "unknown"
    if not isinstance(value, str):
        _fail("invalid_source_field", "AC_RuleAction must be a single text value.")
    if not value.strip():
        return None, "unknown"
    outcome = _ACTION_OUTCOMES.get(value)
    if outcome is None:
        # Preserve no unqualified alias or future enum. The explicit outcome
        # remains unknown and cannot be mistaken for permission.
        return None, "unknown"
    return value, outcome


def _validate_metadata(collection_metadata: Any) -> dict[str, Any]:
    if not isinstance(collection_metadata, dict):
        _fail("invalid_source_metadata", "Collection metadata must be an object.")
    if set(collection_metadata) - _METADATA_KEYS:
        _fail("invalid_source_metadata", "Collection metadata has unknown fields.")
    if collection_metadata.get("product", "ftd") != "ftd":
        _fail("unsupported_projection", "FTD observations require product ftd.")
    if collection_metadata.get("family", "connection_observation") != (
        "connection_observation"
    ):
        _fail(
            "unsupported_projection",
            "FTD observations require family connection_observation.",
        )
    metadata = {
        key: value
        for key, value in collection_metadata.items()
        if key not in {"product", "family"}
    }
    metadata.update(
        product="ftd",
        family="connection_observation",
        objects=[],
    )
    return metadata


def _project_record(record: Any, authority: str) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        _fail(
            "invalid_source_record",
            "Every FTD record requires event_fingerprint, _indextime, and native_event.",
        )
    fingerprint = record.get("event_fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
        _fail(
            "invalid_event_fingerprint",
            "event_fingerprint must be a trusted lowercase SHA-256 value.",
        )
    received_at = _source_epoch(
        record.get("_indextime"), "_indextime", required=True, allow_fraction=True
    )
    native = record.get("native_event")
    if not isinstance(native, dict):
        _fail("invalid_source_record", "native_event must be a JSON object.")
    if native.get("EventType") != "ConnectionEvent":
        _fail(
            "unsupported_source_event",
            "Only eStreamer ConnectionEvent records are supported.",
        )
    source_host = _source_text(native.get("SourceHost"), "SourceHost", required=True)
    if source_host != authority:
        _fail(
            "source_authority_mismatch",
            "SourceHost must match the configured FMC authority.",
        )

    device_ip = _source_ip(native.get("DeviceIP"), "DeviceIP", required=True)
    first_packet_at = _source_epoch(
        native.get("FirstPacketSecond"), "FirstPacketSecond", required=True
    )
    event_detected_at = _source_epoch(native.get("EventSecond"), "EventSecond")
    reported_action, outcome = _native_action(native.get("AC_RuleAction"))

    fields = {
        "device_ip": device_ip,
        "device_uuid": _source_text(native.get("DeviceUUID"), "DeviceUUID"),
        "device_serial": _source_text(
            native.get("DeviceSerialNumber"),
            "DeviceSerialNumber",
            allow_integer=True,
        ),
        "instance_id": _source_id(
            native.get("InstanceID"), "InstanceID", allow_integer=True
        ),
        "connection_id": _source_id(
            native.get("ConnectionID"), "ConnectionID", allow_integer=True
        ),
        "protocol": _source_text(native.get("Protocol"), "Protocol"),
        "reported_initiator_ip": _source_ip(native.get("InitiatorIP"), "InitiatorIP"),
        "reported_initiator_port": _source_port(
            native.get("InitiatorPort"), "InitiatorPort"
        ),
        "reported_responder_ip": _source_ip(native.get("ResponderIP"), "ResponderIP"),
        "reported_responder_port": _source_port(
            native.get("ResponderPort"), "ResponderPort"
        ),
        "reported_action": reported_action,
        "outcome": outcome,
        "firewall_policy_name": _source_text(
            native.get("FirewallPolicy"), "FirewallPolicy"
        ),
        "firewall_rule_name": _source_text(native.get("FirewallRule"), "FirewallRule"),
        "event_fingerprint": fingerprint,
        "evidence_identity_basis": "trusted_indexed_event_fingerprint",
        "first_packet_at": first_packet_at,
        "event_detected_at": event_detected_at,
    }
    return {
        "object_id": fingerprint,
        "revision": None,
        "observed_at": received_at,
        "event_at": event_detected_at,
        "effective_at": None,
        "kind": "operational",
        "actor": None,
        "fields": fields,
    }


def adapt_ftd_connection_records(
    records: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Adapt bounded, indexed TA ConnectionEvent records to observations.

    Each record is a sidecar wrapper with `event_fingerprint`, `_indextime`,
    and a parsed `native_event` object. The fingerprint is supplied by a
    trusted indexed-event query; this function validates its shape but does
    not recompute it from source JSON or trust ConnectionID as identity.
    """

    collection = _validate_metadata(collection_metadata)
    if not isinstance(records, list):
        _fail("invalid_source_records", "FTD records must be a bounded array.")
    if len(records) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-record limit.")
    authority = collection.get("authority")
    if (
        not isinstance(authority, str)
        or not authority
        or authority != authority.strip()
    ):
        _fail("invalid_source_metadata", "Configured FMC authority is required.")
    collection["objects"] = [_project_record(record, authority) for record in records]
    return normalize_collection(collection)
