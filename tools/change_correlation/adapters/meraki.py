"""Pure, allowlisted adapters for Meraki configuration evidence.

The audit API has no native event ID, so its adapter derives a deterministic
identity from only the retained fields and collapses records that are identical
after projection. SSID snapshots use the network ID plus SSID number as their
composite identity; Meraki does not document a durable SSID UID.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..contracts import (
    ContractError,
    MAX_OBJECTS,
    _iso_to_epoch,
    canonical_json,
    normalize_collection,
    sha256_hex,
)

PRODUCT = "meraki"
AUDIT_FAMILY = "configuration_change"
SSID_FAMILY = "ssid_snapshot"


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _records(value: Any, description: str) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _fail("invalid_native_records", f"Meraki {description} records must be a list.")
    if len(value) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if any(not isinstance(record, Mapping) for record in value):
        _fail(
            "invalid_native_record",
            f"Every Meraki {description} record must be an object.",
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
    return result


def _native_integer(value: Any, field: str, *, required: bool = False) -> int | None:
    if value is None:
        if required:
            _fail("missing_native_field", f"Native {field} is required.")
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("invalid_native_field", f"Native {field} must be a non-negative integer.")
    return value


def _native_boolean(value: Any, field: str, *, required: bool = False) -> bool | None:
    if value is None:
        if required:
            _fail("missing_native_field", f"Native {field} is required.")
        return None
    if not isinstance(value, bool):
        _fail("invalid_native_field", f"Native {field} must be true or false.")
    return value


def _event_time(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        _fail("invalid_time", "Native ts must be offset-qualified ISO-8601 text.")
    return _iso_to_epoch(value)


def _collection_metadata(
    value: Any, family: str, *, allow_authoritative_deletions: bool
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    metadata = dict(value)
    if "objects" in metadata:
        _fail("invalid_collection", "Collection metadata must not supply objects.")
    if metadata.get("product", PRODUCT) != PRODUCT:
        _fail("wrong_product", "Collection metadata product must be meraki.")
    if metadata.get("family", family) != family:
        _fail("wrong_family", f"Collection metadata family must be {family}.")
    for field in ("authority", "partition"):
        field_value = metadata.get(field)
        if isinstance(field_value, str):
            metadata[field] = field_value.strip()
    deletions_authoritative = metadata.get("deletions_authoritative", False)
    if not allow_authoritative_deletions and deletions_authoritative is not False:
        _fail(
            "invalid_deletion_authority",
            "Meraki audit collections cannot establish authoritative deletions.",
        )
    if allow_authoritative_deletions and deletions_authoritative is True:
        if (
            metadata.get("status") != "complete"
            or metadata.get("enumeration") != "full"
        ):
            _fail(
                "invalid_deletion_authority",
                "Authoritative Meraki SSID deletions require a complete full enumeration.",
            )
    return {
        **metadata,
        "schema_version": metadata.get("schema_version", 1),
        "product": PRODUCT,
        "family": family,
        "deletions_authoritative": deletions_authoritative,
    }


def _check_organization(record: Mapping[str, Any], authority: Any) -> None:
    """Check TA-added organization ID when present; raw API rows use receipt authority."""

    organization_id = _native_text(record.get("organizationId"), "organizationId")
    if organization_id is not None and organization_id != authority:
        _fail(
            "wrong_authority",
            "Native organizationId does not match the receipt authority.",
        )


def _network_partition_id(partition: Any) -> str:
    prefix = "network:"
    if not isinstance(partition, str) or not partition.startswith(prefix):
        _fail(
            "invalid_native_partition",
            "A network-scoped Meraki receipt requires partition network:<networkId>.",
        )
    network_id = partition[len(prefix) :].strip()
    if not network_id or partition != f"{prefix}{network_id}":
        _fail(
            "invalid_native_partition",
            "Meraki network partition must use network:<networkId> exactly.",
        )
    return network_id


def adapt_meraki_audits(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize Dashboard configuration-change rows as context-only audits.

    ``authority`` is the Meraki organization ID. The API response has no native
    event ID; a local SHA-256 identity is made from the receipt authority and
    partition, ``ts``, ``adminId`` and reviewed scalar fields only. Exact
    duplicate projected rows collapse. This is replay-stable, but distinct
    native actions that differ only in discarded data such as
    ``oldValue``/``newValue`` are indistinguishable.

    Organization-level rows without ``networkId`` remain organization context.
    An ``ssidNumber`` is retained only when the same row identifies its network.
    No name, IP, client ID, URL, email, or raw configuration value is used to
    create a relationship.
    """

    records = _records(native_records, "audit")
    metadata = _collection_metadata(
        collection_metadata,
        AUDIT_FAMILY,
        allow_authoritative_deletions=False,
    )
    authority = metadata.get("authority")
    if not isinstance(authority, str) or not authority:
        _fail(
            "missing_native_authority",
            "Meraki audit receipts require an organization ID authority.",
        )
    partition = metadata.get("partition")
    if partition != authority:
        network_partition_id = _network_partition_id(partition)
    else:
        network_partition_id = None

    normalized_by_id: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for record in records:
        _check_organization(record, authority)
        event_at = _event_time(record.get("ts"))
        actor = _native_text(record.get("adminId"), "adminId")
        network_id = _native_text(record.get("networkId"), "networkId")
        if (
            network_partition_id is not None
            and network_id is not None
            and network_id != network_partition_id
        ):
            _fail(
                "wrong_network_partition",
                "Native networkId does not match the receipt partition.",
            )
        ssid_number = _native_integer(record.get("ssidNumber"), "ssidNumber")

        fields: dict[str, Any] = {}
        if network_id is not None:
            fields["network_id"] = network_id
            if ssid_number is not None:
                fields["ssid_number"] = ssid_number
        for source_name, normalized_name in (("page", "page"), ("label", "label")):
            field_value = _native_text(record.get(source_name), source_name)
            if field_value is not None:
                fields[normalized_name] = field_value

        client = record.get("client")
        if client is not None:
            if not isinstance(client, Mapping):
                _fail("invalid_native_field", "Native client must be an object.")
            client_type = _native_text(client.get("type"), "client.type")
            if client_type is not None:
                if client_type != "oauth":
                    _fail("invalid_native_field", "Native client.type is unsupported.")
                fields["client_type"] = client_type

        safe_identity = {
            "authority": authority,
            "partition": metadata.get("partition"),
            "actor": actor,
            "event_at": event_at,
            "fields": fields,
        }
        signature = canonical_json(safe_identity)
        object_id = sha256_hex(signature)
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
            if previous[0] != signature:
                _fail(
                    "native_identity_collision",
                    "Different projected content uses the same Meraki audit identity.",
                )
            continue
        normalized_by_id[object_id] = (signature, observation)

    normalized_objects = [
        normalized_by_id[object_id][1] for object_id in sorted(normalized_by_id)
    ]
    return normalize_collection({**metadata, "objects": normalized_objects})


def _network_id_from_partition(partition: Any) -> str:
    prefix = "network:"
    if not isinstance(partition, str) or not partition.startswith(prefix):
        _fail(
            "invalid_native_partition",
            "Meraki SSID snapshots require partition network:<networkId>.",
        )
    network_id = partition[len(prefix) :].strip()
    if not network_id or partition != f"{prefix}{network_id}":
        _fail(
            "invalid_native_partition",
            "Meraki network partition must use network:<networkId> exactly.",
        )
    return network_id


def adapt_meraki_ssid_snapshots(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one network's Dashboard wireless SSID list response.

    The request path supplies the network identity through the explicit receipt
    partition ``network:<networkId>``; the routing ``scope`` remains independent
    and is preserved verbatim. Individual SSID response objects expose the
    integer ``number`` but do not expose a durable SSID UID. Only the reviewed
    scalar allowlist is copied. RADIUS, PSK, URLs, arbitrary nested policy and
    all other response fields are ignored.

    A caller may mark removals authoritative only for a complete full
    enumeration with an explicit single-network partition and permission
    fingerprint.
    The adapter itself is offline and cannot verify that collector attestation.
    """

    records = _records(native_records, "SSID snapshot")
    metadata = _collection_metadata(
        collection_metadata,
        SSID_FAMILY,
        allow_authoritative_deletions=True,
    )
    network_id = _network_id_from_partition(metadata.get("partition"))
    authority = metadata.get("authority")
    if not isinstance(authority, str) or not authority:
        _fail(
            "missing_native_authority",
            "Meraki SSID receipts require an organization ID authority.",
        )

    normalized_by_id: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for record in records:
        _check_organization(record, authority)
        row_network_id = _native_text(record.get("networkId"), "networkId")
        if row_network_id is not None and row_network_id != network_id:
            _fail(
                "wrong_network_partition",
                "Native networkId does not match the receipt partition.",
            )

        ssid_number = _native_integer(record.get("number"), "number", required=True)
        ssid_name = _native_text(record.get("name"), "name", required=True)
        enabled = _native_boolean(record.get("enabled"), "enabled", required=True)
        auth_mode = _native_text(record.get("authMode"), "authMode", required=True)
        ip_assignment_mode = _native_text(
            record.get("ipAssignmentMode"), "ipAssignmentMode", required=True
        )

        fields: dict[str, Any] = {
            "network_id": network_id,
            "ssid_number": ssid_number,
            "ssid_name": ssid_name,
            "enabled": enabled,
            "auth_mode": auth_mode,
            "ip_assignment_mode": ip_assignment_mode,
        }
        default_vlan_id = _native_integer(record.get("defaultVlanId"), "defaultVlanId")
        if default_vlan_id is not None:
            fields["default_vlan_id"] = default_vlan_id
        use_vlan_tagging = _native_boolean(
            record.get("useVlanTagging"), "useVlanTagging"
        )
        if use_vlan_tagging is not None:
            fields["use_vlan_tagging"] = use_vlan_tagging

        supports_vlan_tagging = ip_assignment_mode in {
            "Bridge mode",
            "Layer 3 roaming",
        }
        if use_vlan_tagging is not None and not supports_vlan_tagging:
            _fail(
                "invalid_vlan_semantics",
                "Native useVlanTagging requires Bridge mode or Layer 3 roaming.",
            )
        if default_vlan_id is not None and not (
            supports_vlan_tagging and use_vlan_tagging is True
        ):
            _fail(
                "invalid_vlan_semantics",
                "Native defaultVlanId requires Bridge mode or Layer 3 roaming with VLAN tagging enabled.",
            )

        object_id = f"org:{authority}/network:{network_id}/ssid:{ssid_number}"
        observation = {
            "object_id": object_id,
            "revision": None,
            "observed_at": metadata.get("received_at"),
            "event_at": None,
            "effective_at": None,
            "kind": "configuration",
            "actor": None,
            "fields": fields,
        }
        signature = canonical_json(observation["fields"])
        previous = normalized_by_id.get(object_id)
        if previous is not None:
            if previous[0] != signature:
                _fail(
                    "native_identity_collision",
                    "Different SSID state uses the same network and SSID number.",
                )
            continue
        normalized_by_id[object_id] = (signature, observation)

    normalized_objects = [
        normalized_by_id[object_id][1] for object_id in sorted(normalized_by_id)
    ]
    return normalize_collection({**metadata, "objects": normalized_objects})
