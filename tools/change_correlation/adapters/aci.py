"""Pure, allowlisted adapters for Cisco ACI audit evidence.

The adapter accepts either the reviewed flattened fields emitted by Cisco DC
Networking App 1.2.2 or the documented ``aaaModLR`` APIC ``imdata`` object.
It never parses raw event text or arbitrary nested fields.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from ..contracts import ContractError, MAX_OBJECTS, _iso_to_epoch, normalize_collection

PRODUCT = "aci"
FAMILY = "aaa_mod_lr"
NATIVE_CLASS = "aaaModLR"

_AUDIT_FIELDS = {
    "affected": "affected_dn",
    "code": "event_code",
    "ind": "operation",
    "trig": "trigger",
    "txId": "transaction_id",
}

_POLICY_FAMILIES = {
    "filter_entry_snapshot",
    "contract_subject_snapshot",
    "epg_contract_attachment_snapshot",
}
_EPG_RELATIONS = {"fvRsCons", "fvRsProv"}
_EPG_KNOWN_SIBLINGS = {"fvRsBd", "fvRsDomAtt", "fvRsPathAtt"}
_CONSUMER_LABEL_CLASSES = {"vzConsLbl", "vzConsSubjLbl"}
_PROVIDER_LABEL_CLASSES = {"vzProvLbl", "vzProvSubjLbl"}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _native_attributes(record: Any) -> tuple[Mapping[str, Any], Any | None]:
    """Return the one reviewed attributes map and optional TA authority host."""

    if not isinstance(record, Mapping):
        _fail("invalid_native_record", "Every ACI record must be an object.")

    if NATIVE_CLASS in record:
        native_object = record[NATIVE_CLASS]
        if not isinstance(native_object, Mapping):
            _fail("invalid_native_record", "APIC imdata object has an invalid shape.")
        attributes = native_object.get("attributes")
        if not isinstance(attributes, Mapping):
            _fail("invalid_native_record", "APIC imdata attributes are required.")
        return attributes, None

    if record.get("component") != NATIVE_CLASS:
        _fail("wrong_native_class", "Record is not a reviewed aaaModLR record.")
    native_host = record.get("apic_host")
    if not isinstance(native_host, str) or not native_host:
        _fail(
            "missing_native_authority",
            "TA-flattened aaaModLR records require apic_host.",
        )
    return record, native_host


def _native_text(value: Any, field: str, *, numeric: bool = False) -> str | None:
    """Keep source scalar values inert, converting only documented numeric IDs."""

    if value is None:
        return None
    if isinstance(value, str):
        return value
    if numeric and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    _fail("invalid_native_field", f"Native {field} must be text.")


def _event_time(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        _fail("invalid_time", "Native created must be offset-qualified ISO-8601 text.")
    return _iso_to_epoch(value)


def _authority_hosts(authority: str) -> set[str]:
    """Return host spellings that can bind a TA record to its receipt authority."""

    if not authority.startswith("https://"):
        return {authority.casefold()}
    parsed = urlsplit(authority)
    expected = {parsed.netloc.casefold()}
    if parsed.hostname:
        expected.add(parsed.hostname.casefold())
        if parsed.port is not None:
            expected.add(f"{parsed.hostname}:{parsed.port}".casefold())
    return expected


def adapt_aci_audits(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize ACI ``aaaModLR`` records into one immutable audit receipt.

    ``collection_metadata`` supplies receipt fields such as capture ID, APIC
    authority, exact APIC source version, fabric partition/scope, collection
    times, paging status, and permission fingerprint. The adapter fixes the
    product and family and always marks deletions non-authoritative. It uses
    native ``id`` for event identity, ``created`` for source event time, and
    ``user`` for actor; ``affected`` remains a separate managed-object DN.

    TA-flattened records must carry ``component=aaaModLR`` and an ``apic_host``
    matching the receipt authority. The configured ``apic_host`` identifies a
    fabric; ``actual_host`` may be a cluster member and is not used to invent
    a different authority. APIC imdata records have no host field, so their
    authority comes from the explicit collection metadata.
    """

    if not isinstance(native_records, Sequence) or isinstance(
        native_records, (str, bytes, bytearray)
    ):
        _fail("invalid_native_records", "ACI native records must be a bounded list.")
    if len(native_records) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if not isinstance(collection_metadata, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")

    metadata = dict(collection_metadata)
    if "objects" in metadata:
        _fail("invalid_collection", "Collection metadata must not supply objects.")
    if metadata.get("product", PRODUCT) != PRODUCT:
        _fail("wrong_product", "Collection metadata product must be aci.")
    if metadata.get("family", FAMILY) != FAMILY:
        _fail("wrong_family", "Collection metadata family must be aaa_mod_lr.")
    if metadata.get("deletions_authoritative", False) is not False:
        _fail(
            "invalid_deletion_authority",
            "ACI audit collections cannot establish authoritative deletions.",
        )

    normalized_objects: list[dict[str, Any]] = []
    native_hosts: list[Any] = []
    for record in native_records:
        attributes, native_host = _native_attributes(record)
        if native_host is not None:
            native_hosts.append(native_host)

        native_id = _native_text(attributes.get("id"), "id", numeric=True)
        if native_id is None or native_id == "":
            _fail("missing_native_id", "Every aaaModLR record requires native id.")

        actor = _native_text(attributes.get("user"), "user")
        fields: dict[str, str] = {}
        for source_name, normalized_name in _AUDIT_FIELDS.items():
            value = _native_text(
                attributes.get(source_name),
                source_name,
                numeric=source_name == "txId",
            )
            if value is not None and value != "":
                fields[normalized_name] = value

        normalized_objects.append(
            {
                "object_id": native_id,
                "revision": None,
                "observed_at": metadata.get("received_at"),
                "event_at": _event_time(attributes.get("created")),
                "effective_at": None,
                "kind": "audit",
                "actor": actor,
                "fields": fields,
            }
        )

    # The normalizer validates metadata, text safety, times, page coverage, and
    # duplicate/conflicting native IDs before the receipt can be returned.
    normalized = normalize_collection(
        {
            **metadata,
            "schema_version": metadata.get("schema_version", 1),
            "product": PRODUCT,
            "family": FAMILY,
            "deletions_authoritative": False,
            "objects": normalized_objects,
        }
    )

    expected_hosts = _authority_hosts(normalized["authority"])
    for native_host in native_hosts:
        if (
            not isinstance(native_host, str)
            or native_host.casefold() not in expected_hosts
        ):
            _fail(
                "wrong_authority",
                "TA record apic_host does not match the collection authority.",
            )
    return normalized


def _policy_node(
    record: Any,
    node_budget: list[int],
) -> tuple[str, Mapping[str, Any], list[Any], Any | None]:
    """Read one APIC class node or one reviewed TA-flattened record."""

    node_budget[0] += 1
    if node_budget[0] > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if not isinstance(record, Mapping):
        _fail("invalid_native_record", "Every ACI policy record must be an object.")
    if "error" in record:
        _fail("native_source_error", "APIC returned an error object.")

    if "component" in record:
        native_class = record.get("component")
        native_host = record.get("apic_host")
        if not isinstance(native_class, str):
            _fail("invalid_native_record", "TA component must identify an ACI class.")
        if not isinstance(native_host, str) or not native_host:
            _fail(
                "missing_native_authority",
                "TA-flattened policy records require apic_host.",
            )
        if native_class in {"vzFilter", "vzBrCP", "fvAEPg"}:
            _fail(
                "incomplete_native_record",
                "TA-flattened ACI containers cannot prove complete child enumeration.",
            )
        return native_class, record, [], native_host

    if len(record) != 1:
        _fail("invalid_native_record", "APIC imdata element must contain one class.")
    native_class = next(iter(record))
    class_object = record[native_class]
    if not isinstance(class_object, Mapping):
        _fail("invalid_native_record", "APIC class object has an invalid shape.")
    attributes = class_object.get("attributes")
    if not isinstance(attributes, Mapping):
        _fail("invalid_native_record", "APIC class attributes are required.")
    children = class_object.get("children", [])
    if not isinstance(children, list):
        _fail("invalid_native_record", "APIC children must be an array.")
    return native_class, attributes, children, None


def _policy_dn(value: Any) -> str:
    dn = _native_text(value, "dn")
    if dn is None or dn == "":
        _fail("missing_native_dn", "Every ACI policy object requires native dn.")
    return dn


def _put_text(
    fields: dict[str, str], normalized_name: str, value: Any, native_name: str
) -> None:
    text_value = _native_text(value, native_name)
    if text_value is not None and text_value != "":
        fields[normalized_name] = text_value


def _policy_fields(
    family: str,
    native_class: str,
    attributes: Mapping[str, Any],
    *,
    parent_dn: str | None,
    children: list[Any] | None = None,
    node_budget: list[int],
    native_hosts: list[Any],
) -> dict[str, Any]:
    fields: dict[str, str] = {"object_class": native_class}
    _put_text(fields, "name", attributes.get("name"), "name")
    if parent_dn is not None:
        fields["parent_dn"] = parent_dn

    if family == "filter_entry_snapshot":
        if native_class != "vzEntry":
            _fail("unsupported_native_class", "Only vzEntry objects are reviewed here.")
        for source_name, normalized_name in (
            ("etherT", "ether_type"),
            ("prot", "protocol"),
            ("sFromPort", "source_from_port"),
            ("sToPort", "source_to_port"),
            ("dFromPort", "destination_from_port"),
            ("dToPort", "destination_to_port"),
        ):
            _put_text(fields, normalized_name, attributes.get(source_name), source_name)
    elif family == "contract_subject_snapshot":
        if native_class == "vzSubj":
            _put_text(
                fields,
                "reverse_filter_ports",
                attributes.get("revFltPorts"),
                "revFltPorts",
            )
            _put_text(
                fields,
                "provider_match_type",
                attributes.get("provmatchT"),
                "provmatchT",
            )
        elif native_class == "vzRsSubjFiltAtt":
            # tDn is a native reference. tnVzFilterName remains a label; never
            # construct a tenant-qualified DN from that name.
            _put_text(fields, "target_dn", attributes.get("tDn"), "tDn")
            _put_text(
                fields,
                "filter_name",
                attributes.get("tnVzFilterName"),
                "tnVzFilterName",
            )
        else:
            _fail(
                "unsupported_native_class",
                "Only vzSubj and vzRsSubjFiltAtt objects are reviewed here.",
            )
    elif family == "epg_contract_attachment_snapshot":
        if native_class not in _EPG_RELATIONS:
            _fail(
                "unsupported_native_class",
                "Only fvRsCons and fvRsProv objects are reviewed here.",
            )
        fields["role"] = "consumer" if native_class == "fvRsCons" else "provider"
        _put_text(fields, "target_dn", attributes.get("tDn"), "tDn")
        _put_text(
            fields,
            "contract_name",
            attributes.get("tnVzBrCPName"),
            "tnVzBrCPName",
        )
        expected_labels = (
            _CONSUMER_LABEL_CLASSES
            if native_class == "fvRsCons"
            else _PROVIDER_LABEL_CLASSES
        )
        labels: list[str] = []
        for child in children or []:
            child_class, child_attributes, child_children, child_host = _policy_node(
                child, node_budget
            )
            if child_host is not None:
                native_hosts.append(child_host)
            if child_class not in expected_labels or child_children:
                _fail(
                    "unsupported_native_class",
                    "Attachment contains an unreviewed child object.",
                )
            label = _native_text(child_attributes.get("name"), "name")
            if label is None or label == "":
                _fail("missing_native_field", "Attachment label requires native name.")
            labels.append(label)
        if len(labels) > 1:
            _fail(
                "multiple_attachment_labels",
                "Multiple attachment labels cannot be represented by one scalar.",
            )
        if labels:
            fields["match_label"] = labels[0]
    else:
        _fail("unsupported_family", "ACI policy family is not reviewed.")
    return fields


def _append_policy_object(
    output: list[dict[str, Any]],
    family: str,
    native_class: str,
    attributes: Mapping[str, Any],
    *,
    parent_dn: str | None,
    children: list[Any] | None = None,
    node_budget: list[int],
    observed_at: Any,
    native_hosts: list[Any],
) -> None:
    output.append(
        {
            "object_id": _policy_dn(attributes.get("dn")),
            "revision": None,
            "observed_at": observed_at,
            "event_at": None,
            "effective_at": None,
            "kind": "configuration",
            "actor": None,
            "fields": _policy_fields(
                family,
                native_class,
                attributes,
                parent_dn=parent_dn,
                children=children,
                node_budget=node_budget,
                native_hosts=native_hosts,
            ),
        }
    )


def _append_contract_subject(
    output: list[dict[str, Any]],
    attributes: Mapping[str, Any],
    children: list[Any],
    *,
    contract_dn: str | None,
    node_budget: list[int],
    observed_at: Any,
    native_hosts: list[Any],
) -> None:
    subject_dn = _policy_dn(attributes.get("dn"))
    _append_policy_object(
        output,
        "contract_subject_snapshot",
        "vzSubj",
        attributes,
        parent_dn=contract_dn,
        node_budget=node_budget,
        observed_at=observed_at,
        native_hosts=native_hosts,
    )
    for child in children:
        child_class, child_attributes, child_children, child_host = _policy_node(
            child, node_budget
        )
        if child_host is not None:
            native_hosts.append(child_host)
        if child_class != "vzRsSubjFiltAtt" or child_children:
            _fail(
                "unsupported_native_class",
                "Contract subject contains an unreviewed child object.",
            )
        _append_policy_object(
            output,
            "contract_subject_snapshot",
            child_class,
            child_attributes,
            parent_dn=subject_dn,
            node_budget=node_budget,
            observed_at=observed_at,
            native_hosts=native_hosts,
        )


def _append_epg_attachment(
    output: list[dict[str, Any]],
    native_class: str,
    attributes: Mapping[str, Any],
    children: list[Any],
    *,
    epg_dn: str | None,
    node_budget: list[int],
    observed_at: Any,
    native_hosts: list[Any],
) -> None:
    _append_policy_object(
        output,
        "epg_contract_attachment_snapshot",
        native_class,
        attributes,
        parent_dn=epg_dn,
        children=children,
        node_budget=node_budget,
        observed_at=observed_at,
        native_hosts=native_hosts,
    )


def _adapt_policy_records(
    native_records: Sequence[Any], family: str, observed_at: Any
) -> tuple[list[dict[str, Any]], list[Any]]:
    output: list[dict[str, Any]] = []
    native_hosts: list[Any] = []
    node_budget = [0]
    for record in native_records:
        native_class, attributes, children, native_host = _policy_node(
            record, node_budget
        )
        if native_host is not None:
            native_hosts.append(native_host)

        if family == "filter_entry_snapshot":
            if native_class == "vzEntry":
                if children:
                    _fail("unsupported_native_class", "vzEntry must not have children.")
                _append_policy_object(
                    output,
                    family,
                    native_class,
                    attributes,
                    parent_dn=None,
                    node_budget=node_budget,
                    observed_at=observed_at,
                    native_hosts=native_hosts,
                )
            elif native_class == "vzFilter":
                filter_dn = _policy_dn(attributes.get("dn"))
                for child in children:
                    child_class, child_attributes, child_children, child_host = (
                        _policy_node(child, node_budget)
                    )
                    if child_host is not None:
                        native_hosts.append(child_host)
                    if child_class != "vzEntry" or child_children:
                        _fail(
                            "unsupported_native_class",
                            "Filter contains an unreviewed child object.",
                        )
                    _append_policy_object(
                        output,
                        family,
                        child_class,
                        child_attributes,
                        parent_dn=filter_dn,
                        node_budget=node_budget,
                        observed_at=observed_at,
                        native_hosts=native_hosts,
                    )
            else:
                _fail(
                    "unsupported_native_class",
                    "Only vzFilter containers and vzEntry objects are reviewed here.",
                )
        elif family == "contract_subject_snapshot":
            if native_class == "vzBrCP":
                contract_dn = _policy_dn(attributes.get("dn"))
                for child in children:
                    child_class, child_attributes, child_children, child_host = (
                        _policy_node(child, node_budget)
                    )
                    if child_host is not None:
                        native_hosts.append(child_host)
                    if child_class != "vzSubj":
                        _fail(
                            "unsupported_native_class",
                            "Contract contains an unreviewed child object.",
                        )
                    _append_contract_subject(
                        output,
                        child_attributes,
                        child_children,
                        contract_dn=contract_dn,
                        node_budget=node_budget,
                        observed_at=observed_at,
                        native_hosts=native_hosts,
                    )
            elif native_class == "vzSubj":
                _append_contract_subject(
                    output,
                    attributes,
                    children,
                    contract_dn=None,
                    node_budget=node_budget,
                    observed_at=observed_at,
                    native_hosts=native_hosts,
                )
            elif native_class == "vzRsSubjFiltAtt":
                if children:
                    _fail(
                        "unsupported_native_class",
                        "Filter-reference relation must not have children.",
                    )
                _append_policy_object(
                    output,
                    family,
                    native_class,
                    attributes,
                    parent_dn=None,
                    node_budget=node_budget,
                    observed_at=observed_at,
                    native_hosts=native_hosts,
                )
            else:
                _fail(
                    "unsupported_native_class",
                    "Only vzBrCP, vzSubj, and vzRsSubjFiltAtt are reviewed here.",
                )
        elif family == "epg_contract_attachment_snapshot":
            if native_class == "fvAEPg":
                epg_dn = _policy_dn(attributes.get("dn"))
                for child in children:
                    child_class, child_attributes, child_children, child_host = (
                        _policy_node(child, node_budget)
                    )
                    if child_host is not None:
                        native_hosts.append(child_host)
                    if child_class in _EPG_RELATIONS:
                        _append_epg_attachment(
                            output,
                            child_class,
                            child_attributes,
                            child_children,
                            epg_dn=epg_dn,
                            node_budget=node_budget,
                            observed_at=observed_at,
                            native_hosts=native_hosts,
                        )
                    elif child_class not in _EPG_KNOWN_SIBLINGS:
                        _fail(
                            "unsupported_native_class",
                            "EPG contains an unreviewed child object.",
                        )
            elif native_class in _EPG_RELATIONS:
                _append_epg_attachment(
                    output,
                    native_class,
                    attributes,
                    children,
                    epg_dn=None,
                    node_budget=node_budget,
                    observed_at=observed_at,
                    native_hosts=native_hosts,
                )
            else:
                _fail(
                    "unsupported_native_class",
                    "Only fvAEPg, fvRsCons, and fvRsProv are reviewed here.",
                )
        else:
            _fail("unsupported_family", "ACI policy family is not reviewed.")
    return output, native_hosts


def adapt_aci_policy_snapshots(
    native_records: Sequence[Mapping[str, Any]],
    collection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one reviewed ACI policy family into a snapshot receipt.

    The family is selected by required collection metadata and must be one of
    ``filter_entry_snapshot``, ``contract_subject_snapshot``, or
    ``epg_contract_attachment_snapshot``. APIC class nodes can be supplied
    directly or as their documented parent/child tree. TA-flattened class rows
    are also accepted, with parent DNs omitted when the source record does not
    carry its native parent context.

    Object identity is always native ``dn``. Parent DNs come only from an
    enclosing APIC parent object's native DN; cross-object ``target_dn`` is
    taken only from native ``tDn``. Name-based fields remain labels and are
    never expanded into tenant-qualified DNs. Unknown classes, malformed APIC
    error records, unsupported relationship children, and multiple EPG match
    labels fail closed. The shared collection contract validates page counts
    and preserves caller-attested completeness and deletion authority.
    """

    if not isinstance(collection_metadata, Mapping):
        _fail("invalid_collection", "Collection metadata must be an object.")
    metadata = dict(collection_metadata)
    if "objects" in metadata:
        _fail("invalid_collection", "Collection metadata must not supply objects.")
    family = metadata.get("family")
    if not isinstance(family, str) or family not in _POLICY_FAMILIES:
        _fail("unsupported_family", "ACI policy family is not reviewed.")
    if metadata.get("product", PRODUCT) != PRODUCT:
        _fail("wrong_product", "Collection metadata product must be aci.")
    if metadata.get("deletions_authoritative") is True and (
        metadata.get("status") != "complete" or metadata.get("enumeration") != "full"
    ):
        _fail(
            "invalid_deletion_authority",
            "ACI policy deletions require a complete full enumeration.",
        )
    if not isinstance(native_records, Sequence) or isinstance(
        native_records, (str, bytes, bytearray)
    ):
        _fail("invalid_native_records", "ACI native records must be a bounded list.")
    if len(native_records) > MAX_OBJECTS:
        _fail("object_limit", "Input exceeds the 10,000-object limit.")
    if len(native_records) == 1 and isinstance(native_records[0], Mapping):
        maybe_imdata = native_records[0]
        if set(maybe_imdata) == {"imdata"}:
            native_records = maybe_imdata["imdata"]
            if not isinstance(native_records, list):
                _fail("invalid_native_records", "APIC imdata must be an array.")

    objects, native_hosts = _adapt_policy_records(
        native_records, family, metadata.get("received_at")
    )
    normalized = normalize_collection(
        {
            **metadata,
            "schema_version": metadata.get("schema_version", 1),
            "product": PRODUCT,
            "objects": objects,
        }
    )
    expected_hosts = _authority_hosts(normalized["authority"])
    for native_host in native_hosts:
        if (
            not isinstance(native_host, str)
            or native_host.casefold() not in expected_hosts
        ):
            _fail(
                "wrong_authority",
                "TA record apic_host does not match the collection authority.",
            )
    return normalized
