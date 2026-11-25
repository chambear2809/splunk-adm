"""Offline adapters for reviewed Kubernetes and Cilium object receipts.

The adapters accept decoded, versioned Kubernetes API JSON only. They do not
connect to a cluster. Snapshot adapters project a bounded field allowlist before
calling the shared normalized collection contract; watch events use a separate
operational family and never establish snapshot additions or removals.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any, Callable

from ..contracts import (
    MAX_FIELDS,
    MAX_LIST_ITEMS,
    MAX_OBJECTS,
    MAX_TEXT,
    ContractError,
    canonical_json,
    normalize_collection,
)

_BASE_METADATA_KEYS = {
    "schema_version",
    "capture_id",
    "authority",
    "source_version",
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
_CONTROL_METADATA_KEYS = {
    "initial_state_complete",
    "watch_contiguous",
    "watch_ended",
    "start_resource_version",
    "expected_resource_kind",
    "qualified_gvks",
}
_ALLOWED_METADATA_KEYS = _BASE_METADATA_KEYS | _CONTROL_METADATA_KEYS
_RESOURCE_APIS = {
    "Service": "v1",
    "EndpointSlice": "discovery.k8s.io/v1",
    "Pod": "v1",
    "CiliumNetworkPolicy": "cilium.io/v2",
    "CiliumClusterwideNetworkPolicy": "cilium.io/v2",
}
_RESOURCE_LISTS = {
    ("v1", "ServiceList"): ("Service", "kubernetes", "service_snapshot"),
    ("discovery.k8s.io/v1", "EndpointSliceList"): (
        "EndpointSlice",
        "kubernetes",
        "endpointslice_snapshot",
    ),
    ("v1", "PodList"): ("Pod", "kubernetes", "pod_snapshot"),
    ("cilium.io/v2", "CiliumNetworkPolicyList"): (
        "CiliumNetworkPolicy",
        "cilium",
        "policy_snapshot",
    ),
    ("cilium.io/v2", "CiliumClusterwideNetworkPolicyList"): (
        "CiliumClusterwideNetworkPolicy",
        "cilium",
        "policy_snapshot",
    ),
}
_CILIUM_KINDS = {
    "CiliumNetworkPolicy",
    "CiliumClusterwideNetworkPolicy",
}
_CILIUM_LABEL_ALLOWLIST = (
    "app.kubernetes.io/instance",
    "app.kubernetes.io/managed-by",
    "app.kubernetes.io/name",
    "io.cilium.k8s.policy.derived-from",
    "io.cilium.k8s.policy.name",
    "io.cilium.k8s.policy.namespace",
)
_POD_LABEL_ALLOWLIST = (
    "app.kubernetes.io/component",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/name",
    "app.kubernetes.io/part-of",
    "app.kubernetes.io/version",
)
_UID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,512}$")
_RESOURCE_VERSION_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_WATCH_TYPES = {"ADDED", "MODIFIED", "DELETED"}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail("invalid_native_shape", f"{field} must be an object.")
    return value


def _native_text(
    value: Any,
    field: str,
    *,
    required: bool = False,
    max_length: int = MAX_TEXT,
) -> str | None:
    if value is None or value == "":
        if required:
            _fail("missing_native_field", f"{field} is required.")
        return None
    if not isinstance(value, str):
        _fail("invalid_native_field", f"{field} must be text.")
    result = value.strip()
    if not result:
        if required:
            _fail("missing_native_field", f"{field} is required.")
        return None
    if len(result) > max_length or any(
        ord(char) < 32 or ord(char) == 127 for char in result
    ):
        _fail("invalid_native_field", f"{field} is outside the supported text range.")
    return result


def _native_uid(value: Any, field: str = "metadata.uid") -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail("missing_native_field", f"{field} must be a non-empty opaque string.")
    if len(value) > MAX_TEXT or not _UID_PATTERN.fullmatch(value):
        _fail("invalid_native_field", f"{field} is not a supported opaque UID.")
    return value


def _native_resource_version(
    value: Any, field: str = "metadata.resourceVersion"
) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail("invalid_native_field", f"{field} must be a non-empty opaque string.")
    if len(value) > MAX_TEXT or not _RESOURCE_VERSION_PATTERN.fullmatch(value):
        _fail("invalid_native_field", f"{field} is not a supported opaque revision.")
    return value


def _metadata(metadata: Any) -> dict[str, Any]:
    result = dict(_mapping(metadata, "collection_metadata"))
    unknown = set(result) - _ALLOWED_METADATA_KEYS
    if unknown:
        _fail(
            "unknown_adapter_metadata", "Collection metadata contains an unknown field."
        )
    for field in (
        "initial_state_complete",
        "watch_contiguous",
        "watch_ended",
        "deletions_authoritative",
    ):
        if field in result and not isinstance(result[field], bool):
            _fail("invalid_collection_metadata", f"{field} must be boolean.")
    return result


def _collection(
    metadata: dict[str, Any],
    *,
    product: str,
    family: str,
    objects: list[dict[str, Any]],
    status: str | None = None,
    enumeration: str | None = None,
    deletions_authoritative: bool | None = None,
    pages_expected: int | None = None,
    pages_received: int | None = None,
    source_reference: str | None = None,
) -> dict[str, Any]:
    raw = {
        "schema_version": metadata.get("schema_version", 1),
        "capture_id": metadata.get("capture_id"),
        "product": product,
        "authority": metadata.get("authority"),
        "source_version": metadata.get("source_version"),
        "family": family,
        "partition": metadata.get("partition"),
        "scope": metadata.get("scope"),
        "started_at": metadata.get("started_at"),
        "completed_at": metadata.get("completed_at"),
        "received_at": metadata.get("received_at"),
        "status": status if status is not None else metadata.get("status", "partial"),
        "permissions_fingerprint": metadata.get("permissions_fingerprint"),
        "pages_expected": (
            pages_expected
            if pages_expected is not None
            else metadata.get("pages_expected", 0)
        ),
        "pages_received": (
            pages_received
            if pages_received is not None
            else metadata.get("pages_received", 0)
        ),
        "source_reference": (
            source_reference
            if source_reference is not None
            else metadata.get("source_reference")
        ),
        "enumeration": (
            enumeration
            if enumeration is not None
            else metadata.get("enumeration", "incremental")
        ),
        "deletions_authoritative": (
            deletions_authoritative
            if deletions_authoritative is not None
            else metadata.get("deletions_authoritative", False)
        ),
        "objects": objects,
    }
    return normalize_collection(raw)


def _append_source_marker(source_reference: Any, marker: str) -> str:
    reference = _native_text(source_reference, "source_reference")
    if reference is None:
        return marker
    combined = f"{reference}|{marker}"
    if len(combined) > MAX_TEXT:
        digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()[:16]
        return f"{marker}|ref-sha256:{digest}"
    return combined


def _status_error_collection(
    payload: Any,
    metadata: dict[str, Any],
    *,
    product: str,
    family: str,
    marker_prefix: str,
) -> dict[str, Any]:
    error = _mapping(payload, "API Status")
    api_error = _is_api_error(error)
    if api_error is None:
        _fail(
            "invalid_api_error", "Native API error is not a Kubernetes Status object."
        )
    _reason, status_code = api_error
    if status_code == 410:
        status = "partial"
        marker = f"{marker_prefix}:410-gone-relist-required"
    else:
        status = "failed"
        marker = (
            f"{marker_prefix}:error:{status_code}"
            if status_code is not None
            else f"{marker_prefix}:error"
        )
    return _collection(
        metadata,
        product=product,
        family=family,
        objects=[],
        status=status,
        enumeration="incremental",
        deletions_authoritative=False,
        source_reference=_append_source_marker(
            metadata.get("source_reference"), marker
        ),
    )


def _is_watch_payload(payload: Any) -> bool:
    if isinstance(payload, Mapping):
        return "type" in payload and "object" in payload
    return (
        isinstance(payload, Sequence)
        and not isinstance(payload, (str, bytes, bytearray))
        and bool(payload)
        and all(
            isinstance(item, Mapping) and "type" in item and "object" in item
            for item in payload
        )
    )


def _is_api_error(payload: Mapping[str, Any]) -> tuple[str, int | None] | None:
    if payload.get("kind") != "Status":
        return None
    if payload.get("apiVersion") != "v1":
        _fail("invalid_watch", "Watch ERROR uses an unsupported Status API version.")
    reason = _native_text(payload.get("reason"), "status.reason")
    code = payload.get("code")
    if isinstance(code, bool) or not isinstance(code, int):
        code = None
    return reason or "unknown", code


def _authority_partition(metadata: dict[str, Any]) -> tuple[str, str]:
    authority = _native_text(metadata.get("authority"), "authority", required=True)
    partition = _native_text(metadata.get("partition"), "partition", required=True)
    assert authority is not None and partition is not None
    return authority, partition


def _partition_namespace(metadata: dict[str, Any]) -> str | None:
    """Return a selected namespace, or None for the exact cluster authority.

    `scope` is a shared cross-source routing label and is intentionally not
    consulted here. Kubernetes enumeration selection is carried by partition.
    """

    authority, partition = _authority_partition(metadata)
    if partition == authority:
        return None
    prefix = "namespace:"
    if not partition.startswith(prefix):
        _fail(
            "partition_mismatch",
            "Kubernetes partition must equal cluster authority or name one namespace.",
        )
    namespace = partition[len(prefix) :]
    if (
        len(namespace) > 63
        or not _NAMESPACE_PATTERN.fullmatch(namespace)
        or namespace != namespace.lower()
    ):
        _fail(
            "invalid_partition",
            "Kubernetes namespace partition is not a valid native namespace.",
        )
    return namespace


def _check_namespace_partition(metadata: dict[str, Any], namespace: str | None) -> None:
    selected_namespace = _partition_namespace(metadata)
    if namespace is None:
        if selected_namespace is not None:
            _fail(
                "partition_mismatch",
                "Cluster-scoped resource requires the exact cluster authority partition.",
            )
        return
    if selected_namespace is not None and selected_namespace != namespace:
        _fail(
            "partition_mismatch",
            "Native namespace does not match the Kubernetes partition.",
        )


def _validate_list_partition(metadata: dict[str, Any], resource_kind: str) -> None:
    selected_namespace = _partition_namespace(metadata)
    if resource_kind == "CiliumClusterwideNetworkPolicy" and selected_namespace:
        _fail(
            "partition_mismatch",
            "Cluster-scoped resource requires the exact cluster authority partition.",
        )


def _resource_meta(
    value: Any,
    *,
    namespaced: bool = True,
    collection_metadata: dict[str, Any],
) -> tuple[Mapping[str, Any], str, str, str | None]:
    item = _mapping(value, "resource")
    native_metadata = _mapping(item.get("metadata"), "resource.metadata")
    uid = _native_uid(native_metadata.get("uid"))
    resource_version = _native_resource_version(native_metadata.get("resourceVersion"))
    _native_text(native_metadata.get("name"), "metadata.name", required=True)
    namespace = _native_text(native_metadata.get("namespace"), "metadata.namespace")
    if namespaced and namespace is None:
        _fail(
            "missing_native_field", "metadata.namespace is required for this resource."
        )
    if not namespaced and namespace is not None:
        _fail("scope_mismatch", "Cluster-scoped resource must not have a namespace.")
    _check_namespace_partition(collection_metadata, namespace)
    return native_metadata, uid, resource_version, namespace


def _base_object(
    *,
    object_id: str,
    revision: str,
    observed_at: Any,
    kind: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    return {
        "object_id": object_id,
        "revision": revision,
        "observed_at": observed_at,
        "event_at": None,
        "effective_at": None,
        "kind": kind,
        "actor": None,
        "fields": fields,
    }


def _observed_at(metadata: dict[str, Any]) -> Any:
    completed_at = metadata.get("completed_at")
    return completed_at if completed_at is not None else metadata.get("received_at")


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _label_map(value: Any, field: str) -> dict[str, str]:
    if value is None:
        return {}
    labels = _mapping(value, field)
    if len(labels) > MAX_FIELDS:
        _fail("native_field_limit", f"{field} exceeds the supported label count.")
    result: dict[str, str] = {}
    for key, label_value in labels.items():
        if not isinstance(key, str) or key != key.strip():
            _fail("invalid_native_field", f"{field} contains an invalid label key.")
        label_key = _native_text(key, f"{field}.key", required=True, max_length=317)
        if (
            not isinstance(label_value, str)
            or label_value != label_value.strip()
            or len(label_value) > 63
            or any(ord(char) < 32 or ord(char) == 127 for char in label_value)
        ):
            _fail("invalid_native_field", f"{field} must contain bounded text pairs.")
        if label_key is None:
            _fail("invalid_native_field", f"{field} must contain non-empty text pairs.")
        result[label_key] = label_value
    return result


def _service_ports(
    spec: Mapping[str, Any],
) -> tuple[list[int], list[str], list[str], list[str]]:
    raw_ports = spec.get("ports", [])
    if raw_ports is None:
        raw_ports = []
    if not isinstance(raw_ports, list) or len(raw_ports) > MAX_LIST_ITEMS:
        _fail("invalid_native_shape", "spec.ports must be a bounded array.")

    tuples: list[tuple[str, bytes, int, str, str]] = []
    for port in raw_ports:
        native_port = _mapping(port, "spec.ports[]")
        number = native_port.get("port")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not 1 <= number <= 65535
        ):
            _fail(
                "invalid_native_field", "spec.ports[].port must be a valid port number."
            )
        protocol = _native_text(
            native_port.get("protocol") or "TCP", "spec.ports[].protocol", required=True
        )
        if protocol not in {"TCP", "UDP", "SCTP"}:
            _fail("unknown_native_enum", "spec.ports[].protocol is unsupported.")
        target = native_port.get("targetPort", number)
        if isinstance(target, bool) or not isinstance(target, (str, int)):
            _fail(
                "invalid_native_field",
                "spec.ports[].targetPort must be text or an integer.",
            )
        if isinstance(target, int):
            if not 1 <= target <= 65535:
                _fail(
                    "invalid_native_field",
                    "spec.ports[].targetPort is outside the port range.",
                )
            target_text = str(target)
        else:
            target_text = (
                _native_text(target, "spec.ports[].targetPort", required=True) or ""
            )
        name = _native_text(native_port.get("name"), "spec.ports[].name")
        tuple_value = [name, protocol, number, target_text]
        encoded = canonical_json(tuple_value)
        tuples.append((encoded.decode("utf-8"), encoded, number, protocol, target_text))
    tuples = sorted(
        {item[1]: item for item in tuples}.values(),
        key=lambda item: item[1],
    )
    return (
        [item[2] for item in tuples],
        [item[3] for item in tuples],
        [item[4] for item in tuples],
        [item[0] for item in tuples],
    )


def _service_object(
    resource: Any, collection_metadata: dict[str, Any]
) -> dict[str, Any]:
    item = _mapping(resource, "Service")
    if item.get("apiVersion") != "v1" or item.get("kind") != "Service":
        _fail(
            "unknown_resource_kind",
            "Service list contains an unsupported resource kind or version.",
        )
    native_metadata, uid, revision, _namespace = _resource_meta(
        item, collection_metadata=collection_metadata
    )
    spec = _mapping(item.get("spec"), "Service.spec")
    selector = spec.get("selector")
    if selector is None:
        selector_values: dict[str, str] | None = None
        selector_keys: list[str] = []
    else:
        selector_values = _label_map(selector, "Service.spec.selector")
        selector_keys = sorted(selector_values)
    selector_digest = _canonical_digest(
        {"present": selector_values is not None, "values": selector_values or {}}
    )
    port_numbers, protocols, target_ports, port_tuples = _service_ports(spec)
    service_type = _native_text(
        spec.get("type") or "ClusterIP", "Service.spec.type", required=True
    )
    if service_type not in {"ClusterIP", "NodePort", "LoadBalancer", "ExternalName"}:
        _fail("unknown_native_enum", "Service.spec.type is unsupported.")
    external_policy = _native_text(
        spec.get("externalTrafficPolicy") or "Cluster",
        "Service.spec.externalTrafficPolicy",
        required=True,
    )
    internal_policy = _native_text(
        spec.get("internalTrafficPolicy") or "Cluster",
        "Service.spec.internalTrafficPolicy",
        required=True,
    )
    if external_policy not in {"Cluster", "Local"}:
        _fail(
            "unknown_native_enum", "Service.spec.externalTrafficPolicy is unsupported."
        )
    if internal_policy not in {"Cluster", "Local"}:
        _fail(
            "unknown_native_enum", "Service.spec.internalTrafficPolicy is unsupported."
        )
    fields = {
        "service_type": service_type,
        "selector_keys": selector_keys,
        "selector_digest": selector_digest,
        "port_numbers": port_numbers,
        "target_ports": target_ports,
        "protocols": protocols,
        "port_tuples": port_tuples,
        "external_traffic_policy": external_policy,
        "internal_traffic_policy": internal_policy,
    }
    return _base_object(
        object_id=uid,
        revision=revision,
        observed_at=_observed_at(collection_metadata),
        kind="configuration",
        fields=fields,
    )


def _endpoint_slice_ports(spec: Mapping[str, Any]) -> tuple[list[int], list[str]]:
    raw_ports = spec.get("ports", [])
    if raw_ports is None:
        raw_ports = []
    if not isinstance(raw_ports, list) or len(raw_ports) > MAX_LIST_ITEMS:
        _fail("invalid_native_shape", "EndpointSlice.ports must be a bounded array.")
    tuples: list[tuple[bytes, int | None, str]] = []
    for port in raw_ports:
        native_port = _mapping(port, "EndpointSlice.ports[]")
        name = _native_text(native_port.get("name"), "EndpointSlice.ports[].name")
        protocol = _native_text(
            native_port.get("protocol") or "TCP",
            "EndpointSlice.ports[].protocol",
            required=True,
        )
        if protocol not in {"TCP", "UDP", "SCTP"}:
            _fail("unknown_native_enum", "EndpointSlice port protocol is unsupported.")
        number = native_port.get("port")
        if number is not None and (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not 1 <= number <= 65535
        ):
            _fail("invalid_native_field", "EndpointSlice.ports[].port is invalid.")
        encoded = canonical_json([name, protocol, number])
        tuples.append((encoded, number, encoded.decode("utf-8")))
    tuples = sorted(
        {item[0]: item for item in tuples}.values(),
        key=lambda item: item[0],
    )
    return (
        [item[1] for item in tuples if item[1] is not None],
        [item[2] for item in tuples],
    )


def _qualified_pod_target_ref(value: Any, namespace: str) -> str | None:
    if not isinstance(value, Mapping):
        return None
    if value.get("kind") != "Pod" or value.get("apiVersion") != "v1":
        return None
    target_namespace = _native_text(
        value.get("namespace"), "endpoint.targetRef.namespace"
    )
    if target_namespace != namespace:
        return None
    try:
        return _native_uid(value.get("uid"), "endpoint.targetRef.uid")
    except ContractError:
        return None


def _endpoint_slice_object(
    resource: Any, collection_metadata: dict[str, Any]
) -> dict[str, Any]:
    item = _mapping(resource, "EndpointSlice")
    if (
        item.get("apiVersion") != "discovery.k8s.io/v1"
        or item.get("kind") != "EndpointSlice"
    ):
        _fail(
            "unknown_resource_kind",
            "EndpointSlice list contains an unsupported resource kind or version.",
        )
    native_metadata, uid, revision, namespace = _resource_meta(
        item, collection_metadata=collection_metadata
    )
    assert namespace is not None
    address_type = _native_text(
        item.get("addressType"), "EndpointSlice.addressType", required=True
    )
    if address_type not in {"IPv4", "IPv6", "FQDN"}:
        _fail("unknown_native_enum", "EndpointSlice.addressType is unsupported.")
    raw_endpoints = item.get("endpoints", [])
    if raw_endpoints is None:
        raw_endpoints = []
    if not isinstance(raw_endpoints, list) or len(raw_endpoints) > MAX_OBJECTS:
        _fail(
            "invalid_native_shape", "EndpointSlice.endpoints must be a bounded array."
        )

    ready_uids: set[str] = set()
    not_ready_uids: set[str] = set()
    unresolved_count = 0
    readiness_by_uid: dict[str, bool] = {}
    endpoint_count_by_uid: dict[str, int] = {}
    conflicted_uids: set[str] = set()
    for endpoint in raw_endpoints:
        native_endpoint = _mapping(endpoint, "EndpointSlice.endpoints[]")
        target_uid = _qualified_pod_target_ref(
            native_endpoint.get("targetRef"), namespace
        )
        conditions = native_endpoint.get("conditions")
        ready = conditions.get("ready") if isinstance(conditions, Mapping) else None
        if target_uid is None or not isinstance(ready, bool):
            unresolved_count += 1
            continue
        if target_uid in conflicted_uids:
            unresolved_count += 1
            continue
        if target_uid in readiness_by_uid and readiness_by_uid[target_uid] != ready:
            conflicted_uids.add(target_uid)
            unresolved_count += endpoint_count_by_uid[target_uid] + 1
            ready_uids.discard(target_uid)
            not_ready_uids.discard(target_uid)
            continue
        if target_uid in readiness_by_uid:
            endpoint_count_by_uid[target_uid] += 1
        else:
            readiness_by_uid[target_uid] = ready
            endpoint_count_by_uid[target_uid] = 1
            if ready:
                ready_uids.add(target_uid)
            else:
                not_ready_uids.add(target_uid)

    ports, port_tuples = _endpoint_slice_ports(item)
    labels = _label_map(native_metadata.get("labels"), "EndpointSlice.metadata.labels")
    service_name = _native_text(
        labels.get("kubernetes.io/service-name"),
        "EndpointSlice.metadata.labels[kubernetes.io/service-name]",
    )
    fields = {
        "service_name": service_name,
        "address_types": [address_type],
        "ports": ports,
        "port_tuples": port_tuples,
        "ready_count": len(ready_uids),
        "not_ready_count": len(not_ready_uids),
        "ready_backend_uids": sorted(ready_uids),
        "not_ready_backend_uids": sorted(not_ready_uids),
        "unresolved_endpoint_count": unresolved_count,
    }
    return _base_object(
        object_id=uid,
        revision=revision,
        observed_at=_observed_at(collection_metadata),
        kind="operational",
        fields=fields,
    )


def _pod_object(resource: Any, collection_metadata: dict[str, Any]) -> dict[str, Any]:
    item = _mapping(resource, "Pod")
    if item.get("apiVersion") != "v1" or item.get("kind") != "Pod":
        _fail(
            "unknown_resource_kind",
            "Pod list contains an unsupported resource kind or version.",
        )
    native_metadata, uid, revision, namespace = _resource_meta(
        item, collection_metadata=collection_metadata
    )
    assert namespace is not None
    name = _native_text(native_metadata.get("name"), "Pod.metadata.name", required=True)
    labels = _label_map(native_metadata.get("labels"), "Pod.metadata.labels")
    selected_labels = {
        key: labels[key] for key in _POD_LABEL_ALLOWLIST if key in labels
    }
    generation = native_metadata.get("generation")
    if generation is not None and (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or abs(generation) > 9_007_199_254_740_991
    ):
        _fail("invalid_native_field", "Pod.metadata.generation must be a safe integer.")

    owner_references = native_metadata.get("ownerReferences", [])
    if owner_references is None:
        owner_references = []
    if not isinstance(owner_references, list) or len(owner_references) > MAX_LIST_ITEMS:
        _fail(
            "invalid_native_shape",
            "Pod.metadata.ownerReferences must be a bounded array.",
        )
    controllers = [
        _mapping(owner, "Pod.metadata.ownerReferences[]")
        for owner in owner_references
        if isinstance(owner, Mapping) and owner.get("controller") is True
    ]
    if any(not isinstance(owner, Mapping) for owner in owner_references):
        _fail(
            "invalid_native_shape",
            "Pod.metadata.ownerReferences contains an invalid item.",
        )
    if len(controllers) > 1:
        _fail("invalid_native_shape", "Pod has multiple controller owner references.")
    owner_kind = None
    owner_uid = None
    if controllers:
        owner_kind = _native_text(
            controllers[0].get("kind"), "Pod.ownerReference.kind", required=True
        )
        owner_uid = _native_uid(controllers[0].get("uid"), "Pod.ownerReference.uid")

    status = item.get("status")
    phase = None
    if status is not None:
        status_mapping = _mapping(status, "Pod.status")
        phase = _native_text(status_mapping.get("phase"), "Pod.status.phase")
        if phase is not None and phase not in {
            "Pending",
            "Running",
            "Succeeded",
            "Failed",
            "Unknown",
        }:
            _fail("unknown_native_enum", "Pod.status.phase is unsupported.")
    spec = _mapping(item.get("spec"), "Pod.spec")
    fields = {
        "pod_name": name,
        "namespace": namespace,
        "node_name": _native_text(spec.get("nodeName"), "Pod.spec.nodeName"),
        "owner_kind": owner_kind,
        "owner_uid": owner_uid,
        "generation": generation,
        "phase": phase,
        "app_version_label_digest": _canonical_digest(selected_labels),
    }
    return _base_object(
        object_id=uid,
        revision=revision,
        observed_at=_observed_at(collection_metadata),
        kind="operational",
        fields=fields,
    )


def _cilium_policy_labels(native_metadata: Mapping[str, Any]) -> list[str]:
    labels = _label_map(native_metadata.get("labels"), "CiliumPolicy.metadata.labels")
    return sorted(
        f"{key}={_canonical_digest(labels[key])}"
        for key in _CILIUM_LABEL_ALLOWLIST
        if key in labels
    )


def _qualify_cilium_gvk(metadata: dict[str, Any], api_version: str, kind: str) -> None:
    qualified = metadata.get("qualified_gvks")
    if not isinstance(qualified, list) or any(
        not isinstance(item, str) for item in qualified
    ):
        _fail(
            "unqualified_crd",
            "Cilium input requires an explicit qualified_gvks attestation.",
        )
    gvk = f"{api_version}/{kind}"
    if gvk not in qualified:
        _fail(
            "unqualified_crd", "Cilium resource GVK is not in the qualified schema set."
        )


def _cilium_policy_object(
    resource: Any, collection_metadata: dict[str, Any]
) -> dict[str, Any]:
    item = _mapping(resource, "Cilium policy")
    api_version = _native_text(
        item.get("apiVersion"), "CiliumPolicy.apiVersion", required=True
    )
    policy_kind = _native_text(item.get("kind"), "CiliumPolicy.kind", required=True)
    if api_version != "cilium.io/v2" or policy_kind not in _CILIUM_KINDS:
        _fail("unknown_resource_kind", "Cilium policy uses an unsupported GVK.")
    _qualify_cilium_gvk(collection_metadata, api_version, policy_kind)
    namespaced = policy_kind == "CiliumNetworkPolicy"
    native_metadata, uid, revision, namespace = _resource_meta(
        item,
        namespaced=namespaced,
        collection_metadata=collection_metadata,
    )
    generation = native_metadata.get("generation")
    if generation is not None and (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or abs(generation) > 9_007_199_254_740_991
    ):
        _fail(
            "invalid_native_field", "Cilium metadata.generation must be a safe integer."
        )
    fields = {
        "api_version": api_version,
        "policy_kind": policy_kind,
        "namespace": namespace,
        "labels": _cilium_policy_labels(native_metadata),
        "generation": generation,
    }
    return _base_object(
        object_id=uid,
        revision=revision,
        observed_at=_observed_at(collection_metadata),
        kind="configuration",
        fields=fields,
    )


def _list_items(
    payload: Any,
    *,
    collection_metadata: dict[str, Any],
) -> tuple[str, str, list[Any], bool]:
    native_list = _mapping(payload, "list")
    api_version = _native_text(
        native_list.get("apiVersion"), "list.apiVersion", required=True
    )
    list_kind = _native_text(native_list.get("kind"), "list.kind", required=True)
    assert api_version is not None and list_kind is not None
    resource_spec = _RESOURCE_LISTS.get((api_version, list_kind))
    if resource_spec is None:
        _fail(
            "unknown_resource_kind", "Native list kind or API version is unsupported."
        )
    resource_kind, _product, _family = resource_spec
    _validate_list_partition(collection_metadata, resource_kind)
    native_list_metadata = _mapping(native_list.get("metadata"), "list.metadata")
    # A list collection version is an opaque cursor. Validate it, but never use
    # its lexical order or substitute it for individual object revisions.
    _native_resource_version(
        native_list_metadata.get("resourceVersion"), "list.metadata.resourceVersion"
    )
    continuation = native_list_metadata.get("continue")
    if continuation is not None and not isinstance(continuation, str):
        _fail("invalid_native_field", "list.metadata.continue must be text.")
    has_more_pages = bool(continuation)
    items = native_list.get("items")
    if not isinstance(items, list) or len(items) > MAX_OBJECTS:
        _fail("invalid_native_shape", "Native list items must be a bounded array.")
    return resource_kind, api_version, items, has_more_pages


def _snapshot_collection(
    payload: Any,
    collection_metadata: dict[str, Any],
    *,
    expected_list: tuple[str, str],
    mapper: Callable[[Any, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    resource_kind, api_version, items, has_more_pages = _list_items(
        payload, collection_metadata=collection_metadata
    )
    native_list = _mapping(payload, "list")
    list_kind = _native_text(native_list.get("kind"), "list.kind", required=True)
    if (api_version, list_kind) != expected_list:
        _fail("unknown_resource_kind", "Native list does not match this adapter.")
    expected_kind = _RESOURCE_LISTS[expected_list][0]
    for item in items:
        item_mapping = _mapping(item, "list item")
        if (
            item_mapping.get("apiVersion") != api_version
            or item_mapping.get("kind") != expected_kind
        ):
            _fail(
                "unknown_resource_kind",
                "Native list item does not match its declared list kind.",
            )
    objects = [mapper(item, collection_metadata) for item in items]
    status = collection_metadata.get("status", "partial")
    page_expected = collection_metadata.get("pages_expected", 0)
    page_received = collection_metadata.get("pages_received", 0)
    if (
        isinstance(page_expected, int)
        and not isinstance(page_expected, bool)
        and isinstance(page_received, int)
        and not isinstance(page_received, bool)
    ):
        original_page_expected = page_expected
        page_expected = max(page_expected, page_received)
        if has_more_pages:
            page_expected = max(page_expected, page_received + 1, 1)
    else:
        _fail("invalid_collection_metadata", "Page counts must be integers.")
    if (
        has_more_pages
        or page_expected == 0
        or page_received != page_expected
        or page_expected != original_page_expected
    ):
        if status == "complete":
            status = "partial"
    if (
        collection_metadata.get("initial_state_complete") is False
        and status == "complete"
    ):
        status = "partial"
    deletions_authoritative = (
        status == "complete"
        and collection_metadata.get("enumeration") == "full"
        and collection_metadata.get("deletions_authoritative") is True
        and not has_more_pages
    )
    return _collection(
        collection_metadata,
        product="cilium" if resource_kind in _CILIUM_KINDS else "kubernetes",
        family={
            "Service": "service_snapshot",
            "EndpointSlice": "endpointslice_snapshot",
            "Pod": "pod_snapshot",
            "CiliumNetworkPolicy": "network_policy_snapshot",
            "CiliumClusterwideNetworkPolicy": "clusterwide_policy_snapshot",
        }[resource_kind],
        objects=objects,
        status=status,
        enumeration=collection_metadata.get("enumeration", "incremental"),
        deletions_authoritative=deletions_authoritative,
        pages_expected=page_expected,
        pages_received=page_received,
    )


def _event_resource_kind(resource: Any) -> tuple[str, str]:
    item = _mapping(resource, "watch object")
    api_version = _native_text(
        item.get("apiVersion"), "watch.object.apiVersion", required=True
    )
    kind = _native_text(item.get("kind"), "watch.object.kind", required=True)
    assert api_version is not None and kind is not None
    if _RESOURCE_APIS.get(kind) != api_version:
        _fail(
            "unknown_resource_kind",
            "Watch event has an unsupported resource kind or version.",
        )
    return api_version, kind


def _watch_events(
    payload: Any,
    collection_metadata: dict[str, Any],
    *,
    expected_resource_kind: str | None = None,
) -> dict[str, Any]:
    if isinstance(payload, Mapping) and payload.get("kind") == "Status":
        payload = {"type": "ERROR", "object": payload}
    events = (
        list(payload)
        if isinstance(payload, Sequence)
        and not isinstance(payload, (str, bytes, bytearray, Mapping))
        else [payload]
    )
    if not events or len(events) > MAX_OBJECTS:
        _fail(
            "invalid_watch",
            "Watch input must contain a bounded non-empty event sequence.",
        )
    expected = expected_resource_kind or collection_metadata.get(
        "expected_resource_kind"
    )
    if expected is not None and expected not in _RESOURCE_APIS:
        _fail("unknown_resource_kind", "Expected watch resource kind is unsupported.")
    if expected is not None:
        _validate_list_partition(collection_metadata, expected)

    observations: dict[tuple[str, str], dict[str, Any]] = {}
    resource_kind_seen: str | None = None
    had_410 = False
    had_other_error = False
    marker: str | None = None
    for event_value in events:
        event = _mapping(event_value, "watch event")
        event_type = _native_text(event.get("type"), "watch.type", required=True)
        if event_type == "ERROR":
            error_obj = _mapping(event.get("object"), "watch.error.object")
            api_error = _is_api_error(error_obj)
            if api_error is None:
                _fail(
                    "invalid_watch",
                    "Watch ERROR event is not a Kubernetes Status object.",
                )
            _reason, status_code = api_error
            if status_code == 410:
                had_410 = True
                marker = "kubernetes-watch:410-gone-relist-required"
            else:
                had_other_error = True
                marker = "kubernetes-watch:error"
            continue
        if event_type == "BOOKMARK":
            bookmark = _mapping(event.get("object"), "watch.bookmark")
            kind = _native_text(bookmark.get("kind"), "watch.bookmark.kind") or expected
            api_version = _native_text(
                bookmark.get("apiVersion"), "watch.bookmark.apiVersion"
            )
            if kind is None or kind not in _RESOURCE_APIS:
                _fail(
                    "unknown_resource_kind",
                    "Watch bookmark lacks a supported resource kind.",
                )
            _validate_list_partition(collection_metadata, kind)
            if api_version is not None and api_version != _RESOURCE_APIS[kind]:
                _fail(
                    "unknown_resource_kind",
                    "Watch bookmark has an unsupported API version.",
                )
            if expected is not None and kind != expected:
                _fail(
                    "unknown_resource_kind",
                    "Watch bookmark does not match the requested resource kind.",
                )
            if resource_kind_seen is not None and kind != resource_kind_seen:
                _fail(
                    "mixed_watch_resources",
                    "A watch receipt cannot mix resource kinds.",
                )
            resource_kind_seen = kind
            bookmark_meta = _mapping(
                bookmark.get("metadata"), "watch.bookmark.metadata"
            )
            _native_resource_version(
                bookmark_meta.get("resourceVersion"),
                "watch.bookmark.metadata.resourceVersion",
            )
            continue
        if event_type not in _WATCH_TYPES:
            _fail("unknown_watch_event", "Watch event type is unsupported.")
        item = _mapping(event.get("object"), "watch.object")
        api_version, kind = _event_resource_kind(item)
        _validate_list_partition(collection_metadata, kind)
        if expected is not None and kind != expected:
            _fail(
                "unknown_resource_kind",
                "Watch event does not match the requested resource kind.",
            )
        if resource_kind_seen is not None and kind != resource_kind_seen:
            _fail("mixed_watch_resources", "A watch receipt cannot mix resource kinds.")
        resource_kind_seen = kind
        if kind in _CILIUM_KINDS:
            _qualify_cilium_gvk(collection_metadata, api_version, kind)
        native_metadata = _mapping(item.get("metadata"), "watch.object.metadata")
        _native_text(
            native_metadata.get("name"), "watch.object.metadata.name", required=True
        )
        namespaced = kind != "CiliumClusterwideNetworkPolicy"
        namespace = _native_text(
            native_metadata.get("namespace"), "watch.object.metadata.namespace"
        )
        if namespaced and namespace is None:
            _fail("missing_native_field", "Watch resource namespace is required.")
        if not namespaced and namespace is not None:
            _fail(
                "scope_mismatch",
                "Cluster-scoped watch resource must not have a namespace.",
            )
        _check_namespace_partition(collection_metadata, namespace)
        uid = _native_uid(native_metadata.get("uid"), "watch.object.metadata.uid")
        resource_version = _native_resource_version(
            native_metadata.get("resourceVersion"),
            "watch.object.metadata.resourceVersion",
        )
        generation = native_metadata.get("generation")
        if generation is not None and (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or abs(generation) > 9_007_199_254_740_991
        ):
            _fail(
                "invalid_native_field",
                "Watch metadata.generation must be a safe integer.",
            )
        event_key = _canonical_digest(
            {"uid": uid, "event_type": event_type, "resource_version": resource_version}
        )
        fields = {
            "resource_kind": kind,
            "resource_uid": uid,
            "namespace": namespace,
            "event_type": event_type,
            "resource_version": resource_version,
            "generation": generation,
        }
        obj = _base_object(
            object_id=event_key,
            revision=resource_version,
            observed_at=_observed_at(collection_metadata),
            kind="operational",
            fields=fields,
        )
        key = (event_key, resource_version)
        previous = observations.get(key)
        if previous is not None and canonical_json(previous) != canonical_json(obj):
            _fail(
                "conflicting_watch_event",
                "Watch input contains a conflicting native event key.",
            )
        observations[key] = obj

    if resource_kind_seen is None:
        resource_kind_seen = expected
    if resource_kind_seen is None:
        _fail("missing_native_field", "Watch input needs an expected resource kind.")
    objects = [observations[key] for key in sorted(observations)]
    status = collection_metadata.get("status", "partial")
    if status not in {"complete", "partial", "failed"}:
        _fail("invalid_collection_metadata", "status is unsupported.")
    start_resource_version = collection_metadata.get("start_resource_version")
    if start_resource_version is not None:
        _native_resource_version(start_resource_version, "start_resource_version")
    has_cursor = collection_metadata.get("initial_state_complete") is True or bool(
        start_resource_version
    )
    continuity_attested = (
        collection_metadata.get("watch_contiguous") is True
        and collection_metadata.get("watch_ended") is True
        and has_cursor
    )
    if had_410:
        status = "partial"
    elif had_other_error:
        status = "failed"
    elif status == "complete" and not continuity_attested:
        status = "partial"
    marker = marker or "kubernetes-watch"
    source_reference = _append_source_marker(
        collection_metadata.get("source_reference"), marker
    )
    pages_expected = collection_metadata.get("pages_expected", 0)
    pages_received = collection_metadata.get("pages_received", 0)
    if (
        isinstance(pages_expected, bool)
        or not isinstance(pages_expected, int)
        or isinstance(pages_received, bool)
        or not isinstance(pages_received, int)
    ):
        _fail("invalid_collection_metadata", "Page counts must be integers.")
    if status == "complete" and (
        pages_expected == 0 or pages_received != pages_expected
    ):
        status = "partial"
    return _collection(
        collection_metadata,
        product="kubernetes",
        family="object_watch",
        objects=objects,
        status=status,
        enumeration="incremental",
        deletions_authoritative=False,
        source_reference=source_reference,
    )


def _dispatch(
    native_payload: Any,
    collection_metadata: Any,
    *,
    expected_list: tuple[str, str],
    expected_resource_kind: str,
    mapper: Callable[[Any, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    metadata = _metadata(collection_metadata)
    if isinstance(native_payload, Mapping) and native_payload.get("kind") == "Status":
        resource_kind, product, family = _RESOURCE_LISTS[expected_list]
        _validate_list_partition(metadata, resource_kind)
        return _status_error_collection(
            native_payload,
            metadata,
            product=product,
            family=family,
            marker_prefix="kubernetes-list",
        )
    if _is_watch_payload(native_payload):
        return _watch_events(
            native_payload,
            metadata,
            expected_resource_kind=expected_resource_kind,
        )
    return _snapshot_collection(
        native_payload,
        metadata,
        expected_list=expected_list,
        mapper=mapper,
    )


def adapt_services(native_payload: Any, collection_metadata: Any) -> dict[str, Any]:
    """Normalize a versioned ServiceList or Service watch receipt."""

    return _dispatch(
        native_payload,
        collection_metadata,
        expected_list=("v1", "ServiceList"),
        expected_resource_kind="Service",
        mapper=_service_object,
    )


def adapt_endpointslices(
    native_payload: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Normalize a versioned EndpointSliceList or EndpointSlice watch receipt."""

    return _dispatch(
        native_payload,
        collection_metadata,
        expected_list=("discovery.k8s.io/v1", "EndpointSliceList"),
        expected_resource_kind="EndpointSlice",
        mapper=_endpoint_slice_object,
    )


def adapt_pods(native_payload: Any, collection_metadata: Any) -> dict[str, Any]:
    """Normalize a PodList or Pod watch receipt with fixed app-label hashing."""

    return _dispatch(
        native_payload,
        collection_metadata,
        expected_list=("v1", "PodList"),
        expected_resource_kind="Pod",
        mapper=_pod_object,
    )


def adapt_cilium_policies(
    native_payload: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Normalize metadata from an explicitly qualified Cilium v2 policy CRD list."""

    metadata = _metadata(collection_metadata)
    if isinstance(native_payload, Mapping) and native_payload.get("kind") == "Status":
        expected_kind = metadata.get("expected_resource_kind")
        if expected_kind not in _CILIUM_KINDS:
            _fail(
                "ambiguous_native_error",
                "Cilium API errors require an expected policy resource kind.",
            )
        _validate_list_partition(metadata, expected_kind)
        error_family = (
            "network_policy_snapshot"
            if expected_kind == "CiliumNetworkPolicy"
            else "clusterwide_policy_snapshot"
        )
        return _status_error_collection(
            native_payload,
            metadata,
            product="cilium",
            family=error_family,
            marker_prefix="cilium-list",
        )
    if _is_watch_payload(native_payload):
        expected_kind = metadata.get("expected_resource_kind")
        if expected_kind is None:
            events = (
                list(native_payload)
                if isinstance(native_payload, Sequence)
                and not isinstance(native_payload, (str, bytes, bytearray, Mapping))
                else [native_payload]
            )
            for event in events:
                if isinstance(event, Mapping) and isinstance(
                    event.get("object"), Mapping
                ):
                    candidate = _native_text(
                        event["object"].get("kind"), "watch.object.kind"
                    )
                    if candidate in _CILIUM_KINDS:
                        expected_kind = candidate
                        break
        if expected_kind not in _CILIUM_KINDS:
            _fail(
                "unknown_resource_kind", "Cilium watch requires an expected policy GVK."
            )
        return _watch_events(
            native_payload,
            metadata,
            expected_resource_kind=expected_kind,
        )
    resource_kind, api_version, _items, _has_more = _list_items(
        native_payload, collection_metadata=metadata
    )
    if resource_kind not in _CILIUM_KINDS or api_version != "cilium.io/v2":
        _fail(
            "unknown_resource_kind",
            "Cilium adapter accepts only Cilium policy list kinds.",
        )
    _qualify_cilium_gvk(metadata, api_version, resource_kind)
    expected_list = (
        api_version,
        "CiliumNetworkPolicyList"
        if resource_kind == "CiliumNetworkPolicy"
        else "CiliumClusterwideNetworkPolicyList",
    )
    return _snapshot_collection(
        native_payload,
        metadata,
        expected_list=expected_list,
        mapper=_cilium_policy_object,
    )


def adapt_kubernetes_watch(
    native_payload: Any,
    collection_metadata: Any,
    *,
    expected_resource_kind: str | None = None,
) -> dict[str, Any]:
    """Normalize a watch event sequence into operational observations.

    The caller must attest continuity and a starting cursor or initial state in
    collection metadata before the receipt can be complete. HTTP 410 / Expired
    yields a partial receipt that requires a fresh list before resuming.
    """

    return _watch_events(
        native_payload,
        _metadata(collection_metadata),
        expected_resource_kind=expected_resource_kind,
    )
