"""Reviewed field projections and source qualification for normalized records.

Adapters may project only fields listed here. Native fields that are not listed
are dropped by adapters; normalized input that names an unreviewed field is
rejected by :mod:`contracts`. These maps validate normalized exports and do not
qualify a live source adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class FieldSpec:
    """A flat scalar or scalar array; arrays retain source order by default."""

    value_type: str
    ordered: bool = True


@dataclass(frozen=True)
class ProjectionSpec:
    fields: Mapping[str, FieldSpec]
    allowed_kinds: frozenset[str]
    qualification: str = "normalized_export_only"
    native_sample_unqualified: bool = True
    context_only: bool = False
    operational_snapshot: bool = False


def _fields(**values: str) -> Mapping[str, FieldSpec]:
    return {name: FieldSpec(value_type) for name, value_type in values.items()}


def _lists(**values: str) -> Mapping[str, FieldSpec]:
    return {
        name: FieldSpec(value_type, ordered=True) for name, value_type in values.items()
    }


_AUDIT = frozenset({"audit"})
_OPERATIONAL = frozenset({"operational"})
_CONFIGURATION = frozenset({"configuration"})

# These are deliberately conservative projections. Raw configuration
# documents, request/response bodies, policy payloads, freeform details, URLs
# and scripts are never projected. Source-specific native parsing stays in the
# separately qualified adapter module.
PROJECTION_REGISTRY: Mapping[tuple[str, str], ProjectionSpec] = {
    ("atlas", "relationship_attestation"): ProjectionSpec(
        {
            **_fields(
                from_authority="authority",
                from_type="text",
                from_id="text",
                to_authority="authority",
                to_type="text",
                to_id="text",
                scope="text",
                evidence_id="text",
                basis="text",
                semantics="text",
                issuer="text",
                attestation_version="text",
                proof="text",
                proof_qualification="text",
                qualification="text",
                binding_scenario_id="text",
                binding_execution_id="text",
                binding_graph_result_key="text",
                binding_graph_result_sha256="text",
                binding_edge_id="text",
                binding_scope="text",
                binding_query_sha256="text",
                binding_receipt_basis="text",
                binding_query_input_coverage_sha256="text",
                binding_active_traffic_contract_sha256="text",
                valid_from="number",
                valid_to="number",
                binding_window_earliest="number",
                binding_window_latest="number",
            ),
            "binding_receipt_fingerprints": FieldSpec("text_list", ordered=False),
        },
        _OPERATIONAL,
        qualification="administrator_attestation_unqualified",
        context_only=True,
    ),
    ("ftd", "connection_observation"): ProjectionSpec(
        {
            **_fields(
                device_ip="text",
                device_uuid="text",
                device_serial="text",
                instance_id="text",
                connection_id="text",
                protocol="text",
                reported_initiator_ip="text",
                reported_responder_ip="text",
                reported_action="text",
                outcome="text",
                firewall_policy_name="text",
                firewall_rule_name="text",
                event_fingerprint="text",
                evidence_identity_basis="text",
            ),
            "reported_initiator_port": FieldSpec("integer"),
            "reported_responder_port": FieldSpec("integer"),
            "first_packet_at": FieldSpec("number"),
            "event_detected_at": FieldSpec("number"),
        },
        _OPERATIONAL,
    ),
    ("aci", "filter_entry_snapshot"): ProjectionSpec(
        _fields(
            object_class="text",
            name="text",
            parent_dn="text",
            ether_type="text",
            protocol="text",
            source_from_port="text",
            source_to_port="text",
            destination_from_port="text",
            destination_to_port="text",
        ),
        _CONFIGURATION,
    ),
    ("aci", "contract_subject_snapshot"): ProjectionSpec(
        _fields(
            object_class="text",
            name="text",
            parent_dn="text",
            reverse_filter_ports="text",
            provider_match_type="text",
            target_dn="text",
            filter_name="text",
        ),
        _CONFIGURATION,
    ),
    ("aci", "epg_contract_attachment_snapshot"): ProjectionSpec(
        _fields(
            object_class="text",
            name="text",
            parent_dn="text",
            role="text",
            target_dn="text",
            contract_name="text",
            match_label="text",
        ),
        _CONFIGURATION,
    ),
    ("aci", "endpoint_state_snapshot"): ProjectionSpec(
        _fields(
            object_class="text",
            fabric_path_dn="text",
            encapsulation="text",
            learning_classification="text",
            ownership="text",
        ),
        _OPERATIONAL,
        operational_snapshot=True,
    ),
    ("aci", "aaa_mod_lr"): ProjectionSpec(
        _fields(
            affected_dn="text",
            event_code="text",
            operation="text",
            trigger="text",
            transaction_id="text",
        ),
        _AUDIT,
    ),
    ("nxos", "device_snapshot"): ProjectionSpec(
        {
            **_fields(
                hostname="text",
                serial="text",
                model="text",
                software_version="text",
                interface_name="text",
                admin_state="text",
                oper_state="text",
            ),
            "if_index": FieldSpec("integer"),
        },
        _OPERATIONAL,
        qualification="normalized_export_only",
        native_sample_unqualified=True,
    ),
    ("sdwan", "audit_log"): ProjectionSpec(
        _fields(
            device_id="text",
            feature="text",
            module="text",
            tenant="text",
        ),
        _AUDIT,
        context_only=True,
    ),
    ("meraki", "configuration_change"): ProjectionSpec(
        {
            **_fields(
                network_id="text",
                page="text",
                label="text",
                client_type="text",
            ),
            "ssid_number": FieldSpec("number"),
        },
        _AUDIT,
        context_only=True,
    ),
    ("meraki", "ssid_snapshot"): ProjectionSpec(
        _fields(
            network_id="text",
            ssid_number="integer",
            ssid_name="text",
            enabled="boolean",
            auth_mode="text",
            ip_assignment_mode="text",
            default_vlan_id="integer",
            use_vlan_tagging="boolean",
        ),
        _CONFIGURATION,
    ),
    ("catalyst_center", "audit_log"): ProjectionSpec(
        {
            **_fields(
                parent_event_id="text",
                event_name="text",
                event_type="text",
                category="text",
                domain="text",
                subdomain="text",
                source="text",
                event_hierarchy="text",
                network_id="text",
            ),
            "severity": FieldSpec("number"),
            "child_count": FieldSpec("number"),
        },
        _AUDIT,
        context_only=True,
    ),
    ("fmc", "audit_record"): ProjectionSpec(
        _fields(
            action="text",
            subsystem="text",
            source="text",
            domain_id="text",
        ),
        _AUDIT,
    ),
    ("appdynamics", "audit_log"): ProjectionSpec(
        _fields(
            account_name="text",
            security_provider_type="text",
            action="text",
            object_type="text",
            object_name="text",
        ),
        _AUDIT,
        context_only=True,
    ),
    ("thousandeyes", "activity_log"): ProjectionSpec(
        _fields(
            event_name="text",
            event_type="text",
            account_id="text",
            resource_type="text",
            resource_name="text",
        ),
        _AUDIT,
        qualification="normalized_export_only_context_only",
        native_sample_unqualified=True,
        context_only=True,
    ),
    ("kubernetes", "service_snapshot"): ProjectionSpec(
        {
            **_fields(
                service_type="text",
                target_ports="text_list",
                external_traffic_policy="text",
                internal_traffic_policy="text",
                selector_digest="text",
            ),
            **_lists(
                selector_keys="text_list",
                port_numbers="integer_list",
                protocols="text_list",
            ),
            "port_tuples": FieldSpec("text_list", ordered=False),
        },
        _CONFIGURATION,
    ),
    ("kubernetes", "endpointslice_snapshot"): ProjectionSpec(
        {
            **_fields(service_name="text"),
            **_lists(address_types="text_list", ports="integer_list"),
            "ready_count": FieldSpec("number"),
            "not_ready_count": FieldSpec("number"),
            "ready_backend_uids": FieldSpec("text_list", ordered=False),
            "not_ready_backend_uids": FieldSpec("text_list", ordered=False),
            "unresolved_endpoint_count": FieldSpec("integer"),
            "port_tuples": FieldSpec("text_list", ordered=False),
        },
        _OPERATIONAL,
    ),
    ("kubernetes", "pod_snapshot"): ProjectionSpec(
        {
            **_fields(
                pod_name="text",
                namespace="text",
                node_name="text",
                owner_kind="text",
                owner_uid="text",
                phase="text",
                app_version_label_digest="text",
            ),
            "generation": FieldSpec("integer"),
        },
        _OPERATIONAL,
    ),
    ("kubernetes", "object_watch"): ProjectionSpec(
        {
            **_fields(
                resource_kind="text",
                resource_uid="text",
                namespace="text",
                event_type="text",
                resource_version="text",
            ),
            "generation": FieldSpec("integer"),
        },
        _OPERATIONAL,
    ),
    ("cilium", "policy_snapshot"): ProjectionSpec(
        {
            **_fields(api_version="text", policy_kind="text", namespace="text"),
            **_lists(labels="text_list"),
            "generation": FieldSpec("integer"),
        },
        _CONFIGURATION,
    ),
    ("cilium", "network_policy_snapshot"): ProjectionSpec(
        {
            **_fields(api_version="text", policy_kind="text", namespace="text"),
            **_lists(labels="text_list"),
            "generation": FieldSpec("integer"),
        },
        _CONFIGURATION,
    ),
    ("cilium", "clusterwide_policy_snapshot"): ProjectionSpec(
        {
            **_fields(api_version="text", policy_kind="text", namespace="text"),
            **_lists(labels="text_list"),
            "generation": FieldSpec("integer"),
        },
        _CONFIGURATION,
    ),
}


def projection_definition(product: str, family: str) -> ProjectionSpec | None:
    """Return the reviewed immutable definition for a product/family pair."""

    return PROJECTION_REGISTRY.get((product, family))


def projection_for(product: str, family: str) -> Mapping[str, FieldSpec]:
    definition = projection_definition(product, family)
    return definition.fields if definition is not None else {}


def has_projection(product: str, family: str) -> bool:
    return projection_definition(product, family) is not None
