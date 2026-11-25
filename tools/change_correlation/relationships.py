"""Retained, bounded relationships for configuration-change attribution.

Administrator attestations enter history only through the explicit keyword-only
``build_generation(..., administrator_relationships=...)`` path. This module
does not authenticate an administrator or turn an attestation into native source
evidence. It preserves the supplied actor, proof reference and qualification so
callers can make that boundary visible.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable
from typing import Any

from .contracts import (
    MAX_EPOCH,
    ContractError,
    _authority,
    _text,
    canonical_json,
    normalize_collection,
)

MAX_RELATIONSHIPS = 500
MAX_RELATIONSHIP_DEPTH = 8
MAX_ATTRIBUTION_CHAINS = 200
MAX_ATTRIBUTION_STEPS = 5_000
MAX_BINDING_RECEIPTS = 100
CAPTURED_RECEIPT_BASIS = "query_input_coverage_v1"

CAPTURED_DEPENDENCY_AUTHORITY = "atlas:observed_dependency"
CAPTURED_DEPENDENCY_TYPE = "captured_dependency"
CAPTURED_DEPENDENCY_PREFIX = "captured_dependency:"
ADMIN_PRODUCT = "atlas"
ADMIN_FAMILY = "relationship_attestation"
ADMIN_SOURCE_AUTHORITY = "atlas:administrator_attestation"
ADMIN_PARTITION = "administrator_relationship_attestations"
ADMIN_PERMISSION_QUALIFICATION = "unqualified-administrator-attestation"
ADMIN_BASIS = "administrator_attestation"
POTENTIAL_DEPENDENCY = "potential_dependency"
UNVERIFIED_PROOF = "administrator_supplied_unverified"
ADMIN_QUALIFICATIONS = {
    "owned_local_lab_admin_unqualified",
    "synthetic_admin_artifact_unqualified",
}

_BINDING_KEYS = {
    "authority",
    "identity_type",
    "scenario_id",
    "execution_id",
    "graph_result_key",
    "graph_result_sha256",
    "edge_id",
    "scope",
    "window",
    "query_sha256",
    "receipt_basis",
    "query_input_coverage_sha256",
    "active_traffic_contract_sha256",
    "receipt_fingerprints",
}
_ADMIN_ENVELOPE_KEYS = {
    "schema_version",
    "capture_id",
    "issuer",
    "source_version",
    "attestation_version",
    "proof",
    "actor",
    "qualification",
    "recorded_at",
    "source_reference",
    "relationships",
}
_ADMIN_RELATIONSHIP_KEYS = {
    "from_authority",
    "from_type",
    "from_id",
    "to_authority",
    "to_type",
    "to_id",
    "scope",
    "valid_from",
    "valid_to",
    "evidence_id",
    "binding",
}
_ADMIN_ATTRIBUTE_KEYS = {
    "from_authority",
    "from_type",
    "from_id",
    "to_authority",
    "to_type",
    "to_id",
    "scope",
    "valid_from",
    "valid_to",
    "evidence_id",
    "basis",
    "semantics",
    "issuer",
    "attestation_version",
    "proof",
    "proof_qualification",
    "qualification",
    "binding_scenario_id",
    "binding_execution_id",
    "binding_graph_result_key",
    "binding_graph_result_sha256",
    "binding_edge_id",
    "binding_scope",
    "binding_query_sha256",
    "binding_receipt_basis",
    "binding_query_input_coverage_sha256",
    "binding_active_traffic_contract_sha256",
    "binding_window_earliest",
    "binding_window_latest",
    "binding_receipt_fingerprints",
}
_HASH = frozenset("0123456789abcdef")


class RelationshipError(ValueError):
    """A bounded, input-safe relationship validation failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise RelationshipError(code, message)


def _text_value(value: Any, label: str) -> str:
    try:
        result = _text(value, label, required=True)
    except ContractError as exc:
        raise RelationshipError(exc.code, str(exc)) from exc
    if result is None:
        _fail("missing_relationship_field", f"{label} is required.")
    return result


def _authority_value(value: Any, label: str) -> str:
    try:
        return _authority(value)
    except ContractError as exc:
        raise RelationshipError(exc.code, str(exc)) from exc


def _epoch(value: Any, label: str) -> int | float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value < 0
        or value > MAX_EPOCH
        or (isinstance(value, float) and not math.isfinite(value))
    ):
        _fail("invalid_relationship_time", f"{label} is outside the supported range.")
    try:
        # canonical_json is the shared cross-language millisecond-precision gate.
        canonical_json(value)
    except ContractError as exc:
        raise RelationshipError(
            "invalid_relationship_time", f"{label} is invalid."
        ) from exc
    return int(value) if isinstance(value, float) and value.is_integer() else value


def _hash(value: Any, label: str) -> str:
    result = _text_value(value, label)
    if len(result) != 64 or any(char not in _HASH for char in result):
        _fail("invalid_relationship_hash", f"{label} must be lowercase SHA-256 hex.")
    return result


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("invalid_relationship_shape", f"{label} has an unsupported field shape.")
    return value


def normalize_captured_dependency_binding(value: Any) -> dict[str, Any]:
    """Validate and canonicalize the exact capture binding body used by W13."""

    binding = _exact_keys(value, _BINDING_KEYS, "Captured dependency binding")
    if (
        binding["authority"] != CAPTURED_DEPENDENCY_AUTHORITY
        or binding["identity_type"] != CAPTURED_DEPENDENCY_TYPE
    ):
        _fail(
            "invalid_captured_dependency",
            "Captured dependency identity is unsupported.",
        )
    window = _exact_keys(binding["window"], {"earliest", "latest"}, "Binding window")
    earliest = _epoch(window["earliest"], "Binding window start")
    latest = _epoch(window["latest"], "Binding window end")
    if earliest >= latest or latest - earliest > 86_400:
        _fail(
            "invalid_captured_dependency", "Captured dependency window is unsupported."
        )
    receipts = binding["receipt_fingerprints"]
    if not isinstance(receipts, list) or not 1 <= len(receipts) <= MAX_BINDING_RECEIPTS:
        _fail(
            "invalid_captured_dependency",
            "Captured dependency receipts are incomplete.",
        )
    normalized_receipts = [
        _hash(item, "Indexed receipt fingerprint") for item in receipts
    ]
    if normalized_receipts != sorted(set(normalized_receipts)):
        _fail(
            "invalid_captured_dependency",
            "Captured dependency receipts are not sorted and unique.",
        )
    normalized = {
        "authority": CAPTURED_DEPENDENCY_AUTHORITY,
        "identity_type": CAPTURED_DEPENDENCY_TYPE,
        "scenario_id": _text_value(binding["scenario_id"], "Scenario ID"),
        "execution_id": _text_value(binding["execution_id"], "Execution ID"),
        "graph_result_key": _text_value(
            binding["graph_result_key"], "Graph result key"
        ),
        "graph_result_sha256": _hash(
            binding["graph_result_sha256"], "Graph result SHA-256"
        ),
        "edge_id": _text_value(binding["edge_id"], "Captured graph edge ID"),
        "scope": _text_value(binding["scope"], "Binding routing scope"),
        "window": {"earliest": earliest, "latest": latest},
        "query_sha256": _hash(binding["query_sha256"], "Graph query SHA-256"),
        "receipt_basis": _text_value(binding["receipt_basis"], "Receipt basis"),
        "query_input_coverage_sha256": _hash(
            binding["query_input_coverage_sha256"],
            "Query input coverage SHA-256",
        ),
        "active_traffic_contract_sha256": _hash(
            binding["active_traffic_contract_sha256"],
            "Active traffic contract SHA-256",
        ),
        "receipt_fingerprints": normalized_receipts,
    }
    if normalized["receipt_basis"] != CAPTURED_RECEIPT_BASIS:
        _fail(
            "invalid_captured_dependency",
            "Captured dependency receipt basis is unsupported.",
        )
    return normalized


def captured_dependency_identity(value: Any) -> dict[str, Any]:
    """Return W13's deterministic identity and canonical binding body.

    The graph content hash and query-input coverage hash must be computed from
    the retained readbacks by the capture producer. This function binds those
    hashes to the exact edge, routing scope/window, query, traffic contract and
    actual indexed receipts. Coverage is query-level eligible-input context,
    never per-edge event lineage. It makes no claim that any source result or
    administrator is authentic.
    """

    body = normalize_captured_dependency_binding(value)
    identity_hash = hashlib.sha256(canonical_json(body)).hexdigest()
    return {
        "authority": CAPTURED_DEPENDENCY_AUTHORITY,
        "type": CAPTURED_DEPENDENCY_TYPE,
        "id": f"{CAPTURED_DEPENDENCY_PREFIX}{identity_hash}",
        "binding": body,
    }


def _relationship_binding_fields(binding: dict[str, Any]) -> dict[str, Any]:
    window = binding["window"]
    return {
        "binding_scenario_id": binding["scenario_id"],
        "binding_execution_id": binding["execution_id"],
        "binding_graph_result_key": binding["graph_result_key"],
        "binding_graph_result_sha256": binding["graph_result_sha256"],
        "binding_edge_id": binding["edge_id"],
        "binding_scope": binding["scope"],
        "binding_query_sha256": binding["query_sha256"],
        "binding_receipt_basis": binding["receipt_basis"],
        "binding_query_input_coverage_sha256": binding["query_input_coverage_sha256"],
        "binding_active_traffic_contract_sha256": binding[
            "active_traffic_contract_sha256"
        ],
        "binding_window_earliest": window["earliest"],
        "binding_window_latest": window["latest"],
        "binding_receipt_fingerprints": binding["receipt_fingerprints"],
    }


def _binding_from_relationship_fields(fields: dict[str, Any]) -> dict[str, Any]:
    return normalize_captured_dependency_binding(
        {
            "authority": CAPTURED_DEPENDENCY_AUTHORITY,
            "identity_type": CAPTURED_DEPENDENCY_TYPE,
            "scenario_id": fields["binding_scenario_id"],
            "execution_id": fields["binding_execution_id"],
            "graph_result_key": fields["binding_graph_result_key"],
            "graph_result_sha256": fields["binding_graph_result_sha256"],
            "edge_id": fields["binding_edge_id"],
            "scope": fields["binding_scope"],
            "window": {
                "earliest": fields["binding_window_earliest"],
                "latest": fields["binding_window_latest"],
            },
            "query_sha256": fields["binding_query_sha256"],
            "receipt_basis": fields["binding_receipt_basis"],
            "query_input_coverage_sha256": fields[
                "binding_query_input_coverage_sha256"
            ],
            "active_traffic_contract_sha256": fields[
                "binding_active_traffic_contract_sha256"
            ],
            "receipt_fingerprints": fields["binding_receipt_fingerprints"],
        }
    )


def _normalize_admin_relationship(
    value: Any,
    *,
    issuer: str,
    attestation_version: str,
    proof: str,
    qualification: str,
) -> tuple[str, dict[str, Any]]:
    relationship = _exact_keys(
        value, _ADMIN_RELATIONSHIP_KEYS, "Administrator relationship"
    )
    from_authority = _authority_value(
        relationship["from_authority"], "Source authority"
    )
    from_type = _text_value(relationship["from_type"], "Source type")
    from_id = _text_value(relationship["from_id"], "Source ID")
    to_authority = _text_value(relationship["to_authority"], "Target authority")
    to_type = _text_value(relationship["to_type"], "Target type")
    to_id = _text_value(relationship["to_id"], "Target ID")
    scope = _text_value(relationship["scope"], "Relationship routing scope")
    valid_from = _epoch(relationship["valid_from"], "Relationship validity start")
    valid_to = _epoch(relationship["valid_to"], "Relationship validity end")
    evidence_id = _text_value(relationship["evidence_id"], "Relationship evidence ID")
    if valid_from >= valid_to:
        _fail("invalid_relationship_time", "Relationship validity interval is empty.")
    binding = normalize_captured_dependency_binding(relationship["binding"])
    identity = captured_dependency_identity(binding)
    if (
        to_authority != identity["authority"]
        or to_type != identity["type"]
        or to_id != identity["id"]
        or binding["scope"] != scope
    ):
        _fail(
            "invalid_captured_dependency",
            "Relationship target does not match its captured graph binding.",
        )
    fields = {
        "from_authority": from_authority,
        "from_type": from_type,
        "from_id": from_id,
        "to_authority": identity["authority"],
        "to_type": identity["type"],
        "to_id": identity["id"],
        "scope": scope,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "evidence_id": evidence_id,
        "basis": ADMIN_BASIS,
        "semantics": POTENTIAL_DEPENDENCY,
        "issuer": issuer,
        "attestation_version": attestation_version,
        "proof": proof,
        "proof_qualification": UNVERIFIED_PROOF,
        "qualification": qualification,
        **_relationship_binding_fields(binding),
    }
    return scope, {
        "object_id": evidence_id,
        "revision": attestation_version,
        "observed_at": None,
        "event_at": None,
        "effective_at": None,
        "kind": "operational",
        "actor": None,
        "fields": fields,
    }


def administrator_relationship_collections(
    values: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Validate trusted admin envelopes into reserved, normalized collections.

    This function is called only by the builder's explicit keyword-only
    ``administrator_relationships`` input. A vendor JSON record cannot select
    this path by setting a basis or provenance flag.
    """

    if values is None:
        return []
    normalized: list[dict[str, Any]] = []
    seen_envelopes = 0
    relation_count = 0
    identity_contents: dict[str, bytes] = {}
    for raw in values:
        seen_envelopes += 1
        if seen_envelopes > MAX_RELATIONSHIPS:
            _fail(
                "relationship_limit", "Administrator relationship input is over limit."
            )
        envelope = _exact_keys(raw, _ADMIN_ENVELOPE_KEYS, "Administrator attestation")
        if (
            isinstance(envelope["schema_version"], bool)
            or envelope["schema_version"] != 1
        ):
            _fail(
                "unsupported_relationship_schema",
                "Administrator attestation version is unsupported.",
            )
        capture_id = _text_value(envelope["capture_id"], "Administrator capture ID")
        issuer = _text_value(envelope["issuer"], "Administrator issuer")
        source_version = _text_value(
            envelope["source_version"], "Attestation source version"
        )
        attestation_version = _text_value(
            envelope["attestation_version"], "Attestation version"
        )
        proof = _text_value(envelope["proof"], "Administrator proof reference")
        actor = _text_value(envelope["actor"], "Administrator actor")
        qualification = _text_value(
            envelope["qualification"], "Attestation qualification"
        )
        if qualification not in ADMIN_QUALIFICATIONS:
            _fail(
                "unqualified_administrator_input",
                "Administrator qualification is unsupported.",
            )
        recorded_at = _epoch(envelope["recorded_at"], "Attestation recorded time")
        source_reference = envelope["source_reference"]
        if source_reference is not None:
            source_reference = _text_value(
                source_reference, "Administrator source reference"
            )
        relationships = envelope["relationships"]
        if not isinstance(relationships, list) or not relationships:
            _fail(
                "empty_relationship_attestation",
                "Administrator attestation needs at least one relationship.",
            )
        if len(relationships) > MAX_RELATIONSHIPS:
            _fail(
                "relationship_limit", "Administrator relationship input is over limit."
            )
        relation_count += len(relationships)
        if relation_count > MAX_RELATIONSHIPS:
            _fail(
                "relationship_limit", "Administrator relationship input is over limit."
            )
        by_scope: dict[str, list[dict[str, Any]]] = {}
        for raw_relationship in relationships:
            scope, relationship = _normalize_admin_relationship(
                raw_relationship,
                issuer=issuer,
                attestation_version=attestation_version,
                proof=proof,
                qualification=qualification,
            )
            relationship["actor"] = actor
            content = canonical_json(
                {
                    "object_id": relationship["object_id"],
                    "revision": relationship["revision"],
                    "kind": relationship["kind"],
                    "actor": actor,
                    "fields": relationship["fields"],
                    "source_version": source_version,
                }
            )
            previous = identity_contents.get(relationship["object_id"])
            if previous is not None and previous != content:
                _fail(
                    "conflicting_relationship_identity",
                    "A relationship evidence ID has conflicting content.",
                )
            identity_contents[relationship["object_id"]] = content
            by_scope.setdefault(scope, []).append(relationship)

        for scope, objects in sorted(by_scope.items()):
            raw_collection = {
                "schema_version": 1,
                "capture_id": capture_id,
                "product": ADMIN_PRODUCT,
                "authority": ADMIN_SOURCE_AUTHORITY,
                "source_version": source_version,
                "family": ADMIN_FAMILY,
                "partition": ADMIN_PARTITION,
                "scope": scope,
                "started_at": recorded_at,
                "completed_at": recorded_at,
                "received_at": recorded_at,
                "status": "complete",
                "permissions_fingerprint": ADMIN_PERMISSION_QUALIFICATION,
                "pages_expected": 1,
                "pages_received": 1,
                "source_reference": source_reference,
                "enumeration": "incremental",
                "deletions_authoritative": False,
                "objects": [
                    {
                        "object_id": item["object_id"],
                        "revision": item["revision"],
                        "observed_at": recorded_at,
                        "event_at": None,
                        "effective_at": None,
                        "kind": "operational",
                        "actor": actor,
                        "fields": item["fields"],
                    }
                    for item in objects
                ],
            }
            try:
                normalized.append(
                    normalize_collection(raw_collection, _administrator_ingress=True)
                )
            except ContractError as exc:
                raise RelationshipError(exc.code, str(exc)) from exc
    return normalized


def validate_relationship(value: Any) -> dict[str, Any]:
    """Validate one caller-verified relationship link.

    Persisted relationships returned from ``extract_retained_relationships``
    carry the full administrator proof envelope. The base shape remains usable
    for links supplied by an integration that has verified its own evidence.
    """

    base = {
        "from_authority",
        "from_type",
        "from_id",
        "to_authority",
        "to_type",
        "to_id",
        "scope",
        "valid_from",
        "valid_to",
        "evidence_id",
        "basis",
    }
    admin = base | {
        "semantics",
        "issuer",
        "source_version",
        "attestation_version",
        "proof",
        "proof_qualification",
        "actor",
        "qualification",
        "target_binding",
        "generation_id",
        "record_id",
        "source_refs",
    }
    if not isinstance(value, dict) or set(value) not in (base, admin):
        _fail(
            "invalid_relationship_shape", "Relationship has an unsupported field shape."
        )
    result = {
        "from_authority": _authority_value(value["from_authority"], "Source authority"),
        "from_type": _text_value(value["from_type"], "Source type"),
        "from_id": _text_value(value["from_id"], "Source ID"),
        "to_authority": _text_value(value["to_authority"], "Target authority"),
        "to_type": _text_value(value["to_type"], "Target type"),
        "to_id": _text_value(value["to_id"], "Target ID"),
        "scope": _text_value(value["scope"], "Relationship routing scope"),
        "valid_from": _epoch(value["valid_from"], "Relationship validity start"),
        "valid_to": _epoch(value["valid_to"], "Relationship validity end"),
        "evidence_id": _text_value(value["evidence_id"], "Relationship evidence ID"),
        "basis": _text_value(value["basis"], "Relationship basis"),
    }
    if result["basis"] not in {"native", ADMIN_BASIS}:
        _fail("unqualified_relationship_basis", "Relationship basis is unsupported.")
    if result["valid_from"] >= result["valid_to"]:
        _fail("invalid_relationship_time", "Relationship validity interval is empty.")
    if set(value) == admin:
        result.update(
            {
                "semantics": _text_value(value["semantics"], "Relationship semantics"),
                "issuer": _text_value(value["issuer"], "Administrator issuer"),
                "source_version": _text_value(
                    value["source_version"], "Attestation source version"
                ),
                "attestation_version": _text_value(
                    value["attestation_version"], "Attestation version"
                ),
                "proof": _text_value(value["proof"], "Administrator proof reference"),
                "proof_qualification": _text_value(
                    value["proof_qualification"], "Proof qualification"
                ),
                "actor": _text_value(value["actor"], "Administrator actor"),
                "qualification": _text_value(
                    value["qualification"], "Attestation qualification"
                ),
                "target_binding": normalize_captured_dependency_binding(
                    value["target_binding"]
                ),
                "generation_id": _hash(value["generation_id"], "Generation ID"),
                "record_id": _hash(value["record_id"], "Relationship row ID"),
                "source_refs": value["source_refs"],
            }
        )
        if (
            result["basis"] != ADMIN_BASIS
            or result["semantics"] != POTENTIAL_DEPENDENCY
            or result["proof_qualification"] != UNVERIFIED_PROOF
            or result["qualification"] not in ADMIN_QUALIFICATIONS
            or result["to_authority"] != CAPTURED_DEPENDENCY_AUTHORITY
            or result["to_type"] != CAPTURED_DEPENDENCY_TYPE
            or result["scope"] != result["target_binding"]["scope"]
        ):
            _fail(
                "unqualified_relationship",
                "Administrator relationship qualification is unsupported.",
            )
        expected = captured_dependency_identity(result["target_binding"])
        if result["to_id"] != expected["id"]:
            _fail(
                "invalid_captured_dependency",
                "Relationship target binding does not match its identity.",
            )
        refs = result["source_refs"]
        if (
            not isinstance(refs, list)
            or len(refs) > 64
            or any(not isinstance(item, str) for item in refs)
            or refs != sorted(set(refs))
        ):
            _fail(
                "invalid_relationship_source_refs",
                "Relationship source references are invalid.",
            )
    return result


def extract_retained_relationships(
    rows: Iterable[dict[str, Any]], *, generation_id: str
) -> dict[str, Any]:
    """Extract all eligible administrator links from full verified generation rows.

    Call this before applying selected-time display filtering. Any malformed,
    conflicting or over-limit attestation suppresses the complete relationship
    set rather than returning a partial blast radius.
    """

    result: list[dict[str, Any]] = []
    try:
        for row in rows:
            if row.get("product") != ADMIN_PRODUCT or row.get("family") != ADMIN_FAMILY:
                continue
            if (
                row.get("generation_id") != generation_id
                or row.get("authority") != ADMIN_SOURCE_AUTHORITY
                or row.get("partition") != ADMIN_PARTITION
                or row.get("projection_qualification")
                != "administrator_attestation_unqualified"
                or row.get("native_sample_unqualified") is not True
                or row.get("record_type") != "observation"
                or row.get("kind") != "operational"
                or row.get("context_only") is not True
                or row.get("coverage_complete") is not True
                or row.get("gap") is not False
                or row.get("time_qualification") != "unknown_source_time"
                or row.get("clock_uncertainty_unknown") is not True
                or row.get("object_id") is None
                or row.get("actor") is None
                or row.get("source_version") is None
                or row.get("earliest_at") is not None
                or row.get("latest_at") is not None
            ):
                _fail(
                    "invalid_retained_relationship",
                    "Retained relationship row is malformed.",
                )
            fields = row.get("attributes")
            if not isinstance(fields, dict) or set(fields) != _ADMIN_ATTRIBUTE_KEYS:
                _fail(
                    "invalid_retained_relationship",
                    "Retained relationship fields are malformed.",
                )
            _hash(row.get("record_id"), "Relationship row ID")
            _hash(row.get("generation_id"), "Generation ID")
            _text_value(row.get("actor"), "Administrator actor")
            _text_value(row.get("source_version"), "Attestation source version")
            binding = _binding_from_relationship_fields(fields)
            identity = captured_dependency_identity(binding)
            if (
                fields.get("basis") != ADMIN_BASIS
                or fields.get("semantics") != POTENTIAL_DEPENDENCY
                or fields.get("proof_qualification") != UNVERIFIED_PROOF
                or fields.get("qualification") not in ADMIN_QUALIFICATIONS
                or fields.get("to_authority") != identity["authority"]
                or fields.get("to_type") != identity["type"]
                or fields.get("to_id") != identity["id"]
                or fields.get("scope") != binding["scope"]
                or row.get("object_id") != fields.get("evidence_id")
            ):
                _fail(
                    "invalid_retained_relationship",
                    "Retained relationship proof is inconsistent.",
                )
            relationship = {
                **{
                    key: fields[key]
                    for key in (
                        "from_authority",
                        "from_type",
                        "from_id",
                        "to_authority",
                        "to_type",
                        "to_id",
                        "scope",
                        "valid_from",
                        "valid_to",
                        "evidence_id",
                        "basis",
                    )
                },
                "semantics": fields["semantics"],
                "issuer": fields["issuer"],
                "source_version": row["source_version"],
                "attestation_version": fields["attestation_version"],
                "proof": fields["proof"],
                "proof_qualification": fields["proof_qualification"],
                "actor": row["actor"],
                "qualification": fields["qualification"],
                "target_binding": binding,
                "generation_id": generation_id,
                "record_id": row["record_id"],
                "source_refs": row["source_refs"],
            }
            relationship = validate_relationship(relationship)
            result.append(relationship)
            if len(result) > MAX_RELATIONSHIPS:
                _fail("relationship_limit", "Retained relationship set is over limit.")
        by_id: dict[str, bytes] = {}
        deduped: dict[str, dict[str, Any]] = {}
        for relationship in result:
            evidence_id = relationship["evidence_id"]
            content = canonical_json(relationship)
            previous = by_id.get(evidence_id)
            if previous is not None and previous != content:
                _fail(
                    "conflicting_relationship_identity",
                    "A relationship evidence ID conflicts in the generation.",
                )
            by_id[evidence_id] = content
            deduped[evidence_id] = relationship
        ordered = [deduped[key] for key in sorted(deduped)]
        return {"relationships": ordered, "complete": True, "reason": None}
    except (RelationshipError, ContractError) as exc:
        return {
            "relationships": [],
            "complete": False,
            "reason": getattr(exc, "code", "invalid_relationship"),
        }


def _endpoint(value: Any) -> tuple[str, str, str]:
    if not isinstance(value, dict) or set(value) != {"authority", "type", "id"}:
        _fail(
            "invalid_relationship_identity",
            "Relationship identity must be authority-qualified.",
        )
    return (
        _authority_value(value["authority"], "Identity authority"),
        _text_value(value["type"], "Identity type"),
        _text_value(value["id"], "Identity ID"),
    )


def _verified_dependency(value: Any) -> tuple[str, str, str]:
    identity = _endpoint(value)
    if (
        identity[0] != CAPTURED_DEPENDENCY_AUTHORITY
        or identity[1] != CAPTURED_DEPENDENCY_TYPE
        or not identity[2].startswith(CAPTURED_DEPENDENCY_PREFIX)
        or len(identity[2]) != len(CAPTURED_DEPENDENCY_PREFIX) + 64
        or any(
            char not in _HASH for char in identity[2][len(CAPTURED_DEPENDENCY_PREFIX) :]
        )
    ):
        _fail(
            "unverified_dependency_identity",
            "Observed dependency lacks a captured graph binding.",
        )
    return identity


def _attribution_result(
    category: str,
    reason: str,
    chains: list[dict[str, Any]] | None = None,
    *,
    scope: str,
    start: int | float,
    end: int | float,
) -> dict[str, Any]:
    chains = chains or []
    return {
        "attribution_class": category,
        "reason": reason,
        "chain": chains[0]["links"] if chains else [],
        "chains": chains,
        "scope": scope,
        "window": {"start": start, "end": end},
    }


def attribute_change(
    row: dict[str, Any],
    *,
    scope: str,
    start: int | float,
    end: int | float,
    objects: list[dict[str, Any]],
    observed_dependencies: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    relationships_verified: bool = False,
    relationship_evidence_complete: bool = True,
    relationship_evidence_reason: str | None = None,
) -> dict[str, Any]:
    """Return every bounded eligible target/path for one history row.

    Relationship and selected windows are half-open. A change uncertainty
    interval's latest endpoint is inclusive, so a link must remain valid after
    that endpoint. This is potential dependency attribution only; it does not
    establish policy enforcement, packet order, causation or full network reach.
    """

    scope = _text_value(scope, "Selected routing scope")
    start, end = (
        _epoch(start, "Selected window start"),
        _epoch(end, "Selected window end"),
    )
    if start >= end or end - start > 86_400:
        _fail("unsupported_selected_interval", "Selected window is unsupported.")
    try:
        if not isinstance(objects, list) or not isinstance(observed_dependencies, list):
            raise RelationshipError(
                "invalid_relationship_identity", "Relationship identity set is invalid."
            )
        if (
            not isinstance(relationships, list)
            or len(relationships) > MAX_RELATIONSHIPS
        ):
            raise RelationshipError(
                "relationship_limit", "Relationship set is over limit."
            )
        if relationships and relationships_verified is not True:
            raise RelationshipError(
                "unverified_relationship_context",
                "Caller-supplied relationships require independent verification.",
            )
        selected = {_endpoint(item) for item in objects}
        dependencies = {_verified_dependency(item) for item in observed_dependencies}
        if len(selected) + len(dependencies) > MAX_RELATIONSHIPS:
            raise RelationshipError(
                "relationship_identity_limit",
                "Relationship identity set is over limit.",
            )
        links = [validate_relationship(link) for link in relationships]
    except RelationshipError as exc:
        return _attribution_result(
            "context_only",
            getattr(exc, "code", "invalid_relationship"),
            scope=scope,
            start=start,
            end=end,
        )
    if not relationship_evidence_complete:
        return _attribution_result(
            "context_only",
            relationship_evidence_reason or "relationship_evidence_incomplete",
            scope=scope,
            start=start,
            end=end,
        )
    if len(links) > MAX_RELATIONSHIPS:
        return _attribution_result(
            "context_only", "relationship_limit", scope=scope, start=start, end=end
        )
    if row.get("scope") != scope:
        return _attribution_result(
            "excluded", "different_verified_scope", scope=scope, start=start, end=end
        )
    if row.get("context_only") is True:
        return _attribution_result(
            "context_only",
            "source_projection_context_only",
            scope=scope,
            start=start,
            end=end,
        )
    if row.get("earliest_at") is None or row.get("latest_at") is None:
        return _attribution_result(
            "context_only",
            "unknown_or_overwide_change_interval",
            scope=scope,
            start=start,
            end=end,
        )
    try:
        lower = _epoch(row["earliest_at"], "Change interval start")
        upper = _epoch(row["latest_at"], "Change interval end")
    except RelationshipError:
        return _attribution_result(
            "context_only",
            "unknown_or_overwide_change_interval",
            scope=scope,
            start=start,
            end=end,
        )
    if lower > upper or upper - lower > 86_400:
        return _attribution_result(
            "context_only",
            "unknown_or_overwide_change_interval",
            scope=scope,
            start=start,
            end=end,
        )
    if lower >= end or upper < start:
        return _attribution_result(
            "excluded", "outside_selected_interval", scope=scope, start=start, end=end
        )
    try:
        origin = (
            _authority_value(row.get("authority"), "Change authority"),
            _text_value(row.get("family"), "Change family"),
            _text_value(row.get("object_id"), "Change object ID"),
        )
    except RelationshipError:
        return _attribution_result(
            "context_only",
            "no_qualified_relationship_chain",
            scope=scope,
            start=start,
            end=end,
        )
    interval_reason = (
        "overlapping_change_interval"
        if lower < start or upper >= end
        else "qualified_object_reference"
    )
    if origin in selected:
        return _attribution_result(
            "direct_object", interval_reason, scope=scope, start=start, end=end
        )

    link_content: dict[str, bytes] = {}
    deduped_links: dict[str, dict[str, Any]] = {}
    for link in links:
        evidence_id = link["evidence_id"]
        content = canonical_json(link)
        prior = link_content.get(evidence_id)
        if prior is not None and prior != content:
            return _attribution_result(
                "context_only",
                "conflicting_relationship_identity",
                scope=scope,
                start=start,
                end=end,
            )
        link_content[evidence_id] = content
        deduped_links[evidence_id] = link

    graph: dict[
        tuple[str, str, str], list[tuple[tuple[str, str, str], dict[str, Any]]]
    ] = {}
    all_scope_graph: dict[tuple[str, str, str], list[tuple[str, str, str]]] = {}
    partial_links: list[tuple[tuple[str, str, str], dict[str, Any]]] = []
    for link in deduped_links.values():
        if link["scope"] != scope:
            continue
        source = tuple(link["from_" + key] for key in ("authority", "type", "id"))
        target = tuple(link["to_" + key] for key in ("authority", "type", "id"))
        all_scope_graph.setdefault(source, []).append(target)
        if link["valid_from"] > lower or link["valid_to"] <= upper:
            partial_links.append((source, link))
            continue
        graph.setdefault(source, []).append((target, link))
    for edges in graph.values():
        edges.sort(key=lambda item: (item[1]["evidence_id"], item[0]))

    matches: dict[tuple[tuple[str, str, str], tuple[str, ...]], dict[str, Any]] = {}
    truncated = False
    partial_reachable = False
    steps = 0
    stack: list[
        tuple[
            tuple[str, str, str],
            tuple[str, ...],
            tuple[tuple[str, str, str], ...],
            tuple[dict[str, Any], ...],
        ]
    ] = [(origin, (), (origin,), ())]
    while stack:
        node, path_ids, path_nodes, chain = stack.pop()
        for target, link in graph.get(node, []):
            steps += 1
            if steps > MAX_ATTRIBUTION_STEPS:
                truncated = True
                break
            if target in path_nodes:
                continue
            next_ids = (*path_ids, link["evidence_id"])
            next_chain = (*chain, link)
            target_kind = (
                "observed_dependency"
                if target in dependencies
                else "selected_object"
                if target in selected
                else None
            )
            if target_kind is not None:
                matches[(target, next_ids)] = {
                    "target": {
                        "authority": target[0],
                        "type": target[1],
                        "id": target[2],
                    },
                    "target_class": target_kind,
                    "links": list(next_chain),
                }
                if len(matches) > MAX_ATTRIBUTION_CHAINS:
                    truncated = True
                    break
            outgoing = graph.get(target, [])
            if len(next_chain) >= MAX_RELATIONSHIP_DEPTH:
                if any(
                    candidate not in (*path_nodes, target) for candidate, _ in outgoing
                ):
                    truncated = True
                    break
                continue
            stack.append((target, next_ids, (*path_nodes, target), next_chain))
        if truncated:
            break
    if not truncated and partial_links:
        reachable = {origin}
        todo = [origin]
        while todo:
            node = todo.pop()
            for target in all_scope_graph.get(node, []):
                if target not in reachable:
                    reachable.add(target)
                    todo.append(target)
        partial_reachable = any(source in reachable for source, _ in partial_links)
    if truncated:
        return _attribution_result(
            "context_only",
            "relationship_traversal_incomplete",
            scope=scope,
            start=start,
            end=end,
        )
    if partial_reachable and not matches:
        return _attribution_result(
            "context_only",
            "relationship_validity_incomplete",
            scope=scope,
            start=start,
            end=end,
        )
    ordered_matches = sorted(
        matches.values(),
        key=lambda item: (
            item["target"]["authority"],
            item["target"]["type"],
            item["target"]["id"],
            tuple(link["evidence_id"] for link in item["links"]),
        ),
    )
    if not ordered_matches:
        return _attribution_result(
            "context_only",
            "relationship_validity_incomplete"
            if partial_reachable
            else "no_qualified_relationship_chain",
            scope=scope,
            start=start,
            end=end,
        )
    category = (
        "observed_dependency"
        if any(
            item["target_class"] == "observed_dependency" for item in ordered_matches
        )
        else "direct_object"
    )
    return _attribution_result(
        category, interval_reason, ordered_matches, scope=scope, start=start, end=end
    )
