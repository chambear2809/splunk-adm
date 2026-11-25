"""Fail-closed FMC native adapters and normalized-only contract export."""

from __future__ import annotations

from typing import Any

from ..contracts import ContractError, normalize_collection
from ..export import render_generation_hec
from ..history import build_generation


def _refuse_native_schema(message: str) -> None:
    raise ContractError("unsupported_source_schema", message)


def adapt_fmc_policy_details(
    native_records: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Refuse unqualified native policy-detail payloads from the Cisco TA.

    The reviewed Cisco Security Cloud 3.7.2 collector emits each FMC detail
    response as full JSON but does not establish its detail field paths or
    timestamp/collection metadata. Its use of list-item id only builds the
    detail URL; that list response is not emitted with the detail event.
    """

    _refuse_native_schema(
        "Native FMC policy-detail records require a version-matched sanitized "
        "TA output sample and per-poll collection metadata before adaptation."
    )


def adapt_fmc_audits(native_records: Any, collection_metadata: Any) -> dict[str, Any]:
    """Refuse native FMC audit records until their on-prem schema is qualified."""

    _refuse_native_schema(
        "Native FMC audit records require a version-matched on-prem response "
        "schema and sanitized sample before adaptation."
    )


def adapt_fmc_access_rules(
    native_records: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Refuse rule payloads until their schema, order, and identity are qualified."""

    _refuse_native_schema(
        "Native FMC access-rule records require a version-matched schema and "
        "sanitized sample before adaptation."
    )


def adapt_fmc_deployment_jobs(
    native_records: Any, collection_metadata: Any
) -> dict[str, Any]:
    """Refuse deployment payloads until per-device result fields are qualified."""

    _refuse_native_schema(
        "Native FMC deployment records require a version-matched schema and "
        "sanitized per-device result sample before adaptation."
    )


def normalize_fmc_audit_export(normalized_collection: Any) -> dict[str, Any]:
    """Validate an already normalized FMC audit collection, without parsing API data."""

    if not isinstance(normalized_collection, dict):
        raise ContractError("invalid_collection", "Collection must be an object.")
    if (
        normalized_collection.get("product") != "fmc"
        or normalized_collection.get("family") != "audit_record"
    ):
        raise ContractError(
            "unsupported_projection",
            "Normalized FMC audit export requires product fmc and family audit_record.",
        )
    return normalize_collection(normalized_collection)


def render_fmc_audit_normalized_export(
    normalized_collection: Any, *, index: str
) -> str:
    """Render an already normalized FMC audit collection as offline HEC NDJSON.

    This helper preserves contract-level evidence through the generic immutable
    history pipeline. It does not collect, parse, or qualify FMC-native records.
    """

    collection = normalize_fmc_audit_export(normalized_collection)
    generation = build_generation([collection])
    return render_generation_hec(generation, index=index)
