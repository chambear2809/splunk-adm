"""Offline connected-source bundle factory for scenario contract v2.

This is deliberately distinct from the installed v1 capture bundle. It carries
source-shaped facts and phase proof only; indexed receipts and activation are
added by the installed capture path after independent readback.
"""
from __future__ import annotations

from typing import Any

from tools.change_correlation.contracts import canonical_json, sha256_hex
from tools.change_scenarios_v2 import load_scenario, scenario_template_hash
from tools.raw_fixtures.change_scenarios_v2 import (
    assert_source_phase_buckets,
    native_payload_sha256,
    prepare_source_inputs,
)

SCHEMA_VERSION = 2
KIND = "connected_scenario_source_bundle_v2"
FORBIDDEN = {
    "indexed_receipt_epoch",
    "event_fingerprint",
    "readback_epoch",
    "received_at",
}
MAX_SAFE = 9_007_199_254_740_991


class ConnectedBundleError(ValueError):
    pass


def _portable(value: Any) -> Any:
    if isinstance(value, int) and abs(value) > MAX_SAFE:
        return str(value)
    if isinstance(value, list):
        return [_portable(item) for item in value]
    if isinstance(value, dict):
        return {key: _portable(item) for key, item in value.items()}
    return value


def _assert_safe(value: Any) -> None:
    if isinstance(value, dict):
        if FORBIDDEN.intersection(value):
            raise ConnectedBundleError("Connected bundle contains receipt claims.")
        for item in value.values():
            _assert_safe(item)
    elif isinstance(value, list):
        for item in value:
            _assert_safe(item)


def _body(scenario_id: str, variant_id: str | None, execution_id: str, anchor_epoch: int) -> dict[str, Any]:
    scenario = load_scenario(scenario_id, variant_id)
    inputs = prepare_source_inputs(scenario, execution_id=execution_id, anchor_epoch=anchor_epoch)
    portable_events = _portable(inputs["events"])
    for item in portable_events:
        raw_events = item.get("raw_events", [])
        expected = item.get("readback_expected", [])
        for ordinal, readback in enumerate(expected):
            if ordinal < len(raw_events) and isinstance(raw_events[ordinal], dict):
                readback["native_payload_sha256"] = native_payload_sha256(
                    raw_events[ordinal].get("event")
                )
    phase_proof = assert_source_phase_buckets(
        scenario, {"events": portable_events}, anchor_epoch=anchor_epoch
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "scenario_id": scenario["scenario_id"],
        "variant_id": scenario["variant_id"],
        "template_sha256": scenario_template_hash(scenario),
        "execution_id": execution_id,
        "anchor_epoch": anchor_epoch,
        "application": scenario["application"],
        "connected_services": scenario.get("connected_services", []),
        "identities": inputs["identities"],
        "events": portable_events,
        "phase_proof": phase_proof,
        "limitations": inputs.get("limitations", []),
    }


def build_connected_bundle(
    scenario_id: str,
    *,
    variant_id: str | None = None,
    execution_id: str,
    anchor_epoch: int,
) -> dict[str, Any]:
    body = _body(scenario_id, variant_id, execution_id, anchor_epoch)
    encoded = canonical_json(body)
    _assert_safe(body)
    return {**body, "bundle_sha256": sha256_hex(encoded)}


def verify_connected_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict) or bundle.get("schema_version") != SCHEMA_VERSION:
        raise ConnectedBundleError("Connected bundle schema is unsupported.")
    digest = bundle.get("bundle_sha256")
    body = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    if digest != sha256_hex(canonical_json(body)):
        raise ConnectedBundleError("Connected bundle hash does not match content.")
    if bundle.get("kind") != KIND or not isinstance(bundle.get("events"), list):
        raise ConnectedBundleError("Connected bundle shape is invalid.")
    _assert_safe(body)
    expected = _body(
        bundle["scenario_id"], bundle["variant_id"],
        bundle["execution_id"], bundle["anchor_epoch"],
    )
    if canonical_json(body) != canonical_json(expected):
        raise ConnectedBundleError("Connected bundle content is not deterministic.")
    return bundle
