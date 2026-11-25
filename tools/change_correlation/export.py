"""Deterministic offline HEC NDJSON export for evidence and generations."""

from __future__ import annotations

import re
from typing import Any

from .contracts import MAX_INPUT_BYTES, MAX_RECORD_BYTES, canonical_json

EVIDENCE_SOURCETYPE = "adm:configuration_evidence:v1"
CHANGE_SOURCETYPE = "adm:configuration_change:v1"
MANIFEST_SOURCETYPE = "adm:configuration_change_manifest:v1"
HEC_SOURCE = "atlas:configuration_history"
MAX_MANIFEST_BYTES = 512 * 1024
INDEX_RE = re.compile(r"^[a-z][a-z0-9_-]{0,79}$")


def _source_time(record: dict[str, Any]) -> int | float:
    for key in ("latest_at", "event_at", "observed_at", "received_at"):
        value = record.get(key)
        if value is not None:
            return value
    return 0


def _hec_event(
    event: dict[str, Any], *, index: str, sourcetype: str, time: int | float
) -> bytes:
    return canonical_json(
        {
            "time": time,
            "index": index,
            "sourcetype": sourcetype,
            "source": HEC_SOURCE,
            "event": event,
        }
    )


def render_generation_hec(generation: dict[str, Any], *, index: str) -> str:
    """Render receipt, object, generation row and manifest HEC events.

    The output is a local transport file only. This function does not send HEC
    requests. One administrator-selected literal index is used for every row.
    """

    if not isinstance(index, str) or not INDEX_RE.fullmatch(index):
        raise ValueError("Index must be a safe literal Splunk index name.")
    receipts = generation.get("receipts")
    observations = generation.get("observations")
    rows = generation.get("rows")
    manifest = generation.get("manifest")
    if not all(isinstance(items, list) for items in (receipts, observations, rows)):
        raise ValueError("Generation evidence and rows must be arrays.")
    if not isinstance(manifest, dict):
        raise ValueError("Generation manifest must be an object.")
    manifest_bytes = canonical_json(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError("Generation manifest exceeds the 512 KiB limit.")

    events: list[bytes] = []
    for receipt in receipts:
        event = _hec_event(
            receipt,
            index=index,
            sourcetype=EVIDENCE_SOURCETYPE,
            time=receipt["received_at"],
        )
        if len(event) > MAX_RECORD_BYTES:
            raise ValueError("Receipt HEC event exceeds the 64 KiB limit.")
        events.append(event)
    for observation in observations:
        event = _hec_event(
            observation,
            index=index,
            sourcetype=EVIDENCE_SOURCETYPE,
            time=_source_time(observation),
        )
        if len(event) > MAX_RECORD_BYTES:
            raise ValueError("Object evidence HEC event exceeds the 64 KiB limit.")
        events.append(event)
    for row in rows:
        event = _hec_event(
            row,
            index=index,
            sourcetype=CHANGE_SOURCETYPE,
            time=_source_time(row),
        )
        if len(event) > MAX_RECORD_BYTES:
            raise ValueError("Generation row HEC event exceeds the 64 KiB limit.")
        events.append(event)
    # The materialized manifest uses the generation's source coordinate for
    # lookup. Actual ingest remains _indextime; receipt clocks stay in evidence.
    # A late export or future-reported native clock must not strand the manifest
    # outside the bounded source-time query containing its history rows.
    manifest_time = manifest["source_latest"]
    if manifest_time is None:
        # Empty audit exports may retain receipt evidence, but cannot activate.
        manifest_time = max((receipt["received_at"] for receipt in receipts), default=0)
    manifest_event = _hec_event(
        manifest,
        index=index,
        sourcetype=MANIFEST_SOURCETYPE,
        time=manifest_time,
    )
    if len(manifest_event) > MAX_MANIFEST_BYTES:
        raise ValueError("Generation manifest HEC event exceeds the 512 KiB limit.")
    events.append(manifest_event)
    output = b"\n".join(events) + b"\n"
    if len(output) > MAX_INPUT_BYTES:
        raise ValueError("HEC output exceeds the 50 MiB limit.")
    return output.decode("utf-8")


def render_manifest_json(generation: dict[str, Any]) -> str:
    """Render the exact immutable manifest sidecar as one JSON line."""

    manifest = generation.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("Generation manifest must be an object.")
    payload = canonical_json(manifest)
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ValueError("Generation manifest exceeds the 512 KiB limit.")
    return (payload + b"\n").decode("utf-8")
