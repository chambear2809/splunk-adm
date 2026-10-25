#!/usr/bin/env python3
"""Validate the offline semantic artifacts for Atlas processor templates.

This validates fixtures, expected output fingerprints, deployment descriptors,
and the reviewed pass-through templates. It does not parse or execute SPL2 and
does not establish Edge Processor or Ingest Processor runtime behavior.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
from typing import Any


class ProcessorContractError(ValueError):
    """A fixture or profile does not match the v1 Atlas processor contract."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessorContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ProcessorContractError(f"non-finite JSON number: {value}")


def strict_json_loads(text: str) -> Any:
    """Parse JSON while rejecting duplicate keys and non-JSON numeric values."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except ProcessorContractError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProcessorContractError(f"invalid JSON: {exc.msg}") from None


def canonical_sha256(value: Any) -> str:
    """Fingerprint semantic JSON values, ignoring object key order and spacing."""
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProcessorContractError("value is not canonical JSON data") from exc
    return hashlib.sha256(payload).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProcessorContractError(message)


def _repo_file(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        raise ProcessorContractError(
            f"fixture path escapes repository: {relative}"
        ) from None
    if not path.is_file():
        raise ProcessorContractError(f"fixture file is missing: {relative}")
    return path


def _read_json(root: Path, relative: str) -> Any:
    return strict_json_loads(_repo_file(root, relative).read_text(encoding="utf-8"))


def _read_ndjson(root: Path, relative: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        _repo_file(root, relative).read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            raise ProcessorContractError(
                f"blank JSON Lines record: {relative}:{line_number}"
            )
        value = strict_json_loads(line)
        if not isinstance(value, dict):
            raise ProcessorContractError(
                f"HEC envelope must be an object: {relative}:{line_number}"
            )
        records.append(value)
    return records


def _validate_hec_envelope(
    envelope: dict[str, Any],
    *,
    label: str,
    required_index: str | None,
    index_must_be_absent: bool = False,
) -> dict[str, Any]:
    required = {"time", "host", "source", "sourcetype", "event"}
    _require(required.issubset(envelope), f"{label}: missing HEC envelope keys")
    timestamp = envelope["time"]
    _require(
        isinstance(timestamp, (int, float))
        and not isinstance(timestamp, bool)
        and math.isfinite(timestamp)
        and timestamp >= 0,
        f"{label}: HEC time must be a finite nonnegative number of seconds",
    )
    for key in ("host", "source", "sourcetype"):
        _require(
            isinstance(envelope[key], str) and bool(envelope[key]),
            f"{label}: HEC {key} must be a nonempty string",
        )
    _require(
        isinstance(envelope["event"], dict), f"{label}: HEC event must be a JSON object"
    )
    if index_must_be_absent:
        _require(
            "index" not in envelope,
            f"{label}: producer fixture must not define an index",
        )
    if required_index is not None:
        _require(
            envelope.get("index") == required_index, f"{label}: unexpected input index"
        )
    if "fields" in envelope:
        _require(
            isinstance(envelope["fields"], dict),
            f"{label}: HEC fields must be a flat object",
        )
        _require(
            all(
                not isinstance(value, (dict, list))
                for value in envelope["fields"].values()
            ),
            f"{label}: HEC indexed fields must be flat scalar values",
        )
    return envelope["event"]


def _output_metadata_digest(envelope: dict[str, Any], target_index: str) -> str:
    return canonical_sha256(
        {
            "time": envelope["time"],
            "host": envelope["host"],
            "source": envelope["source"],
            "sourcetype": envelope["sourcetype"],
            "index": target_index,
        }
    )


def _epoch(timestamp: str) -> float:
    try:
        parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ProcessorContractError(
            f"invalid RFC3339 timestamp in golden input: {timestamp!r}"
        ) from None
    _require(
        parsed.tzinfo is not None, "NetFlow event timestamp must include a UTC offset"
    )
    return parsed.timestamp()


def _validate_netflow_search_facts(
    sources: list[tuple[str, dict[str, Any]]], golden_facts: dict[str, Any]
) -> None:
    """Check the direct-input search projection recorded for the installed TA."""
    _require(
        golden_facts.get("search_macro") == "adm_flows_netflow",
        "NetFlow installed-search macro changed",
    )
    _require(
        golden_facts.get("purpose")
        == "Expected direct-ingestion facts for installed TA/search validation only; not Edge or Ingest Processor output.",
        "NetFlow installed-search facts must remain direct-input expectations",
    )
    facts = golden_facts.get("records")
    _require(
        isinstance(facts, list) and len(facts) == len(sources),
        "NetFlow installed-search fact count changed",
    )
    transport_names = {1: "icmp", 6: "tcp", 17: "udp"}
    for (label, envelope), expected in zip(sources, facts, strict=True):
        event = envelope["event"]
        _require(
            expected.get("input") == label,
            f"NetFlow installed-search input order changed at {label}",
        )
        _require(
            expected.get("metadata")
            == {
                key: envelope[key]
                for key in ("time", "host", "source", "sourcetype", "index")
            },
            f"NetFlow direct HEC metadata differs from installed-search expectation: {label}",
        )
        expected_raw = {
            key: event[key]
            for key in (
                "exporter_ip",
                "seqnumber",
                "src_ip",
                "dest_ip",
                "protoid",
                "bytes",
                "packets",
                "exporter_sampling_interval",
                "timestamp",
                "endtime",
                "input_snmpidx",
                "output_snmpidx",
                "src_port",
                "dest_port",
            )
            if key in event
        }
        _require(
            expected.get("raw") == expected_raw,
            f"NetFlow direct search fields differ from fixture: {label}",
        )
        _require(
            event.get("protoid") in transport_names,
            f"{label}: expected protocol is outside the installed-search golden set",
        )
        sampling = event.get("exporter_sampling_interval", 1)
        sampling = sampling if sampling > 1 else 1
        normalized = expected.get("normalized", {})
        _require(
            normalized.get("adm_observer") == event.get("exporter_ip"),
            f"{label}: observer differs from exporter authority",
        )
        _require(
            normalized.get("adm_exporter") == event.get("exporter_ip"),
            f"{label}: exporter identity changed",
        )
        _require(
            normalized.get("adm_transport") == transport_names[event["protoid"]],
            f"{label}: normalized transport changed",
        )
        _require(
            normalized.get("adm_sampling") == sampling,
            f"{label}: sampling value changed",
        )
        _require(
            normalized.get("adm_bytes_fwd") == event["bytes"] * sampling,
            f"{label}: sampled bytes changed",
        )
        _require(
            normalized.get("adm_packets") == event["packets"] * sampling,
            f"{label}: sampled packets changed",
        )
        _require(
            math.isclose(
                normalized.get("adm_start_epoch", -1),
                _epoch(event["timestamp"]),
                abs_tol=0.000001,
            ),
            f"{label}: start time projection changed",
        )
        _require(
            math.isclose(
                normalized.get("adm_end_epoch", -1),
                _epoch(event["endtime"]),
                abs_tol=0.000001,
            ),
            f"{label}: end time projection changed",
        )
        _require(
            normalized.get("adm_in_ifindex") == event.get("input_snmpidx"),
            f"{label}: input interface index changed",
        )
        _require(
            normalized.get("adm_out_ifindex") == event.get("output_snmpidx"),
            f"{label}: output interface index changed",
        )


def _validate_profiles(root: Path) -> list[str]:
    sources = {
        "stream_netflow": {
            "file": "stream_netflow.spl2",
            "sourcetype": "stream:netflow",
            "index": "netflow",
        },
        "atlas_o11y_health": {
            "file": "atlas_o11y_health.spl2",
            "sourcetype": "atlas:o11y_health",
            "index": "atlas_o11y",
        },
    }
    checked: list[str] = []
    for product in ("edge", "ingest"):
        descriptor_path = f"integrations/processors/v1/{product}/deployment.json"
        descriptor = _read_json(root, descriptor_path)
        expected_id = "edge_processor" if product == "edge" else "ingest_processor"
        expected_profile = "edgeProcessor" if product == "edge" else "ingestProcessor"
        _require(
            descriptor.get("id") == expected_id, f"{product}: unexpected profile id"
        )
        _require(
            descriptor.get("spl2_profile") == expected_profile,
            f"{product}: wrong SPL2 profile",
        )
        _require(
            descriptor.get("enabled_by_default") is False,
            f"{product}: profile must remain optional",
        )
        _require(
            descriptor.get("scope_exclusions")
            == [
                "Observability detector-event sourcetypes",
                "AppDynamics sourcetypes",
                "All other sourcetypes outside the two selected partitions",
            ],
            f"{product}: out-of-scope source families must remain explicit",
        )
        _require(
            "directly or separately qualify"
            in descriptor.get("excluded_input_handling", ""),
            f"{product}: excluded sources need a separate route or fallback qualification",
        )
        _require(
            descriptor.get("serialization", {}).get("explicit_null_fields")
            == {
                "pod_uid": None,
                "container_name": None,
                "host_name": None,
                "jvm_memory_pool_name": None,
            },
            f"{product}: health optional null fields must be documented",
        )
        _require(
            descriptor.get("serialization", {}).get("runtime_null_roundtrip")
            == "unqualified; verify explicit nulls in product preview and indexed readback before qualification.",
            f"{product}: runtime null round-trip must remain unqualified",
        )
        behavior = descriptor.get("behavior")
        _require(isinstance(behavior, dict), f"{product}: behavior section missing")
        for disabled in ("filtering_enabled", "fanout_enabled", "masking_enabled"):
            _require(
                behavior.get(disabled) is False,
                f"{product}: {disabled} must remain false",
            )

        pipelines = descriptor.get("pipelines")
        _require(
            isinstance(pipelines, list) and len(pipelines) == len(sources),
            f"{product}: expected two pipelines",
        )
        by_source = {
            entry.get("id"): entry for entry in pipelines if isinstance(entry, dict)
        }
        _require(
            set(by_source) == {"stream_netflow_v1", "atlas_o11y_health_v1"},
            f"{product}: unexpected pipeline set",
        )
        for pipeline_id, spec in (
            ("stream_netflow_v1", sources["stream_netflow"]),
            ("atlas_o11y_health_v1", sources["atlas_o11y_health"]),
        ):
            entry = by_source[pipeline_id]
            _require(
                entry.get("partition_sourcetype") == spec["sourcetype"],
                f"{product}/{pipeline_id}: source type changed",
            )
            _require(
                entry.get("target_index") == spec["index"],
                f"{product}/{pipeline_id}: target index changed",
            )
            _require(
                entry.get("destination_count") == 1,
                f"{product}/{pipeline_id}: exactly one destination is required",
            )
            _require(
                entry.get("partition_conditions")
                == [
                    {
                        "field": "sourcetype",
                        "operator": "equals",
                        "value": spec["sourcetype"],
                    }
                ],
                f"{product}/{pipeline_id}: exact sourcetype partition changed",
            )
            _require(
                entry.get("preserve_input_host_source_sourcetype_time") is True,
                f"{product}/{pipeline_id}: source metadata must be preserved",
            )
            relative = f"integrations/processors/v1/{product}/{spec['file']}"
            template = _repo_file(root, relative).read_text(encoding="utf-8").strip()
            expected = f'$pipeline = | from $source | eval index="{spec["index"]}" | into $destination;'
            _require(
                template == expected,
                f"{relative}: only the reviewed index-routing identity pipeline is allowed",
            )
            checked.append(relative)

    edge = _read_json(root, "integrations/processors/v1/edge/deployment.json")
    _require(
        edge.get("input", {}).get("selected_endpoint") == "/services/collector",
        "Edge must select structured /services/collector input",
    )
    _require(
        "/services/collector/raw"
        in edge.get("input", {}).get("supported_endpoints", []),
        "Edge raw endpoint behavior must be documented",
    )
    _require(
        "disabled" in edge.get("input", {}).get("indexer_acknowledgement", "").lower(),
        "Edge HEC acknowledgements must be disabled",
    )
    _require(
        edge.get("input", {}).get("event_metadata_preserved")
        == ["time", "host", "source", "sourcetype", "fields"],
        "Edge HEC metadata preservation contract changed",
    )
    _require(
        edge.get("serialization", {}).get("pipeline_changes_no_event_body_fields")
        is True,
        "Edge pipeline must remain a pass-through",
    )
    ingest = _read_json(root, "integrations/processors/v1/ingest/deployment.json")
    _require(
        "8088" in str(ingest.get("input", {}).get("default_hec_port")),
        "Ingest Processor HEC port must be documented",
    )
    _require(
        "disabled"
        in ingest.get("input", {}).get("indexer_acknowledgement", "").lower(),
        "Ingest Processor HEC acknowledgements must be disabled",
    )
    _require(
        ingest.get("input", {}).get("raw_endpoint_supported") is False,
        "Ingest Processor must not claim an undocumented raw endpoint",
    )
    _require(
        ingest.get("minimum_platform_version") == "9.1.2308",
        "Ingest Processor minimum Cloud version changed",
    )
    _require(
        ingest.get("input", {}).get("event_metadata_preserved")
        == ["time", "host", "source", "sourcetype", "fields"],
        "Ingest Processor HEC metadata preservation contract changed",
    )
    _require(
        ingest.get("serialization", {}).get("pipeline_changes_no_event_body_fields")
        is True,
        "Ingest Processor pipeline must remain a pass-through",
    )
    return checked


def validate_processor_contract(root: Path) -> dict[str, Any]:
    """Validate static contract artifacts and return an offline-only summary."""
    root = root.resolve()
    manifest = _read_json(root, "fixtures/processors/v1/manifest.json")
    golden = _read_json(root, "fixtures/processors/v1/golden_outputs.json")
    _require(
        manifest.get("selected_sourcetypes") == ["stream:netflow", "atlas:o11y_health"],
        "selected processor source set changed",
    )
    _require(
        manifest.get("expected_output_fingerprints")
        == "fixtures/processors/v1/golden_outputs.json",
        "manifest golden-output path changed",
    )
    _require(
        manifest.get("qualification") == "offline_semantic_expectations_only",
        "fixture manifest must be marked offline-only",
    )
    _require(
        golden.get("qualification") == "offline_semantic_expectations_only",
        "golden outputs must be marked offline-only",
    )
    _require(
        golden.get("processors_executed") is False,
        "golden output must not claim processor execution",
    )

    template_paths = _validate_profiles(root)

    netflow_expected = golden.get("netflow", {})
    netflow_inputs = netflow_expected.get("source_fixtures", [])
    _require(
        netflow_inputs == manifest.get("inputs", {}).get("stream_netflow"),
        "NetFlow source fixture list differs from manifest",
    )
    netflow_records: list[tuple[str, dict[str, Any]]] = []
    required_netflow_fields = set(netflow_expected.get("required_event_fields", []))
    _require(
        bool(required_netflow_fields), "NetFlow required event field list is empty"
    )
    for relative in netflow_inputs:
        for line_number, envelope in enumerate(_read_ndjson(root, relative), 1):
            label = f"{relative}:{line_number}"
            event = _validate_hec_envelope(
                envelope, label=label, required_index="netflow"
            )
            _require(
                envelope["source"] == "stream:netflow"
                and envelope["sourcetype"] == "stream:netflow",
                f"{label}: NetFlow source metadata changed",
            )
            _require(
                required_netflow_fields.issubset(event),
                f"{label}: required NetFlow fact missing",
            )
            for key in ("src_port", "dest_port"):
                if event.get("protoid") == 1:
                    _require(
                        key not in event,
                        f"{label}: ICMP fixture must keep {key} absent",
                    )
            netflow_records.append((label, envelope))
    expected_netflow_records = netflow_expected.get("required_event_hashes", [])
    _require(
        len(netflow_records) == netflow_expected.get("expected_record_count"),
        "NetFlow fixture event count changed",
    )
    _require(
        len(netflow_records) == len(expected_netflow_records),
        "NetFlow golden event count changed",
    )
    for (label, envelope), expected in zip(
        netflow_records, expected_netflow_records, strict=True
    ):
        _require(
            expected.get("input") == label,
            f"NetFlow golden input order changed at {label}",
        )
        _require(
            expected.get("event_sha256") == canonical_sha256(envelope["event"]),
            f"NetFlow event differs from golden output: {label}",
        )
        _require(
            expected.get("output_metadata_sha256")
            == _output_metadata_digest(envelope, "netflow"),
            f"NetFlow HEC metadata differs from golden output: {label}",
        )
    for sample in netflow_expected.get("samples", []):
        relative, line_text = sample["input"].rsplit(":", 1)
        line_number = int(line_text)
        records = _read_ndjson(root, relative)
        event = records[line_number - 1]["event"]
        for key, expected_value in sample["facts"].items():
            if key == "ports_absent":
                _require(
                    expected_value is True
                    and "src_port" not in event
                    and "dest_port" not in event,
                    f"{sample['input']}: missing-port sample changed",
                )
            else:
                _require(
                    event.get(key) == expected_value,
                    f"{sample['input']}: golden sample fact {key} changed",
                )
    _validate_netflow_search_facts(
        netflow_records, netflow_expected.get("installed_search_facts", {})
    )

    health_expected = golden.get("o11y_health_v1", {})
    health_file = manifest.get("inputs", {}).get("atlas_o11y_health_v1", [])
    _require(
        health_file == [health_expected.get("source_fixture")],
        "health fixture path differs from manifest",
    )
    health_doc = _read_json(root, health_expected["source_fixture"])
    _require(
        isinstance(health_doc, dict) and isinstance(health_doc.get("events"), list),
        "health fixture must contain an event list",
    )
    health_envelopes = health_doc["events"]
    _require(
        len(health_envelopes) == health_expected.get("expected_record_count"),
        "health fixture event count changed",
    )
    _require(
        "target_index" in health_expected.get("metadata_contract", {})
        and health_expected["metadata_contract"].get("input_index_absent") is True,
        "health index routing expectation missing",
    )
    required_null_fields = [
        "pod_uid",
        "container_name",
        "host_name",
        "jvm_memory_pool_name",
    ]
    _require(
        health_expected.get("required_null_fields") == required_null_fields,
        "health optional null-field list changed",
    )
    _require(
        health_expected.get("required_null_values")
        == {field: None for field in required_null_fields},
        "health golden output must encode the optional fields as JSON null",
    )
    labels: list[str] = []
    completion: list[dict[str, Any]] = []
    health_hashes = health_expected.get("required_event_hashes", [])
    _require(
        len(health_envelopes) == len(health_hashes), "health golden event count changed"
    )
    for index, (envelope, expected) in enumerate(
        zip(health_envelopes, health_hashes, strict=True)
    ):
        label = f"{health_expected['source_fixture']}:events[{index}]"
        event = _validate_hec_envelope(
            envelope, label=label, required_index=None, index_must_be_absent=True
        )
        _require(
            envelope["source"] == "atlas:o11y_health/export"
            and envelope["sourcetype"] == "atlas:o11y_health",
            f"{label}: health source metadata changed",
        )
        _require(
            event.get("schema") == "application_atlas.o11y_health.v1",
            f"{label}: health schema must remain v1",
        )
        _require(
            event.get("captured_at") == envelope["time"],
            f"{label}: envelope time must remain capture time",
        )
        _require(
            envelope["host"] == event.get("observer_id"),
            f"{label}: health host and observer authority differ",
        )
        _require(
            expected.get("input") == label,
            f"{label}: health golden input order changed",
        )
        _require(
            expected.get("output_metadata_sha256")
            == _output_metadata_digest(envelope, "atlas_o11y"),
            f"{label}: health HEC metadata differs from golden output",
        )
        if event.get("event_type") == "metric":
            for field in required_null_fields:
                _require(
                    field in event and event[field] is None,
                    f"{label}: health optional field {field} must remain explicit JSON null",
                )
            labels.append(event.get("signal_label"))
            _require(
                event.get("unit")
                == health_expected.get("expected_units", {}).get(
                    event.get("signal_label")
                ),
                f"{label}: metric unit changed",
            )
        elif event.get("event_type") == "export_completion":
            completion.append(event)
        else:
            raise ProcessorContractError(f"{label}: unexpected health event type")
        _require(
            expected.get("event_sha256") == canonical_sha256(event),
            f"{label}: health event differs from golden output",
        )
    _require(
        len(labels) == health_expected.get("expected_metric_count"),
        "health metric count changed",
    )
    _require(
        sorted(labels) == health_expected.get("expected_signal_labels"),
        "health signal labels changed",
    )
    _require(
        len(completion) == health_expected.get("expected_completion_count") == 1,
        "health completion event missing or duplicated",
    )
    _require(
        health_envelopes[-1]["event"].get("event_type") == "export_completion",
        "health completion event must be final",
    )
    _require(
        completion[0].get("expected_record_count") == len(labels),
        "health completion count differs from metric records",
    )
    _require(
        completion[0].get("capture_id")
        == health_envelopes[0]["event"].get("capture_id"),
        "health capture identity differs",
    )

    otel_expected = golden.get("otel_hec_external_fields", {})
    otel_copy = _read_ndjson(
        root, "fixtures/processors/v1/inputs/otel_trace_with_hec_fields.ndjson"
    )
    _require(
        len(otel_copy) == otel_expected.get("expected_record_count") == 1,
        "OTel HEC boundary fixture must have one record",
    )
    otel = otel_copy[0]
    _require(
        manifest.get("inputs", {}).get("otel_external_hec_fields_boundary_case")
        == [otel_expected.get("source_fixture", "").rsplit(":", 1)[0]],
        "OTel HEC boundary fixture path differs from manifest",
    )
    _require(
        hashlib.sha256(
            _repo_file(
                root, "fixtures/processors/v1/inputs/otel_trace_with_hec_fields.ndjson"
            ).read_bytes()
        ).hexdigest()
        == otel_expected.get("input_bytes_sha256"),
        "OTel fixture bytes differ from the reviewed copy",
    )
    _validate_hec_envelope(
        otel, label="OTel external HEC metadata", required_index="otel_traces"
    )
    external_fields = otel.get("fields")
    _require(
        isinstance(external_fields, dict),
        "OTel resource metadata must remain in top-level HEC fields",
    )
    outside_event = otel_expected.get("identity_fields_remain_outside_event", [])
    _require(
        all(
            key in external_fields and key not in otel["event"] for key in outside_event
        ),
        "OTel identity fields moved into event or went missing",
    )
    _require(
        external_fields == otel_expected.get("external_fields"),
        "OTel external HEC fields differ from golden output",
    )
    _require(
        canonical_sha256(external_fields)
        == otel_expected.get("external_fields_sha256"),
        "OTel external HEC metadata hash differs from golden output",
    )
    _require(
        canonical_sha256(otel["event"]) == otel_expected.get("event_sha256"),
        "OTel event body differs from golden output",
    )

    negative = manifest.get("negative_inputs", {})
    duplicate_path = negative.get("duplicate_json_key")
    malformed_path = negative.get("malformed_json")
    _require(
        bool(duplicate_path) and bool(malformed_path), "negative JSON cases are missing"
    )
    for relative in (duplicate_path, malformed_path):
        lines = _repo_file(root, relative).read_text(encoding="utf-8").splitlines()
        _require(
            len(lines) == 1, f"negative fixture must contain one input: {relative}"
        )
        try:
            strict_json_loads(lines[0])
        except ProcessorContractError:
            pass
        else:
            raise ProcessorContractError(
                f"negative fixture unexpectedly parsed as valid JSON: {relative}"
            )
    unmatched_path = negative.get("unmatched_sourcetype")
    unmatched = _read_ndjson(root, unmatched_path)
    _require(
        len(unmatched) == 1,
        "unmatched partition fixture must have one valid HEC envelope",
    )
    _validate_hec_envelope(
        unmatched[0], label="unmatched source fixture", required_index="main"
    )
    _require(
        unmatched[0]["sourcetype"] not in manifest.get("selected_sourcetypes", []),
        "unmatched fixture unexpectedly matches a selected pipeline",
    )

    return {
        "qualification": "offline_semantic_expectations_only",
        "processors_executed": False,
        "profile_templates_checked": template_paths,
        "netflow_records": len(netflow_records),
        "health_metric_records": len(labels),
        "health_completion_records": len(completion),
        "health_explicit_null_fields": required_null_fields,
        "otel_external_fields_records": len(otel_copy),
        "negative_json_inputs_rejected": 2,
        "runtime_qualification": {
            "edge_processor": "unqualified",
            "ingest_processor": "unqualified",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="directory containing integrations/ and fixtures/ (defaults to the unpacked toolkit root)",
    )
    args = parser.parse_args()
    try:
        summary = validate_processor_contract(args.root)
    except (OSError, UnicodeError, ProcessorContractError, KeyError, TypeError) as exc:
        parser.exit(1, f"processor contract validation failed: {exc}\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
