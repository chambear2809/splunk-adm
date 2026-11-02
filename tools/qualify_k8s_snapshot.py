"""Offline validator for one native Kubernetes point snapshot; no ownership inference."""

from __future__ import annotations

from decimal import Decimal
import hashlib
import ipaddress
import json
import math
import re
import uuid

MAX_ROWS = 10_001
MAX_BYTES = 16 * 1024 * 1024
MAX_EVENT = 65_536
MAX_WINDOW = 3600
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}\Z")
INDEX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
SCHEMAS = {
    "node": ("application_atlas.k8s_node_snapshot.v1", "adm:k8s_node_snapshot:v1"),
    "pod": (
        "application_atlas.k8s_pod_node_snapshot.v1",
        "adm:k8s_pod_node_snapshot:v1",
    ),
}


class SnapshotQualificationError(ValueError):
    """Invalid or incomplete point-snapshot evidence."""


def _require(condition, reason):
    if not condition:
        raise SnapshotQualificationError(reason)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def _string(value):
    # Go encoding/json escapes HTML and U+2028/U+2029 even with UTF-8 output.
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        encoded = (
            encoded.replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )
        return encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    except (TypeError, UnicodeError):
        raise SnapshotQualificationError("invalid_string") from None


def go_json(value):
    """Reproduce encoding/json for this contract's finite JSON scalar domain."""
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        _require(math.isfinite(value), "nonfinite_number")
        if value == 0:
            return "-0" if math.copysign(1, value) < 0 else "0"
        text = repr(value)
        magnitude = abs(value)
        if 1e-6 <= magnitude < 1e21:
            return format(Decimal(text), "f").removesuffix(".0")
        mantissa, exponent = text.lower().split("e")
        mantissa = mantissa.removesuffix(".0")
        n = int(exponent)
        return mantissa + "e" + ("+" if n >= 0 else "-") + str(abs(n))
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(go_json(v) for v in value) + "]"
    if isinstance(value, dict):
        _require(all(isinstance(k, str) for k in value), "invalid_json_key")
        return (
            "{"
            + ",".join(_string(k) + ":" + go_json(value[k]) for k in sorted(value))
            + "}"
        )
    raise SnapshotQualificationError("invalid_json_value")


def _sha(text):
    try:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        raise SnapshotQualificationError("invalid_unicode") from None


def _number(value, name):
    _require(
        type(value) in (float, int)
        and math.isfinite(value)
        and 0 <= value <= 253402300799,
        name,
    )
    return float(value)


def _identity(value, name):
    _require(isinstance(value, str) and bool(IDENTITY.fullmatch(value)), name)
    return value


def _ip(value):
    try:
        parsed = ipaddress.ip_address(value)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            raise ValueError()
        if parsed.is_unspecified or parsed.is_multicast or str(parsed) != value:
            raise ValueError()
        return str(parsed)
    except (ValueError, TypeError):
        raise SnapshotQualificationError("invalid_address") from None


def validate_snapshot(
    rows,
    *,
    resource,
    index,
    source,
    sourcetype,
    host,
    producer_id,
    cluster,
    scope,
    now,
    receipt_cutoff,
    max_age,
    max_receipt_delay,
    completion_count,
    truncated,
):
    """Validate exactly one fully delivered generation against administrator bindings.

    Rows contain _raw, _time, _indextime, index, source, sourcetype and host.
    Completion count and truncation must come from independent native job metadata.
    Output remains point-only, with no node UID inferred from a pod's node name.
    """
    _require(resource in SCHEMAS, "invalid_resource")
    schema, expected_sourcetype = SCHEMAS[resource]
    _require(isinstance(index, str) and INDEX.fullmatch(index), "invalid_index")
    for v, label in (
        (source, "invalid_source"),
        (host, "invalid_host"),
        (producer_id, "invalid_producer"),
        (cluster, "invalid_cluster"),
        (scope, "invalid_scope"),
    ):
        _identity(v, label)
    _require(
        scope.lower().split(":", 1)[0] not in ("unknown", "unmapped", "reserved"),
        "invalid_scope",
    )
    _require(sourcetype == expected_sourcetype, "invalid_sourcetype")
    now, receipt_cutoff, max_age, max_receipt_delay = [
        _number(v, "invalid_time")
        for v in (now, receipt_cutoff, max_age, max_receipt_delay)
    ]
    _require(
        receipt_cutoff <= now
        and 0 < max_age <= MAX_WINDOW
        and 0 <= max_receipt_delay <= MAX_WINDOW,
        "invalid_window",
    )
    _require(
        isinstance(rows, list)
        and 1 <= len(rows) <= MAX_ROWS
        and type(completion_count) is int
        and completion_count == len(rows)
        and truncated is False,
        "incomplete_or_truncated",
    )
    events, receipt_values, total = [], [], 0
    for row in rows:
        _require(
            isinstance(row, dict)
            and all(
                row.get(k) == v
                for k, v in (
                    ("index", index),
                    ("source", source),
                    ("sourcetype", sourcetype),
                    ("host", host),
                )
            ),
            "source_mismatch",
        )
        raw = row.get("_raw")
        _require(isinstance(raw, str), "raw_missing")
        try:
            size = len(raw.encode("utf-8"))
            _require(size < MAX_EVENT, "event_cap")
            total += size + 1
            _require(total <= MAX_BYTES, "input_cap")
            event = json.loads(
                raw,
                object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    SnapshotQualificationError("nonfinite_number")
                ),
            )
        except (UnicodeError, ValueError, TypeError):
            raise SnapshotQualificationError("invalid_event") from None
        _require(isinstance(event, dict), "invalid_event")
        try:
            _require(
                type(row["_time"]) is not bool and type(row["_indextime"]) is not bool,
                "invalid_receipt",
            )
            event_time, receipt = float(row["_time"]), float(row["_indextime"])
        except (KeyError, ValueError, TypeError, OverflowError):
            raise SnapshotQualificationError("invalid_receipt") from None
        _require(
            math.isfinite(event_time)
            and math.isfinite(receipt)
            and 0 <= receipt <= receipt_cutoff,
            "invalid_receipt",
        )
        events.append(event)
        receipt_values.append((event_time, receipt))
    manifests = [e for e in events if e.get("kind") == "manifest"]
    objects = [e for e in events if e.get("kind") == "object"]
    _require(len(manifests) == 1 and len(events) == len(objects) + 1, "manifest_count")
    manifest = manifests[0]
    common_fields = {
        "schema",
        "schema_version",
        "kind",
        "generation_id",
        "cluster",
        "scope",
        "producer_id",
        "observation_started_at",
        "observation_completed_at",
    }
    manifest_fields = common_fields | {
        "resource_version",
        "expected_count",
        "records_sha256",
        "complete",
        "validity_basis",
        "namespace_scope",
    }
    object_fields = (
        common_fields
        | {"uid", "name", "record_fingerprint"}
        | (
            {"addresses"}
            if resource == "node"
            else {"namespace", "node_name", "host_network", "pod_ips", "phase"}
        )
    )
    _require(
        set(manifest) == manifest_fields
        and all(set(e) == object_fields for e in objects),
        "unexpected_fields",
    )
    generation = manifest.get("generation_id")
    try:
        parsed = uuid.UUID(generation)
        _require(
            str(parsed) == generation and parsed.version == 4, "generation_invalid"
        )
    except (ValueError, TypeError, AttributeError):
        raise SnapshotQualificationError("generation_invalid") from None
    _require(
        manifest.get("complete") is True
        and manifest.get("validity_basis") == "point_snapshot"
        and manifest.get("namespace_scope") == "all",
        "manifest_invalid",
    )
    _require(
        type(manifest.get("expected_count")) is int
        and 0 <= manifest["expected_count"] <= 10000
        and manifest["expected_count"] == len(objects),
        "record_count",
    )
    rv = manifest.get("resource_version")
    _require(
        isinstance(rv, str)
        and 0 < len(rv) <= 4096
        and not any(0xD800 <= ord(c) <= 0xDFFF for c in rv)
        and len(rv.encode("utf-8")) <= 4096,
        "resource_version",
    )
    start = _number(manifest.get("observation_started_at"), "observation_invalid")
    end = _number(manifest.get("observation_completed_at"), "observation_invalid")
    _require(
        start <= end <= receipt_cutoff
        and end - start <= MAX_WINDOW
        and 0 <= now - end <= max_age,
        "observation_window",
    )
    common = {
        "schema": schema,
        "schema_version": 1,
        "generation_id": generation,
        "cluster": cluster,
        "scope": scope,
        "producer_id": producer_id,
        "observation_started_at": manifest["observation_started_at"],
        "observation_completed_at": manifest["observation_completed_at"],
    }
    for event, (event_time, receipt) in zip(events, receipt_values):
        _require(
            type(event.get("schema_version")) is int
            and all(event.get(k) == v for k, v in common.items()),
            "common_binding_mismatch",
        )
        _require(
            abs(event_time - end) <= 0.000001
            and end - 1 <= receipt <= receipt_cutoff
            and receipt - end <= max_receipt_delay,
            "receipt_window",
        )
    seen_uids, seen_names, node_ips = set(), set(), {}
    ordered = []
    for e in objects:
        uid = _identity(e.get("uid"), "uid_invalid")
        name = _identity(e.get("name"), "name_invalid")
        _require(uid not in seen_uids, "duplicate_uid")
        seen_uids.add(uid)
        namespace = (
            _identity(e.get("namespace"), "namespace_invalid")
            if resource == "pod"
            else None
        )
        name_key = (namespace, name) if resource == "pod" else name
        _require(name_key not in seen_names, "duplicate_name")
        seen_names.add(name_key)
        if resource == "node":
            addresses = e.get("addresses")
            _require(
                isinstance(addresses, list) and len(addresses) <= 512,
                "addresses_invalid",
            )
            pairs = []
            for a in addresses:
                _require(
                    isinstance(a, dict)
                    and set(a) == {"type", "address"}
                    and a.get("type") in ("InternalIP", "ExternalIP"),
                    "address_invalid",
                )
                ip = _ip(a.get("address"))
                pairs.append((a["type"], ip))
                _require(ip not in node_ips or node_ips[ip] == uid, "competing_node_ip")
                node_ips[ip] = uid
            _require(pairs == sorted(set(pairs)), "addresses_invalid")
        else:
            _identity(e.get("namespace"), "namespace_invalid")
            _require(
                e.get("node_name") == ""
                or (
                    isinstance(e.get("node_name"), str)
                    and bool(IDENTITY.fullmatch(e["node_name"]))
                ),
                "node_name_invalid",
            )
            _require(
                type(e.get("host_network")) is bool
                and isinstance(e.get("phase"), str)
                and len(e["phase"]) <= 256,
                "pod_invalid",
            )
            ips = e.get("pod_ips")
            _require(isinstance(ips, list) and len(ips) <= 512, "pod_ips_invalid")
            normalized = [_ip(ip) for ip in ips]
            _require(normalized == sorted(set(normalized)), "pod_ips_invalid")
        fingerprint = e.get("record_fingerprint")
        _require(
            isinstance(fingerprint, str) and HEX.fullmatch(fingerprint),
            "fingerprint_invalid",
        )
        _require(
            _sha(go_json({k: v for k, v in e.items() if k != "record_fingerprint"}))
            == fingerprint,
            "fingerprint_mismatch",
        )
        ordered.append(e)
    ordered.sort(key=lambda e: e["uid"])
    expected_digest = manifest.get("records_sha256")
    _require(
        isinstance(expected_digest, str)
        and HEX.fullmatch(expected_digest)
        and _sha("\n".join(go_json(e) for e in ordered)) == expected_digest,
        "digest_mismatch",
    )
    return {
        "schema": schema,
        "generation_id": generation,
        "cluster": cluster,
        "scope": scope,
        "producer_id": producer_id,
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "host": host,
        "observation_started_at": start,
        "observation_completed_at": end,
        "validity_basis": "point_snapshot",
        "records_sha256": expected_digest,
        "first_received_at": min(receipt for _, receipt in receipt_values),
        "last_received_at": max(receipt for _, receipt in receipt_values),
        "records": ordered,
    }
