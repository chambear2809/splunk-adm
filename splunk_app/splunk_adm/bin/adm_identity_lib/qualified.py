"""Read-time service identity from complete, attested finite ownership windows.

No document is written, no service lifetime is interpolated, and no traffic or
physical path is inferred from a trace relationship.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
import ipaddress
import json
import math
import re

from .protocol import canonical, owners_digest

INDEX = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}\Z")
NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
HEX32, HEX16 = re.compile(r"[0-9a-f]{32}\Z"), re.compile(r"[0-9a-f]{16}\Z")
KINDS = {
    "SPAN_KIND_" + name.upper(): name
    for name in ("client", "server", "internal", "producer", "consumer")
}
MAX_INPUT = 50000


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def number(value, label):
    if isinstance(value, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
        value = float(value)
    require(
        type(value) in (int, float) and math.isfinite(value) and value >= 0,
        "Invalid " + label + ".",
    )
    return value


def text(value, label, pattern=TEXT):
    require(
        isinstance(value, str) and bool(pattern.fullmatch(value)),
        "Invalid " + label + ".",
    )
    return value


def ip(value):
    try:
        parsed = str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        raise EvidenceError("Invalid ownership IP.") from None
    require(parsed == value, "Ownership IP must be canonical.")
    return parsed


def profile_config(value):
    require(
        isinstance(value, dict) and value.get("enabled") is True,
        "Qualified identity is disabled.",
    )
    result = dict(value)
    for name in (
        "cluster",
        "environment",
        "scope",
        "producer_id",
        "interval_source",
        "span_source",
    ):
        text(result.get(name), name)
    for name in ("interval_index", "span_index"):
        text(result.get(name), name, INDEX)
    require(
        result.get("interval_sourcetype") == "adm:pod_ip_interval:v2"
        and result.get("span_sourcetype") == "otel:traces",
        "Unsupported identity source schema.",
    )
    namespaces = result.get("namespaces")
    require(
        isinstance(namespaces, list)
        and 0 < len(namespaces) <= 20
        and len(set(namespaces)) == len(namespaces),
        "Explicit namespace coverage is required.",
    )
    for ns in namespaces:
        text(ns, "namespace", NAMESPACE)
    return result


def decode(row):
    value = row.get("_raw")
    require(
        isinstance(value, str) and len(value) <= 1048576,
        "Raw evidence is missing or over budget.",
    )
    try:
        result = json.loads(value)
    except (ValueError, TypeError):
        raise EvidenceError("Malformed identity event JSON.") from None
    require(isinstance(result, dict), "Identity event must be an object.")
    return result


def resources(row, raw):
    containers = [raw]
    attributes = raw.get("attributes")
    if isinstance(attributes, dict):
        # Explicit collector-side copies survive HEC's raw/metadata split.
        containers.append(
            {
                key.removeprefix("atlas.resource."): value
                for key, value in attributes.items()
                if key.startswith("atlas.resource.")
            }
        )
    resource = raw.get("resource")
    if isinstance(resource, dict):
        containers.append(resource)
        attributes = resource.get("attributes")
        if isinstance(attributes, dict):
            containers.append(attributes)
        elif isinstance(attributes, list):
            mapped = {}
            for item in attributes:
                require(
                    isinstance(item, dict) and isinstance(item.get("key"), str),
                    "Malformed OTel resource attributes.",
                )
                key = item["key"]
                value = item.get("value", {})
                value = value.get("stringValue") if isinstance(value, dict) else value
                require(
                    key not in mapped or mapped[key] == value,
                    "Conflicting OTel resource attributes.",
                )
                mapped[key] = value
            containers.append(mapped)
    result = {}
    for field, aliases in {
        "service": ["service.name"],
        "environment": ["deployment.environment.name", "deployment.environment"],
        "cluster": ["k8s.cluster.name"],
        "namespace": ["k8s.namespace.name"],
        "pod_uid": ["k8s.pod.uid"],
    }.items():
        values = []
        for container in containers:
            for alias in aliases:
                if alias in container:
                    value = container[alias]
                    if isinstance(value, dict):
                        value = value.get("stringValue")
                    if value is not None:
                        values.append(value)
        require(
            len({canonical(v) for v in values}) <= 1,
            "Contradictory span resource identity.",
        )
        result[field] = values[0] if values else None
        # Extracted fields may corroborate raw identity, never establish it.
        for alias in aliases:
            if alias in row:
                require(
                    row[alias] == result[field],
                    "Extracted identity disagrees with raw event.",
                )
    return result


def ns_time(value):
    require(
        type(value) is int or isinstance(value, str) and re.fullmatch(r"[0-9]+", value),
        "Span times must be OTLP integer nanoseconds.",
    )
    value = int(value)
    require(0 < value < 2**64, "Invalid OTLP timestamp.")
    return value / 1_000_000_000


def overlap(a, b, c, d):
    return a < d and c < b


def qualify(rows, profile, window_start, as_of):
    try:
        return _qualify(rows, profile, window_start, as_of)
    except (EvidenceError, ValueError, TypeError, KeyError, OverflowError) as exc:
        message = (
            str(exc)
            if isinstance(exc, EvidenceError)
            else "Malformed qualified identity evidence."
        )
        return {
            "complete": False,
            "catalog_rows": [],
            "bindings": [],
            "warnings": [message],
            "graph_rows": [],
        }


def _qualify(rows, profile, window_start, as_of):
    p = profile_config(profile)
    start, cutoff = number(window_start, "window start"), number(as_of, "as-of")
    require(
        start < cutoff and cutoff - start <= 300,
        "Qualified identity windows must be between 0 and 300 seconds.",
    )
    require(
        isinstance(rows, list) and len(rows) <= MAX_INPUT,
        "Qualified identity input exceeds its budget.",
    )
    manifests, owners, span_events = {}, {}, {}
    span_resources = {}
    for row in rows:
        require(isinstance(row, dict), "Evidence row is not an object.")
        family = None
        for candidate in ("interval", "span"):
            if all(
                row.get(key) == p[candidate + "_" + key]
                for key in ("index", "source", "sourcetype")
            ):
                family = candidate
        require(
            family is not None, "Evidence does not match the attested source profile."
        )
        event = number(row.get("event_time"), "event time")
        receipt = number(row.get("receipt_time"), "receipt time")
        if receipt > cutoff:
            continue  # Not knowledge available at this as-of.
        require(
            start <= event <= cutoff,
            "Evidence lies outside the requested knowledge horizon.",
        )
        raw = decode(row)
        if family == "span":
            trace = text(raw.get("trace_id"), "trace ID", HEX32)
            sid = text(raw.get("span_id"), "span ID", HEX16)
            require(
                trace != "0" * 32 and sid != "0" * 16,
                "Zero span/trace identifiers are invalid.",
            )
            attrs = resources(row, raw)
            signature = canonical({"raw": raw, "resources": attrs, "event_time": event})
            key = (trace, sid)
            if key in span_events:
                require(
                    span_events[key]["signature"] == signature,
                    "Conflicting duplicate span identity.",
                )
                span_events[key]["receipt"] = min(span_events[key]["receipt"], receipt)
                continue
            span_events[key] = {
                "raw": raw,
                "event": event,
                "receipt": receipt,
                "signature": signature,
            }
            span_resources[key] = attrs
            continue
        require(
            raw.get("schema") == "adm:pod_ip_interval:v2",
            "Unsupported interval event schema.",
        )
        for key in ("cluster", "environment", "producer_id"):
            require(
                raw.get(key) == p[key],
                "Interval authority does not match its attestation.",
            )
        text(raw.get("producer_epoch"), "producer epoch")
        snapshot = text(raw.get("snapshot_id"), "snapshot ID")
        vf, vt, observed = [
            number(raw.get(k), k) for k in ("valid_from", "valid_to", "observed_at")
        ]
        require(
            vf < vt <= observed <= receipt <= cutoff and event == observed,
            "Invalid interval observation/receipt clocks.",
        )
        kind = raw.get("kind")
        if kind == "manifest":
            require(
                raw.get("namespace_scope") == "all",
                "A complete all-namespace manifest is required.",
            )
            text(raw.get("checkpoint_nonce"), "checkpoint nonce")
            require(
                type(raw.get("expected_count")) is int
                and 0 <= raw["expected_count"] <= 10000,
                "Invalid owner count.",
            )
            require(
                isinstance(raw.get("invalidated_ips"), list)
                and len(raw["invalidated_ips"]) <= 10000,
                "Invalid uncertainty coverage.",
            )
            for address in raw["invalidated_ips"]:
                ip(address)
            require(
                len(set(raw["invalidated_ips"])) == len(raw["invalidated_ips"]),
                "Duplicate invalidated IP.",
            )
            if snapshot in manifests:
                require(
                    canonical(manifests[snapshot]) == canonical(raw),
                    "Conflicting replayed manifest.",
                )
            manifests[snapshot] = raw
        elif kind == "owner":
            rid = text(raw.get("record_id"), "owner record ID")
            body = {k: v for k, v in raw.items() if k != "record_id"}
            require(
                hashlib.sha256(canonical(body).encode()).hexdigest() == rid,
                "Owner record identity changed.",
            )
            require(
                raw.get("operation") == "present"
                and type(raw.get("host_network")) is bool,
                "Unsupported ownership operation.",
            )
            text(raw.get("namespace"), "namespace", NAMESPACE)
            text(raw.get("pod_uid"), "pod UID")
            text(raw.get("node_name"), "node name")
            ip(raw.get("ip"))
            if rid in owners:
                require(
                    canonical(owners[rid]) == canonical(raw),
                    "Conflicting replayed owner.",
                )
            owners[rid] = raw  # Exact immutable replay does not count twice.
        else:
            raise EvidenceError("Unknown interval event kind.")
    require(bool(manifests), "No complete interval snapshot is available.")
    require(
        len(manifests) <= 100, "Snapshot count exceeds the qualified window budget."
    )
    grouped = defaultdict(list)
    for owner in owners.values():
        require(
            owner["snapshot_id"] in manifests,
            "An observed owner snapshot is incomplete.",
        )
        grouped[owner["snapshot_id"]].append(owner)
    shared = (
        "schema",
        "cluster",
        "environment",
        "producer_id",
        "producer_epoch",
        "snapshot_id",
        "valid_from",
        "valid_to",
        "observed_at",
    )
    by_ip = defaultdict(list)
    pod_addresses = defaultdict(set)
    blocked = defaultdict(list)
    for sid, manifest in manifests.items():
        records = grouped[sid]
        require(
            len(records) == manifest["expected_count"]
            and owners_digest(records) == manifest.get("owners_sha256"),
            "Snapshot owner count/checksum is incomplete.",
        )
        for owner in records:
            require(
                all(owner[k] == manifest[k] for k in shared),
                "Owner and manifest authority/window disagree.",
            )
            by_ip[owner["ip"]].append(owner)
            pod_addresses[(owner["pod_uid"], owner["namespace"])].add(owner["ip"])
        for address in manifest["invalidated_ips"]:
            blocked[address].append((manifest["valid_from"], manifest["valid_to"]))
    # Every manifest describes the entire Pod inventory. Conflicting complete
    # windows (including an owner absent in one epoch) cannot certify ownership.
    snapshot_values = list(manifests.items())
    signatures = {
        sid: {
            (o["ip"], o["namespace"], o["pod_uid"], o["host_network"])
            for o in grouped[sid]
        }
        for sid in manifests
    }
    for offset, (sid, manifest) in enumerate(snapshot_values):
        for other_sid, other in snapshot_values[offset + 1 :]:
            if overlap(
                manifest["valid_from"],
                manifest["valid_to"],
                other["valid_from"],
                other["valid_to"],
            ):
                require(
                    signatures[sid] == signatures[other_sid],
                    "Overlapping complete snapshots disagree about ownership.",
                )
    bindings = []
    excluded = Counter()
    for key, item in span_events.items():
        attrs = span_resources[key]
        raw = item["raw"]
        if (
            attrs["cluster"] != p["cluster"]
            or attrs["environment"] != p["environment"]
            or attrs["namespace"] not in p["namespaces"]
        ):
            excluded["outside_selected_scope"] += 1
            continue
        if not all(
            isinstance(attrs[k], str) and TEXT.fullmatch(attrs[k]) for k in attrs
        ):
            excluded["incomplete_resource_identity"] += 1
            continue
        try:
            st, et = ns_time(raw.get("start_time")), ns_time(raw.get("end_time"))
        except EvidenceError:
            excluded["invalid_span_clock"] += 1
            continue
        kind = KINDS.get(raw.get("kind"))
        parent = raw.get("parent_span_id") or None
        if parent == "0" * 16:
            parent = None
        if kind is None or parent is not None and not HEX16.fullmatch(parent):
            excluded["invalid_span_kind_or_parent"] += 1
            continue
        if (
            not start <= st < et <= cutoff
            or not st <= item["event"] < et
            or item["receipt"] < et
        ):
            excluded["unqualified_span_clock"] += 1
            continue
        valid_ips = set()
        snapshots = set()
        for address in pod_addresses[(attrs["pod_uid"], attrs["namespace"])]:
            candidates = by_ip[address]
            matching = [
                o
                for o in candidates
                if not o["host_network"]
                and o["pod_uid"] == attrs["pod_uid"]
                and o["namespace"] == attrs["namespace"]
                and o["valid_from"] <= st
                and et <= o["valid_to"]
            ]
            if not matching:
                continue
            if any(overlap(st, et, a, b) for a, b in blocked[address]):
                continue
            if any(
                (o["pod_uid"], o["namespace"]) != (attrs["pod_uid"], attrs["namespace"])
                and overlap(st, et, o["valid_from"], o["valid_to"])
                for o in candidates
            ):
                continue
            valid_ips.add(address)
            snapshots.update(o["snapshot_id"] for o in matching)
        if not valid_ips:
            excluded["missing_or_ambiguous_ownership"] += 1
            continue
        bindings.append(
            {
                **attrs,
                "trace_id": key[0],
                "span_id": key[1],
                "parent_span_id": parent,
                "kind": kind,
                "ip_candidates": sorted(valid_ips),
                "snapshot_ids": sorted(snapshots),
                "valid_from": st,
                "valid_to": et,
                "observed_at": item["event"],
                "scope": p["scope"],
            }
        )
    catalog = []
    services = defaultdict(list)
    for b in bindings:
        services[
            tuple(b[k] for k in ("service", "environment", "cluster", "namespace"))
        ].append(b)
    for identity, values in sorted(services.items()):
        catalog.append(
            {
                "_key": hashlib.sha256(canonical(identity).encode()).hexdigest(),
                **dict(
                    zip(("service", "environment", "cluster", "namespace"), identity)
                ),
                "identity_contract": "qualified_v2",
                "pods": len({b["pod_uid"] for b in values}),
                "first_seen": int(min(b["observed_at"] for b in values)),
                "last_seen": int(max(b["observed_at"] for b in values)),
                "updated": int(cutoff),
                "window_start": int(start),
                "window_end": int(cutoff),
            }
        )
    warnings = [
        "Service identities are finite ownership/span observations; they do not establish network traffic or an ACI path."
    ]
    if excluded:
        warnings.append(
            str(sum(excluded.values()))
            + " spans were excluded because scope, clocks, or finite ownership could not be qualified."
        )
    return {
        "complete": True,
        "catalog_rows": catalog,
        "bindings": bindings,
        "warnings": warnings,
        "excluded": dict(excluded),
        "window_start": int(start),
        "window_end": int(cutoff),
        "generated_at": int(cutoff),
        "scope": p["scope"],
        # These records are exposed only after complete manifests, record IDs,
        # counts, digests and overlapping-snapshot consistency were verified.
        # Network observations must still resolve ownership at their own times.
        "owner_records": [dict(value) for value in owners.values()],
        "ownership_invalidations": [
            {"ip": address, "valid_from": first, "valid_to": last}
            for address, periods in blocked.items()
            for first, last in periods
        ],
    }


def service_id(binding):
    return "service:" + "/".join(
        binding[k] for k in ("cluster", "namespace", "service", "environment")
    )


def graph_rows(result, selection=None):
    if not result.get("complete"):
        return []
    bindings = result["bindings"]
    parents = {(b["trace_id"], b["span_id"]): b for b in bindings}
    nodes = {}
    edges = {}
    calls = defaultdict(set)
    for binding in bindings:
        ident = service_id(binding)
        nodes[ident] = {
            "row_type": "node",
            "id": ident,
            "label": binding["service"],
            "kind": "service",
            "cluster": binding["cluster"],
            "namespace": binding["namespace"],
            "attr_environment": binding["environment"],
            "attr_identity_basis": "complete finite pod-IP snapshot and explicit OTel span",
        }
    for b in bindings:
        parent = parents.get((b["trace_id"], b["parent_span_id"]))
        if b["kind"] != "server" or not parent or parent["kind"] != "client":
            continue
        pair = (service_id(parent), service_id(b))
        calls[pair].add((b["trace_id"], b["span_id"]))
    for pair, proof in calls.items():
        edges[pair] = {
            "row_type": "edge",
            "id": "calls:" + hashlib.sha256(canonical(pair).encode()).hexdigest(),
            "source": pair[0],
            "target": pair[1],
            "relationship": "calls",
            "confidence": "observed",
            "evidence": ["parent/child OTel spans; complete finite pod-IP ownership"],
            "count": len(proof),
            "sources": ["otel"],
            "span_ids": sorted({sid for _, sid in proof}),
            "scope": result["scope"],
        }
    if selection:
        root = service_id(selection)
        require(
            root in nodes,
            "Selected service has no qualified observations in this window.",
        )
        seen = {root}
        pending = deque([root])
        while pending:
            node = pending.popleft()
            for a, b in edges:
                other = b if a == node else a if b == node else None
                if other is not None and other not in seen:
                    seen.add(other)
                    pending.append(other)
        nodes = {k: v for k, v in nodes.items() if k in seen}
        edges = {k: v for k, v in edges.items() if k[0] in seen and k[1] in seen}
    require(
        len(nodes) <= 500 and len(edges) <= 2000,
        "Qualified graph exceeds the pilot budget.",
    )
    meta = {
        "row_type": "meta",
        "window_start": result["window_start"],
        "window_end": result["window_end"],
        "generated_at": result["generated_at"],
        "nodes": len(nodes),
        "edges": len(edges),
        "spans": len(bindings),
        "warnings": result["warnings"],
    }
    return [*nodes.values(), *edges.values(), meta]
