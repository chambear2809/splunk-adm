"""Qualified workload observations alongside independently qualified service calls.

A graph is a set of facts in a selected window. A span-to-pod membership is not
interpolated into continuous service ownership or a packet/application cause.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from bisect import bisect_right
import hashlib
import ipaddress
import json

from .native_network import normalize_records, validate_profiles
from .protocol import canonical
from .qualified import graph_rows, ip, number, require, service_id, text

MAX_NODES = 500
MAX_EDGES = 2000
OBSERVATIONS_PER_EDGE = 64
# Keep collection bounded even when an exporter sends an unusually large
# number of distinct edge identities.  The rendered edge budget remains the
# authoritative cap; records beyond these limits are reported in graph meta.
MAX_GROUPS = MAX_EDGES
MAX_STORED_OBSERVATIONS = MAX_EDGES * OBSERVATIONS_PER_EDGE


def configuration(value, identity_profile):
    require(isinstance(value, dict), "Network configuration must be an object.")
    require(type(value.get("enabled", False)) is bool, "Invalid network enabled flag.")
    if not value.get("enabled", False):
        return {"enabled": False, "profiles": [], "frontends": []}
    profiles = validate_profiles(value.get("profiles"), identity_profile)
    frontends = value.get("frontends", [])
    require(
        isinstance(frontends, list) and len(frontends) <= 20,
        "Invalid frontend intents.",
    )
    cleaned = []
    windows = defaultdict(list)
    for original in frontends:
        require(isinstance(original, dict), "Frontend intent must be an object.")
        item = dict(original)
        for key in ("scope", "service", "environment", "cluster", "namespace"):
            text(item.get(key), "frontend " + key)
        require(
            item["cluster"] == identity_profile["cluster"]
            and item["environment"] == identity_profile["environment"]
            and item["namespace"] in identity_profile["namespaces"],
            "Frontend intent is outside the attested application scope.",
        )
        item["address"] = ip(item.get("address"))
        item["valid_from"] = number(item.get("valid_from"), "frontend intent start")
        item["valid_to"] = number(item.get("valid_to"), "frontend intent end")
        require(
            0 < item["valid_to"] - item["valid_from"] <= 3600,
            "Frontend intent must have an explicit window of at most one hour.",
        )
        require(
            any(
                p["kind"] == "netflow" and p["scope"] == item["scope"] for p in profiles
            ),
            "Frontend intent requires a registered exporter scope.",
        )
        key = (item["scope"], item["address"])
        require(
            all(
                item["valid_to"] <= start or item["valid_from"] >= end
                for start, end in windows[key]
            ),
            "Ambiguous frontend intent.",
        )
        windows[key].append((item["valid_from"], item["valid_to"]))
        cleaned.append(item)
    return {"enabled": True, "profiles": profiles, "frontends": cleaned}


def _intersects(first, last, start, end):
    # Point observations must not use overlap(t,t,a,b), which misses boundaries.
    return start <= first < end if first == last else first < end and start <= last


def evidence_indexes(result):
    owners = defaultdict(list)
    invalidations = defaultdict(list)
    bindings = defaultdict(lambda: defaultdict(list))
    for owner in result["owner_records"]:
        owners[owner["ip"]].append(owner)
    for item in result["ownership_invalidations"]:
        invalidations[item["ip"]].append(item)
    for binding in result["bindings"]:
        for address in binding["ip_candidates"]:
            bindings[(binding["pod_uid"], binding["namespace"], address)][
                service_id(binding)
            ].append(binding)
    service_indexes = {}
    for key, services in bindings.items():
        service_indexes[key] = {}
        for sid, values in services.items():
            values.sort(key=lambda value: value["valid_from"])
            starts, maximum_ends = [], []
            latest_end = float("-inf")
            for value in values:
                starts.append(value["valid_from"])
                latest_end = max(latest_end, value["valid_to"])
                maximum_ends.append(latest_end)
            service_indexes[key][sid] = (starts, maximum_ends)
    return {
        "owners": owners,
        "invalidations": invalidations,
        "services": service_indexes,
    }


def owner_at(result, address, first, last, owner_scope, indexes=None):
    if owner_scope != result.get("scope"):
        return None, "unattested_address_domain"
    indexes = indexes if indexes is not None else evidence_indexes(result)
    if any(
        _intersects(first, last, v["valid_from"], v["valid_to"])
        for v in indexes["invalidations"].get(address, [])
    ):
        return None, "invalidated_ownership"
    overlapping = [
        o
        for o in indexes["owners"].get(address, [])
        if _intersects(first, last, o["valid_from"], o["valid_to"])
    ]
    identities = {(o["pod_uid"], o["namespace"]) for o in overlapping}
    if len(identities) > 1:
        return None, "ambiguous_ownership"
    covering = [
        o
        for o in overlapping
        if not o["host_network"] and o["valid_from"] <= first and last < o["valid_to"]
    ]
    if not covering:
        return None, "ownership_not_covered"
    require(
        len({(o["pod_uid"], o["namespace"]) for o in covering}) == 1,
        "Conflicting covering owners.",
    )
    chosen = dict(covering[0])
    chosen["snapshot_ids"] = sorted({o["snapshot_id"] for o in covering})
    chosen["node_names"] = sorted({o["node_name"] for o in covering})
    return chosen, "qualified"


def service_at(result, owner, address, first, last, indexes=None):
    if owner is None:
        return "not_pod_attributed", ()
    indexes = indexes if indexes is not None else evidence_indexes(result)
    services = set()
    for sid, (starts, maximum_ends) in (
        indexes["services"]
        .get((owner["pod_uid"], owner["namespace"], address), {})
        .items()
    ):
        offset = bisect_right(starts, first) - 1
        if offset >= 0 and last < maximum_ends[offset]:
            services.add(sid)
    return (
        "concurrent_span"
        if len(services) == 1
        else "ambiguous_service"
        if services
        else "workload_only"
    ), tuple(sorted(services))


def pod_id(cluster, owner):
    return "pod:" + "/".join((cluster, owner["namespace"], owner["pod_uid"]))


def frontend_at(frontends, record, address):
    """The configured frontend containing the whole observation, for any service.

    ``configuration`` rejects overlapping windows per (scope, address), so at
    most one frontend can contain an observation.
    """
    return next(
        (
            f
            for f in frontends
            if f["scope"] == record["scope"]
            and f["address"] == address
            and f["valid_from"] <= record["first_seen"]
            and record["last_seen"] < f["valid_to"]
        ),
        None,
    )


SELECTION_KEYS = ("service", "environment", "cluster", "namespace")


def _intent_at(frontends, record, address, selection):
    found = frontend_at(frontends, record, address)
    if found is not None and all(found[k] == selection[k] for k in SELECTION_KEYS):
        return found
    return None


def attribute(result, record, indexes):
    """Selection-independent ownership/service attribution of one native record.

    Returns None when a sensor namespace claim contradicts a finite owner.
    """
    first, last = record["first_seen"], record["last_seen"]
    source_owner, source_status = owner_at(
        result, record["source_ip"], first, last, record.get("owner_scope"), indexes
    )
    dest_owner, dest_status = owner_at(
        result,
        record["destination_ip"],
        first,
        last,
        record.get("owner_scope"),
        indexes,
    )
    # Namespace is a sensor claim. A contradictory claim cannot replace a witness.
    if any(
        owner is not None and ns not in (None, "", owner["namespace"])
        for owner, ns in [
            (source_owner, record.get("source_namespace")),
            (dest_owner, record.get("destination_namespace")),
        ]
    ):
        return None
    return {
        "source_owner": source_owner,
        "source_status": source_status,
        "dest_owner": dest_owner,
        "dest_status": dest_status,
        "source_service": service_at(
            result, source_owner, record["source_ip"], first, last, indexes
        ),
        "dest_service": service_at(
            result, dest_owner, record["destination_ip"], first, last, indexes
        ),
    }


def endpoint_id(record, address, owner):
    if owner:
        return pod_id(record["cluster"], owner)
    return (
        "network-endpoint:"
        + hashlib.sha256(canonical([record["scope"], address]).encode()).hexdigest()
    )


def endpoint_node(ident, scope, cluster, address, intent):
    public = ipaddress.ip_address(address).is_global
    return {
        "row_type": "node",
        "id": ident,
        "kind": "endpoint",
        "endpoint_kind": "k8s_service"
        if intent
        else "external"
        if public
        else "unresolved",
        "label": address + (" (configured frontend)" if intent else ""),
        "addresses": [address],
        "cluster": cluster,
        "reason": "Configured frontend intent; backend translation is not established."
        if intent
        else "Observed peer address; no pod identity or physical adjacency is inferred.",
        "attr_scope": scope,
        "attr_identity_basis": "configured_frontend_intent"
        if intent
        else "native_observed_address",
    }


def workload_node(ident, owner, names, addresses, cluster, scope):
    return {
        "row_type": "node",
        "id": ident,
        "kind": "workload",
        "label": next(iter(names))
        if len(names) == 1
        else "Pod " + owner["pod_uid"][:12],
        "namespace": owner["namespace"],
        "cluster": cluster,
        "addresses": sorted(addresses),
        "attr_pod_uid": owner["pod_uid"],
        "attr_identity_basis": "complete finite pod-IP ownership at each observation time",
        "attr_ownership_scope": scope,
        "attr_sensor_name_basis": "Hubble-reported label; ownership is joined by IP and UID, not name",
    }


def membership_edge(sid, ident, binding_count, binding_ids, scope):
    eid = "membership:" + hashlib.sha256(canonical([sid, ident]).encode()).hexdigest()
    return {
        "row_type": "edge",
        "id": eid,
        "source": sid,
        "target": ident,
        "relationship": "runs_on",
        "confidence": "observed",
        "count": binding_count,
        "sources": ["otel"],
        "span_ids": binding_ids[:256],
        "scope": scope,
        "evidence": [
            "Explicit qualified OTel span-to-pod association within the selected window only.",
            "This does not interpolate continuous service ownership or establish packet/application causality.",
        ],
        "reason": f"{binding_count} verified supporting spans; up to 256 IDs displayed. Network observations retain independent event-time attribution.",
    }


def observation_payload(r):
    observation = {
        "source": r["kind"],
        "source_authority": r["profile_id"],
        "scope": r["scope"],
        "cluster": r["cluster"],
        "profile": r["profile_id"],
        "record_fingerprint": r["record_id"],
        "event_identity_status": "indexed_record",
        "records": 1,
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "received_time": r["received_time"],
        "source_ip": r["source_ip"],
        "destination_ip": r["destination_ip"],
        "transport": r["transport"].lower(),
        "observation_point": str(r["observer"])
        + ("/" + str(r["observation_point"]) if r.get("observation_point") else ""),
        "metrics_authoritative": False,
        "quality_status": "accepted_with_warning",
        "counter_semantics": "native observation record; not unique connections or aggregate traffic totals",
        "quality_warnings": "Workload and configured-frontend observations are independent of traced calls; no route or translation is inferred.",
    }
    for field in (
        "source_port",
        "destination_port",
        "raw_bytes",
        "raw_packets",
        "direction",
        "verdict",
        "is_reply",
    ):
        if r.get(field) is not None:
            observation[field] = (
                str(r[field]) if field in ("direction", "verdict") else r[field]
            )
    if r["kind"] == "netflow":
        observation["exporter_ip"] = r["observer"]
        observation["netflow_version"] = r["netflow_version"]
        observation["observation_domain_present"] = int(r["observation_domain_present"])
        if r.get("observation_domain_id") is not None:
            observation["observation_domain_id"] = str(r["observation_domain_id"])
    return observation


def observation_evidence(source_status, dest_status, source_service, dest_service):
    return [
        "Raw native tuple and observer provenance; finite pod ownership is required for workload endpoints.",
        f"Source ownership: {source_status}; destination ownership: {dest_status}.",
        f"Source service at observation time: {source_service}; destination service at observation time: {dest_service}.",
        "Service card grouping describes selected-window spans, not continuous service ownership, NAT, or physical path continuity.",
    ]


def counter_totals(records):
    """Per-edge raw counter sums; every edge has one observer, so no cross-sensor sum."""
    totals = {
        "first_seen": min(r["first_seen"] for r in records),
        "last_seen": max(r["last_seen"] for r in records),
    }
    for field in ("raw_bytes", "raw_packets"):
        values = [r[field] for r in records if r.get(field) is not None]
        if values:
            totals[field] = sum(values)
    blocked = sum(1 for r in records if r.get("verdict") == "DROPPED")
    if blocked:
        totals["blocked_records"] = blocked
    return totals


def network_warnings(identity_warnings, decoded_warnings, excluded, partial, observed):
    warnings = [
        *identity_warnings,
        *decoded_warnings,
        "Network edges are source observations. Service-to-pod grouping is limited to explicit spans in this window and is not a continuous service or packet-causality claim.",
        "Exporter observations are not joined across NAT or forwarding boundaries; configured frontend intent is not backend translation evidence.",
    ]
    if excluded:
        warnings.append(
            str(sum(excluded.values()))
            + " native records were not included: "
            + ", ".join(f"{k}={v}" for k, v in sorted(excluded.items()))
        )
    if partial:
        warnings.append(
            "Partial native graph: qualified native records exceeded the bounded "
            "graph/observation budget; omission counters are included in graph metadata."
        )
    if not observed:
        warnings.append(
            "No qualified native observations were returned for this selected workload context. This is not evidence that no traffic exists."
        )
    return warnings


def decorate_netflow(decoded, profiles):
    profiles_by_id = {profile["id"]: profile for profile in profiles}
    for native_record in decoded["records"]:
        if native_record["kind"] == "netflow":
            # The normalizer validates these against the profile.  Copy the
            # attested values into the graph record so provenance remains
            # visible without trusting event-provided metadata.
            profile = profiles_by_id[native_record["profile_id"]]
            native_record["netflow_version"] = profile["netflow_version"]
            native_record["observation_domain_present"] = profile[
                "observation_domain_present"
            ]
    return decoded


def assemble(result, rows, config, selection, decoded=None):
    require(
        result.get("complete") is True,
        "Complete qualified identity evidence is required.",
    )
    require(
        "owner_records" in result and "ownership_invalidations" in result,
        "Verified owner witnesses are missing.",
    )
    base = graph_rows(result, selection)
    nodes = {r["id"]: r for r in base if r["row_type"] == "node"}
    edges = {r["id"]: r for r in base if r["row_type"] == "edge"}
    meta = dict(next(r for r in base if r["row_type"] == "meta"))
    indexes = evidence_indexes(result)
    selected_ids = set(nodes)
    selected_bindings = [b for b in result["bindings"] if service_id(b) in selected_ids]
    relevant_uids = {(b["pod_uid"], b["namespace"]) for b in selected_bindings}
    if decoded is None:
        decoded = normalize_records(
            rows, config["profiles"], result["window_start"], result["window_end"]
        )
    decorate_netflow(decoded, config["profiles"])
    excluded = Counter(decoded["excluded"])
    groups = defaultdict(list)
    group_omissions = Counter()
    edge_budget_omitted = 0
    stored_observations = 0
    pod_addresses = defaultdict(set)
    pod_claims = defaultdict(set)
    pod_owners = {}

    def endpoint(record, address, owner, sensor_name, intent):
        ident = endpoint_id(record, address, owner)
        if owner:
            pod_addresses[ident].add(address)
            if isinstance(sensor_name, str) and sensor_name:
                pod_claims[ident].add(sensor_name)
            pod_owners[ident] = owner
        else:
            nodes.setdefault(
                ident,
                endpoint_node(
                    ident, record["scope"], record["cluster"], address, intent
                ),
            )
        require(
            len(nodes) + len(pod_owners) <= MAX_NODES,
            "Qualified network node budget exceeded.",
        )
        return ident

    # Budget admission must not depend on search result order.  Splunk can
    # return equally qualified events in different orders across refreshes.
    for record in sorted(
        decoded["records"], key=lambda item: (item["record_id"], item["event_time"])
    ):
        attributed = attribute(result, record, indexes)
        if attributed is None:
            excluded["sensor_namespace_conflict"] += 1
            continue
        source_owner = attributed["source_owner"]
        dest_owner = attributed["dest_owner"]
        source_intent = _intent_at(
            config["frontends"], record, record["source_ip"], selection
        )
        dest_intent = _intent_at(
            config["frontends"], record, record["destination_ip"], selection
        )
        relevant_owner = any(
            o is not None and (o["pod_uid"], o["namespace"]) in relevant_uids
            for o in (source_owner, dest_owner)
        )
        if not relevant_owner and source_intent is None and dest_intent is None:
            excluded["outside_selected_workload_context"] += 1
            continue
        source = endpoint(
            record,
            record["source_ip"],
            source_owner,
            record.get("source_pod"),
            source_intent,
        )
        target = endpoint(
            record,
            record["destination_ip"],
            dest_owner,
            record.get("destination_pod"),
            dest_intent,
        )
        # Ports are observations, not endpoint identity.  Keeping them out of
        # the grouping key prevents high-cardinality ephemeral ports from
        # turning one qualified relationship into thousands of graph edges.
        # Every retained native tuple still carries its ports in the payload.
        key = (
            record["profile_id"],
            record["scope"],
            source,
            target,
            record["source_ip"],
            record["destination_ip"],
            record["transport"].lower(),
            record["observer"],
            record.get("observation_point"),
            record.get("observation_domain_id"),
            record.get("observation_domain_present"),
            record.get("netflow_version"),
            record.get("direction"),
            record.get("verdict"),
            record.get("is_reply"),
            attributed["source_status"],
            attributed["dest_status"],
            attributed["source_service"],
            attributed["dest_service"],
        )
        if key not in groups and len(groups) >= MAX_GROUPS:
            edge_budget_omitted += 1
            continue
        if stored_observations >= MAX_STORED_OBSERVATIONS:
            group_omissions[key] += 1
            continue
        groups[key].append(record)
        stored_observations += 1

    for ident, owner in pod_owners.items():
        nodes[ident] = workload_node(
            ident,
            owner,
            pod_claims[ident],
            pod_addresses[ident],
            selection["cluster"],
            result["scope"],
        )
        bindings = [
            b
            for b in selected_bindings
            if b["pod_uid"] == owner["pod_uid"] and b["namespace"] == owner["namespace"]
        ]
        services = {service_id(b) for b in bindings}
        if len(services) == 1:
            sid = next(iter(services))
            edge = membership_edge(
                sid,
                ident,
                len({(b["trace_id"], b["span_id"]) for b in bindings}),
                sorted({b["span_id"] for b in bindings}),
                result["scope"],
            )
            edges[edge["id"]] = edge

    observation_records = 0
    for key, values in sorted(groups.items(), key=lambda item: canonical(item[0])):
        source_id, target_id = key[2], key[3]
        source_status, dest_status, source_service, dest_service = key[15:19]
        values.sort(key=lambda r: (r["event_time"], r["record_id"]))
        for offset in range(0, len(values), OBSERVATIONS_PER_EDGE):
            if len(edges) >= MAX_EDGES:
                edge_budget_omitted += len(values) - offset
                break
            chunk = values[offset : offset + OBSERVATIONS_PER_EDGE]
            record = chunk[0]
            rid = hashlib.sha256(
                canonical([key, sorted(r["record_id"] for r in chunk)]).encode()
            ).hexdigest()
            edges["traffic-observation:" + rid] = traffic_edge(
                rid,
                source_id,
                target_id,
                record,
                observation_evidence(
                    source_status, dest_status, source_service[0], dest_service[0]
                ),
                [observation_payload(r) for r in chunk],
                len(chunk),
                counter_totals(chunk),
                {
                    f: record[f]
                    for f in ("source_port", "destination_port")
                    if record.get(f) is not None and len({r.get(f) for r in chunk}) == 1
                },
            )
            omitted = group_omissions.get(key, 0)
            if omitted:
                edges["traffic-observation:" + rid]["observation_omitted_count"] = (
                    omitted
                )
            observation_records += len(chunk)
    require(
        len(nodes) <= MAX_NODES and len(edges) <= MAX_EDGES,
        "Qualified network graph exceeds the pilot budget; narrow the window.",
    )
    if edge_budget_omitted:
        excluded["edge_budget"] += edge_budget_omitted
    if group_omissions:
        excluded["observation_budget"] += sum(group_omissions.values())
    warnings = network_warnings(
        result["warnings"],
        decoded["warnings"],
        excluded,
        bool(edge_budget_omitted or group_omissions),
        observation_records,
    )
    meta.update(
        nodes=len(nodes),
        edges=len(edges),
        warnings=warnings,
        network_records=observation_records,
        conversations_in_scope=0,
        matched_conversations=0,
        unresolved_conversations=0,
        ambiguous_conversations=0,
        network_edge_budget=MAX_EDGES,
        network_edge_budget_used=len(edges),
        network_edge_budget_remaining=MAX_EDGES - len(edges),
        network_edge_budget_omitted=edge_budget_omitted,
        network_observation_budget_omitted=sum(group_omissions.values()),
    )
    return [*nodes.values(), *edges.values(), meta]


def traffic_edge(
    rid, source_id, target_id, record, evidence, payload, records, totals, ports
):
    return {
        "row_type": "edge",
        "id": "traffic-observation:" + rid,
        "traffic_observation_id": rid,
        "source": source_id,
        "target": target_id,
        "relationship": "traffic_observation",
        "confidence": "correlated",
        "count": records,
        "records": records,
        "sources": [record["kind"]],
        "observers": [record["observer"]],
        "scope": record["scope"],
        "cluster": record["cluster"],
        "source_authority": record["profile_id"],
        "source_ip": record["source_ip"],
        "destination_ip": record["destination_ip"],
        "transport": record["transport"].lower(),
        "evidence": evidence,
        "reason": "Native flow observations, not a traced call or proven forwarding path.",
        "metrics_authoritative": 0,
        "traffic_observations": json.dumps(payload, separators=(",", ":")),
        **totals,
        **ports,
    }
