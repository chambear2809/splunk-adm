"""Five-minute qualified graph summaries (``source=adm:qualified`` in adm_summary_v2).

A summary run qualifies one absolute 300-second slice with exactly the rules
of the interactive reader: complete ownership manifests, raw span
containment, event-time native ownership and service attribution, and the
same frontend-intent and namespace-claim checks. It stores the selection-
independent result as aggregates so any selected service can later be read
with ``stats`` instead of re-reading raw evidence.

Selection only decides which facts are relevant. For a selected service R a
slice contributes the call component containing R, pods bound to a service
of that component and the frontend intents of R. Every stored row therefore
lists the root services (``q_roots``) it is relevant to; the reader filters
by one root and sums, giving the union of per-slice graphs without sampling.
Identities are never merged by name: workload IDs carry the pod UID and
endpoint IDs the scoped address.

Replay safety: a run is identified by slice, knowledge horizon and the
configuration fingerprint, so a replay of the same slice writes identical
documents with identical ``q_doc`` IDs. A manifest row states how many rows a
run wrote; readers use only complete runs, pick the largest horizon per slice
and drop exact duplicate documents.
"""

from __future__ import annotations

import base64
from collections import Counter, defaultdict
import hashlib
import heapq
import json
import re
import zlib

from .network_graph import (
    MAX_EDGES,
    MAX_NODES,
    attribute,
    counter_totals,
    decorate_netflow,
    endpoint_id,
    endpoint_node,
    evidence_indexes,
    frontend_at,
    membership_edge,
    network_warnings,
    observation_evidence,
    observation_payload,
    pod_id,
    traffic_edge,
    workload_node,
)
from .protocol import canonical
from .qualified import service_id

SLICE = 300
CONTRACT = "qualified-summary-1"
SOURCE = "adm:qualified"
SAMPLE = 8
SPAN_SAMPLE = 32
MAX_SLICE_ROWS = 20000
# One week plus a day: the reader's window bound.
MAX_READ_SLICES = 8 * 288
MAX_EXCLUDED_RUNS = 2000
# aggregate_query pseudo-kind: one row per summary run the aggregate read.
RUN_KIND = "r"
_TOKEN = re.compile(r"r[0-9a-f]{16}\Z")
_HEX = re.compile(r"[0-9a-f]{8,64}\Z")
_INDEX = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
IDENTITY_KEYS = (
    "cluster",
    "environment",
    "scope",
    "producer_id",
    "interval_source",
    "span_source",
    "interval_index",
    "span_index",
    "interval_sourcetype",
    "span_sourcetype",
    "namespaces",
)


class SummaryError(ValueError):
    pass


def _sha(value, size=64):
    return hashlib.sha256(
        (value if isinstance(value, str) else canonical(value)).encode()
    ).hexdigest()[:size]


def root_token(sid):
    return "r" + _sha(sid, 16)


def fingerprint(profile, network):
    """Configuration identity. Summaries built under other rules are not read."""
    identity = {k: profile.get(k) for k in IDENTITY_KEYS}
    rules = None
    if network:
        rules = {"profiles": network["profiles"], "frontends": network["frontends"]}
    return _sha([CONTRACT, identity, rules], 24)


def run_id(start, end, horizon, fp):
    return _sha([CONTRACT, int(start), int(end), int(horizon), fp], 24)


def pack(value):
    data = zlib.compress(canonical(value).encode(), 9)
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unpack(text, limit=1 << 20):
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200000}", text):
        raise SummaryError("Malformed summary payload.")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        inflater = zlib.decompressobj()
        body = inflater.decompress(data, limit)
        if inflater.unconsumed_tail:
            raise SummaryError("Summary payload exceeds its bound.")
        return json.loads(body)
    except (ValueError, zlib.error):
        raise SummaryError("Malformed summary payload.") from None


def slices_of(start, end):
    if start % SLICE or end % SLICE or end <= start:
        raise SummaryError("Summary windows must be whole aligned 300-second slices.")
    return [(s, s + SLICE) for s in range(start, end, SLICE)]


# --------------------------------------------------------------------- writer


def _components(services, pairs):
    parent = {sid: sid for sid in services}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in pairs:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    groups = defaultdict(set)
    for sid in services:
        groups[find(sid)].add(sid)
    return {sid: frozenset(groups[find(sid)]) for sid in services}


def summarize(
    result, decoded, config, start, end, horizon, fp, status="ok", native_rows=None
):
    """Summary documents (dicts of scalar fields) for one slice.

    ``result`` is a complete qualify() result, or None for a slice without
    complete evidence (``status`` then names the reason). ``decoded`` is the
    normalize_records() output or None when native observations are disabled.
    """
    run = run_id(start, end, horizon, fp)
    common = {
        "_time": int(start),
        "q_run": run,
        "q_slice": int(start),
        "q_fp": fp,
        "q_horizon": int(horizon),
    }
    docs = []

    def emit(kind, key, roots, si="-", di="-", **fields):
        doc = {
            **common,
            "q_kind": kind,
            "q_key": key,
            "q_si": si,
            "q_di": di,
            "q_roots": " ".join(sorted(roots)),
            "q_doc": _sha([run, kind, key, si, di], 24),
        }
        doc.update({k: v for k, v in fields.items() if v is not None})
        docs.append(doc)

    meta = {
        "status": status,
        "spans": 0,
        "spans_excluded": 0,
        "relevant_records": 0,
        "excluded": {},
        "native_rows": native_rows or {},
        "network": decoded is not None,
        "warnings": [],
    }
    if result is not None:
        _summarize_result(result, decoded, config, emit, meta)
    if len(docs) + 1 > MAX_SLICE_ROWS:
        raise SummaryError("Qualified summary slice exceeds its row budget.")
    digest = _sha(sorted(d["q_doc"] for d in docs))
    manifest = {
        **common,
        "q_kind": "m",
        "q_key": "manifest",
        "q_si": "-",
        "q_di": "-",
        "q_roots": "-",
        "q_doc": _sha([run, "m"], 24),
        "q_expected": len(docs) + 1,
        "q_status": status,
        "q_digest": digest,
        "q_meta": pack(meta),
        "q_contract": CONTRACT,
    }
    return [manifest, *docs]


def _summarize_result(result, decoded, config, emit, meta):
    bindings = result["bindings"]
    meta["spans"] = len(bindings)
    meta["spans_excluded"] = sum((result.get("excluded") or {}).values())
    meta["warnings"] = list(result["warnings"][:1])
    services = {}
    for b in bindings:
        sid = service_id(b)
        services.setdefault(
            sid,
            {
                "row_type": "node",
                "id": sid,
                "label": b["service"],
                "kind": "service",
                "cluster": b["cluster"],
                "namespace": b["namespace"],
                "attr_environment": b["environment"],
                "attr_identity_basis": "complete finite pod-IP snapshot and explicit OTel span",
            },
        )
    parents = {(b["trace_id"], b["span_id"]): b for b in bindings}
    calls = defaultdict(set)
    for b in bindings:
        parent = parents.get((b["trace_id"], b["parent_span_id"]))
        if b["kind"] != "server" or not parent or parent["kind"] != "client":
            continue
        calls[(service_id(parent), service_id(b))].add((b["trace_id"], b["span_id"]))
    component = _components(services, calls)
    tokens = {sid: root_token(sid) for sid in services}

    def roots_of(sids):
        return {tokens[s] for s in sids}

    for sid, node in services.items():
        emit("s", tokens[sid], roots_of(component[sid]), q_body=pack(node))
    for pair, proof in calls.items():
        emit(
            "c",
            _sha(pair, 24),
            roots_of(component[pair[0]]),
            q_body=pack(list(pair)),
            q_count=len(proof),
            q_spans=",".join(sorted({sid for _, sid in proof})[:SPAN_SAMPLE]),
        )
    pod_services = defaultdict(set)
    member_proof = defaultdict(set)
    for b in bindings:
        pk = (b["pod_uid"], b["namespace"])
        sid = service_id(b)
        pod_services[pk].add(sid)
        member_proof[(sid, pk)].add((b["trace_id"], b["span_id"]))
    pod_roots = {
        pk: set().union(*(component[s] for s in sids))
        for pk, sids in pod_services.items()
    }
    if decoded is None:
        return
    indexes = evidence_indexes(result)
    decorate_netflow(decoded, config["profiles"])
    excluded = Counter(decoded["excluded"])
    groups = {}
    endpoints = defaultdict(dict)  # root service -> {pod key: workload id}
    relevant = 0
    for record in sorted(
        decoded["records"], key=lambda item: (item["record_id"], item["event_time"])
    ):
        attributed = attribute(result, record, indexes)
        if attributed is None:
            excluded["sensor_namespace_conflict"] += 1
            continue
        so, do = attributed["source_owner"], attributed["dest_owner"]
        spk = (so["pod_uid"], so["namespace"]) if so else None
        dpk = (do["pod_uid"], do["namespace"]) if do else None
        intents = []
        for address in (record["source_ip"], record["destination_ip"]):
            found = frontend_at(config["frontends"], record, address)
            sid = service_id(found) if found is not None else None
            # A frontend selects a slice only when its service has spans here.
            intents.append(sid if sid in services else None)
        roots = set()
        for pk in (spk, dpk):
            if pk is not None:
                roots |= pod_roots.get(pk, set())
        roots |= {sid for sid in intents if sid}
        if not roots:
            excluded["outside_selected_workload_context"] += 1
            continue
        relevant += 1
        src = endpoint_id(record, record["source_ip"], so)
        tgt = endpoint_id(record, record["destination_ip"], do)
        for root in roots:
            for pk, ident in ((spk, src), (dpk, tgt)):
                if pk is not None:
                    endpoints[root][pk] = ident
        key = (
            src,
            tgt,
            record["profile_id"],
            record["scope"],
            record["cluster"],
            record["source_ip"],
            record["destination_ip"],
            record["transport"].lower(),
            record["observer"],
            record["kind"],
            attributed["source_status"],
            attributed["dest_status"],
            attributed["source_service"][0],
            attributed["dest_service"][0],
        )
        si = tokens[intents[0]] if intents[0] else "-"
        di = tokens[intents[1]] if intents[1] else "-"
        gkey = (key, tuple(sorted(tokens[r] for r in roots)), si, di)
        group = groups.get(gkey)
        if group is None:
            group = groups[gkey] = {
                "records": [],
                "spod": list(spk) if spk else None,
                "dpod": list(dpk) if dpk else None,
                "sn": set(),
                "dn": set(),
            }
        group["records"].append(record)
        for name, side in (
            (record.get("source_pod"), "sn"),
            (record.get("destination_pod"), "dn"),
        ):
            pod = spk if side == "sn" else dpk
            if (
                pod is not None
                and isinstance(name, str)
                and name
                and len(group[side]) < 2
            ):
                group[side].add(name)
    meta["relevant_records"] = relevant
    meta["excluded"] = dict(excluded)
    for (key, roots, si, di), group in groups.items():
        values = group["records"]
        totals = counter_totals(values)
        newest = heapq.nlargest(
            SAMPLE, values, key=lambda r: (r["event_time"], r["record_id"])
        )
        newest.reverse()
        ports = {}
        for field, label in (("source_port", "q_sp"), ("destination_port", "q_dp")):
            seen = {r.get(field) for r in values}
            value = next(iter(seen)) if len(seen) == 1 else "*"
            ports[label] = "-" if value is None else str(value)
        emit(
            "f",
            _sha(key, 24),
            set(roots),
            si,
            di,
            q_body=pack({"k": list(key), "sp": group["spod"], "dp": group["dpod"]}),
            q_records=len(values),
            q_bytes=totals.get("raw_bytes"),
            q_packets=totals.get("raw_packets"),
            q_blocked=totals.get("blocked_records", 0),
            q_first=totals["first_seen"],
            q_last=totals["last_seen"],
            q_sample=pack([observation_payload(r) for r in newest]),
            q_sn=",".join(sorted(group["sn"])) or None,
            q_dn=",".join(sorted(group["dn"])) or None,
            **ports,
        )
    members = defaultdict(set)
    for root, pods in endpoints.items():
        for pk, ident in pods.items():
            selected = pod_services.get(pk, set()) & component[root]
            if len(selected) == 1:
                members[(next(iter(selected)), pk, ident)].add(tokens[root])
    for (sid, pk, ident), roots in members.items():
        proof = member_proof[(sid, pk)]
        emit(
            "w",
            _sha([sid, ident], 24),
            roots,
            q_body=pack([sid, ident]),
            q_count=len(proof),
            q_spans=",".join(sorted({span for _, span in proof})[:SPAN_SAMPLE]),
        )


# --------------------------------------------------------------------- reader


def manifest_query(index, fp, start, end, root):
    _check_query(index, fp, root)
    return (
        f'search index={index} source="{SOURCE}" q_fp={fp} earliest={int(start)} latest={int(end)} '
        f'| eval q_root=if(q_kind=="s" AND q_key=="{root}", 1, 0) '
        "| stats count AS rows dc(q_doc) AS docs max(q_root) AS root max(q_expected) AS expected "
        "max(q_horizon) AS horizon first(q_status) AS status first(q_meta) AS meta by q_slice q_run"
    )


def aggregate_query(index, fp, start, end, root, exclude_runs=(), dedup=False):
    _check_query(index, fp, root)
    for run in exclude_runs:
        if not _HEX.fullmatch(run):
            raise SummaryError("Invalid summary run identity.")
    if len(exclude_runs) > MAX_EXCLUDED_RUNS:
        raise SummaryError("Too many superseded summary runs in this window.")
    exclusion = (
        " NOT q_run IN (" + ",".join(sorted(exclude_runs)) + ")" if exclude_runs else ""
    )
    return (
        f'search index={index} source="{SOURCE}" q_fp={fp} earliest={int(start)} latest={int(end)} '
        f"TERM({root}) NOT q_kind=m{exclusion} "
        f'| where like(" ".q_roots." ", "% {root} %") '
        + ("| dedup q_doc " if dedup else "")
        # Every document also counts toward one run row (q_kind=r, q_key=run),
        # so the reader can prove which runs the aggregate actually saw: a run
        # collected between this read and the manifest read is detected and
        # excluded instead of being counted twice (summary and raw tail).
        # Keys are hex tokens or "-", so ":" cannot occur inside a part.
        + '| eval q_grp=mvappend(q_kind.":".q_key.":".q_si.":".q_di, "r:".q_run.":-:-") '
        "| stats sum(q_records) AS records sum(q_bytes) AS bytes sum(q_packets) AS packets "
        "sum(q_blocked) AS blocked min(q_first) AS first max(q_last) AS last "
        "latest(q_sample) AS sample dc(q_sp) AS spdc first(q_sp) AS sp dc(q_dp) AS dpdc "
        "first(q_dp) AS dp values(q_sn) AS sn values(q_dn) AS dn sum(q_count) AS count "
        "latest(q_spans) AS spans first(q_body) AS body count AS slices "
        "by q_grp "
        '| eval q_grp=split(q_grp, ":"), q_kind=mvindex(q_grp, 0), q_key=mvindex(q_grp, 1), '
        "q_si=mvindex(q_grp, 2), q_di=mvindex(q_grp, 3) "
        "| fields - q_grp"
    )


def split_runs(rows):
    """Separate aggregate_query run rows from data rows.

    Returns (data rows, set of run IDs whose documents the aggregate read).
    """
    data, seen = [], set()
    for row in rows:
        kind = row.get("q_kind")
        if isinstance(kind, list):
            kind = kind[0] if kind else None
        if kind == RUN_KIND:
            run = row.get("q_key")
            if isinstance(run, list):
                run = run[0] if run else None
            if not isinstance(run, str) or not _HEX.fullmatch(run):
                raise SummaryError("Malformed summary run row.")
            seen.add(run)
        else:
            data.append(row)
    return data, seen


def _check_query(index, fp, root):
    if not _INDEX.fullmatch(index or "") or not _HEX.fullmatch(fp or ""):
        raise SummaryError("Invalid summary index or fingerprint.")
    if not _TOKEN.fullmatch(root or ""):
        raise SummaryError("Invalid summary root.")


def _int(value, label, default=None):
    if isinstance(value, list):
        value = value[0] if value else None
    if value in (None, ""):
        if default is not None:
            return default
        raise SummaryError("Summary " + label + " is missing.")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise SummaryError("Summary " + label + " is invalid.") from None
    if number != number or number < 0 or number > 2**62:
        raise SummaryError("Summary " + label + " is invalid.")
    return int(number)


def choose_runs(rows, start, end):
    """Pick one complete run per slice: the largest knowledge horizon.

    Returns (chosen {slice: info}, excluded run IDs, duplicated run IDs).
    A run is complete when its row count is a whole multiple of the count
    its manifest declares and its distinct document count equals it.
    """
    by_slice = defaultdict(list)
    for row in rows:
        try:
            slice_start = _int(row.get("q_slice"), "slice")
            run = row.get("q_run")
            if not isinstance(run, str) or not _HEX.fullmatch(run):
                continue
            if slice_start % SLICE or not start <= slice_start < end:
                continue
            info = {
                "slice": slice_start,
                "run": run,
                "rows": _int(row.get("rows"), "rows"),
                "docs": _int(row.get("docs"), "docs", 0),
                "expected": _int(row.get("expected"), "expected", 0),
                "horizon": _int(row.get("horizon"), "horizon", 0),
                "root": _int(row.get("root"), "root", 0) == 1,
                "status": row.get("status")
                if isinstance(row.get("status"), str)
                else "",
                "meta": row.get("meta"),
            }
        except SummaryError:
            continue
        by_slice[slice_start].append(info)
    chosen, excluded, duplicated = {}, set(), set()
    for slice_start, runs in by_slice.items():
        complete = [
            r
            for r in runs
            if r["expected"] > 0
            and r["docs"] == r["expected"]
            and r["rows"] % r["expected"] == 0
            and r["horizon"] >= slice_start + SLICE
        ]
        best = max(complete, key=lambda r: (r["horizon"], r["run"]), default=None)
        for r in runs:
            if best is None or r["run"] != best["run"]:
                excluded.add(r["run"])
        if best is None:
            continue
        try:
            best["meta"] = unpack(best["meta"]) if best["meta"] else {}
        except SummaryError:
            excluded.add(best["run"])
            continue
        if not isinstance(best["meta"], dict):
            excluded.add(best["run"])
            continue
        if best["rows"] > best["expected"]:
            duplicated.add(best["run"])
        chosen[slice_start] = best
    return chosen, sorted(excluded), sorted(duplicated)


def aggregate(docs, root, chosen_runs):
    """Reference implementation of aggregate_query over summary documents."""
    seen, groups, runs = set(), {}, set()
    for doc in sorted(docs, key=lambda d: d["_time"]):
        if doc["q_kind"] == "m" or doc["q_run"] not in chosen_runs:
            continue
        if root not in doc["q_roots"].split(" ") or doc["q_doc"] in seen:
            continue
        seen.add(doc["q_doc"])
        runs.add(doc["q_run"])
        key = (doc["q_kind"], doc["q_key"], doc["q_si"], doc["q_di"])
        g = groups.setdefault(
            key,
            {
                "q_kind": key[0],
                "q_key": key[1],
                "q_si": key[2],
                "q_di": key[3],
                "slices": 0,
                "_sp": set(),
                "_dp": set(),
                "sn": set(),
                "dn": set(),
            },
        )
        g["slices"] += 1
        for field, out in (
            ("q_records", "records"),
            ("q_bytes", "bytes"),
            ("q_packets", "packets"),
            ("q_blocked", "blocked"),
            ("q_count", "count"),
        ):
            if doc.get(field) is not None:
                g[out] = g.get(out, 0) + int(doc[field])
        if doc.get("q_first") is not None:
            g["first"] = min(g.get("first", doc["q_first"]), doc["q_first"])
            g["last"] = max(g.get("last", doc["q_last"]), doc["q_last"])
        for field, out in (("q_sample", "sample"), ("q_spans", "spans")):
            if doc.get(field) is not None:
                g[out] = doc[field]  # latest by _time
        g.setdefault("body", doc.get("q_body"))
        for field, out in (("q_sp", "_sp"), ("q_dp", "_dp")):
            if doc.get(field) is not None:
                g.setdefault(field.replace("q_", ""), doc[field])
                g[out].add(doc[field])
        for field, out in (("q_sn", "sn"), ("q_dn", "dn")):
            if doc.get(field):
                g[out].add(doc[field])
    result = []
    for g in groups.values():
        g["spdc"], g["dpdc"] = len(g.pop("_sp")), len(g.pop("_dp"))
        g["sn"], g["dn"] = sorted(g["sn"]), sorted(g["dn"])
        result.append(g)
    for run in sorted(runs):
        result.append({"q_kind": RUN_KIND, "q_key": run, "q_si": "-", "q_di": "-"})
    return result


def _names(value):
    values = value if isinstance(value, list) else [value] if value else []
    names = set()
    for item in values:
        if isinstance(item, str):
            names.update(x for x in item.split(",") if x)
    return names


def _port(dc, value):
    if _int(dc, "port count", 0) != 1 or not isinstance(value, str):
        return None
    return int(value) if re.fullmatch(r"[0-9]{1,5}", value) else None


def render(rows, selection, root_sid, chosen, scope, cluster, network_enabled):
    """One graph output (nodes, edges, meta) for the summary-covered slices.

    Returns None when the selected service has no summarized observations.
    The output has the shape of a per-slice reader output and is meant to be
    merged with raw tail slices by ``slices.merge``.
    """
    root = root_token(root_sid)
    present = [c for c in chosen.values() if c["root"]]
    services, calls, members, flows = {}, [], [], []
    for row in rows:
        kind = row.get("q_kind")
        if isinstance(kind, list):
            kind = kind[0]
        if kind == RUN_KIND:
            continue
        body = unpack(
            row.get("body") if not isinstance(row.get("body"), list) else row["body"][0]
        )
        if kind == "s":
            if not isinstance(body, dict) or not isinstance(body.get("id"), str):
                raise SummaryError("Malformed summary service.")
            services[body["id"]] = body
        elif kind == "c":
            calls.append((body, row))
        elif kind == "w":
            members.append((body, row))
        elif kind == "f":
            flows.append((body, row))
    if root_sid not in services or not present:
        return None
    nodes = dict(services)
    edges = {}
    for (source, target), row in calls:
        if source not in nodes or target not in nodes:
            continue
        ident = (
            "calls:" + hashlib.sha256(canonical([source, target]).encode()).hexdigest()
        )
        edges[ident] = {
            "row_type": "edge",
            "id": ident,
            "source": source,
            "target": target,
            "relationship": "calls",
            "confidence": "observed",
            "evidence": ["parent/child OTel spans; complete finite pod-IP ownership"],
            "count": _int(row.get("count"), "count", 0),
            "sources": ["otel"],
            "span_ids": sorted(_names(row.get("spans"))),
            "scope": scope,
        }
    spans = sum(int(c["meta"].get("spans") or 0) for c in present)
    spans_excluded = sum(int(c["meta"].get("spans_excluded") or 0) for c in present)
    identity_warnings = [
        "Service identities are finite ownership/span observations; they do not establish network traffic or an ACI path."
    ]
    if spans_excluded:
        identity_warnings.append(
            f"{spans_excluded} spans were excluded because scope, clocks, or finite ownership could not be qualified."
        )
    meta = {
        "row_type": "meta",
        "spans": spans,
        "warnings": identity_warnings,
    }
    if not network_enabled:
        meta.update(nodes=len(nodes), edges=len(edges))
        return [*nodes.values(), *edges.values(), meta]
    pod_names, pod_addresses, pod_owner, endpoints = (
        defaultdict(set),
        defaultdict(set),
        {},
        {},
    )
    merged = {}
    for body, row in flows:
        key = body.get("k")
        if not isinstance(key, list) or len(key) != 14:
            raise SummaryError("Malformed summary flow.")
        first = float(row.get("first") or 0)
        for ident, pod, address, names, intent in (
            (key[0], body.get("sp"), key[5], row.get("sn"), row.get("q_si")),
            (key[1], body.get("dp"), key[6], row.get("dn"), row.get("q_di")),
        ):
            if pod:
                pod_owner[ident] = {"pod_uid": pod[0], "namespace": pod[1]}
                pod_addresses[ident].add(address)
                pod_names[ident] |= _names(names)
            else:
                candidate = (first, intent == root, key[3], key[4], address)
                if ident not in endpoints or candidate < endpoints[ident]:
                    endpoints[ident] = candidate
        merged.setdefault(tuple(key), {"rows": []})["rows"].append(row)
    for ident, (_, intent, record_scope, record_cluster, address) in endpoints.items():
        nodes[ident] = endpoint_node(
            ident, record_scope, record_cluster, address, intent
        )
    for ident, owner in pod_owner.items():
        nodes[ident] = workload_node(
            ident,
            owner,
            pod_names[ident],
            pod_addresses[ident],
            selection["cluster"],
            scope,
        )
    for (sid, ident), row in members:
        if sid in nodes and ident in pod_owner:
            edge = membership_edge(
                sid,
                ident,
                _int(row.get("count"), "count", 0),
                sorted(_names(row.get("spans"))),
                scope,
            )
            edges[edge["id"]] = edge
    observation_records = 0
    for key, group in sorted(merged.items(), key=lambda item: canonical(list(item[0]))):
        rows_ = group["rows"]
        records = sum(_int(r.get("records"), "records", 0) for r in rows_)
        totals = {
            "first_seen": min(float(r.get("first") or 0) for r in rows_),
            "last_seen": max(float(r.get("last") or 0) for r in rows_),
        }
        for field, out in (("bytes", "raw_bytes"), ("packets", "raw_packets")):
            values = [r.get(field) for r in rows_ if r.get(field) not in (None, "")]
            if values:
                totals[out] = sum(_int(v, field) for v in values)
        blocked = sum(_int(r.get("blocked"), "blocked", 0) for r in rows_)
        if blocked:
            totals["blocked_records"] = blocked
        newest = max(rows_, key=lambda r: float(r.get("last") or 0))
        sample = unpack(newest.get("sample")) if newest.get("sample") else []
        if not isinstance(sample, list):
            raise SummaryError("Malformed summary sample.")
        ports = {}
        for field, dc, value in (
            ("source_port", "spdc", "sp"),
            ("destination_port", "dpdc", "dp"),
        ):
            found = {_port(r.get(dc), r.get(value)) for r in rows_}
            if len(found) == 1 and None not in found:
                ports[field] = next(iter(found))
        record = {
            "kind": key[9],
            "observer": key[8],
            "scope": key[3],
            "cluster": key[4],
            "profile_id": key[2],
            "source_ip": key[5],
            "destination_ip": key[6],
            "transport": key[7],
        }
        rid = _sha(["summary", list(key)])
        edge = traffic_edge(
            rid,
            key[0],
            key[1],
            record,
            observation_evidence(key[10], key[11], key[12], key[13]),
            sample,
            records,
            totals,
            ports,
        )
        if records > len(sample):
            edge["observation_omitted_count"] = records - len(sample)
        edges[edge["id"]] = edge
        observation_records += records
    excluded = Counter()
    relevant_total = 0
    for c in present:
        for name, value in (c["meta"].get("excluded") or {}).items():
            excluded[str(name)] += int(value)
        relevant_total += int(c["meta"].get("relevant_records") or 0)
    outside = relevant_total - observation_records
    if outside > 0:
        excluded["outside_selected_workload_context"] += outside
    meta.update(
        nodes=len(nodes),
        edges=len(edges),
        network_records=observation_records,
        warnings=network_warnings(
            identity_warnings, [], excluded, False, observation_records
        ),
        conversations_in_scope=0,
        matched_conversations=0,
        unresolved_conversations=0,
        ambiguous_conversations=0,
        network_edge_budget=MAX_EDGES,
        network_edge_budget_omitted=0,
        network_observation_budget_omitted=0,
    )
    return [*nodes.values(), *edges.values(), meta]


__all__ = [
    "CONTRACT",
    "MAX_NODES",
    "SLICE",
    "SOURCE",
    "SummaryError",
    "aggregate",
    "aggregate_query",
    "choose_runs",
    "fingerprint",
    "manifest_query",
    "pack",
    "pod_id",
    "render",
    "root_token",
    "run_id",
    "slices_of",
    "summarize",
    "unpack",
]
