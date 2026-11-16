"""Long graph windows composed from independently qualified 300-second slices.

Every slice is read and qualified exactly like a short window: complete
ownership manifests, raw span containment and event-time native attribution.
Slices are never interpolated into each other. Merging is a union keyed by the
qualified node IDs (pod UID, service identity, scoped address), so no two
identities are merged by name. Without summaries, beyond ``MAX_SLICES`` the
window is sampled at evenly spaced slices (always including the newest) and
the metadata says so; counts then describe the sampled slices only. With
summaries (``rollup``), every summarized slice contributes and only the
not-yet-summarized tail is read raw.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

from .protocol import canonical

SLICE_SECONDS = 300
MAX_SLICES = 6
# One week plus a day of slack; longer windows are rejected before dispatch.
MAX_WINDOW_SECONDS = 8 * 86400
OBSERVATIONS_PER_EDGE = 64
MAX_NODES = 500
MAX_EDGES = 2000


def plan(start: int, as_of: int, max_slices: int = MAX_SLICES):
    """Return (slices, total) where slices are (start, end) pairs, newest last."""
    if not (0 <= start < as_of) or as_of - start > MAX_WINDOW_SECONDS:
        raise ValueError("graph window must be between 1 second and 8 days")
    total = math.ceil((as_of - start) / SLICE_SECONDS)
    picks = (
        range(total)
        if total <= max_slices
        else sorted(
            {round(i * (total - 1) / (max_slices - 1)) for i in range(max_slices)}
        )
    )
    slices = []
    for index in picks:
        end = as_of - (total - 1 - index) * SLICE_SECONDS
        slices.append((max(start, end - SLICE_SECONDS), end))
    return slices, total


def _list(value):
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _observation_key(edge):
    fields = (
        "source",
        "target",
        "source_authority",
        "scope",
        "cluster",
        "source_ip",
        "destination_ip",
        "transport",
    )
    return canonical(
        [
            [edge.get(f) for f in fields],
            sorted(_list(edge.get("observers"))),
            sorted(_list(edge.get("sources"))),
            _list(edge.get("evidence")),
        ]
    )


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate context field")
        result[key] = value
    return result


def _merged_identity_context(outputs, start, as_of, total, windows):
    """Preserve provenance only for a complete, contiguous raw-slice read.

    This reports the observation window; it makes no lifetime or traffic claim.
    Any missing, ambiguous, summarized, or malformed context is unavailable.
    """
    try:
        if (
            type(start) is not int
            or type(as_of) is not int
            or type(total) is not int
            or as_of > 9007199254740991
        ):
            return None
        planned, planned_total = plan(start, as_of)
        if (
            total != planned_total
            or len(planned) != total
            or list(windows) != planned
            or len(outputs) != total
            or any(
                not isinstance(window, (tuple, list))
                or len(window) != 2
                or any(type(value) is not int for value in window)
                for window in windows
            )
        ):
            return None
        common = None
        disallowed = {
            "sampled",
            "is_sampled",
            "sampled_windows",
            "progressive",
            "capped",
            "truncated",
            "summary",
            "is_summary",
            "summary_run",
            "summary_contract",
            "window_slices",
            "window_slices_read",
            "window_seconds_read",
            "read_coverage",
            "raw_pending_seconds",
            "summary_slices",
            "summary_seconds",
            "summary_through",
            "raw_seconds",
            "raw_tail_seconds",
        }
        for rows, window in zip(outputs, planned):
            meta_rows = [
                row
                for row in rows
                if isinstance(row, dict) and row.get("row_type") == "meta"
            ]
            if len(meta_rows) != 1:
                return None
            meta = meta_rows[0]
            if (
                disallowed.intersection(meta)
                or type(meta.get("window_start")) is not int
                or type(meta.get("window_end")) is not int
                or (meta["window_start"], meta["window_end"]) != window
            ):
                return None
            encoded = meta.get("identity_context")
            if not isinstance(encoded, str) or len(encoded) > 4096:
                return None
            context = json.loads(encoded, object_pairs_hook=_unique_pairs)
            if not isinstance(context, dict) or set(context) != {
                "schemaVersion",
                "contract",
                "authority",
                "scope",
                "configRevision",
                "observedWindow",
            }:
                return None
            observation = context["observedWindow"]
            if (
                type(context["schemaVersion"]) is not int
                or context["schemaVersion"] != 1
                or context["contract"] != "qualified_v2"
                or not isinstance(context["authority"], str)
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}", context["authority"]
                )
                or not isinstance(context["scope"], str)
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}", context["scope"]
                )
                or not isinstance(context["configRevision"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", context["configRevision"])
                or not isinstance(observation, dict)
                or set(observation) != {"start", "end"}
                or type(observation["start"]) is not int
                or type(observation["end"]) is not int
                or (observation["start"], observation["end"]) != window
            ):
                return None
            identity = {
                k: context[k]
                for k in (
                    "schemaVersion",
                    "contract",
                    "authority",
                    "scope",
                    "configRevision",
                )
            }
            if common is not None and identity != common:
                return None
            common = identity
        if common is None:
            return None
        return canonical({**common, "observedWindow": {"start": start, "end": as_of}})
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return None


def merge(outputs, start, as_of, total, sampled_windows):
    """Union per-slice graph rows into one graph over [start, as_of]."""
    nodes, edges, metas = {}, {}, []
    for rows in outputs:
        for row in rows:
            kind = row.get("row_type")
            if kind == "meta":
                metas.append(row)
            elif kind == "node":
                current = nodes.get(row["id"])
                if current is None:
                    nodes[row["id"]] = dict(row)
                elif row.get("addresses"):
                    current["addresses"] = sorted(
                        set(_list(current.get("addresses")))
                        | set(_list(row["addresses"]))
                    )
            elif kind == "edge":
                _merge_edge(edges, row)
    omitted = 0
    # Keep the heaviest observations; traced calls and memberships first.
    ranked = sorted(
        edges.items(),
        key=lambda item: (
            item[1].get("relationship") == "traffic_observation",
            -int(item[1].get("records") or item[1].get("count") or 0),
            item[0],
        ),
    )
    if len(edges) > MAX_EDGES:
        omitted = len(ranked) - MAX_EDGES
        ranked = ranked[:MAX_EDGES]
        edges = dict(ranked)
    used = {e["source"] for e in edges.values()} | {e["target"] for e in edges.values()}
    if len(nodes) > MAX_NODES:
        nodes = {
            k: v for k, v in nodes.items() if k in used or v.get("kind") == "service"
        }
    if len(nodes) > MAX_NODES:
        # Long windows accumulate pods and peers: admit the heaviest
        # relationships whose endpoints still fit the node budget.
        keep = {k for k, v in nodes.items() if v.get("kind") == "service"}
        kept = {}
        for ident, edge in ranked:
            need = {edge["source"], edge["target"]} - keep
            if len(keep) + len(need) > MAX_NODES:
                omitted += 1
                continue
            keep |= need
            kept[ident] = edge
        edges = kept
        nodes = {k: v for k, v in nodes.items() if k in keep}
    if len(nodes) > MAX_NODES:
        raise ValueError("Qualified graph exceeds the pilot budget; narrow the window.")
    covered = sum(b - a for a, b in sampled_windows)
    warnings = []
    for meta in metas:
        for warning in _list(meta.get("warnings")):
            if warning not in warnings:
                warnings.append(warning)
    if len(sampled_windows) < total:
        warnings.insert(
            0,
            f"Read {len(sampled_windows)} of {total} five-minute slices "
            f"({covered // 60} of {(as_of - start) // 60} minutes); counts describe the slices read.",
        )
    if omitted:
        warnings.append(
            f"{omitted} lighter observation edges were omitted to stay within the "
            f"{MAX_EDGES}-edge and {MAX_NODES}-node budget."
        )
    meta = {
        "row_type": "meta",
        "window_start": int(start),
        "window_end": int(as_of),
        "generated_at": int(as_of),
        "nodes": len(nodes),
        "edges": len(edges),
        "spans": sum(int(m.get("spans") or 0) for m in metas),
        "network_records": sum(int(m.get("network_records") or 0) for m in metas),
        "warnings": warnings,
        "window_slices": total,
        "window_slices_read": len(sampled_windows),
        "window_seconds_read": covered,
        "network_edge_budget": MAX_EDGES,
        "network_edge_budget_used": len(edges),
        "network_edge_budget_remaining": MAX_EDGES - len(edges),
        "network_edge_budget_omitted": omitted
        + sum(int(m.get("network_edge_budget_omitted") or 0) for m in metas),
        "network_observation_budget_omitted": sum(
            int(m.get("network_observation_budget_omitted") or 0) for m in metas
        ),
    }
    for key in (
        "conversations_in_scope",
        "matched_conversations",
        "unresolved_conversations",
        "ambiguous_conversations",
    ):
        if any(key in m for m in metas):
            meta[key] = sum(int(m.get(key) or 0) for m in metas)
    context = _merged_identity_context(outputs, start, as_of, total, sampled_windows)
    if context is not None:
        meta["identity_context"] = context
    return [*nodes.values(), *edges.values(), meta]


def _merge_edge(edges, row):
    if row.get("relationship") != "traffic_observation":
        current = edges.get(row["id"])
        if current is None:
            edges[row["id"]] = dict(row)
            return
        current["count"] = int(current.get("count") or 0) + int(row.get("count") or 0)
        if row.get("span_ids") or current.get("span_ids"):
            current["span_ids"] = sorted(
                set(_list(current.get("span_ids"))) | set(_list(row.get("span_ids")))
            )[:256]
        return
    key = _observation_key(row)
    ident = "traffic-observation:" + hashlib.sha256(key.encode()).hexdigest()
    current = edges.get(ident)
    if current is None:
        merged = dict(row)
        merged["id"] = ident
        merged["traffic_observation_id"] = ident.split(":", 1)[1]
        edges[ident] = merged
        return
    for field in (
        "count",
        "records",
        "observation_omitted_count",
        "raw_bytes",
        "raw_packets",
        "blocked_records",
    ):
        if field in row or field in current:
            current[field] = int(current.get(field) or 0) + int(row.get(field) or 0)
    for field, pick in (("first_seen", min), ("last_seen", max)):
        values = [v for v in (current.get(field), row.get(field)) if v is not None]
        if values:
            current[field] = pick(values)
    observations = json.loads(current.get("traffic_observations") or "[]") + json.loads(
        row.get("traffic_observations") or "[]"
    )
    if len(observations) > OBSERVATIONS_PER_EDGE:
        extra = len(observations) - OBSERVATIONS_PER_EDGE
        current["observation_omitted_count"] = (
            int(current.get("observation_omitted_count") or 0) + extra
        )
        # Keep the newest individual tuples; the record count stays a total.
        observations = sorted(observations, key=lambda o: o.get("last_seen") or 0)[
            -OBSERVATIONS_PER_EDGE:
        ]
    current["traffic_observations"] = json.dumps(observations, separators=(",", ":"))
    for field in ("source_port", "destination_port"):
        if current.get(field) != row.get(field):
            current.pop(field, None)
