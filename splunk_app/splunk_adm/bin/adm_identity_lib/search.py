"""Bounded caller-context search helpers for admqualified."""

from __future__ import annotations
import re
from typing import Any

MAX_ROWS = 50000
# Result page size. Each page stays well below the 48 MiB response bound.
PAGE_ROWS = 4000
MODES = {"catalog", "graph"}


class SearchError(ValueError):
    pass


def validate_args(
    mode: str,
    service=None,
    environment=None,
    namespace=None,
    cluster=None,
    start=None,
    as_of=None,
):
    if mode not in MODES:
        raise SearchError("mode must be catalog or graph")
    if start is None or as_of is None:
        raise SearchError("start and as_of are required")
    import math

    try:
        start_value, as_of_value = float(start), float(as_of)
    except (TypeError, ValueError):
        raise SearchError("start and as_of must be finite numbers") from None
    if (
        not math.isfinite(start_value)
        or not math.isfinite(as_of_value)
        or as_of_value <= start_value
        or as_of_value - start_value > 300
    ):
        raise SearchError("identity window exceeds 300 seconds")
    pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}\Z")
    for name, value in (
        ("service", service),
        ("environment", environment),
        ("namespace", namespace),
        ("cluster", cluster),
    ):
        if value is not None and (
            not isinstance(value, str) or not pattern.fullmatch(value)
        ):
            raise SearchError(f"invalid {name}")


def bounded_query(
    profile: dict[str, Any],
    mode: str,
    service=None,
    environment=None,
    namespace=None,
    cluster=None,
    start=None,
    as_of=None,
    horizon=None,
) -> str:
    from .qualified import profile_config

    profile = profile_config(profile)
    validate_args(mode, service, environment, namespace, cluster, start, as_of)
    known = _horizon(as_of, horizon)
    families = [
        f'(index={profile["interval_index"]} source="{profile["interval_source"]}" sourcetype="{profile["interval_sourcetype"]}")',
        f'(index={profile["span_index"]} source="{profile["span_source"]}" sourcetype="{profile["span_sourcetype"]}")',
    ]
    return (
        f"search ({' OR '.join(families)}) earliest={start} latest={as_of} _index_latest={known} "
        "| eval event_time=_time,receipt_time=_indextime | fields _raw index source sourcetype event_time receipt_time "
        "| eventstats count AS _atlas_total | head 50001"
    )


def _horizon(as_of, horizon):
    if horizon is None:
        return as_of
    import math

    try:
        value = int(horizon)
    except (TypeError, ValueError):
        raise SearchError("horizon must be an integer epoch") from None
    if (
        not math.isfinite(value)
        or value < int(float(as_of))
        or value - float(as_of) > 86400
    ):
        raise SearchError("horizon must lie within one day after the window")
    return value


def complete_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) > MAX_ROWS or any(
        r.get("_atlas_total") in ("50001", 50001) for r in rows
    ):
        raise SearchError("identity evidence is truncated")
    if not rows:
        raise SearchError("identity evidence is empty")
    markers = {r.get("_atlas_total") for r in rows}
    if len(markers) != 1:
        raise SearchError("identity completion marker is missing")
    total = next(iter(markers))
    try:
        total = int(total)
    except (TypeError, ValueError):
        raise SearchError("identity completion marker is missing") from None
    if total <= 0:
        raise SearchError("identity evidence is empty")
    if total != len(rows):
        raise SearchError("identity evidence is incomplete")
    if any(r.get("_raw") is None for r in rows):
        raise SearchError("identity raw evidence is missing")
    return rows


def reduce_rows(rows, profile, mode, start, as_of, selection=None):
    from .qualified import qualify

    result = qualify(complete_rows(rows), profile, start, as_of)
    if not result.get("complete"):
        raise SearchError("qualified identity evidence is incomplete")
    if mode == "catalog":
        return result["catalog_rows"]
    from .qualified import graph_rows

    return graph_rows(result, selection)


class NativeSearch:
    """Read-only nested job with native completion proof, using the caller token."""

    def __init__(self, request, clock=None, sleep=None):
        import time

        self.request = request
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep

    def run(self, query, allow_empty=False, evidence=True, max_rows=MAX_ROWS):
        """Run one owned job. ``evidence`` rows must carry the completion
        marker and raw events; summary reads return transformed rows."""
        from urllib.parse import quote

        deadline = self.clock() + 45

        def request(method, path, data=None):
            if self.clock() >= deadline:
                raise SearchError("identity search completion deadline exceeded")
            result = self.request(method, path, data)
            if self.clock() >= deadline:
                raise SearchError("identity search completion deadline exceeded")
            return result

        created = request(
            "POST",
            "/servicesNS/nobody/splunk_adm/search/v2/jobs",
            {
                "search": query,
                "exec_mode": "normal",
                "max_time": "30",
                "auto_cancel": "45",
                "status_buckets": "0",
            },
        )
        sid = created.get("sid")
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid):
            raise SearchError("identity search did not return an owned job")
        path = "/services/search/v2/jobs/" + quote(sid, safe="")
        try:
            while True:
                response = request("GET", path)
                try:
                    content = response["entry"][0]["content"]
                except (KeyError, IndexError, TypeError):
                    raise SearchError("identity search metadata is missing") from None
                if content.get("dispatchState") == "FAILED" or content.get(
                    "isFailed"
                ) in (True, 1, "1"):
                    raise SearchError("identity search failed")
                if (
                    content.get("isDone") in (True, 1, "1")
                    or content.get("dispatchState") == "DONE"
                ):
                    break
                if self.clock() >= deadline:
                    raise SearchError("identity search completion deadline exceeded")
                self.sleep(0.25)
            false = (False, 0, "0")
            if (
                content.get("dispatchState") != "DONE"
                or content.get("isDone") not in (True, 1, "1")
                or content.get("isFinalized") not in false
                or content.get("eventIsTruncated") not in false
                or content.get("resultIsTruncated", False) not in false
                or str(content.get("dropCount")) != "0"
            ):
                raise SearchError("identity search is finalized or truncated")
            total = content.get("resultCount")
            if (
                not re.fullmatch(r"[0-9]+", str(total))
                or not 0 <= int(total) <= max_rows
            ):
                raise SearchError("identity search exceeds its result budget")
            total = int(total)
            rows, notes = [], list(content.get("messages", []))
            for offset in range(0, max(total, 1), PAGE_ROWS):
                result = request(
                    "GET",
                    path + f"/results?count={PAGE_ROWS}&offset=" + str(offset),
                )
                if result.get("preview") not in (False, 0, "0") or not isinstance(
                    result.get("results"), list
                ):
                    raise SearchError(
                        "identity search returned preview or malformed results"
                    )
                rows.extend(result["results"])
                notes.extend(result.get("messages", []))
                if len(rows) > max_rows:
                    raise SearchError("identity result budget exceeded")
            if len(rows) != total:
                raise SearchError("identity search result pages are incomplete")
            if any(
                not isinstance(n, dict)
                or n.get("type", "").upper() not in ("INFO", "DEBUG")
                for n in notes
            ):
                raise SearchError("identity search returned warnings or errors")
            if total == 0 and allow_empty:
                return []
            if not evidence:
                return rows
            return complete_rows(rows)
        finally:
            try:
                self.request("DELETE", path)
            except Exception:
                # An owned read-only job expires automatically. Never delete an
                # unknown SID and never expose transport details/session keys.
                pass


def bounded_network_query(profiles, identity_profile, start, as_of, horizon=None):
    """Read full registered source families, never IP-token/extracted-field subsets.

    Source completion proves the evidence budget, not absence of network traffic.
    Relevance and canonical address matching are evaluated against raw JSON later.
    """
    from .native_network import validate_profiles

    validate_args("graph", start=start, as_of=as_of)
    known = _horizon(as_of, horizon)
    profiles = validate_profiles(profiles, identity_profile)
    families = sorted(
        {
            f'(index={p["index"]} source="{p["source"]}" sourcetype="{p["sourcetype"]}")'
            for p in profiles
        }
    )
    return (
        f"search ({' OR '.join(families)}) earliest={start} latest={as_of} _index_latest={known} "
        "| eval event_time=_time,receipt_time=_indextime "
        "| fields _raw index source sourcetype event_time receipt_time host k8s.cluster.name _bkt _cd "
        "| eventstats count AS _atlas_total | head 50001"
    )


def reduce_network_rows(
    identity_rows, network_rows, profile, network_configuration, start, as_of, selection
):
    from .qualified import qualify
    from .network_graph import assemble, configuration

    config = configuration(network_configuration, profile)
    result = qualify(complete_rows(identity_rows), profile, start, as_of)
    if not result.get("complete"):
        raise SearchError("Qualified identity evidence is incomplete.")
    return assemble(result, network_rows, config, selection)
