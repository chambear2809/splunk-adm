"""Caller-scoped, reproducible captures of fixed qualified graph comparisons.

The injected runner must execute the supplied fixed query as the named caller,
reject incomplete/preview/warning results, and enforce native job time limits.
This module is not a Splunk transport or an authorization host.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re

CONTRACT = "admqualified-comparison-v1"
MAX_REFERENCE_BYTES = 4096
MAX_ROWS = 2000
MAX_BYTES = 512 * 1024
MAX_DEPTH = 20
MAX_VALUES = 50000
RULES = {
    "service": re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\Z"),
    "environment": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"),
    "cluster": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z"),
    "namespace": re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z"),
}


class SourceError(ValueError):
    """Untrusted source input or evidence did not satisfy the contract."""


def _canonical(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=True,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise SourceError("invalid JSON") from exc


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SourceError("duplicate JSON key")
        out[key] = value
    return out


def _reference(reference):
    if (
        not isinstance(reference, str)
        or len(reference.encode("utf-8")) > MAX_REFERENCE_BYTES
    ):
        raise SourceError("invalid reference")
    try:
        value = json.loads(
            reference,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(SourceError("invalid JSON")),
        )
    except (ValueError, RecursionError) as exc:
        raise SourceError("invalid reference") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "scope", "windows"}
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or _canonical(value) != reference
    ):
        raise SourceError("invalid reference")
    scope = value["scope"]
    if (
        not isinstance(scope, dict)
        or set(scope) != set(RULES)
        or any(
            not isinstance(scope[k], str) or not RULES[k].fullmatch(scope[k])
            for k in RULES
        )
    ):
        raise SourceError("invalid scope")
    windows = value["windows"]
    if not isinstance(windows, list) or len(windows) not in (2, 3):
        raise SourceError("invalid windows")
    last_end = None
    for window in windows:
        if not isinstance(window, dict) or set(window) != {"start", "end"}:
            raise SourceError("invalid window")
        start, end = window["start"], window["end"]
        if (
            type(start) is not int
            or type(end) is not int
            or start < 0
            or not 0 < end - start <= 300
            or (last_end is not None and start < last_end)
        ):
            raise SourceError("invalid window")
        last_end = end
    return value


def _check_json(value):
    pending = [(value, 0)]
    seen = 0
    while pending:
        node, depth = pending.pop()
        seen += 1
        if depth > MAX_DEPTH or seen > MAX_VALUES:
            raise SourceError("JSON bounds")
        if node is None or type(node) in (str, int, bool):
            continue
        if type(node) is float:
            if not math.isfinite(node):
                raise SourceError("invalid JSON")
            continue
        if type(node) is list:
            pending.extend((x, depth + 1) for x in node)
        elif type(node) is dict and all(type(k) is str for k in node):
            pending.extend((x, depth + 1) for x in node.values())
        else:
            raise SourceError("invalid JSON")


def _epoch(value):
    if type(value) is int:
        return value
    if type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,15}", value):
        return int(value)
    raise SourceError("invalid graph window")


def _rows(rows, scope, window):
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise SourceError("row limit")
    _check_json(rows)
    if len(_canonical(rows).encode("utf-8")) > MAX_BYTES:
        raise SourceError("byte limit")
    meta = []
    root_id = "service:" + "/".join(
        scope[k] for k in ("cluster", "namespace", "service", "environment")
    )
    roots = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("row_type"), str)
            or row.get("row_type")
            not in {
                "node",
                "edge",
                "meta",
            }
        ):
            raise SourceError("unknown graph row")
        if row["row_type"] == "edge":
            # These fields are the minimum relationship contract consumed by
            # the graph parser.  A row without an endpoint is not evidence of
            # a relationship and must not be admitted to a saved capture.
            for key in ("id", "source", "target", "relationship", "confidence"):
                if not isinstance(row.get(key), str) or not row[key]:
                    raise SourceError("invalid graph edge")
        if row["row_type"] == "meta":
            meta.append(row)
        if row["row_type"] == "node" and row.get("id") == root_id:
            roots.append(row)
    if (
        len(meta) != 1
        or _epoch(meta[0].get("window_start")) != window["start"]
        or _epoch(meta[0].get("window_end")) != window["end"]
    ):
        raise SourceError("graph window mismatch")
    _epoch(meta[0].get("generated_at"))
    if (
        len(roots) != 1
        or roots[0].get("kind") != "service"
        or roots[0].get("cluster") != scope["cluster"]
        or roots[0].get("namespace") != scope["namespace"]
        or roots[0].get("attr_environment") != scope["environment"]
    ):
        raise SourceError("graph boundary mismatch")
    return json.loads(_canonical(rows))


def _digest(windows):
    stable = []
    for window in windows:
        rows = []
        for row in window["rows"]:
            row = dict(row)
            if row["row_type"] == "meta":
                row.pop("generated_at", None)
            rows.append(_canonical(row))
        stable.append(
            {"start": window["start"], "end": window["end"], "rows": sorted(rows)}
        )
    return hashlib.sha256(_canonical(stable).encode()).hexdigest()


class ComparisonSource:
    def __init__(self, run, fingerprint, clock=None):
        if (
            not callable(run)
            or not callable(fingerprint)
            or (clock is not None and not callable(clock))
        ):
            raise SourceError("invalid source callbacks")
        self.run = run
        self.fingerprint = fingerprint
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def resolve(self, principal, reference):
        if not isinstance(principal, str) or not principal.strip():
            raise SourceError("missing principal")
        requested = _reference(reference)
        now = self.clock()
        if (
            not isinstance(now, dt.datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise SourceError("invalid clock")
        if any(window["end"] > int(now.timestamp()) for window in requested["windows"]):
            raise SourceError("future window")
        fingerprint = self.fingerprint()
        if not isinstance(fingerprint, str) or not re.fullmatch(
            r"[A-Za-z0-9._:-]{1,256}", fingerprint
        ):
            raise SourceError("invalid configuration fingerprint")
        scope = requested["scope"]
        windows = []
        for window in requested["windows"]:
            query = (
                "| admqualified mode=graph "
                + " ".join(
                    f'{key}="{scope[key]}"'
                    for key in ("service", "environment", "cluster", "namespace")
                )
                + f" start={window['start']} as_of={window['end']}"
            )
            rows = _rows(
                self.run(principal, query, window["start"], window["end"]),
                scope,
                window,
            )
            windows.append({**window, "rows": rows})
        if self.fingerprint() != fingerprint:
            raise SourceError("configuration changed")
        completed = self.clock()
        if (
            not isinstance(completed, dt.datetime)
            or completed.tzinfo is None
            or completed.utcoffset() is None
            or completed.timestamp() < now.timestamp()
        ):
            raise SourceError("invalid clock")
        digest = _digest(windows)
        return {
            "captured_at": completed.astimezone(dt.timezone.utc).isoformat(),
            "data": {
                "schema": 1,
                "scope": scope,
                "windows": windows,
                "source_contract": CONTRACT,
                "configuration_fingerprint": fingerprint,
                "evidence_digest": digest,
                "limits": {"rows_per_window": MAX_ROWS, "bytes_per_window": MAX_BYTES},
            },
            "source": {
                "reference": reference,
                "contract": CONTRACT,
                "fingerprint": fingerprint,
                "rows_digest": digest,
            },
        }

    def entitled(self, principal, kind, item):
        try:
            if kind != "capture" or not isinstance(item, dict):
                return False
            source, data = item["source"], item["data"]
            if (
                not isinstance(source, dict)
                or set(source)
                != {"reference", "contract", "fingerprint", "rows_digest"}
                or not isinstance(data, dict)
                or set(data)
                != {
                    "schema",
                    "scope",
                    "windows",
                    "source_contract",
                    "limits",
                    "configuration_fingerprint",
                    "evidence_digest",
                }
            ):
                return False
            reference = _reference(source["reference"])
            if (
                data["schema"] != 1
                or data["source_contract"] != CONTRACT
                or source["contract"] != CONTRACT
                or data["scope"] != reference["scope"]
                or data["configuration_fingerprint"] != source["fingerprint"]
                or data["evidence_digest"] != source["rows_digest"]
                or data["limits"]
                != {"rows_per_window": MAX_ROWS, "bytes_per_window": MAX_BYTES}
                or len(data["windows"]) != len(reference["windows"])
            ):
                return False
            for captured, expected in zip(data["windows"], reference["windows"]):
                if (
                    not isinstance(captured, dict)
                    or set(captured) != {"start", "end", "rows"}
                    or {k: captured[k] for k in ("start", "end")} != expected
                ):
                    return False
                _rows(captured["rows"], reference["scope"], expected)
            if _digest(data["windows"]) != source["rows_digest"]:
                return False
            fresh = self.resolve(principal, source["reference"])
            return fresh["source"] == source
        except Exception:
            return False
