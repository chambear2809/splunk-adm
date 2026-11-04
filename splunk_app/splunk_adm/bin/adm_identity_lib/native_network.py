"""Fail-closed normalization of native Hubble and NetFlow observations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from datetime import datetime, timezone


class NativeEvidenceError(ValueError):
    pass


_INDEX = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}\Z")
_SOURCE = re.compile(r"[A-Za-z0-9/][A-Za-z0-9_.:/@-]{0,254}\Z")
_MAX_BODY = 1_048_576
_MAX_ROWS = 50_000
_MAX_WINDOW = 300
_PROTO = {6: "TCP", 17: "UDP", 132: "SCTP", 1: "ICMP", 58: "IPv6-ICMP"}


def _fail(message):
    raise NativeEvidenceError(message)


def _text(value, label, pattern=_SAFE):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _fail(f"invalid {label}")
    return value


def _finite(value, label):
    if isinstance(value, str) and re.fullmatch(
        r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value
    ):
        value = float(value)
    if (
        type(value) not in (int, float)
        or isinstance(value, bool)
        or not math.isfinite(value)
    ):
        _fail(f"invalid {label}")
    return float(value)


def _ip(value):
    try:
        parsed = str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        _fail("invalid IP")
    if parsed != value:
        _fail("IP must be canonical")
    return parsed


def _rfc(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[^Z]+Z|[^+]+[+-][0-9]{2}:[0-9]{2}", value
    ):
        _fail("invalid RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("invalid RFC3339 timestamp")
    if parsed.tzinfo is None:
        _fail("timestamp timezone required")
    return parsed.astimezone(timezone.utc).timestamp()


def _raw(row):
    value = row.get("_raw")
    if not isinstance(value, str) or len(value) > _MAX_BODY:
        _fail("raw evidence missing or over budget")
    try:
        result = json.loads(
            value,
            parse_constant=lambda _: _fail("non-finite JSON"),
            object_pairs_hook=_pairs,
        )
        if not isinstance(result, dict):
            _fail("native JSON must be an object")
        return result
    except NativeEvidenceError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        _fail("malformed native JSON")


def _attested_metadata(value, label):
    if isinstance(value, list):
        if (
            not value
            or any(not isinstance(item, str) for item in value)
            or len(set(value)) != 1
        ):
            _fail(f"conflicting {label}")
        return value[0]
    if not isinstance(value, str):
        _fail(f"missing {label}")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON object key")
        result[key] = value
    return result


def validate_profiles(profiles, identity_profile):
    if not isinstance(profiles, list) or not profiles or len(profiles) > 100:
        _fail("profiles must be a non-empty list")
    if not isinstance(identity_profile, dict):
        _fail("identity profile is invalid")
    cluster = identity_profile.get("cluster")
    owner_scope = identity_profile.get("owner_scope", identity_profile.get("scope"))
    seen, result = set(), []
    for original in profiles:
        if not isinstance(original, dict):
            _fail("profile is not an object")
        p = dict(original)
        pid = _text(p.get("id"), "profile id")
        if pid in seen:
            _fail("duplicate profile id")
        seen.add(pid)
        kind = p.get("kind")
        if kind not in ("hubble", "netflow"):
            _fail("unsupported native profile kind")
        for key in ("index", "source", "sourcetype"):
            pattern = (
                _INDEX if key == "index" else _SOURCE if key == "source" else _SAFE
            )
            value = _text(p.get(key), key, pattern)
            if any(x in value for x in ("*", "|", "=", "\n", "\r")):
                _fail("unsafe source profile")
        if cluster is not None and p.get("cluster") != cluster:
            _fail("profile cluster differs from identity profile")
        _text(p.get("cluster"), "profile cluster")
        _text(p.get("scope"), "profile scope")
        if (
            kind == "hubble"
            and owner_scope is not None
            and p.get("owner_scope") != owner_scope
        ):
            _fail("profile owner scope differs from identity profile")
        if kind == "hubble":
            observers = p.get("observers")
            if (
                not isinstance(observers, list)
                or not observers
                or len(set(observers)) != len(observers)
            ):
                _fail("hubble observer allowlist required")
            for observer in observers:
                _text(observer, "observer")
        else:
            if not isinstance(p.get("exporter_ip"), str):
                _fail("netflow exporter required")
            _ip(p["exporter_ip"])
            if type(p.get("netflow_version")) is not int or p[
                "netflow_version"
            ] not in (9, 10):
                _fail("netflow version required")
            if type(p.get("observation_domain_present")) is not bool:
                _fail("observation domain presence required")
            if (
                p["observation_domain_present"]
                and type(p.get("observation_domain_id")) is not int
            ):
                _fail("observation domain id required")
        result.append(p)
    for i, left in enumerate(result):
        for right in result[i + 1 :]:
            if (left["kind"], left["source"], left["index"]) != (
                right["kind"],
                right["source"],
                right["index"],
            ):
                continue
            if left["kind"] == "hubble" or (
                left.get("exporter_ip"),
                left.get("netflow_version"),
                left.get("observation_domain_present"),
                left.get("observation_domain_id"),
            ) == (
                right.get("exporter_ip"),
                right.get("netflow_version"),
                right.get("observation_domain_present"),
                right.get("observation_domain_id"),
            ):
                _fail("overlapping native authority registrations")
    return result


def _metadata(row, profile):
    for key in ("index", "source", "sourcetype"):
        if row.get(key) != profile[key]:
            _fail("row provenance does not match profile")
    event, receipt = (
        _finite(row.get("event_time"), "event time"),
        _finite(row.get("receipt_time"), "receipt time"),
    )
    if receipt < 0:
        _fail("invalid receipt time")
    return event, receipt


def _record(row, profile, event, receipt, raw, window_start, window_end):
    start = end = event
    if profile["kind"] == "hubble":
        flow = raw.get("flow")
        if not isinstance(flow, dict):
            _fail("hubble flow wrapper required")
        if raw.get("node_name") != flow.get("node_name") or not isinstance(
            flow.get("node_name"), str
        ):
            _fail("conflicting hubble observer")
        observer = os.path.basename(flow["node_name"])
        if (
            observer not in profile["observers"]
            or _attested_metadata(row.get("host"), "host") != observer
        ):
            _fail("unattested hubble observer")
        if _attested_metadata(row.get("k8s.cluster.name"), "cluster") != profile.get(
            "cluster"
        ):
            _fail("unattested cluster")
        if flow.get("Type") != "L3_L4":
            _fail("unsupported hubble flow type")
        if flow.get("verdict") not in ("FORWARDED", "DROPPED"):
            _fail("invalid hubble verdict")
        start = end = _rfc(flow.get("time"))
        if not (window_start <= start < window_end) or abs(start - event) > 0.01:
            _fail("invalid native clocks")
        if end >= receipt + 1:
            _fail("unreceived native clock")
        for key, expected in (
            ("flow_start_time_milli", start),
            ("flow_end_time_milli", end),
        ):
            if key in raw and abs(_finite(raw[key], key) / 1000 - expected) > 0.001:
                _fail("native millisecond clock conflict")
        outer = raw.get("time")
        if outer is not None and abs(_rfc(outer) - start) > 0.001:
            _fail("hubble clock conflict")
        ipobj = flow.get("IP")
        l4 = flow.get("l4")
        if not isinstance(ipobj, dict) or not isinstance(l4, dict):
            _fail("malformed hubble flow")
        transports = [k for k in ("TCP", "UDP", "SCTP") if isinstance(l4.get(k), dict)]
        if (
            sum(k in l4 and isinstance(l4.get(k), dict) for k in ("ICMPv4", "ICMPv6"))
            + len(transports)
            != 1
        ):
            _fail("ambiguous hubble protocol")
        transport = transports[0] if transports else None
        if transport:
            ports = l4[transport]
            sport, dport = ports.get("source_port"), ports.get("destination_port")
            if (
                type(sport) is not int
                or type(dport) is not int
                or not (0 <= sport <= 65535 and 0 <= dport <= 65535)
            ):
                _fail("invalid hubble port")
        elif isinstance(l4.get("ICMPv4"), dict):
            transport, sport, dport = "ICMP", None, None
        elif isinstance(l4.get("ICMPv6"), dict):
            transport, sport, dport = "IPv6-ICMP", None, None
        else:
            _fail("unsupported hubble protocol")
        src, dst = _ip(ipobj.get("source")), _ip(ipobj.get("destination"))
        source, destination = flow.get("source", {}), flow.get("destination", {})
        if not isinstance(source, dict) or not isinstance(destination, dict):
            _fail("malformed hubble endpoint")
        result = {
            "observer": observer,
            "observation_point": flow.get("trace_observation_point"),
            "direction": flow.get("traffic_direction"),
            "verdict": flow.get("verdict"),
            "is_reply": flow.get("is_reply")
            if type(flow.get("is_reply")) is bool
            else None,
            "source_namespace": source.get("namespace"),
            "destination_namespace": destination.get("namespace"),
            "source_pod": source.get("pod_name"),
            "destination_pod": destination.get("pod_name"),
            "raw_bytes": None,
            "raw_packets": None,
            "observation_domain_present": None,
            "observation_domain_id": None,
        }
    else:
        if (
            raw.get("exporter_ip") != profile["exporter_ip"]
            or raw.get("netflow_version") != profile["netflow_version"]
        ):
            _fail("netflow authority mismatch")
        present = "observation_domain_id" in raw
        if present and type(raw["observation_domain_id"]) is not int:
            _fail("invalid observation domain id")
        if present != profile["observation_domain_present"] or (
            present
            and raw["observation_domain_id"] != profile.get("observation_domain_id")
        ):
            _fail("observation domain mismatch")
        src, dst = _ip(raw.get("src_ip")), _ip(raw.get("dest_ip"))
        start, end = _rfc(raw.get("timestamp")), _rfc(raw.get("endtime"))
        if (
            start > end
            or not (window_start <= start and end < window_end)
            or end >= receipt + 1
            or event < start - 0.01
            or abs(end - event) > 0.01
        ):
            _fail("invalid native clocks")
        for key, expected in (
            ("flow_start_time_milli", start),
            ("flow_end_time_milli", end),
        ):
            if key in raw and abs(_finite(raw[key], key) / 1000 - expected) > 0.001:
                _fail("native millisecond clock conflict")
        proto = raw.get("protoid")
        if type(proto) is not int or proto not in _PROTO:
            _fail("unsupported protocol")
        transport = _PROTO[proto]
        sport, dport = raw.get("src_port"), raw.get("dest_port")
        if transport in ("TCP", "UDP", "SCTP") and (
            type(sport) is not int
            or type(dport) is not int
            or not (0 <= sport <= 65535 and 0 <= dport <= 65535)
        ):
            _fail("invalid netflow ports")
        elif transport in ("ICMP", "IPv6-ICMP"):
            sport = dport = None
        result = {
            "observer": raw.get("exporter_ip"),
            "observation_point": None,
            "direction": raw.get("flow_dir"),
            "verdict": None,
            "source_namespace": None,
            "destination_namespace": None,
            "source_pod": None,
            "destination_pod": None,
            "raw_bytes": _counter(raw.get("bytes_in"), "bytes")
            if "bytes_in" in raw
            else None,
            "raw_packets": _counter(raw.get("packets_in"), "packets")
            if "packets_in" in raw
            else None,
            "observation_domain_present": present,
            "observation_domain_id": raw.get("observation_domain_id"),
        }
    for field in (
        "observation_point",
        "direction",
        "source_namespace",
        "destination_namespace",
        "source_pod",
        "destination_pod",
    ):
        value = result.get(field)
        if value is None or value == "":
            continue
        if (
            field == "direction"
            and profile["kind"] == "netflow"
            and type(value) is int
            and 0 <= value <= 255
        ):
            continue
        _text(value, "native " + field)
    return {
        "record_id": hashlib.sha256(
            json.dumps(
                [row["index"], row["_bkt"], row["_cd"]], separators=(",", ":")
            ).encode()
        ).hexdigest(),
        "kind": profile["kind"],
        "profile_id": profile["id"],
        "scope": profile.get("scope"),
        "cluster": profile.get("cluster"),
        "owner_scope": profile.get("owner_scope"),
        "source_ip": src,
        "destination_ip": dst,
        "source_port": sport,
        "destination_port": dport,
        "transport": transport,
        "first_seen": start,
        "last_seen": end,
        "event_time": event,
        "received_time": receipt,
        **result,
    }


def _counter(value, label):
    if type(value) is not int or value < 0 or value > 2**53 - 1:
        _fail(f"invalid {label} counter")
    return value


def normalize_records(rows, profiles, start, as_of):
    if (
        type(start) not in (int, float)
        or type(as_of) not in (int, float)
        or not math.isfinite(start)
        or not math.isfinite(as_of)
        or not (start < as_of <= start + _MAX_WINDOW)
    ):
        _fail("invalid native window")
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        _fail("native input exceeds budget")
    if (
        sum(
            len(row.get("_raw", ""))
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("_raw", ""), str)
        )
        > 50 * 1024 * 1024
    ):
        _fail("native raw input exceeds budget")
    by_provenance = {}
    for profile in profiles:
        by_provenance.setdefault(
            (profile["index"], profile["source"], profile["sourcetype"]), []
        ).append(profile)
    records, excluded, warnings, by_id, raw_by_id = [], {}, [], {}, {}
    for row in rows:
        try:
            if not isinstance(row, dict):
                _fail("row is not an object")
            if (
                not isinstance(row.get("index"), str)
                or not isinstance(row.get("_bkt"), str)
                or not row["_bkt"]
                or len(row["_bkt"]) > 512
                or not isinstance(row.get("_cd"), str)
                or not row["_cd"]
                or len(row["_cd"]) > 512
            ):
                _fail("missing bounded provenance")
            rid = hashlib.sha256(
                json.dumps(
                    [row["index"], row["_bkt"], row["_cd"]], separators=(",", ":")
                ).encode()
            ).hexdigest()
            # Immutable indexed evidence must agree even when a conflicting copy
            # is malformed, out of scope, or has an invalid receipt clock.
            try:
                raw_signature = hashlib.sha256(
                    json.dumps(
                        [
                            (key in row, row.get(key))
                            for key in (
                                "_raw",
                                "index",
                                "source",
                                "sourcetype",
                                "event_time",
                                "receipt_time",
                                "host",
                                "k8s.cluster.name",
                            )
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                ).hexdigest()
            except (TypeError, ValueError, RecursionError):
                _fail("invalid replay signature")
            if rid in raw_by_id and raw_by_id[rid] != raw_signature:
                _fail("conflicting replay evidence")
            raw_by_id[rid] = raw_signature
            candidates = by_provenance.get(
                (row.get("index"), row.get("source"), row.get("sourcetype"))
            )
            if not candidates:
                _fail("unknown native provenance")
            event, receipt = _metadata(row, candidates[0])
            if receipt >= as_of:
                raise NativeEvidenceError("future receipt")
            if not (start <= event < as_of):
                raise NativeEvidenceError("event outside window")
            raw = _raw(row)
            matches = []
            for candidate in candidates:
                try:
                    _record(row, candidate, event, receipt, raw, start, as_of)
                    matches.append(candidate)
                except NativeEvidenceError:
                    pass
            if len(matches) != 1:
                _fail("ambiguous or unmatched native authority")
            profile = matches[0]
            record = _record(row, profile, event, receipt, raw, start, as_of)
            rid = record["record_id"]
            signature = json.dumps(
                [
                    profile,
                    raw,
                    row.get("index"),
                    row.get("source"),
                    row.get("sourcetype"),
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            if rid in by_id and by_id[rid] != signature:
                _fail("conflicting replay evidence")
            if rid not in by_id:
                by_id[rid] = signature
                records.append(record)
        except NativeEvidenceError as exc:
            if str(exc) == "conflicting replay evidence":
                raise
            excluded[str(exc)] = excluded.get(str(exc), 0) + 1
    return {"records": records, "excluded": excluded, "warnings": warnings}
