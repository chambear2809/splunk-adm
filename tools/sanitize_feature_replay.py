"""Offline allowlisted sanitized replay projection. Never persists or logs secrets."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import ipaddress
import json
import math
import re

from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import validate_profiles


class SanitizationError(ValueError):
    pass


def _fail():
    raise SanitizationError("unsupported replay input")


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            _fail()
        out[key] = value
    return out


def _token(value):
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value
    ):
        _fail()
    return value


def _boolean(value):
    if value is None or type(value) is bool or value in ("true", "false"):
        return value
    _fail()


def _number(value):
    if value is None or type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value):
        return value
    _fail()


def _clock(value, shift, multiplier=1):
    if value is None:
        return None
    offset = shift * multiplier
    if type(value) is int:
        return value + offset
    if type(value) is float:
        if not math.isfinite(value):
            _fail()
        result = value + offset
        if (
            not math.isfinite(result)
            or Decimal.from_float(result) != Decimal.from_float(value) + offset
        ):
            _fail()
        return result
    if not isinstance(value, str):
        _fail()
    if len(value) <= 32 and re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value):
        try:
            number = Decimal(value) + offset
            digits = len(value.partition(".")[2])
            return f"{number:.{digits}f}"
        except (InvalidOperation, ValueError):
            _fail()
    if multiplier != 1:
        _fail()
    match = re.fullmatch(
        r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{1,9})?(Z|[+-]\d\d:\d\d)", value
    )
    if not match:
        _fail()
    try:
        date = dt.datetime.fromisoformat(
            match[1] + ("+00:00" if match[3] == "Z" else match[3])
        )
        shifted = date + dt.timedelta(seconds=shift)
        return shifted.strftime("%Y-%m-%dT%H:%M:%S") + (match[2] or "") + match[3]
    except (ValueError, OverflowError):
        _fail()


class Aliases:
    def __init__(self, key):
        if not isinstance(key, bytes) or len(key) < 32:
            _fail()
        self.key = key
        self.forward = {}
        self.reverse = {}
        self.rv_offset = int.from_bytes(
            hmac.digest(key, b"resource-version", "sha256")[:6], "big"
        )

    def _digest(self, domain, value):
        return hmac.digest(self.key, (domain + "\0" + value).encode("utf-8"), "sha256")

    def _assign(self, domain, value, result):
        token = (domain, value)
        collision = (domain, result)
        if collision in self.reverse and self.reverse[collision] != value:
            _fail()
        self.reverse[collision] = value
        self.forward[token] = result
        return result

    def text(self, domain, value):
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 4096
            or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
        ):
            _fail()
        result = (
            domain.replace(":", "-")
            + ("_" if domain == "index" else "-")
            + self._digest(domain, value).hex()[:24]
        )
        return self._assign(domain, value, result)

    def token(self, domain, value):
        return self.text(domain, _token(value))

    def node(self, value):
        if value is None:
            return None
        if not isinstance(value, str):
            _fail()
        parts = value.split("/")
        if len(parts) == 1:
            return self.token("node", value)
        if len(parts) != 2 or not all(parts):
            _fail()
        return self.token("cluster", parts[0]) + "/" + self.token("node", parts[1])

    def ip(self, value):
        if value is None:
            return None
        if not isinstance(value, str):
            _fail()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            _fail()
        canonical = str(address)
        if canonical != value:
            # Production admission rejects noncanonical spellings. Never turn
            # invalid evidence or contradictory spellings into accepted input.
            _fail()
        digest = self._digest("ip" + str(address.version), canonical)
        if address.version == 4:
            number = int.from_bytes(digest[:8], "big") % (3 * 254)
            prefix = ("192.0.2.", "198.51.100.", "203.0.113.")[number // 254]
            result = prefix + str(number % 254 + 1)
        else:
            result = str(
                ipaddress.IPv6Address(
                    int(ipaddress.IPv6Address("2001:db8::"))
                    | int.from_bytes(digest[:12], "big")
                )
            )
        return self._assign("ip" + str(address.version), canonical, result)

    def resource_version(self, value):
        if value is None:
            return None
        if type(value) is int and value >= 0:
            result = value + self.rv_offset
        elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,64}", value):
            result = str(int(value) + self.rv_offset)
        else:
            _fail()
        self._assign(
            "resource-version",
            type(value).__name__ + ":" + str(value),
            type(result).__name__ + ":" + str(result),
        )
        return result


_ENUMS = {
    "flow_type": {"L3_L4", "L7", "UNKNOWN", "UNKNOWN_TYPE", "SOCK"},
    "observation": {
        "TO_STACK",
        "FROM_STACK",
        "TO_HOST",
        "FROM_HOST",
        "TO_OVERLAY",
        "FROM_OVERLAY",
        "TO_CRYPTO",
        "FROM_CRYPTO",
        "UNKNOWN_POINT",
        "TO_ENDPOINT",
        "FROM_ENDPOINT",
        "TO_NETWORK",
        "FROM_NETWORK",
        "TO_PROXY",
        "FROM_PROXY",
        "UNKNOWN",
    },
    "direction": {"INGRESS", "EGRESS", "UNKNOWN", "TRAFFIC_DIRECTION_UNKNOWN"},
    "verdict": {
        "FORWARDED",
        "DROPPED",
        "VERDICT_UNKNOWN",
        "ERROR",
        "AUDIT",
        "REDIRECTED",
        "TRACED",
        "TRANSLATED",
        "UNKNOWN",
    },
    "watch": {"ADDED", "MODIFIED", "DELETED", "BOOKMARK", "ERROR"},
    "phase": {"Pending", "Running", "Succeeded", "Failed", "Unknown"},
    "condition": {
        "Ready",
        "Initialized",
        "ContainersReady",
        "PodScheduled",
        "PodReadyToStartContainers",
        "DisruptionTarget",
    },
    "condition_status": {"True", "False", "Unknown"},
    "kind": {
        "Pod",
        "ReplicaSet",
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "Job",
        "CronJob",
        "ReplicationController",
        "Node",
    },
}


def _enum(value, kind):
    if value is None:
        return None
    if not isinstance(value, str) or value not in _ENUMS[kind]:
        _fail()
    return value


def _object(value, path, handlers, omitted):
    if value is None:
        return None
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        _fail()
    omitted[path] = omitted.get(path, 0) + len(set(value) - set(handlers))
    return {key: handlers[key](item) for key, item in value.items() if key in handlers}


def _list(value, transform):
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 1000:
        _fail()
    return [transform(item) for item in value]


def _hubble(raw, aliases, shift, omitted):
    def endpoint(value):
        if value is None:
            return None
        if not isinstance(value, dict):
            _fail()
        namespace = value.get("namespace")
        if namespace is not None:
            _token(namespace)
        return _object(
            value,
            "flow.endpoint",
            {
                "namespace": lambda v: aliases.token("namespace", v),
                "pod_name": lambda v: (
                    aliases.text("pod", (namespace or "<missing>") + "\0" + _token(v))
                    if v is not None and isinstance(v, str)
                    else (_fail() if v is not None else None)
                ),
                "workloads": lambda v: _list(
                    v,
                    lambda item: _object(
                        item,
                        "flow.workload",
                        {
                            "name": lambda x: (
                                aliases.text(
                                    "workload",
                                    (namespace or "<missing>") + "\0" + _token(x),
                                )
                                if x is not None and isinstance(x, str)
                                else (_fail() if x is not None else None)
                            ),
                            "kind": lambda x: _enum(x, "kind"),
                        },
                        omitted,
                    ),
                ),
            },
            omitted,
        )

    def transport(value):
        return _object(
            value,
            "flow.transport",
            {
                "source_port": _number,
                "destination_port": _number,
                "flags": lambda v: _object(
                    v,
                    "flow.flags",
                    {
                        k: _boolean
                        for k in (
                            "SYN",
                            "ACK",
                            "FIN",
                            "RST",
                            "PSH",
                            "URG",
                            "ECE",
                            "CWR",
                            "NS",
                        )
                    },
                    omitted,
                ),
                "type": _number,
                "code": _number,
            },
            omitted,
        )

    def flow(value):
        return _object(
            value,
            "flow",
            {
                "time": lambda v: _clock(v, shift),
                "node_name": aliases.node,
                "Type": lambda v: _enum(v, "flow_type"),
                "event_type": lambda v: _object(
                    v,
                    "flow.event_type",
                    {"type": _number, "sub_type": _number},
                    omitted,
                ),
                "trace_observation_point": lambda v: _enum(v, "observation"),
                "traffic_direction": lambda v: _enum(v, "direction"),
                "is_reply": _boolean,
                "verdict": lambda v: _enum(v, "verdict"),
                "IP": lambda v: _object(
                    v,
                    "flow.IP",
                    {"source": aliases.ip, "destination": aliases.ip},
                    omitted,
                ),
                "l4": lambda v: _object(
                    v,
                    "flow.l4",
                    {k: transport for k in ("TCP", "UDP", "SCTP", "ICMPv4", "ICMPv6")},
                    omitted,
                ),
                "source": endpoint,
                "destination": endpoint,
            },
            omitted,
        )

    return _object(
        raw,
        "hubble",
        {
            "node_name": aliases.node,
            "time": lambda v: _clock(v, shift),
            "flow_start_time_milli": lambda v: _clock(v, shift, 1000),
            "flow_end_time_milli": lambda v: _clock(v, shift, 1000),
            "flow": flow,
        },
        omitted,
    )


def _pod(raw, aliases, shift, omitted):
    def pod(value, outer=False):
        if value is None:
            return None
        if not isinstance(value, dict):
            _fail()
        meta = value.get("metadata")
        namespace = meta.get("namespace") if isinstance(meta, dict) else None
        if namespace is not None:
            _token(namespace)

        def name(v):
            if v is None:
                return None
            if not isinstance(v, str):
                _fail()
            return aliases.text("pod", (namespace or "<missing>") + "\0" + _token(v))

        def workload(v):
            if v is None:
                return None
            if not isinstance(v, str):
                _fail()
            return aliases.text(
                "workload", (namespace or "<missing>") + "\0" + _token(v)
            )

        def owner(v):
            return _object(
                v,
                "pod.owner",
                {
                    "name": workload,
                    "kind": lambda x: _enum(x, "kind"),
                    "uid": lambda x: aliases.token("uid", x),
                    "controller": _boolean,
                    "blockOwnerDeletion": _boolean,
                },
                omitted,
            )

        def condition(v):
            return _object(
                v,
                "pod.condition",
                {
                    "type": lambda x: _enum(x, "condition"),
                    "status": lambda x: _enum(x, "condition_status"),
                    "lastProbeTime": lambda x: _clock(x, shift),
                    "lastTransitionTime": lambda x: _clock(x, shift),
                },
                omitted,
            )

        return _object(
            value,
            "pod.object",
            {
                **(
                    {
                        "type": lambda v: _enum(v, "watch"),
                        "resourceVersion": aliases.resource_version,
                        "object": pod,
                    }
                    if outer
                    else {}
                ),
                "metadata": lambda v: _object(
                    v,
                    "pod.metadata",
                    {
                        "name": name,
                        "namespace": lambda x: aliases.token("namespace", x),
                        "uid": lambda x: aliases.token("uid", x),
                        "resourceVersion": aliases.resource_version,
                        "creationTimestamp": lambda x: _clock(x, shift),
                        "deletionTimestamp": lambda x: _clock(x, shift),
                        "ownerReferences": lambda x: _list(x, owner),
                    },
                    omitted,
                ),
                "spec": lambda v: _object(
                    v,
                    "pod.spec",
                    {"nodeName": aliases.node, "hostNetwork": _boolean},
                    omitted,
                ),
                "status": lambda v: _object(
                    v,
                    "pod.status",
                    {
                        "phase": lambda x: _enum(x, "phase"),
                        "podIP": aliases.ip,
                        "hostIP": aliases.ip,
                        "podIPs": lambda x: _list(
                            x,
                            lambda y: _object(
                                y, "pod.podIP", {"ip": aliases.ip}, omitted
                            ),
                        ),
                        "hostIPs": lambda x: _list(
                            x,
                            lambda y: _object(
                                y, "pod.hostIP", {"ip": aliases.ip}, omitted
                            ),
                        ),
                        "conditions": lambda x: _list(x, condition),
                    },
                    omitted,
                ),
            },
            omitted,
        )

    return pod(raw, outer=True)


def sanitize(
    families,
    *,
    key,
    original_window,
    replay_window,
    identity_profile=None,
    network_profiles=None,
):
    """Return sanitized rows/profiles and a value-free report; never retain a key mapping."""
    try:
        if not isinstance(families, dict) or set(families) - {"hubble", "pods"}:
            _fail()
        if (
            not isinstance(original_window, dict)
            or not isinstance(replay_window, dict)
            or set(original_window) != {"start", "end"}
            or set(replay_window) != {"start", "end"}
            or any(
                type(window[k]) is not int
                for window in (original_window, replay_window)
                for k in ("start", "end")
            )
            or original_window["start"] < 0
            or not 0 < original_window["end"] - original_window["start"] <= 300
            or replay_window["start"] < 0
            or replay_window["end"] - replay_window["start"]
            != original_window["end"] - original_window["start"]
        ):
            _fail()
        shift = replay_window["start"] - original_window["start"]
        aliases, omitted = Aliases(key), {}
        rows_out = {}
        if (
            sum(
                len(rows) if isinstance(rows, list) else 100
                for rows in families.values()
            )
            > 8
        ):
            _fail()
        for family, rows in families.items():
            if not isinstance(rows, list) or len(rows) > 4:
                _fail()
            result = []
            for row in rows:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("_raw"), str)
                    or len(row["_raw"].encode()) > 128 * 1024
                ):
                    _fail()
                raw = json.loads(
                    row["_raw"],
                    object_pairs_hook=_pairs,
                    parse_constant=lambda _: _fail(),
                )
                if not isinstance(raw, dict):
                    _fail()
                projected = (
                    _hubble(raw, aliases, shift, omitted)
                    if family == "hubble"
                    else _pod(raw, aliases, shift, omitted)
                )
                handlers = {
                    "_raw": lambda _: json.dumps(
                        projected,
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ),
                    "_time": lambda v: _clock(v, shift),
                    "_indextime": lambda v: _clock(v, shift),
                    "index": lambda v: aliases.text("index", v),
                    "source": lambda v: aliases.text("source", v),
                    "sourcetype": lambda v: (
                        v
                        if v is None
                        or v
                        == (
                            "cilium:hubble:flow"
                            if family == "hubble"
                            else "kube:object:pods"
                        )
                        else _fail()
                    ),
                    "host": aliases.node,
                    "k8s.cluster.name": lambda v: aliases.text("cluster", v),
                    "_bkt": lambda v: aliases.text("bucket", v),
                    "_cd": lambda v: aliases.text("offset", v),
                }
                result.append(_object(row, "row", handlers, omitted))
            rows_out[family] = result
        identity_out, profiles_out = None, []
        profiles = [] if network_profiles is None else network_profiles
        if not isinstance(profiles, list) or any(
            not isinstance(p, dict) or p.get("kind") != "hubble" for p in profiles
        ):
            _fail()
        if identity_profile is not None:
            if not isinstance(identity_profile, dict):
                _fail()
            enabled = identity_profile.get("enabled")
            if not (
                enabled is True or (type(enabled) is str and enabled in ("1", "true"))
            ):
                _fail()
            for name in ("cluster", "scope", "owner_scope"):
                if name == "owner_scope" and name not in identity_profile:
                    continue
                value = identity_profile.get(name)
                if (
                    not isinstance(value, str)
                    or not value
                    or value.strip() != value
                    or not value.isprintable()
                    or len(value) > 256
                ):
                    _fail()
            identity = identity_profile
            fields = {
                "enabled": lambda value: value,
                "cluster": lambda v: aliases.text("cluster", v),
                "environment": lambda v: aliases.text("environment", v),
                "scope": lambda v: aliases.text("scope", v),
                "owner_scope": lambda v: aliases.text("scope", v),
                "producer_id": lambda v: aliases.text("producer", v),
                "interval_index": lambda v: aliases.text("index", v),
                "span_index": lambda v: aliases.text("index", v),
                "interval_source": lambda v: aliases.text("source", v),
                "span_source": lambda v: aliases.text("source", v),
                "interval_sourcetype": lambda v: (
                    v if v == "adm:pod_ip_interval:v2" else _fail()
                ),
                "span_sourcetype": lambda v: v if v == "otel:traces" else _fail(),
                "namespaces": lambda v: _list(
                    v, lambda x: aliases.token("namespace", x)
                ),
            }
            identity_out = _object(identity, "identity_profile", fields, omitted)
        elif profiles:
            _fail()
        if profiles:
            validated = validate_profiles(profiles, identity_profile)
            fields = {
                "id": lambda v: aliases.text("profile", v),
                "kind": lambda v: v if v == "hubble" else _fail(),
                "index": lambda v: aliases.text("index", v),
                "source": lambda v: aliases.text("source", v),
                "sourcetype": lambda v: v if v == "cilium:hubble:flow" else _fail(),
                "scope": lambda v: aliases.text("scope", v),
                "owner_scope": lambda v: aliases.text("scope", v),
                "cluster": lambda v: aliases.text("cluster", v),
                "observers": lambda v: _list(v, aliases.node),
            }
            profiles_out = [
                _object(profile, "network_profile", fields, omitted)
                for profile in validated
            ]
            validate_profiles(profiles_out, identity_out)
        canonical = json.dumps(
            {
                "families": rows_out,
                "identity_profile": identity_out,
                "network_profiles": profiles_out,
                "window": replay_window,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        return {
            "families": rows_out,
            "identity_profile": identity_out,
            "network_profiles": profiles_out,
            "window": dict(replay_window),
            "report": {
                "sha256": hashlib.sha256(canonical).hexdigest(),
                "omitted_counts": omitted,
                "identity_scope": "limited_native_profile"
                if identity_out is not None
                else "unavailable",
                "sample_counts": {
                    family: len(rows) for family, rows in rows_out.items()
                },
                "approved_paths": sorted(
                    [
                        *(
                            "row." + key
                            for key in (
                                "_raw",
                                "_time",
                                "_indextime",
                                "index",
                                "source",
                                "sourcetype",
                                "host",
                                "k8s.cluster.name",
                                "_bkt",
                                "_cd",
                            )
                        ),
                        *(
                            "hubble." + key
                            for key in (
                                "node_name",
                                "time",
                                "flow_start_time_milli",
                                "flow_end_time_milli",
                            )
                        ),
                        *(
                            "flow." + key
                            for key in (
                                "time",
                                "node_name",
                                "Type",
                                "trace_observation_point",
                                "traffic_direction",
                                "is_reply",
                                "verdict",
                                "event_type.type",
                                "event_type.sub_type",
                                "IP.source",
                                "IP.destination",
                            )
                        ),
                        *(
                            f"flow.l4.{protocol}.{field}"
                            for protocol in ("TCP", "UDP", "SCTP", "ICMPv4", "ICMPv6")
                            for field in (
                                "source_port",
                                "destination_port",
                                "type",
                                "code",
                            )
                        ),
                        *(
                            f"flow.l4.{protocol}.flags.{flag}"
                            for protocol in ("TCP", "UDP", "SCTP", "ICMPv4", "ICMPv6")
                            for flag in (
                                "SYN",
                                "ACK",
                                "FIN",
                                "RST",
                                "PSH",
                                "URG",
                                "ECE",
                                "CWR",
                                "NS",
                            )
                        ),
                        *(
                            f"flow.{endpoint}.{field}"
                            for endpoint in ("source", "destination")
                            for field in (
                                "namespace",
                                "pod_name",
                                "workloads[].name",
                                "workloads[].kind",
                            )
                        ),
                        *(
                            "pod." + key
                            for key in (
                                "type",
                                "resourceVersion",
                                "object",
                                "metadata.name",
                                "metadata.namespace",
                                "metadata.uid",
                                "metadata.resourceVersion",
                                "metadata.creationTimestamp",
                                "metadata.deletionTimestamp",
                                "metadata.ownerReferences[].name",
                                "metadata.ownerReferences[].kind",
                                "metadata.ownerReferences[].uid",
                                "metadata.ownerReferences[].controller",
                                "metadata.ownerReferences[].blockOwnerDeletion",
                                "spec.nodeName",
                                "spec.hostNetwork",
                                "status.phase",
                                "status.podIP",
                                "status.hostIP",
                                "status.podIPs[].ip",
                                "status.hostIPs[].ip",
                                "status.conditions[].type",
                                "status.conditions[].status",
                                "status.conditions[].lastProbeTime",
                                "status.conditions[].lastTransitionTime",
                            )
                        ),
                        *(
                            "identity_profile." + key
                            for key in (
                                "enabled",
                                "cluster",
                                "environment",
                                "scope",
                                "owner_scope",
                                "producer_id",
                                "interval_index",
                                "span_index",
                                "interval_source",
                                "span_source",
                                "interval_sourcetype",
                                "span_sourcetype",
                                "namespaces",
                            )
                        ),
                        *(
                            "network_profile." + key
                            for key in (
                                "id",
                                "kind",
                                "index",
                                "source",
                                "sourcetype",
                                "scope",
                                "owner_scope",
                                "cluster",
                                "observers",
                            )
                        ),
                    ]
                ),
                "address_class_note": "Addresses are documentation ranges; routing and address-class semantics are not preserved.",
                "complete": False,
            },
        }
    except SanitizationError:
        raise
    except Exception:
        raise SanitizationError("unsupported replay input") from None
