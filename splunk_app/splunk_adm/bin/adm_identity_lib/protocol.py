"""Pure, replay-safe Kubernetes pod-IP identity interval protocol."""

import hashlib
import ipaddress
import json
import math
import re
import uuid

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_RV = re.compile(r"[A-Za-z0-9._:-]{1,256}\Z")


class ProtocolError(ValueError):
    """Input or clock evidence cannot safely produce an interval."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def owners_digest(owner_records):
    return _digest(sorted(owner_records, key=canonical))


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _text(value, label):
    if not isinstance(value, str) or not value or not _TOKEN.fullmatch(value):
        raise ProtocolError(f"invalid {label}")
    return value


def _rv(value):
    if not isinstance(value, str) or not _RV.fullmatch(value):
        raise ProtocolError("invalid resourceVersion")


def _pod(record):
    if not isinstance(record, dict):
        raise ProtocolError("pod is not an object")
    metadata, status, spec = (record.get(key) for key in ("metadata", "status", "spec"))
    if not all(isinstance(value, dict) for value in (metadata, status, spec)):
        raise ProtocolError("pod metadata/status/spec is incomplete")
    uid, namespace, name = (
        _text(metadata.get(key), key) for key in ("uid", "namespace", "name")
    )
    host_network = spec.get("hostNetwork", False)
    if type(host_network) is not bool:
        raise ProtocolError("invalid hostNetwork")
    node_name = spec.get("nodeName")
    if node_name is not None:
        node_name = _text(node_name, "nodeName")
    listed, legacy = status.get("podIPs"), status.get("podIP")
    if listed is not None and not isinstance(listed, list):
        raise ProtocolError("invalid podIPs")
    values = [
        item.get("ip") if isinstance(item, dict) else item for item in (listed or [])
    ]
    if legacy is not None and listed is not None and legacy not in values:
        raise ProtocolError("podIP contradicts podIPs")
    if listed is None:
        values = [legacy] if legacy is not None else []
    ips = []
    for value in values:
        if not isinstance(value, str):
            raise ProtocolError("invalid pod IP")
        try:
            text = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ProtocolError("invalid pod IP") from exc
        if text in ips:
            raise ProtocolError("duplicate pod IP")
        ips.append(text)
    return {
        "namespace": namespace,
        "pod_uid": uid,
        "pod_name": name,
        "ips": tuple(sorted(ips)),
        "host_network": host_network,
        "node_name": node_name,
        "phase": status.get("phase"),
        "terminating": metadata.get("deletionTimestamp") is not None,
    }


def _pods(value):
    if isinstance(value, dict):
        if value.get("kind") not in (None, "PodList") or not isinstance(
            value.get("items"), list
        ):
            raise ProtocolError("expected complete PodList")
        values = value["items"]
    elif isinstance(value, list):
        values = value
    else:
        raise ProtocolError("expected complete pod list")
    result = {}
    for value in values:
        pod = _pod(value)
        if pod["pod_uid"] in result and result[pod["pod_uid"]] != pod:
            raise ProtocolError("duplicate UID has contradictory ownership")
        result[pod["pod_uid"]] = pod
    return result


def _owners(pods):
    result = {}
    for pod in pods.values():
        if pod["terminating"] or pod["phase"] in ("Succeeded", "Failed"):
            continue
        owner = {
            key: pod[key]
            for key in ("namespace", "pod_uid", "host_network", "node_name")
        }
        for ip in pod["ips"]:
            result.setdefault(ip, []).append(owner)
    return {ip: tuple(sorted(values, key=canonical)) for ip, values in result.items()}


def _blocked_ips(pods):
    blocked = set()
    for pod in pods.values():
        if pod["terminating"] or pod["phase"] not in (
            "Pending",
            "Running",
            "Succeeded",
            "Failed",
        ):
            blocked.update(pod["ips"])
        elif pod["ips"] and pod["node_name"] is None:
            blocked.update(pod["ips"])
    return blocked


class IntervalState:
    def __init__(self, cluster, environment, producer_id):
        self.cluster, self.environment, self.producer_id = (
            _text(cluster, "cluster"),
            _text(environment, "environment"),
            _text(producer_id, "producer_id"),
        )
        self.reset("initial")

    def reset(self, reason):
        if not isinstance(reason, str) or not reason:
            raise ProtocolError("invalid reset reason")
        self.producer_epoch = str(uuid.uuid4())
        self._pods, self._owners = {}, {}
        self._invalidated, self._blocked = set(), set()
        self._last_received, self._last_rv = None, None
        self._barriers, self._expected = {}, None
        self._baseline, self._last_checkpoint, self._replay = None, None, {}

    def expect_checkpoint(self, nonce, pod_uid):
        if (
            not isinstance(nonce, str)
            or not nonce
            or not isinstance(pod_uid, str)
            or not pod_uid
        ):
            raise ProtocolError("invalid checkpoint expectation")
        self._expected = (nonce, pod_uid)

    def start_epoch(self, pods, resource_version, received_at):
        try:
            _rv(resource_version)
            if not _finite(received_at):
                raise ProtocolError("invalid LIST receive time")
            normalized = _pods(pods)
        except ProtocolError:
            self.reset("malformed-list")
            raise
        self.producer_epoch = str(uuid.uuid4())
        self._pods, self._owners = normalized, _owners(normalized)
        self._invalidated, self._blocked = set(), _blocked_ips(normalized)
        self._last_received, self._last_rv = received_at, resource_version
        self._barriers, self._expected = {}, None
        self._baseline, self._last_checkpoint, self._replay = None, None, {}

    def observe(self, event, received_at):
        try:
            if not _finite(received_at) or (
                self._last_received is not None and received_at < self._last_received
            ):
                raise ProtocolError("watch timestamps must be monotonic finite")
            if not isinstance(event, dict):
                raise ProtocolError("watch event is not an object")
            kind, obj = event.get("type"), event.get("object", event)
            metadata = obj.get("metadata") if isinstance(obj, dict) else None
            if kind != "BOOKMARK" and not isinstance(metadata, dict):
                raise ProtocolError("watch metadata is invalid")
            rv = event.get("resourceVersion") or (metadata or {}).get("resourceVersion")
            if rv is None:
                raise ProtocolError("watch event lacks resourceVersion")
            _rv(rv)
            self._last_received, self._last_rv = received_at, rv
            if kind == "BOOKMARK":
                return
            if kind not in ("ADDED", "MODIFIED", "DELETED"):
                raise ProtocolError("invalid watch event")
            pod = _pod(obj)
            before = self._owners
            old_blocked = self._blocked
            if kind == "DELETED":
                self._pods.pop(pod["pod_uid"], None)
            else:
                self._pods[pod["pod_uid"]] = pod
            self._blocked = _blocked_ips(self._pods)
            after = _owners(self._pods)
            for ip in set(before) | set(after):
                if before.get(ip) != after.get(ip):
                    self._invalidated.add(ip)
            # A transiently ambiguous owner (termination, unknown phase, or
            # missing node) invalidates the whole interval even if it later
            # disappears and the surviving owner map looks unchanged.
            for ip in old_blocked | self._blocked:
                if ip in old_blocked or ip in self._blocked:
                    self._invalidated.add(ip)
            self._owners = after
            if self._expected and kind == "MODIFIED":
                nonce, uid = self._expected
                annotations = metadata.get("annotations", {})
                if not isinstance(annotations, dict):
                    raise ProtocolError("watch annotations are invalid")
                if (
                    pod["pod_uid"] == uid
                    and annotations.get("atlas.splunk.com/checkpoint") == nonce
                ):
                    self._barriers[nonce], self._expected = received_at, None
        except (AttributeError, ProtocolError, TypeError, ValueError):
            self.reset("malformed-watch")
            raise ProtocolError("malformed or discontinuous watch")

    def close_window(self, patch_started_at, observed_at, checkpoint_nonce):
        if (
            not _finite(patch_started_at)
            or not _finite(observed_at)
            or not isinstance(checkpoint_nonce, str)
        ):
            self.reset("invalid-close")
            raise ProtocolError("invalid close arguments")
        if checkpoint_nonce in self._replay:
            return self._replay[checkpoint_nonce]
        barrier = self._barriers.get(checkpoint_nonce)
        if barrier is None or barrier != observed_at or patch_started_at > barrier:
            raise ProtocolError("matching checkpoint barrier and clock are required")
        if self._baseline is None:
            self._baseline, self._last_checkpoint, self._invalidated = (
                self._owners,
                barrier,
                set(),
            )
            self._replay[checkpoint_nonce] = []
            self._barriers.pop(checkpoint_nonce, None)
            return []
        start, end, observation = (
            math.ceil(self._last_checkpoint),
            math.floor(patch_started_at),
            math.ceil(barrier),
        )
        if end <= start or observation < end:
            self.reset("invalid-interval-clock")
            raise ProtocolError("interval timestamps are invalid")
        snapshot_id = str(uuid.uuid4())
        records = [
            self._owner_event(owner, ip, start, end, observation, snapshot_id)
            for ip, owners in self._baseline.items()
            if ip not in self._invalidated and ip not in self._blocked
            for owner in owners
        ]
        records.sort(key=lambda item: item["record_id"])
        events = records + [
            self._manifest(
                records, snapshot_id, start, end, observation, checkpoint_nonce
            )
        ]
        self._replay[checkpoint_nonce] = events
        self._barriers.pop(checkpoint_nonce, None)
        while len(self._replay) > 2:
            self._replay.pop(next(iter(self._replay)))
        self._baseline, self._invalidated, self._last_checkpoint = (
            self._owners,
            set(),
            barrier,
        )
        return events

    def _owner_event(self, owner, ip, start, end, observed, snapshot_id):
        value = {
            "schema": "adm:pod_ip_interval:v2",
            "kind": "owner",
            "cluster": self.cluster,
            "environment": self.environment,
            "snapshot_id": snapshot_id,
            "producer_id": self.producer_id,
            "producer_epoch": self.producer_epoch,
            "valid_from": start,
            "valid_to": end,
            "observed_at": observed,
            **owner,
            "ip": ip,
            "operation": "present",
        }
        value["record_id"] = _digest(value)
        return value

    def _manifest(self, records, snapshot_id, start, end, observed, nonce):
        return {
            "schema": "adm:pod_ip_interval:v2",
            "kind": "manifest",
            "cluster": self.cluster,
            "environment": self.environment,
            "snapshot_id": snapshot_id,
            "producer_id": self.producer_id,
            "producer_epoch": self.producer_epoch,
            "valid_from": start,
            "valid_to": end,
            "observed_at": observed,
            "checkpoint_nonce": nonce,
            "namespace_scope": "all",
            "expected_count": len(records),
            "owners_sha256": owners_digest(records),
            "invalidated_ips": sorted(self._invalidated | self._blocked),
        }
