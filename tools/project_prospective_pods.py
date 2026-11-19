#!/usr/bin/env python3
"""Project paired offline CoreDNS Pod attestations; no API or network access."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys

MAX_BYTES = 1024 * 1024
MAX_PODS = 20
MAX_CONTAINERS = 20
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?\Z")
REV = re.compile(r"[0-9]{1,20}\Z")


def pairs(values):
    obj = {}
    for key, value in values:
        if key in obj:
            raise ValueError("duplicate")
        obj[key] = value
    return obj


def no_constant(_value):
    raise ValueError("constant")


def read(path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("safe open unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not regular")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("size")
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_constant
    )


def checked(value, pattern):
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError("invalid identity")
    return value


def opaque(value):
    if (
        type(value) is not str
        or not 1 <= len(value) <= 512
        or any(ord(c) < 32 or ord(c) > 126 for c in value)
    ):
        raise ValueError("invalid opaque field")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hashed(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def metadata(obj, kind):
    if (
        type(obj) is not dict
        or obj.get("apiVersion") != "v1"
        and kind == "Pod"
        or obj.get("kind") != kind
    ):
        raise ValueError("kind")
    if kind != "Pod" and obj.get("apiVersion") != "apps/v1":
        raise ValueError("api version")
    meta = obj.get("metadata")
    if type(meta) is not dict or meta.get("namespace") != "kube-system":
        raise ValueError("namespace")
    return (
        meta,
        checked(meta.get("name"), NAME),
        checked(meta.get("uid"), UID),
        checked(meta.get("resourceVersion"), REV),
    )


def controller(meta, kind):
    refs = meta.get("ownerReferences")
    if type(refs) is not list or not 1 <= len(refs) <= 20:
        raise ValueError("owners")
    if any(
        type(ref) is not dict
        or ("controller" in ref and type(ref["controller"]) is not bool)
        for ref in refs
    ):
        raise ValueError("owner shape")
    owners = [r for r in refs if r.get("controller") is True]
    if (
        len(owners) != 1
        or owners[0].get("kind") != kind
        or owners[0].get("apiVersion") != "apps/v1"
    ):
        raise ValueError("controller")
    return checked(owners[0].get("name"), NAME), checked(owners[0].get("uid"), UID)


def project(snapshot, expected_uid):
    if type(snapshot) is not dict or set(snapshot) != {
        "deployment",
        "replicasets",
        "pods",
    }:
        raise ValueError("snapshot")
    _, name, uid, revision = metadata(snapshot["deployment"], "Deployment")
    if name != "coredns" or uid != expected_uid:
        raise ValueError("deployment")
    sets = snapshot["replicasets"]
    pods = snapshot["pods"]
    if (
        type(sets) is not list
        or not 1 <= len(sets) <= MAX_PODS
        or type(pods) is not list
        or not 1 <= len(pods) <= MAX_PODS
    ):
        raise ValueError("population")
    owners = {}
    rs_names = set()
    for rs in sets:
        meta, rs_name, rs_uid, rs_rev = metadata(rs, "ReplicaSet")
        if (
            controller(meta, "Deployment") != ("coredns", expected_uid)
            or rs_uid in owners
            or rs_name in rs_names
        ):
            raise ValueError("replicaset")
        owners[rs_uid] = (rs_name, rs_rev)
        rs_names.add(rs_name)
    output = []
    seen_uids = set()
    seen_names = set()
    for pod in pods:
        meta, pod_name, pod_uid, pod_rev = metadata(pod, "Pod")
        if pod_uid in seen_uids or pod_name in seen_names:
            raise ValueError("duplicate pod")
        seen_uids.add(pod_uid)
        seen_names.add(pod_name)
        labels = meta.get("labels")
        if type(labels) is not dict or labels.get("k8s-app") != "kube-dns":
            raise ValueError("selector")
        rs_name, rs_uid = controller(meta, "ReplicaSet")
        if rs_uid not in owners or owners[rs_uid][0] != rs_name:
            raise ValueError("owner chain")
        spec = pod.get("spec")
        status = pod.get("status")
        if type(spec) is not dict or type(status) is not dict:
            raise ValueError("pod shape")
        containers, statuses = spec.get("containers"), status.get("containerStatuses")
        if (
            type(containers) is not list
            or not 1 <= len(containers) <= MAX_CONTAINERS
            or type(statuses) is not list
            or len(statuses) != len(containers)
        ):
            raise ValueError("containers")
        declared = {}
        for c in containers:
            if type(c) is not dict:
                raise ValueError("container")
            cn = checked(c.get("name"), NAME)
            if cn in declared:
                raise ValueError("duplicate container")
            declared[cn] = opaque(c.get("image"))
        observed = {}
        for st in statuses:
            if type(st) is not dict:
                raise ValueError("container status")
            cn = checked(st.get("name"), NAME)
            if (
                cn not in declared
                or cn in observed
                or type(st.get("ready")) is not bool
                or type(st.get("restartCount")) is not int
                or not 0 <= st["restartCount"] <= 2**31 - 1
            ):
                raise ValueError("ambiguous status")
            state = st.get("state")
            if (
                type(state) is not dict
                or len(state) != 1
                or next(iter(state)) not in ("running", "waiting", "terminated")
                or type(next(iter(state.values()))) is not dict
            ):
                raise ValueError("state")
            observed[cn] = {
                "name_sha256": hashed(cn),
                "declared_image_sha256": declared[cn],
                "image_id_sha256": opaque(st.get("imageID")),
                "ready": st["ready"],
                "restart_count": st["restartCount"],
                "state": next(iter(state)),
            }
        phase = status.get("phase")
        if phase not in ("Pending", "Running", "Succeeded", "Failed", "Unknown"):
            raise ValueError("phase")
        output.append(
            {
                "pod_name_sha256": hashed(pod_name),
                "pod_uid_sha256": hashed(pod_uid),
                "pod_revision_sha256": hashed(pod_rev),
                "owner_uid_sha256": hashed(rs_uid),
                "owner_revision_sha256": hashed(owners[rs_uid][1]),
                "phase": phase,
                "containers": [observed[x] for x in sorted(observed)],
            }
        )
    return {
        "deployment_uid_sha256": hashed(uid),
        "deployment_revision_sha256": hashed(revision),
        "replicasets": sorted(
            [
                {
                    "name_sha256": hashed(v[0]),
                    "uid_sha256": hashed(k),
                    "revision_sha256": hashed(v[1]),
                }
                for k, v in owners.items()
            ],
            key=lambda x: x["uid_sha256"],
        ),
        "pods": sorted(output, key=lambda x: x["pod_uid_sha256"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected_deployment_uid")
    parser.add_argument("first")
    parser.add_argument("second")
    args = parser.parse_args()
    try:
        expected = checked(args.expected_deployment_uid, UID)
        first = project(read(args.first), expected)
        second = project(read(args.second), expected)
        if first != second:
            raise ValueError("changed")
        result = {
            "status": "paired_projection_consistent",
            "projection": first,
            "scope": "offline claims only; process, effective configuration and coverage unknown",
        }
        code = 0
    except (OSError, ValueError, TypeError, RecursionError):
        result = {"status": "insufficient", "reason": "invalid_or_changed"}
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
