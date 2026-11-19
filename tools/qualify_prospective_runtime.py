"""Assemble read-only CoreDNS provenance through an injected bounded caller.

This module does not contact Kubernetes or authenticate. The caller must enforce
its own fixed-context, executable, credential-provider, TLS, timeout and byte
bounds. Results represent current metadata only, not source qualification.
"""

import json

import project_prospective_pods as pod

VIEW = ("config", "view", "--minify", "-o", "json")
CA = (
    "config",
    "view",
    "--minify",
    "--raw",
    "-o",
    "jsonpath={.clusters[0].cluster.certificate-authority-data}",
)
WHO = ("auth", "whoami", "-o", "json")
NAMESPACE = ("get", "namespace", "kube-system", "-o", "json")
DEPLOYMENT = ("get", "deployment", "coredns", "-n", "kube-system", "-o", "json")
REPLICASETS = (
    "get",
    "replicasets",
    "-n",
    "kube-system",
    "-l",
    "k8s-app=kube-dns",
    "--chunk-size=0",
    "-o",
    "json",
)
PODS = (
    "get",
    "pods",
    "-n",
    "kube-system",
    "-l",
    "k8s-app=kube-dns",
    "--chunk-size=0",
    "-o",
    "json",
)
ALLOWED = frozenset((VIEW, CA, WHO, NAMESPACE, DEPLOYMENT, REPLICASETS, PODS))


def allowed_request(args):
    return type(args) in (tuple, list) and tuple(args) in ALLOWED


def decode(data):
    if type(data) is not bytes or len(data) > pod.MAX_BYTES:
        raise ValueError("response limit")
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError("nesting limit")
        elif byte in (93, 125):
            depth -= 1
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=pod.pairs,
        parse_constant=pod.no_constant,
    )


def namespace(value, expected):
    if (
        type(value) is not dict
        or value.get("apiVersion") != "v1"
        or value.get("kind") != "Namespace"
    ):
        raise ValueError("namespace kind")
    m = value.get("metadata")
    if (
        type(m) is not dict
        or m.get("name") != "kube-system"
        or m.get("uid") != expected
    ):
        raise ValueError("namespace identity")
    pod.checked(expected, pod.UID)
    return (expected, pod.checked(m.get("resourceVersion"), pod.REV))


def list_items(value, kind):
    if type(value) is not dict or (value.get("apiVersion"), value.get("kind")) not in (
        ("v1", "List"),
        ("apps/v1" if kind == "ReplicaSet" else "v1", kind + "List"),
    ):
        raise ValueError("list kind")
    meta = value.get("metadata", {})
    if (
        type(meta) is not dict
        or meta.get("continue") not in (None, "")
        or meta.get("remainingItemCount") not in (None, 0)
    ):
        raise ValueError("incomplete list")
    rows = value.get("items")
    if type(rows) is not list or not 1 <= len(rows) <= pod.MAX_PODS:
        raise ValueError("list bounds")
    return rows


def declaration(deployment):
    """Project ConfigMap references without reading values or environment."""
    try:
        template = deployment["spec"]["template"]["spec"]
    except (KeyError, TypeError):
        raise ValueError("template") from None
    if type(template) is not dict:
        raise ValueError("template")
    refs = []

    def record(kind, name):
        refs.append((kind, pod.hashed(pod.checked(name, pod.NAME))))
        if len(refs) > 100:
            raise ValueError("reference bounds")

    volumes = template.get("volumes", [])
    if type(volumes) is not list or len(volumes) > 100:
        raise ValueError("volumes")
    for volume in volumes:
        if type(volume) is not dict:
            raise ValueError("volume")
        if "configMap" in volume:
            cm = volume["configMap"]
            if type(cm) is not dict:
                raise ValueError("configmap")
            record("volume", cm.get("name"))
        if "projected" in volume:
            projected = volume["projected"]
            sources = projected.get("sources") if type(projected) is dict else None
            if type(sources) is not list or len(sources) > 100:
                raise ValueError("projected")
            for source in sources:
                if type(source) is not dict:
                    raise ValueError("source")
                if "configMap" in source:
                    cm = source["configMap"]
                    if type(cm) is not dict:
                        raise ValueError("configmap")
                    record("projected", cm.get("name"))
    return [{"type": k, "name_sha256": v} for k, v in sorted(refs)]


def collect(call, identity, expected_deployment, expected_namespace):
    """Call only exact reviewed requests. Raw responses remain in memory."""
    pod.checked(expected_deployment, pod.UID)
    pod.checked(expected_namespace, pod.UID)

    def get(command):
        if not allowed_request(command):
            raise ValueError("request")
        return call(list(command))

    before = identity(get(WHO))
    start = namespace(decode(get(NAMESPACE)), expected_namespace)
    projections = []
    declarations = []
    for _ in range(2):
        deployment = decode(get(DEPLOYMENT))
        replicasets = list_items(decode(get(REPLICASETS)), "ReplicaSet")
        pods = list_items(decode(get(PODS)), "Pod")
        projections.append(
            pod.project(
                {"deployment": deployment, "replicasets": replicasets, "pods": pods},
                expected_deployment,
            )
        )
        declarations.append(declaration(deployment))
    end = namespace(decode(get(NAMESPACE)), expected_namespace)
    after = identity(get(WHO))
    if (
        start != end
        or before != after
        or projections[0] != projections[1]
        or declarations[0] != declarations[1]
    ):
        raise ValueError("changed")
    return {
        "status": "paired_projection_consistent",
        "namespace_uid_sha256": pod.hashed(start[0]),
        "namespace_revision_sha256": pod.hashed(start[1]),
        "projection": projections[0],
        "configmap_volume_references": declarations[0],
        "scope": "paired declarations only; process, effective configuration and completeness unknown",
    }
