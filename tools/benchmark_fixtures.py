"""Deterministic, streaming benchmark data grounded in fixtures/raw/FIELDS.md.

One frontend calls N backend services. NetFlow records repeat a fixed connection
per observer to vary record volume independently of connection-list cardinality.
History is the total incarnations per backend IP, including the current pod.
This models search-time data, not real network exporters or collector throughput.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

RAW = Path(__file__).resolve().parents[1] / "fixtures/raw"
NS = uuid.UUID("a97b9f0a-4e28-4d7a-9e70-8c1f1b2e3d40")
BASE = 1791373800
CLUSTER = "benchmark-cluster"
SCOPE = "benchmark"
FRONTEND_IP = "10.42.10.5"
TEMPLATES = ("kube_object_pods.ndjson", "stream_netflow.ndjson", "otel_traces.ndjson")


@dataclass(frozen=True)
class Workload:
    pods: int = 3  # current backend pods; the frontend adds one more
    flow_copies: int = 1
    history: int = 1
    exporters: int = 1
    observer_copies: int = 1
    connections_per_pair: int = 1

    def __post_init__(self):
        for name, maximum in (
            ("pods", 10000),
            ("flow_copies", 10000),
            ("history", 100),
            ("exporters", 128),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in 1..{maximum}")
        if (
            type(self.observer_copies) is not int
            or not 1 <= self.observer_copies <= self.exporters
        ):
            raise ValueError("observer_copies must be in 1..exporters")
        if type(
            self.connections_per_pair
        ) is not int or not 1 <= self.connections_per_pair <= min(
            self.flow_copies, 1000
        ):
            raise ValueError(
                "connections_per_pair must be in 1..min(flow_copies, 1000)"
            )
        if self.pods * self.flow_copies * self.observer_copies > 2_000_000:
            raise ValueError("Workload exceeds the two-million-record lab guardrail")


def uid(index, incarnation=0):
    return str(uuid.uuid5(NS, f"pod:{index}:{incarnation}"))


def hexadecimal(*parts, length):
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:length]


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000000Z"
    )


@lru_cache(maxsize=1)
def templates():
    data = {
        name: [
            json.loads(line) for line in (RAW / name).read_text().splitlines() if line
        ]
        for name in TEMPLATES
    }
    pod = next(
        e
        for e in data[TEMPLATES[0]]
        if e["event"]["object"]["metadata"]["name"].startswith("frontend-")
        and e["event"]["object"].get("status", {}).get("podIP")
    )
    flow = data[TEMPLATES[1]][0]
    spans = data[TEMPLATES[2]]
    root = next(
        e
        for e in spans
        if e["fields"]["service.name"] == "frontend"
        and e["event"]["kind"].endswith("SERVER")
    )
    client = next(
        e
        for e in spans
        if e["fields"]["service.name"] == "frontend"
        and e["event"]["kind"].endswith("CLIENT")
    )
    server = next(
        e
        for e in spans
        if e["fields"]["service.name"] == "checkout"
        and e["event"]["kind"].endswith("SERVER")
    )
    return pod, flow, (root, client, server)


def pod_event(index, incarnation, ip):
    envelope = copy.deepcopy(templates()[0])
    service = "frontend" if index == -1 else f"backend-{index}"
    name = f"{service}-{incarnation}"
    epoch = BASE - 600 - incarnation * 3600
    envelope["time"] = epoch
    envelope["event"]["type"] = "ADDED"
    obj = envelope["event"]["object"]
    obj["metadata"].update(
        name=name,
        uid=uid(index, incarnation),
        namespace="shop",
        creationTimestamp=iso(epoch),
    )
    obj["metadata"]["labels"] = {
        "app.kubernetes.io/name": service,
        "pod-template-hash": "benchmark",
    }
    obj["metadata"]["ownerReferences"][0].update(
        name=f"{service}-benchmark", uid=str(uuid.uuid5(NS, service))
    )
    obj["spec"]["nodeName"] = "node-a"
    obj["status"].update(
        podIP=ip,
        podIPs=[{"ip": ip}],
        hostIP="10.10.20.11",
        hostIPs=[{"ip": "10.10.20.11"}],
        phase="Running",
        startTime=iso(epoch),
    )
    # The collector's observed fields and the Kubernetes object's identity agree.
    envelope["fields"].update(
        {
            "k8s.cluster.name": CLUSTER,
            "k8s.namespace.name": "shop",
            "k8s.pod.name": name,
            "k8s.pod.uid": uid(index, incarnation),
        }
    )
    return envelope


def iter_events(config):
    yield pod_event(-1, 0, FRONTEND_IP)
    for index in range(config.pods):
        ip = str(ipaddress.ip_address("10.42.10.10") + index)
        for incarnation in reversed(range(config.history)):
            yield pod_event(index, incarnation, ip)
        for number in range(config.flow_copies):
            for observer in range(config.observer_copies):
                envelope = copy.deepcopy(templates()[1])
                envelope["time"] = BASE + 1
                exporter = (index + observer) % config.exporters
                envelope["event"].update(
                    src_ip=FRONTEND_IP,
                    dest_ip=ip,
                    src_port=43001 + number % config.connections_per_pair,
                    dest_port=8080,
                    exporter_ip=f"192.0.2.{11 + exporter}",
                    exporter_sampling_interval=1,
                    timestamp=iso(BASE),
                    endtime=iso(BASE + 1),
                    bytes=300,
                    packets=1,
                    seqnumber=100000
                    + (index * config.flow_copies + number) * config.observer_copies
                    + observer,
                )
                yield envelope
        trace_id = hexadecimal("trace", index, length=32)
        span_ids = [hexadecimal("span", index, role, length=16) for role in range(3)]
        for role, template in enumerate(templates()[2]):
            envelope = copy.deepcopy(template)
            envelope["time"] = BASE + 1
            backend = role == 2
            service = f"backend-{index}" if backend else "frontend"
            envelope["event"].update(
                trace_id=trace_id,
                span_id=span_ids[role],
                parent_span_id="" if role == 0 else span_ids[role - 1],
            )
            envelope["event"]["attributes"]["network.peer.address"] = (
                FRONTEND_IP if backend else ip
            )
            envelope["fields"].update(
                {
                    "service.name": service,
                    "k8s.cluster.name": CLUSTER,
                    "k8s.namespace.name": "shop",
                    "k8s.pod.name": f"{service}-0",
                    "k8s.pod.uid": uid(index if backend else -1),
                    "k8s.node.name": "node-a",
                }
            )
            yield envelope


def manifest(config):
    flows = config.pods * config.flow_copies * config.observer_copies
    pods = 1 + config.pods * config.history
    traces = 3 * config.pods
    template_hashes = {
        name: hashlib.sha256((RAW / name).read_bytes()).hexdigest()
        for name in TEMPLATES
    }
    identity = json.dumps(
        {
            "schema": "adm-pipeline-workload-v1",
            "configuration": asdict(config),
            "templates": template_hashes,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    generated_events = pods + flows + traces
    used = {
        (i + j) % config.exporters
        for i in range(config.pods)
        for j in range(config.observer_copies)
    }
    return {
        "expected": {
            "events": generated_events,
            "flows": flows,
            "pod_events": pods,
            "traces": traces,
            "flow_bytes": 300 * flows,
            "graph_bytes": 300 * config.pods * config.flow_copies,
            "graph_connections": config.pods * config.connections_per_pair,
            "identity_rows": pods + 1,
            "bindings": config.pods + 1,
            "graph_nodes": 2 * (config.pods + 1),
            "graph_edges": 3 * config.pods + 1,
            "active_exporters": len(used),
        },
        "graph_args": {
            "service": "frontend",
            "environment": "demo",
            "cluster": CLUSTER,
            "namespace": "shop",
        },
        "workload_id": hashlib.sha256(identity).hexdigest(),
        "generator_schema": "adm-pipeline-workload-v1",
        "cardinality": {
            "input_events": generated_events,
            "graph_nodes": 2 * (config.pods + 1),
            "graph_edges": 3 * config.pods + 1,
            "graph_rows": 2 * (config.pods + 1) + 3 * config.pods + 2,
            "flow_observations": flows,
            "logical_connections": config.pods * config.connections_per_pair,
            "identity_history_rows": pods,
            "trace_spans": traces,
        },
        "source_mix": {
            "kube:object:pods": pods,
            "stream:netflow": flows,
            "otel:traces": traces,
        },
        "input_time_range": {
            "earliest": str(BASE - 600 - (config.history - 1) * 3600),
            "latest": str(BASE + 1),
            "basis": "synthetic HEC event time; UTC epoch seconds",
        },
        "window": {"earliest": str(BASE - 300), "latest": str(BASE + 600)},
        "scope_rows": [
            {
                "observer_kind": "cluster",
                "observer": CLUSTER,
                "scope": SCOPE,
                "cluster": CLUSTER,
            }
        ]
        + [
            {
                "observer_kind": "exporter",
                "observer": f"192.0.2.{11 + i}",
                "scope": SCOPE,
                "cluster": "",
            }
            for i in range(config.exporters)
        ],
        "provenance": {
            "template_files": [f"fixtures/raw/{name}" for name in TEMPLATES],
            "template_sha256": template_hashes,
            "fields_contract": "fixtures/raw/FIELDS.md",
        },
        "template_sha256": template_hashes,
    }
