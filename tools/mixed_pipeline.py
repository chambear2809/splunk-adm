#!/usr/bin/env python3
"""Exercise real Splunk normalization, rollup and graph across four flow sources."""

from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests/splunk"))
# ruff: noqa: E402
from benchmark_fixtures import (
    BASE,
    CLUSTER,
    SCOPE,
    Workload,
    iter_events,
    manifest,
    iso,
)
from benchmark_pipeline import (
    Runner,
    preflight,
    reset_lab,
    require,
    wait_count,
    graph_check,
)
from soak_pipeline import (
    checked_search,
    closed_boundary,
    post_batches,
    graph_query,
    rollup,
)

SOURCES = ("netflow", "nd", "ftd", "hubble")
COUNTERS = {"netflow": (300, 0), "nd": (250, 0), "ftd": (120, 80), "hubble": (0, 0)}


@dataclass(frozen=True)
class MixedConfig:
    pods: int = 3
    records_per_pair: int = 4
    connections_per_pair: int = 2
    observers_per_source: int = 2

    def __post_init__(self):
        for name, maximum in [
            ("pods", 100),
            ("records_per_pair", 1000),
            ("connections_per_pair", 100),
            ("observers_per_source", 8),
        ]:
            require(
                type(getattr(self, name)) is int
                and 1 <= getattr(self, name) <= maximum,
                f"invalid {name}",
            )
        require(
            self.connections_per_pair <= self.records_per_pair,
            "connections exceed records",
        )
        require(
            self.pods * self.records_per_pair * self.observers_per_source * 4 <= 100000,
            "mixed workload exceeds 100000 records",
        )

    def workload(self):
        return Workload(
            pods=self.pods,
            flow_copies=self.records_per_pair,
            connections_per_pair=self.connections_per_pair,
        )


CASES = {
    "smoke": MixedConfig(),
    "baseline": MixedConfig(20, 100, 5, 2),
    "scale": MixedConfig(50, 100, 5, 4),
}


def template(path):
    return json.loads((ROOT / path).read_text().splitlines()[0])


def observer(source, number):
    return {
        "netflow": f"192.0.2.{11 + number}",
        "nd": f"mixed-fabric-{number}",
        "ftd": f"192.0.2.{71 + number}",
        "hubble": f"mixed-node-{number}",
    }[source]


def scope_rows(config):
    rows = [
        {
            "observer_kind": "cluster",
            "observer": CLUSTER,
            "scope": SCOPE,
            "cluster": CLUSTER,
        }
    ]
    for number in range(config.observers_per_source):
        for source, kind in [
            ("netflow", "exporter"),
            ("nd", "fabric"),
            ("ftd", "firewall"),
        ]:
            rows.append(
                {
                    "observer_kind": kind,
                    "observer": observer(source, number),
                    "scope": SCOPE,
                    "cluster": CLUSTER,
                }
            )
    return rows


def corpus(config):
    nd_template = template("fixtures/raw/nd_flows.ndjson")
    ftd_template = template("fixtures/raw/ftd_estreamer.ndjson")
    hubble_template = template("fixtures/raw-aci/hubble_flows.ndjson")
    for envelope in iter_events(config.workload()):
        if envelope["sourcetype"] != "stream:netflow":
            yield envelope
            continue
        flow = envelope["event"]
        for number in range(config.observers_per_source):
            nf = copy.deepcopy(envelope)
            nf["event"]["exporter_ip"] = observer("netflow", number)
            yield nf
            nd = copy.deepcopy(nd_template)
            event = json.loads(nd["event"])
            event.update(
                srcIp=flow["src_ip"],
                dstIp=flow["dest_ip"],
                srcPort=flow["src_port"],
                dstPort=flow["dest_port"],
                protocolName="TCP",
                ts=iso(BASE),
                fabricName=observer("nd", number),
            )
            event["stats"][0].update(
                ingressByteCount=250,
                egressByteCount=250,
                ingressPktCount=1,
                egressPktCount=1,
            )
            nd.update(time=BASE + 1, event=json.dumps(event))
            yield nd
            ftd = copy.deepcopy(ftd_template)
            event = json.loads(ftd["event"])
            event.update(
                FirstPacketSecond=BASE,
                DeviceIP=observer("ftd", number),
                ConnectionID=flow["seqnumber"],
                InitiatorIP=flow["src_ip"],
                ResponderIP=flow["dest_ip"],
                InitiatorPort=flow["src_port"],
                ResponderPort=flow["dest_port"],
                InitiatorBytes=120,
                ResponderBytes=80,
                InitiatorPackets=1,
                ResponderPackets=1,
            )
            ftd.update(time=BASE + 1, event=json.dumps(event))
            yield ftd
            hubble = copy.deepcopy(hubble_template)
            event = json.loads(hubble["event"])
            node = observer("hubble", number)
            event.update(time=iso(BASE), node_name=CLUSTER + "/" + node)
            event["flow"].update(
                time=iso(BASE),
                node_name=CLUSTER + "/" + node,
                uuid=str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL, f"mixed/{flow['seqnumber']}/{number}"
                    )
                ),
            )
            event["flow"]["IP"] = {
                "source": flow["src_ip"],
                "destination": flow["dest_ip"],
                "ipVersion": "IPv4",
            }
            event["flow"]["l4"] = {
                "TCP": {
                    "source_port": flow["src_port"],
                    "destination_port": flow["dest_port"],
                    "flags": {"SYN": True},
                }
            }
            # Endpoint metadata is deliberately absent: attribution must use the app's actual identity lookup.
            event["flow"].pop("source", None)
            event["flow"].pop("destination", None)
            hubble["fields"].update(
                {"k8s.cluster.name": CLUSTER, "k8s.node.name": node}
            )
            hubble.update(time=BASE + 1, event=json.dumps(event))
            yield hubble


def expected_observations(config):
    count = config.pods * config.records_per_pair
    return {
        (source, observer(source, n)): {
            "records": count,
            "bytes_fwd": count * COUNTERS[source][0],
            "bytes_rev": count * COUNTERS[source][1],
        }
        for source in SOURCES
        for n in range(config.observers_per_source)
    }


def check_observations(rows, config):
    expected = expected_observations(config)
    actual = {(r["flow_source"], r["observer"]): r for r in rows}
    require(
        len(actual) == len(rows) and actual.keys() == expected.keys(),
        "source/observer groups differ",
    )
    for key, values in expected.items():
        row = actual[key]
        for field, value in values.items():
            require(
                float(row.get(field) or 0) == value,
                f"{key}: {field} differs: {row.get(field)} != {value}",
            )
        require(row.get("scope") == SCOPE, f"{key}: observer scope lost")
        require(int(row.get("excluded") or 0) == 0, f"{key}: invalid raw fields")


def check_graph(rows, config):
    errors = graph_check(rows, manifest(config.workload())["expected"])
    require(not errors, "; ".join(errors))
    expected = {
        f"{s}:{observer(s, n)}"
        for s in SOURCES
        for n in range(config.observers_per_source)
    }
    for row in rows:
        if row.get("relationship") != "communicates_with":
            continue
        sources = row.get("sources", [])
        observers = row.get("observers", [])
        require(
            isinstance(sources, list) and set(sources) == set(SOURCES),
            "graph lost source attribution",
        )
        require(
            isinstance(observers, list)
            and len(observers) == len(expected)
            and {":".join(value.split(":", 2)[:2]) for value in observers} == expected,
            "graph lost observer attribution",
        )
        require(row.get("confidence") == "correlated", "graph endpoints are unresolved")
        require(
            int(row["count"]) == config.connections_per_pair,
            "graph collapsed distinct ports or counted observers as connections",
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset-lab", action="store_true", required=True)
    parser.add_argument("--case", choices=CASES, default="smoke")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/mixed/latest.json")
    args = parser.parse_args(argv)
    config = CASES[args.case]
    runner = Runner(180)
    report = {"status": "failed", "case": args.case, "parameters": asdict(config)}
    try:
        report["environment"] = preflight()
        reset_lab(scope_rows(config))
        start = closed_boundary()
        lines = [json.dumps(e, sort_keys=True).encode() for e in corpus(config)]
        report["fixture_sha256"] = hashlib.sha256(b"\n".join(lines)).hexdigest()
        report["submitted"] = post_batches(lines)
        wait_count(
            runner,
            "index=netflow OR index=cisco_dc OR index=cisco_secure_fw OR index=cilium_hubble OR index=k8s OR index=otel_traces",
            len(lines),
            180,
        )
        end = closed_boundary()
        raw = checked_search(
            runner,
            "mixed-normalization",
            '| `adm_flows` | stats count AS records sum(adm_bytes_fwd) AS bytes_fwd sum(adm_bytes_rev) AS bytes_rev values(adm_scope) AS scope count(eval(adm_quality_status="excluded")) AS excluded by adm_source adm_observer | rename adm_source AS flow_source adm_observer AS observer',
        )
        check_observations(raw, config)
        report["normalization"] = raw
        for name in (
            "ADM - Identity builder",
            "ADM - Service binding",
            "ADM - Service backends",
        ):
            checked_search(runner, name, name, saved=True, index_window=(start, end))
        expected = (
            config.pods
            * config.records_per_pair
            * config.observers_per_source
            * len(SOURCES)
        )
        rollup(runner, start, end, expected, 180)
        summary = checked_search(
            runner,
            "mixed-summary",
            'index=adm_summary source="adm:conversation" | `adm_summary_dedup` | stats sum(records) AS records sum(bytes_c2s) AS bytes_fwd sum(bytes_s2c) AS bytes_rev values(scope) AS scope by flow_source observer | eval observer=replace(observer,"^[^:]+:","")',
        )
        check_observations(summary, config)
        report["summary"] = summary
        rows = checked_search(
            runner,
            "mixed-graph",
            graph_query(config.workload()),
            **manifest(config.workload())["window"],
        )
        check_graph(rows, config)
        report["graph"] = [
            r for r in rows if r.get("relationship") == "communicates_with"
        ]
        report["flow_observations"] = expected
        report["graph_connections"] = config.pods * config.connections_per_pair
        report["graph_bytes"] = config.pods * config.records_per_pair * 300
        report["status"] = "complete"
    except Exception as exc:
        report["error"] = str(exc)[:2000]
    report["jobs"] = runner.jobs
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
