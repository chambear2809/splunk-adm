#!/usr/bin/env python3
"""Inspectable coordinator driver; retain one host lock and failures until cleanup.

Run with --apply --interactive, or import Driver into the coordinator's existing
locked command loop. No credentials are accepted as arguments. A failed phase
does not tear down the lab or mark itself complete. Explicit phase retries use
``run_phase(name, rerun=True)`` after the coordinator inspects/repairs the cause.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import configparser
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
import unittest
import urllib.parse
import urllib.request
import uuid

import qualification_shc as client
from qualification_shc_lab import Lab, OwnedContainerStopped

BUILDERS = (
    "ADM - Identity builder",
    "ADM - Service binding",
    "ADM - Interface inventory",
    "ADM - Service backends",
    "ADM - ACI policy",
)
ROLLUP = "ADM - Conversation rollup"
V2_WRITERS = ("ADM - Conversation rollup v2", "ADM - Traffic observation rollup v2")
SCOPES = (
    ("exporter", "192.0.2.101", "prod", ""),
    ("exporter", "192.0.2.102", "prod", ""),
    ("exporter", "192.0.2.103", "prod", ""),
    ("fabric", "aci-1", "prod", ""),
    ("hec_source", "http:isovalent", "prod", "demo-cluster"),
    ("cluster", "demo-cluster", "prod", "demo-cluster"),
    ("cluster", "pull-cluster", "pull", "pull-cluster"),
    ("apic", "192.0.2.50", "prod", ""),
    ("nd_host", "192.0.2.60", "prod", ""),
)


class SavedSearchDeadline(RuntimeError):
    """A transition exceeded its total wall-clock request/body budget."""


@contextmanager
def saved_search_deadline(deadline):
    """Own one Unix process timer, including body reads and JSON parsing."""
    client.require(
        threading.current_thread() is threading.main_thread(),
        "saved-search transitions require the main thread",
    )
    client.require(
        signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
        "saved-search transitions cannot share a process deadline timer",
    )
    old_handler = signal.getsignal(signal.SIGALRM)
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    client.require(
        signal.SIGALRM not in old_mask,
        "saved-search transitions require an unblocked deadline signal",
    )

    def expired(_number, _frame):
        # Api.json catches OSError/TimeoutError; this must propagate unchanged.
        raise SavedSearchDeadline("saved-search configuration deadline expired")

    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        signal.signal(signal.SIGALRM, expired)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            expired(None, None)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        yield
        if time.monotonic() >= deadline:
            expired(None, None)
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        finally:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                # Discard pending owned alarms before restoring the caller's
                # handler, including a signal queued during timer disarming.
                signal.signal(signal.SIGALRM, signal.SIG_IGN)
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            finally:
                try:
                    signal.signal(signal.SIGALRM, old_handler)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def normalized(rows):
    return sorted(
        (
            {key: value for key, value in row.items() if key != "generated_at"}
            for row in rows
        ),
        key=lambda row: client.canonical(row),
    )


def as_list(value):
    return value if isinstance(value, list) else ([] if value is None else [value])


def complete_collection_rows(api, path, limit=10000):
    """Prove a bounded ordered scan is complete despite a smaller server cap."""
    client.require(
        type(limit) is int and 1 < limit <= 10000,
        "collection snapshot limit is outside the qualified bound",
    )

    def read(skip):
        rows = api.json(
            "GET",
            path
            + "?"
            + urllib.parse.urlencode({"limit": limit, "sort": "_key:1", "skip": skip}),
        )
        client.require(
            isinstance(rows, list) and len(rows) < limit,
            "collection snapshot is malformed or reaches its bound",
        )
        keys = [row.get("_key") if isinstance(row, dict) else None for row in rows]
        client.require(
            all(isinstance(key, str) and key for key in keys)
            and keys == sorted(set(keys)),
            "collection snapshot keys are malformed, unordered or duplicated",
        )
        return rows

    for _attempt in range(2):
        rows = read(0)
        shifted = read(1)
        # A real final page shrinks by exactly one. A shorter hidden hard cap
        # instead fills the shifted page with another previously omitted row.
        if shifted == rows[1:] and read(0) == rows:
            return rows
        # One bounded retry permits ordinary replication/update convergence;
        # persistent truncation or instability can never become a snapshot.
    raise client.Refused(
        "collection snapshot is capped or unstable during completeness proof"
    )


def semantic_graph(rows, expected):
    """Assert the existing independent base-fixture node/edge/meta contract."""
    nodes = {row["id"]: row for row in rows if row.get("row_type") == "node"}
    edges = [row for row in rows if row.get("row_type") == "edge"]
    client.require(
        set(nodes) == set(expected["nodes"]), "graph node identity set differs"
    )

    def attributes(got, wanted):
        for key, value in wanted.items():
            if value is None:
                client.require(key not in got, "unexpected graph attribute")
            elif isinstance(value, list):
                client.require(
                    sorted(as_list(got.get(key))) == sorted(value),
                    "graph multivalue attribute differs",
                )
            else:
                client.require(got.get(key) == value, "graph attribute differs: " + key)

    for key, wanted in expected["nodes"].items():
        attributes(nodes[key], wanted)
    counts = {}
    for row in edges:
        client.require(
            row["source"] in nodes and row["target"] in nodes,
            "graph edge references missing node",
        )
        relationship = row["relationship"]
        counts[relationship] = counts.get(relationship, 0) + 1
    client.require(
        counts == expected["edge_counts"], "graph relationship counts differ"
    )
    for wanted in expected["edges"]:
        matches = [
            row
            for row in edges
            if all(
                row.get(key) == wanted[key]
                for key in ("relationship", "source", "target")
            )
            and (
                wanted["relationship"] != "forwards_to"
                or row.get("handoff_basis") == wanted.get("handoff_basis")
            )
        ]
        client.require(len(matches) == 1, "expected edge missing or duplicated")
        attributes(matches[0], wanted)
    meta = [row for row in rows if row.get("row_type") == "meta"]
    client.require(
        len(meta) == 1 and not meta[0].get("warnings"), "graph meta/warnings differ"
    )
    attributes(meta[0], expected["meta"])
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "sha256": client.digest(normalized(rows)),
    }


def semantic_topology(rows, expected):
    """Assert the independently specified ACI device/link inventory contract."""
    device_rows = [row for row in rows if row.get("row_type") == "device"]
    devices = {row["device_id"]: row for row in device_rows}
    links = [row for row in rows if row.get("row_type") == "link"]
    client.require(bool(devices) and bool(links), "topology inventory is empty")
    client.require(
        len(devices) == len(device_rows) and set(devices) == set(expected["devices"]),
        "topology device identity set differs or is duplicated",
    )
    for name, attributes in expected["devices"].items():
        for key, value in attributes.items():
            client.require(
                devices[name].get(key) == value,
                "topology device attribute differs: " + key,
            )
    actual_links = {
        (
            row["link_source"],
            row["a_device"],
            row.get("a_interface"),
            row["b_device"],
            None if row["link_source"] == "lldp" else row.get("b_interface"),
        )
        for row in links
    }
    wanted_links = {tuple(row) for row in expected["links"]}
    client.require(
        actual_links == wanted_links and len(links) == len(wanted_links),
        "topology links differ or are duplicated",
    )
    meta = [row for row in rows if row.get("row_type") == "meta"]
    client.require(
        len(meta) == 1 and not meta[0].get("warnings"),
        "topology metadata is incomplete or has warnings",
    )
    for key, value in expected["meta"].items():
        client.require(meta[0].get(key) == value, "topology metadata differs: " + key)
    client.require(
        int(meta[0]["devices"]) == len(devices) and int(meta[0]["links"]) == len(links),
        "topology metadata counts differ from actual inventory",
    )
    return {
        "devices": len(devices),
        "links": len(links),
        "sha256": client.digest(normalized(rows)),
    }


def semantic_v2_graph(rows, expected):
    """Positive span/owner evidence independent of cross-member agreement.

    The base fixture has no Catalyst/Meraki client history. Its same-node
    frontend-b → checkout connection has Hubble/Isovalent/span evidence and no
    NetFlow wire record, so its existing oracle remains valid under V2.
    """
    nodes = {row["id"]: row for row in rows if row.get("row_type") == "node"}
    edges = [row for row in rows if row.get("row_type") == "edge"]
    services = {
        key
        for key, value in expected["nodes"].items()
        if value.get("kind") == "service"
    }
    client.require(
        bool(edges) and services.issubset(nodes),
        "V2 graph lacks fixture service owners/evidence",
    )
    client.require(
        all(row.get("source") in nodes and row.get("target") in nodes for row in edges),
        "V2 graph edge has a missing endpoint",
    )
    client.require(
        len(nodes) == len([row for row in rows if row.get("row_type") == "node"])
        and len({row["id"] for row in edges}) == len(edges),
        "V2 graph contains duplicate identities",
    )
    meta = [row for row in rows if row.get("row_type") == "meta"]
    client.require(
        len(meta) == 1
        and str(meta[0].get("root_present")) == "1"
        and not meta[0].get("warnings"),
        "V2 graph root or coverage is incomplete",
    )
    client.require(
        meta[0].get("spans") == expected["meta"]["spans"],
        "V2 graph lost raw fixture spans",
    )
    client.require(
        int(meta[0].get("nodes", 0)) == len(nodes)
        and int(meta[0].get("edges", 0)) == len(edges),
        "V2 graph metadata counts differ from actual evidence",
    )
    labels = {value.get("label"): key for key, value in expected["nodes"].items()}
    same_node = (labels["frontend-7d9c6b5f4-q4m9z"], labels["checkout-5f8b9c7d6-m4n7q"])
    witnesses = [
        row
        for row in expected["edges"]
        if row["relationship"] == "calls"
        or (
            row["relationship"] == "communicates_with"
            and (row["source"], row["target"]) == same_node
        )
    ]
    client.require(len(witnesses) >= 2, "independent V2 evidence witnesses missing")
    for wanted in witnesses:
        matches = [
            row
            for row in edges
            if all(
                row.get(key) == wanted[key]
                for key in ("relationship", "source", "target")
            )
        ]
        client.require(
            len(matches) == 1, "V2 fixture span/owner edge is missing or duplicated"
        )
        for key, value in wanted.items():
            got = matches[0].get(key)
            if value is None:
                client.require(
                    key not in matches[0], "V2 witness gained unsupported evidence"
                )
            elif isinstance(value, list):
                client.require(
                    sorted(as_list(got)) == sorted(value),
                    "V2 witness provenance differs",
                )
            else:
                client.require(got == value, "V2 witness attribute differs: " + key)
    client.require(
        not any(row.get("relationship") == "traffic_observation" for row in edges),
        "V2 graph invented client attachment context without client history",
    )
    client.require(
        all("netflow" not in as_list(row.get("sources")) for row in edges),
        "V2 graph promoted NetFlow context into conversation evidence",
    )
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "spans": meta[0]["spans"],
        "independent_witnesses": len(witnesses),
        "sha256": client.digest(normalized(rows)),
    }


def v2_fixture_inventory(source):
    scenario = json.loads((source / "fixtures/raw-aci/scenario.json").read_text())
    fabric = scenario["fabric"]
    authority = fabric["apic"]["oob"]
    expected = {}
    for node in [*fabric["switches"], {**fabric["apic"], "role": "controller"}]:
        native = f"pod-{fabric['pod_id']}/node-{node['node_id']}"
        identity = "aci:" + client.digest(["aci_topSystem", authority, native])
        expected[identity] = {
            "name": node["name"],
            "device_authority": authority,
            "native_device_id": native,
            "role": node["role"],
            "mgmt_ip": node["oob"],
            "mapping_status": "unmapped",
        }
    for line in (
        (source / "fixtures/raw-aci/kube_objects.ndjson").read_text().splitlines()
    ):
        envelope = json.loads(line)
        if envelope["sourcetype"] != "kube:object:nodes":
            continue
        metadata = envelope["event"]["object"]["metadata"]
        cluster = envelope["fields"]["k8s.cluster.name"]
        identity = "host:" + client.digest(
            ["kubernetes_node", cluster, metadata["uid"]]
        )
        expected[identity] = {
            "name": metadata["name"],
            "native_device_id": metadata["uid"],
            "device_authority": cluster,
            "device_kind": "host",
            "cluster": cluster,
            "scope": "prod",
            "mapping_status": "mapped",
        }
    return expected


def semantic_v2_topology(rows, inventory):
    devices = [row for row in rows if row.get("row_type") == "device"]
    by_id = {row["device_id"]: row for row in devices}
    client.require(
        bool(inventory) and set(by_id) == set(inventory) and len(by_id) == len(devices),
        "V2 topology lost or duplicated source-qualified fixture identities",
    )
    for identity, wanted in inventory.items():
        row = by_id[identity]
        for key, value in wanted.items():
            client.require(
                row.get(key) == value,
                "V2 topology authority/owner attribute differs: " + key,
            )
        if identity.startswith("aci:"):
            client.require(
                row.get("scope") in (None, "") and row.get("cluster") in (None, ""),
                "V2 topology invented a cluster for unmapped APIC inventory",
            )
    client.require(
        not any(row.get("row_type") in ("link", "interface") for row in rows),
        "V2 topology invented adjacency across the fixture's unmapped ACI boundary",
    )
    meta = [row for row in rows if row.get("row_type") == "meta"]
    client.require(
        len(meta) == 1
        and int(meta[0].get("devices", 0)) == len(inventory)
        and int(meta[0].get("links", -1)) == 0,
        "V2 topology counts differ",
    )
    warnings = as_list(meta[0].get("warnings"))
    required = (
        "No retained Catalyst client history is available;",
        "Some inventory records, links, or interfaces have missing",
        "Nexus Dashboard fabric labels are not yet correlated",
    )
    allowed = (*required, "Some LLDP peers could not be matched")
    client.require(
        all(isinstance(value, str) for value in warnings)
        and all(
            any(value.startswith(prefix) for value in warnings) for prefix in required
        )
        and all(
            isinstance(value, str) and value.startswith(allowed) for value in warnings
        ),
        "V2 topology uncertainty diagnostics are missing or unexpected",
    )
    return {
        "devices": len(devices),
        "links": 0,
        "warnings": warnings,
        "sha256": client.digest(normalized(rows)),
    }


def traffic_projection(row, raw=False):
    def number(value):
        return None if value in (None, "") else float(value)

    return (
        row.get("exporter_ip") if raw else row.get("adm_scope_authority"),
        row.get("src_ip") if raw else row.get("source_ip"),
        row.get("dest_ip") if raw else row.get("destination_ip"),
        number(row.get("src_port") if raw else row.get("source_port")),
        number(row.get("dest_port") if raw else row.get("destination_port")),
        number(row.get("bytes") if raw else row.get("raw_bytes")),
        number(row.get("packets") if raw else row.get("raw_packets")),
    )


class Driver:
    ORDER = (
        "prepare",
        "create",
        "support",
        "start",
        "bootstrap",
        "bundle",
        "peers",
        "interfaces",
        "collections",
        "base",
        "graph",
        "topology",
        "v2",
        "viewer",
        "scheduler",
        "settings",
        "refusal",
        "reapply",
        "manifest",
        "cleanup",
    )

    def __init__(
        self,
        lab: Lab,
        source: Path,
        archive: Path,
        source_sha: str,
        addon_roots: list[Path],
        reference_graph: Path | None = None,
    ):
        self.lab, self.source, self.archive = (
            lab,
            Path(source).resolve(),
            Path(archive).resolve(),
        )
        self.source_sha, self.addons = source_sha, list(map(Path, addon_roots))
        self.reference = Path(reference_graph) if reference_graph else None
        self.completed, self.results = [], {}
        self.expected = json.loads(
            (self.source / "tests/splunk/expected/aci_graph.json").read_text()
        )
        self.window = tuple(
            str(self.expected["window"][key]) for key in ("earliest", "latest")
        )
        args = ", ".join(
            '"' + self.expected["args"][key] + '"'
            for key in ("service", "environment", "cluster", "namespace")
        )
        self.graph_query = "`adm_graph(" + args + ")`"
        self.expected_topology = json.loads(
            (self.source / "tests/splunk/expected/aci_topology.json").read_text()
        )
        self.topology_window = tuple(
            str(self.expected_topology["window"][key]) for key in ("earliest", "latest")
        )
        self.graph_v2_query = self.graph_query.replace(
            "`adm_graph(", "`adm_graph_v2(", 1
        )
        self.v2_inventory = v2_fixture_inventory(self.source)

    def inspect(self):
        return {
            "task": self.lab.task,
            "completed": self.completed,
            "next": next(
                (phase for phase in self.ORDER if phase not in self.completed), None
            ),
            "resources": self.lab.state.get("created", {}),
            "results": self.results,
        }

    def _record(self, name, result):
        directory = self.lab.directory / "evidence"
        if directory.is_dir():
            return client.write_evidence(
                directory, name + "-" + uuid.uuid4().hex, result
            )
        return None

    def run_phase(self, name, *, rerun=False):
        self.lab._owned()
        client.require(name in self.ORDER, "unknown phase")
        if name in self.completed and not rerun:
            return {"phase": name, "already_complete": True}
        if rerun and name in self.completed and name not in ("manifest", "cleanup"):
            index = self.ORDER.index(name)
            self.completed = [
                phase for phase in self.completed if self.ORDER.index(phase) < index
            ]
        if name not in ("cleanup", "manifest"):
            index = self.ORDER.index(name)
            client.require(
                all(phase in self.completed for phase in self.ORDER[:index]),
                "complete preceding phases before this phase",
            )
            for relative, expected_hash in self.lab.state.get(
                "test_hashes", {}
            ).items():
                client.require(
                    hashlib.sha256((self.source / relative).read_bytes()).hexdigest()
                    == expected_hash,
                    "qualification source/test file changed after snapshot",
                )
        started = time.monotonic()
        self._record(
            name + "-started",
            {"phase": name, "utc": datetime.now(timezone.utc).isoformat()},
        )
        try:
            result = getattr(self, "phase_" + name)()
        except Exception as error:
            failure = {
                "phase": name,
                "outcome": "failed",
                "error_type": type(error).__name__,
                "http_status": getattr(error, "status", None),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "utc": datetime.now(timezone.utc).isoformat(),
            }
            self.results[name] = failure
            self._record(name + "-failed", failure)
            # Preserve this process, lab, lock and prior evidence for inspection.
            raise
        outcome = {
            "phase": name,
            "outcome": "passed",
            "result": result,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "utc": datetime.now(timezone.utc).isoformat(),
        }
        self.results[name] = outcome
        if name not in self.completed:
            self.completed.append(name)
        self._record(name + "-passed", outcome)
        return outcome

    def phase_prepare(self):
        client.require(bool(self.addons), "explicit reviewed add-on roots are required")
        self.lab.prepare(self.source, self.archive, source_sha=self.source_sha)
        self.lab.state["test_hashes"]["tools/qualification_shc_run.py"] = (
            hashlib.sha256(
                (self.source / "tools/qualification_shc_run.py").read_bytes()
            ).hexdigest()
        )
        self.lab.state["test_hashes"]["tools/cisco_contract_migration.py"] = (
            hashlib.sha256(
                (self.source / "tools/cisco_contract_migration.py").read_bytes()
            ).hexdigest()
        )
        for relative in (
            "tests/splunk/expected/aci_graph.json",
            "tests/splunk/expected/aci_topology.json",
            "research/cisco-pipeline-interface.json",
            "fixtures/raw-aci/scenario.json",
            "fixtures/raw-aci/kube_objects.ndjson",
            "fixtures/raw-aci/stream_netflow.ndjson",
        ):
            self.lab.state["test_hashes"][relative] = hashlib.sha256(
                (self.source / relative).read_bytes()
            ).hexdigest()
        self.lab.save()
        return {
            "archive_sha256": self.lab.state["archive_sha256"],
            "source_sha": self.source_sha,
            "test_hashes": self.lab.state["test_hashes"],
        }

    def phase_create(self):
        self.lab.create()
        return {role: item["id"] for role, item in self.lab.state["created"].items()}

    def phase_support(self):
        self.lab.install_support(self.source, self.addons)
        self.lab.install_candidate()
        return {"support_files": self.lab.state["support_files"]}

    def _wait(self, check, timeout=1200, running_roles=()):
        last = {}

        def attempt():
            if running_roles:
                statuses = [self.lab.container_status(role) for role in running_roles]
                if any(value["status"] in ("exited", "dead") for value in statuses):
                    self._record("startup-stopped", {"containers": statuses})
                    raise OwnedContainerStopped(
                        "an ID/name/label-verified startup container stopped"
                    )
            try:
                return check()
            except (client.Refused, client.ApiError, KeyError) as error:
                last.update(
                    {
                        "error_type": type(error).__name__,
                        "http_status": getattr(error, "status", None),
                    }
                )
                if isinstance(error, client.Refused):
                    # Fixed reviewed descriptions, never server response bodies.
                    last["reason"] = str(error)
                return False

        try:
            return client.wait_for(attempt, timeout=timeout, interval=5)
        except OwnedContainerStopped:
            raise
        except client.Refused:
            self._record(
                "convergence-deadline",
                {"last_condition": last, "timeout_seconds": timeout},
            )
            raise

    def phase_start(self):
        for role in client.ROLES:
            self.lab.start(role)
        client.configure(self.lab.directory / "state.json")

        def ready():
            for role in client.ROLES:
                value = client.Api(role).json("GET", "/services/server/info")["entry"][
                    0
                ]["content"]
                client.require(
                    value.get("serverName") == self.lab.state["created"][role]["name"]
                    and value.get("version") == "10.6.0.5",
                    "instance identity mismatch",
                )
            return True

        self._wait(ready, running_roles=client.ROLES)
        return {"all_management_tls_and_identity": "passed"}

    def phase_bootstrap(self):
        self.lab.bootstrap()
        return self._wait(client.verify_shc_ready)

    def phase_bundle(self):
        self.lab.apply_bundle()
        self._wait(client.verify_shc_ready)
        return self.lab.verify_candidate()

    def phase_peers(self):
        client.add_remote_peer()
        return self._wait(client.verify_instances)

    def _ingest(self, paths):
        api = client.Api("idx")
        token = client.protected_file(self.lab.directory / "hec.secret").read_text()
        mgmt = urllib.parse.urlsplit(api.url)
        endpoint = f"https://{mgmt.hostname}:{mgmt.port - 1}/services/collector/event"
        count, hashes = 0, {}
        for path in map(Path, paths):
            data = path.read_bytes()
            hashes[str(path.relative_to(self.source))] = hashlib.sha256(
                data
            ).hexdigest()
            lines = [line for line in data.splitlines() if line.strip()]
            for line in lines:
                json.loads(line)
            client.require(
                len(data) <= 5 * 1024 * 1024, "fixture exceeds bounded HEC batch"
            )
            request = urllib.request.Request(
                endpoint,
                data=b"\n".join(lines),
                method="POST",
                headers={
                    "Authorization": "Splunk " + token,
                    "Content-Type": "application/json",
                },
            )
            try:
                with api.opener.open(request, timeout=30) as response:
                    value = json.loads(response.read())
            except Exception:
                raise client.Refused("verified fixture ingestion failed") from None
            client.require(value.get("code") == 0, "HEC rejected fixture")
            count += len(lines)
        return {"events": count, "fixture_hashes": hashes}

    def phase_interfaces(self):
        if "interface_ingestion" not in self.lab.state:
            self.slice_start = int(time.time()) - 1
            self.lab.state["fixture_index_earliest"] = self.slice_start
            # Mark before POST: a lost HEC response is an inspectable uncertainty,
            # never an automatic duplicate ingestion on phase retry.
            self.lab.state["interface_ingestion"] = {"state": "started"}
            self.lab.save()
            loaded = self._ingest(
                [self.source / "fixtures/raw-aci/stream_netflow.ndjson"]
            )
            self.lab.state["interface_ingestion"] = {"state": "acknowledged", **loaded}
            self.lab.save()
        loaded = self.lab.state["interface_ingestion"]
        client.require(
            loaded.get("state") == "acknowledged",
            "interface ingestion is uncertain; inspect indexed data before retry",
        )
        self._wait(
            lambda: (
                int(
                    client.Api("sh1").search(
                        'search index=netflow sourcetype="stream:netflow" | stats count',
                        *self.window,
                    )[0][0]["count"]
                )
                == loaded["events"]
            ),
            timeout=180,
        )
        path = self.source / "tests/splunk/test_distributed_interfaces.py"
        spec = importlib.util.spec_from_file_location(
            "final_distributed_interfaces", path
        )
        module = importlib.util.module_from_spec(spec)
        with __import__("unittest.mock", fromlist=["patch"]).patch.dict(
            os.environ,
            {
                "ADM_SHC_QUALIFICATION": "1",
                "ADM_SHC_CLIENT_MODULE": "qualification_shc",
                "ADM_SHC_STATE": str(self.lab.directory / "state.json"),
                "ADM_SHC_EARLIEST": self.window[0],
                "ADM_SHC_LATEST": self.window[1],
            },
        ):
            spec.loader.exec_module(module)
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            output = io.StringIO()
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        # Do not persist traceback text, which can include server details.
        summary = {
            "run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
            "failed_test_ids": [test.id() for test, _trace in result.failures],
            "error_test_ids": [test.id() for test, _trace in result.errors],
            "jobs": getattr(module.DistributedInterfacesTest, "jobs", []),
            **loaded,
        }
        self._record("original-interface-tests", summary)
        client.require(
            result.testsRun == 2 and result.wasSuccessful() and not result.skipped,
            "the two original distributed interface regressions did not pass",
        )
        return summary

    def phase_collections(self):
        definitions = configparser.RawConfigParser()
        definitions.read(
            self.lab.directory / "stage/splunk_adm/default/collections.conf"
        )
        return client.collection_convergence(definitions.sections())

    @staticmethod
    def _saved_flags(content):
        client.require(
            isinstance(content, dict), "saved-search configuration is malformed"
        )
        result = {}
        for key in ("disabled", "is_scheduled"):
            value = content.get(key)
            client.require(
                type(value) is bool
                or (type(value) is int and value in (0, 1))
                or value in ("0", "1"),
                "saved-search configuration flags are malformed",
            )
            result[key] = value in (True, 1, "1")
        return result

    def _set_saved_flags(self, role, name, *, disabled, is_scheduled, timeout=120):
        client.require(
            0 < timeout <= 120,
            "saved-search configuration deadline is outside its bound",
        )
        deadline = time.monotonic() + timeout
        desired = {"disabled": disabled, "is_scheduled": is_scheduled}
        client.require(
            all(type(value) is bool for value in desired.values()),
            "saved-search target flags must be boolean",
        )
        path = client.APP + "/saved/searches/" + urllib.parse.quote(name, safe="")
        evidence = {
            "role": role,
            "name": name,
            "desired": desired,
            "members": {},
            "converged": False,
        }

        def agrees():
            for member in client.MEMBERS:
                remaining = deadline - time.monotonic()
                client.require(
                    remaining > 0, "saved-search configuration deadline expired"
                )
                content = client.Api(member).json(
                    "GET", path, timeout=min(30, remaining)
                )["entry"][0]["content"]
                if time.monotonic() >= deadline:
                    raise SavedSearchDeadline(
                        "saved-search configuration deadline expired"
                    )
                evidence["members"][member] = self._saved_flags(content)
            return all(value == desired for value in evidence["members"].values())

        try:
            with saved_search_deadline(deadline):
                client.Api(role).json(
                    "POST",
                    path,
                    data={key: str(int(value)) for key, value in desired.items()},
                    timeout=min(30, timeout),
                )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SavedSearchDeadline(
                        "saved-search configuration deadline expired"
                    )
                self._wait(agrees, timeout=remaining)
            evidence["converged"] = True
            return evidence
        finally:
            self._record("saved-search-config", evidence)

    def _saved(self, role, name, *, index_window=None, earliest="0", latest="now"):
        api = client.Api(role)
        path = client.APP + "/saved/searches/" + urllib.parse.quote(name, safe="")
        data = {
            "trigger_actions": "1",
            "dispatch.earliest_time": earliest,
            "dispatch.latest_time": latest,
        }
        if index_window:
            data.update(
                {
                    "dispatch.index_earliest": str(index_window[0]),
                    "dispatch.index_latest": str(index_window[1]),
                }
            )
        dispatches = self.lab.state.setdefault("builder_dispatch", {})
        signature = client.digest({"role": role, "name": name, "dispatch": data})
        if name in dispatches:
            record = dispatches[name]
            client.require(
                record.get("signature") == signature and record.get("sid"),
                "builder dispatch is uncertain or arguments changed; inspect before retry",
            )
            return self._job(api, record["sid"])
        config = self._set_saved_flags(role, name, disabled=False, is_scheduled=False)
        record = {
            "role": role,
            "name": name,
            "signature": signature,
            "state": "dispatching",
            "config": config,
        }
        dispatches[name] = record
        self.lab.save()
        self._record("saved-search-predispatch", record)
        sid = api.json("POST", path + "/dispatch", data=data)["sid"]
        client.require(
            isinstance(sid, str) and bool(sid), "builder dispatch returned no valid SID"
        )
        record.update({"sid": sid, "state": "dispatched"})
        self.lab.save()
        self._record("saved-search-dispatched", record)
        return self._job(api, sid)

    def _job(self, api, sid, timeout=600):
        path = "/services/search/v2/jobs/" + urllib.parse.quote(sid, safe="")

        def done():
            value = api.json("GET", path)["entry"][0]["content"]
            client.reject_messages(value.get("messages", []))
            client.require(
                value.get("dispatchState") != "FAILED", "builder search failed"
            )
            return value if value.get("isDone") in (True, 1, "1") else False

        job = self._wait(done, timeout=timeout)
        value = api.json("GET", path + "/results?count=0")
        client.reject_messages(value.get("messages", []))
        return value.get("results", []), {
            "sid": sid,
            "dispatchState": job.get("dispatchState"),
            "resultCount": job.get("resultCount"),
        }

    def phase_base(self):
        paths = sorted(
            path
            for path in (self.source / "fixtures/raw-aci").glob("*.ndjson")
            if path.name != "stream_netflow.ndjson"
        )
        if "base_ingestion" not in self.lab.state:
            self.lab.state["base_ingestion"] = {"state": "started"}
            self.lab.save()
            loaded = self._ingest(paths)
            self.lab.state["base_ingestion"] = {"state": "acknowledged", **loaded}
            self.lab.save()
        loaded = self.lab.state["base_ingestion"]
        client.require(
            loaded.get("state") == "acknowledged",
            "base ingestion is uncertain; inspect indexed data before retry",
        )
        expected_counts = {}
        for path in (self.source / "fixtures/raw-aci").glob("*.ndjson"):
            for line in path.read_text().splitlines():
                if line.strip():
                    index = json.loads(line)["index"]
                    expected_counts[index] = expected_counts.get(index, 0) + 1
        raw_query = (
            "search ("
            + " OR ".join("index=" + name for name in sorted(expected_counts))
            + ")"
        )

        def indexed():
            rows, job = client.Api("sh1").search(
                raw_query + " | stats count by index sourcetype", "0", "now"
            )
            observed = {}
            for row in rows:
                observed[row["index"]] = observed.get(row["index"], 0) + int(
                    row["count"]
                )
            return {"rows": rows, "job": job} if observed == expected_counts else False

        classification = self._wait(indexed, timeout=180)
        csv = "observer_kind,observer,scope,cluster\n" + "\n".join(
            ",".join(row) for row in SCOPES
        )
        client.Api("sh1").search(
            '| makeresults format=csv data="' + csv + '" '
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            "_key=sha256(json_array(observer_kind, observer)) "
            "| fields _key observer_kind observer scope cluster | outputlookup adm_observer_scope"
        )
        self._wait(
            lambda: all(
                len(
                    client.Api(role).json(
                        "GET",
                        client.APP
                        + "/storage/collections/data/adm_observer_scope?limit=100",
                    )
                )
                == len(SCOPES)
                for role in client.MEMBERS
            ),
            timeout=120,
        )
        if "base_index_window" not in self.lab.state:
            self.lab.state["base_index_window"] = [
                self.lab.state["fixture_index_earliest"],
                int(time.time()) + 1,
            ]
            self.lab.state["fixture_index_latest"] = self.lab.state[
                "base_index_window"
            ][1]
            # Freeze the receipt slice before any builder SID can be recorded.
            self.lab.save()
        index_window = self.lab.state["base_index_window"]
        client.require(
            isinstance(index_window, list)
            and len(index_window) == 2
            and all(type(value) is int for value in index_window)
            and index_window[0] == self.lab.state["fixture_index_earliest"]
            and index_window[0] < index_window[1]
            and index_window[1] == self.lab.state["fixture_index_latest"],
            "base builder receipt window is malformed or changed",
        )
        index_window = tuple(index_window)
        self.slice_end = index_window[1]
        time.sleep(2)
        jobs = {}
        for i, name in enumerate((*BUILDERS, ROLLUP)):
            _, jobs[name] = self._saved(
                client.MEMBERS[i % 3], name, index_window=index_window
            )
            if name != ROLLUP:
                self._wait(self.collection_snapshot, timeout=120)
        self._wait(
            lambda: bool(
                client.Api("sh1").search(
                    'search index=adm_summary source="adm:conversation" | head 1',
                    *self.window,
                )[0]
            ),
            timeout=180,
        )
        return {
            **loaded,
            "index_window": index_window,
            "jobs": jobs,
            "raw_classification": classification,
        }

    def collection_snapshot(self):
        definitions = configparser.RawConfigParser()
        definitions.read(
            self.lab.directory / "stage/splunk_adm/default/collections.conf"
        )
        result = {}
        for name in definitions.sections():
            hashes = []
            for role in client.MEMBERS:
                rows = complete_collection_rows(
                    client.Api(role), client.APP + "/storage/collections/data/" + name
                )
                hashes.append(
                    {
                        "rows": len(rows),
                        "sha256": client.digest(
                            sorted(rows, key=lambda row: client.canonical(row))
                        ),
                    }
                )
            if not all(value == hashes[0] for value in hashes):
                return False
            result[name] = hashes[0]
        return result

    def _graphs(self, account="admin"):
        result, canonical_rows = {}, None
        for role in client.MEMBERS:
            rows, job = client.Api(role, account).search(self.graph_query, *self.window)
            result[role] = {**semantic_graph(rows, self.expected), "job": job}
            if canonical_rows is None:
                canonical_rows = normalized(rows)
            client.require(
                normalized(rows) == canonical_rows, "member graph rows differ"
            )
        return result, canonical_rows

    def phase_graph(self):
        result, rows = self._graphs()
        self.graph_rows = rows
        self._record(
            "exact-graph-rows",
            {"archive_sha256": self.lab.state["archive_sha256"], "rows": rows},
        )
        if self.reference:
            reference = json.loads(self.reference.read_text())
            client.require(
                reference.get("archive_sha256") == self.lab.state["archive_sha256"],
                "standalone oracle belongs to another archive",
            )
            client.require(
                normalized(reference["rows"]) == rows,
                "SHC graph differs from exact standalone oracle",
            )
            result["standalone_oracle_sha256"] = hashlib.sha256(
                self.reference.read_bytes()
            ).hexdigest()
        else:
            result["standalone_oracle"] = (
                "not supplied; semantic and all-member equality only"
            )
        return result

    def _topologies(self, account="admin"):
        result, canonical_rows = {}, None
        for role in client.MEMBERS:
            # adm_topology expands to an index-based search, never a leading pipe.
            rows, job = client.Api(role, account).search(
                "`adm_topology`", *self.topology_window
            )
            self._record(
                "topology-rows-" + role + "-" + account,
                {
                    "archive_sha256": self.lab.state["archive_sha256"],
                    "member": role,
                    "account": account,
                    "window": self.topology_window,
                    "job": job,
                    "rows": rows,
                },
            )
            result[role] = {
                **semantic_topology(rows, self.expected_topology),
                "job": job,
            }
            if canonical_rows is None:
                canonical_rows = normalized(rows)
            client.require(
                normalized(rows) == canonical_rows,
                "member topology semantic rows differ",
            )
        return result, canonical_rows

    def phase_topology(self):
        result, self.topology_rows = self._topologies()
        return {
            "members": result,
            "window": self.topology_window,
            "comparison": "all row fields equal except generated_at",
            "expected_fixture": "tests/splunk/expected/aci_topology.json",
        }

    def public_selectors(self):
        interface = json.loads(
            (self.source / "research/cisco-pipeline-interface.json").read_text()
        )
        result = {}
        for role in client.MEMBERS:
            values = {}
            for selector in interface["activation"]["cutover_selectors"]:
                value = client.Api(role).json("GET", selector["rest_target"])["entry"][
                    0
                ]["content"]
                values[selector["name"]] = value[selector["field"]]
            client.require(
                values.get("adm_data_contract_version", "").strip() == "1",
                "staged SHC qualification must retain the V1 public contract",
            )
            result[role] = values
        client.require(
            all(value == result["sh1"] for value in result.values()),
            "public selectors disagree across members",
        )
        return result

    def _v2_seed(self):
        cluster = self.expected["args"]["cluster"]
        raw = [
            json.loads(line)
            for line in (self.source / "fixtures/raw-aci/stream_netflow.ndjson")
            .read_text()
            .splitlines()
        ]
        exporters = sorted({str(row["event"]["exporter_ip"]) for row in raw})
        profiles = []
        for exporter in exporters:
            mapping = client.digest(
                ["stream_ipfix", exporter, "exporter", "0", "", "", ""]
            )
            row = {
                "mapping_key": mapping,
                "source": "stream_ipfix",
                "source_authority": exporter,
                "domain_kind": "exporter",
                "observation_domain_present": "0",
                "observation_domain_id": "",
                "vpn_id": "",
                "routing_domain": "",
                "scope": "prod",
                "cluster": cluster,
                "mapping_status": "mapped",
                "profile": "standard_netflow",
                "duplicate_count": 1,
            }
            row["_key"] = client.digest(
                [mapping, row["scope"], cluster, row["profile"], "mapped"]
            )
            profiles.append(row)
        settings = {
            "_key": client.digest([self.lab.task, "cilium", cluster]),
            "cluster": cluster,
            "mapping_status": "mapped",
            "lb_mode": "snat",
            "ingress_mode": "dedicated",
            "l2announcements_enabled": 0,
        }
        for name, wanted in (
            ("adm_network_source_scope", profiles),
            ("adm_cilium_cluster_settings", [settings]),
        ):
            path = client.APP + "/storage/collections/data/" + name
            existing = complete_collection_rows(client.Api("sh1"), path)
            permitted = {row["_key"] for row in wanted}
            for row in existing:
                overlaps = (
                    row.get("mapping_key")
                    in {item.get("mapping_key") for item in wanted}
                    if name == "adm_network_source_scope"
                    else row.get("cluster") == cluster
                )
                client.require(
                    not overlaps or row["_key"] in permitted,
                    "V2 fixture seed overlaps an existing mapping",
                )
            for row in wanted:
                present = next(
                    (item for item in existing if item["_key"] == row["_key"]), None
                )
                if present is None:
                    # Exact-key insert retries can recover after a lost response;
                    # keyed updates and replacement of existing evidence are forbidden.
                    try:
                        client.Api("sh1").json("POST", path, raw=client.canonical(row))
                    except client.ApiError as error:
                        if error.status != 409:
                            raise
                    present = client.Api("sh1").json("GET", path + "/" + row["_key"])
                client.require(
                    all(present.get(key) == value for key, value in row.items()),
                    "V2 fixture seed differs from existing source evidence",
                )
        self._wait(self.collection_snapshot, timeout=180)
        self.v2_exporters, self.v2_traffic_count = exporters, len(raw)
        self.v2_raw_fingerprints = Counter(
            traffic_projection(row["event"], raw=True) for row in raw
        )
        return {
            "exporters": exporters,
            "profile": "standard_netflow",
            "expected_traffic_records": len(raw),
            "cluster_settings": settings,
            "observer_scope_preserved": True,
        }

    def _staged_v2_writer(self, role, name):
        api = client.Api(role)
        path = client.APP + "/saved/searches/" + urllib.parse.quote(name, safe="")
        records = self.lab.state.setdefault("v2_writer_dispatch", {})
        if name in records:
            record = records[name]
            client.require(
                isinstance(record, dict)
                and record.get("role") == role
                and isinstance(record.get("sid"), str)
                and bool(record["sid"]),
                "V2 writer dispatch outcome is uncertain; inspect before retry",
            )
            original_flags = self._saved_flags(
                {
                    "disabled": record.get("original_disabled"),
                    "is_scheduled": record.get("original_scheduled"),
                }
            )
        else:
            original = api.json("GET", path)["entry"][0]["content"]
            original_flags = self._saved_flags(original)
            record = {
                "state": "preparing",
                "role": role,
                "original_disabled": original_flags["disabled"],
                "original_scheduled": original_flags["is_scheduled"],
            }
            records[name] = record
            self.lab.save()
        client.require(
            original_flags["disabled"], "staged V2 writer must begin disabled"
        )
        try:
            if "sid" not in record:
                self._set_saved_flags(role, name, disabled=False, is_scheduled=False)
                record["state"] = "dispatching"
                self.lab.save()
                sid = api.json(
                    "POST",
                    path + "/dispatch",
                    data={
                        "trigger_actions": "1",
                        "dispatch.earliest_time": "0",
                        "dispatch.latest_time": "now",
                        "dispatch.index_earliest": str(
                            self.lab.state["fixture_index_earliest"]
                        ),
                        "dispatch.index_latest": str(
                            self.lab.state["fixture_index_latest"]
                        ),
                    },
                )["sid"]
                client.require(
                    isinstance(sid, str) and bool(sid),
                    "V2 writer dispatch returned no valid SID",
                )
                record.update({"sid": sid, "state": "dispatched"})
                self.lab.save()
                self._record(
                    "saved-search-dispatched", {"role": role, "name": name, "sid": sid}
                )
            evidence = self._job(api, record["sid"])[1]
        finally:
            self._set_saved_flags(role, name, **original_flags)
        record["state"] = "completed"
        self.lab.save()
        return evidence

    def _v2_summaries(self, role, account):
        query = (
            'search index=adm_summary_v2 (source="adm:conversation" OR source="adm:traffic_observation") '
            "| table source contract_version rollup_id flow_source records counter_semantics metrics_authoritative "
            "scope cluster source_ip destination_ip source_port destination_port raw_bytes raw_packets "
            "bytes bytes_c2s bytes_s2c packets "
            "adm_scope_source adm_scope_authority adm_scope_domain_kind "
            "adm_scope_observation_domain_present adm_scope_observation_domain_id adm_scope_vpn_id "
            "adm_scope_routing_domain adm_profile_status adm_registered_profiles traffic_observations"
        )
        rows, job = client.Api(role, account).search(query, *self.window)
        conversations = [row for row in rows if row.get("source") == "adm:conversation"]
        traffic = [
            row for row in rows if row.get("source") == "adm:traffic_observation"
        ]
        client.require(
            bool(conversations) and len(traffic) == self.v2_traffic_count,
            "V2 staged summaries are missing or duplicated",
        )
        client.require(
            all(
                str(row.get("contract_version")) == "2" and row.get("rollup_id")
                for row in rows
            ),
            "V2 staged summaries have invalid contract/replay identities",
        )
        client.require(
            len({row["rollup_id"] for row in rows}) == len(rows),
            "V2 staged summary replay identities are duplicated",
        )
        client.require(
            all(row.get("flow_source") != "netflow" for row in conversations),
            "NetFlow records entered authoritative V2 conversations",
        )
        client.require(
            Counter(traffic_projection(row) for row in traffic)
            == self.v2_raw_fingerprints,
            "V2 traffic changed source tuples or raw counters",
        )
        for row in traffic:
            client.require(
                row.get("counter_semantics") == "unknown"
                and str(row.get("metrics_authoritative")) == "0"
                and str(row.get("records")) == "1"
                and all(
                    row.get(key) in (None, "")
                    for key in ("bytes", "bytes_c2s", "bytes_s2c", "packets")
                )
                and row.get("adm_scope_source") == "stream_ipfix"
                and row.get("adm_scope_authority") in self.v2_exporters
                and row.get("adm_scope_domain_kind") == "exporter"
                and str(row.get("adm_scope_observation_domain_present")) == "0"
                and all(
                    row.get(key) in (None, "")
                    for key in (
                        "adm_scope_observation_domain_id",
                        "adm_scope_vpn_id",
                        "adm_scope_routing_domain",
                    )
                )
                and row.get("adm_profile_status") == "mapped"
                and row.get("scope") == "prod"
                and row.get("cluster") == self.expected["args"]["cluster"],
                "V2 traffic lost exact profile/authority or non-authoritative semantics",
            )
            payload = json.loads(row["traffic_observations"])
            client.require(
                isinstance(payload, list) and len(payload) == 1,
                "V2 traffic envelope is incomplete",
            )
            observation = payload[0]
            client.require(
                observation.get("counter_semantics") == "unknown"
                and str(observation.get("metrics_authoritative")) == "0"
                and int(observation.get("records", 0)) == 1
                and observation.get("profile") == "standard_netflow"
                and observation.get("source") == "stream_ipfix"
                and observation.get("scope") == "prod"
                and observation.get("cluster") == self.expected["args"]["cluster"]
                and str(observation.get("observation_domain_present")) == "0"
                and all(
                    observation.get(key) in (None, "")
                    for key in ("observation_domain_id", "vpn_id", "routing_domain")
                )
                and observation.get("source_authority") == row["adm_scope_authority"],
                "V2 stored traffic provenance differs from raw-source contract",
            )
        return {
            "conversation_rows": len(conversations),
            "traffic_rows": len(traffic),
            "sha256": client.digest(normalized(rows)),
            "job": job,
        }, normalized(rows)

    def _v2_views(self, account="admin"):
        result, reference = {}, None
        for role in client.MEMBERS:
            summary, summary_rows = self._v2_summaries(role, account)
            graph, graph_job = client.Api(role, account).search(
                self.graph_v2_query, *self.window
            )
            topology, topology_job = client.Api(role, account).search(
                "`adm_topology_v2`", *self.topology_window
            )
            self._record(
                "v2-rows-" + role + "-" + account,
                {
                    "member": role,
                    "account": account,
                    "archive_sha256": self.lab.state["archive_sha256"],
                    "graph": graph,
                    "topology": topology,
                    "graph_job": graph_job,
                    "topology_job": topology_job,
                    "graph_window": self.window,
                    "topology_window": self.topology_window,
                    "summary": summary,
                    "summary_rows": summary_rows,
                },
            )
            result[role] = {
                "summaries": summary,
                "graph": {**semantic_v2_graph(graph, self.expected), "job": graph_job},
                "topology": {
                    **semantic_v2_topology(topology, self.v2_inventory),
                    "job": topology_job,
                },
            }
            current = {
                "summaries": summary_rows,
                "graph": normalized(graph),
                "topology": normalized(topology),
            }
            if reference is None:
                reference = current
            client.require(current == reference, "V2 staged member/viewer rows differ")
        return result, reference

    def phase_v2(self):
        before = self.public_selectors()
        scope_path = client.APP + "/storage/collections/data/adm_observer_scope"
        observer_scope = complete_collection_rows(client.Api("sh1"), scope_path)
        seed = self._v2_seed()
        jobs = {
            name: self._staged_v2_writer(client.MEMBERS[i + 1], name)
            for i, name in enumerate(V2_WRITERS)
        }
        self._wait(
            lambda: all(
                client.Api(role)
                .json(
                    "GET",
                    client.APP + "/saved/searches/" + urllib.parse.quote(name, safe=""),
                )["entry"][0]["content"]
                .get("disabled")
                in (True, 1, "1")
                for role in client.MEMBERS
                for name in V2_WRITERS
            ),
            timeout=120,
        )
        views, self.v2_rows = self._wait(self._v2_views, timeout=300)
        self.public_selector_rows = before
        client.require(
            self.public_selectors() == before, "V2 staging changed V1 public selectors"
        )
        client.require(
            complete_collection_rows(client.Api("sh1"), scope_path) == observer_scope,
            "V2 staging changed original observer-scope evidence",
        )
        _, graph = self._graphs()
        _, topology = self._topologies()
        client.require(
            graph == self.graph_rows and topology == self.topology_rows,
            "V2 staging changed V1 graph/topology behavior",
        )
        self._record(
            "v1-selector-preservation",
            {"before": before, "after": self.public_selectors()},
        )
        reference_status = (
            "not supplied; independent fixture invariants and all-member parity only"
        )
        if self.reference:
            reference = json.loads(self.reference.read_text())
            keys = ("v2_graph_rows", "v2_topology_rows")
            client.require(
                all(key in reference for key in keys)
                or not any(key in reference for key in keys),
                "V2 standalone reference is partial",
            )
            if all(key in reference for key in keys):
                client.require(
                    reference.get("archive_sha256") == self.lab.state["archive_sha256"]
                    and normalized(reference[keys[0]]) == self.v2_rows["graph"]
                    and normalized(reference[keys[1]]) == self.v2_rows["topology"],
                    "V2 staged reads differ from exact standalone reference",
                )
                reference_status = (
                    "exact same-archive standalone V2 graph/topology match"
                )
        return {
            "seed": seed,
            "writer_jobs": jobs,
            "members": views,
            "v1_public_selectors_unchanged": True,
            "v1_graph_topology_unchanged": True,
            "original_observer_scope_sha256": client.digest(observer_scope),
            "standalone_v2_reference": reference_status,
            "boundary": "explicit staged V2 queries; no SHC cutover/rollback/failover qualification",
        }

    def phase_viewer(self):
        api = client.Api("sh1")
        role_name = self.lab.task + "-viewer"
        allowed = [
            "netflow",
            "cisco_dc",
            "cisco_secure_fw",
            "cisco_isovalent",
            "k8s",
            "otel_traces",
            "cilium_hubble",
            "adm_summary",
            "adm_summary_v2",
            "adm",
            "cisco_catalyst",
            "cisco_meraki",
        ]
        api.json(
            "POST",
            "/services/authorization/roles",
            data={
                "name": role_name,
                "capabilities": "search",
                "srchIndexesAllowed": allowed,
                "srchIndexesDisallowed": ["_internal", "_audit"],
            },
        )
        api.json(
            "POST",
            "/services/authorization/roles/" + role_name,
            data={"capabilities": "search"},
        )
        viewer = json.loads(
            client.protected_file(self.lab.directory / "viewer.json").read_text()
        )
        api.json(
            "POST",
            "/services/authentication/users",
            data={
                "name": viewer["username"],
                "password": viewer["password"],
                "roles": role_name,
            },
        )
        graphs, rows = self._wait(lambda: self._graphs("viewer"), timeout=180)
        client.require(
            rows == self.graph_rows, "viewer graph differs from administrator"
        )
        topologies, topology_rows = self._wait(
            lambda: self._topologies("viewer"), timeout=180
        )
        client.require(
            topology_rows == self.topology_rows,
            "viewer topology differs from administrator",
        )
        v2_views, v2_rows = self._wait(lambda: self._v2_views("viewer"), timeout=300)
        client.require(
            v2_rows == self.v2_rows,
            "least-privileged V2 staged reads differ from administrator",
        )
        acl = client.restricted_acl(
            ["adm_recovery_state", "adm_recovery_audit"], BUILDERS + (ROLLUP,)
        )
        writes = {}
        for role in client.MEMBERS:
            key = "adm-shc-viewer-" + uuid.uuid4().hex
            path = client.APP + "/storage/collections/data/adm_observer_scope"
            writes[role] = client.assert_denied(
                client.Api(role, "viewer"),
                "POST",
                path,
                raw=client.canonical({"_key": key, "observer": "denied"}),
            )
        return {
            "graphs": graphs,
            "topologies": topologies,
            "v2_staged_reads": v2_views,
            "acl": acl,
            "stored_writes": writes,
        }

    def phase_scheduler(self):
        api = client.Api("sh1")
        path = client.APP + "/saved/searches/" + urllib.parse.quote(ROLLUP, safe="")
        original = api.json("GET", path)["entry"][0]["content"]
        client.require(
            original.get("cron_schedule") == "*/5 * * * *",
            "shipped scheduler cron differs",
        )
        if "scheduler_original_flags" not in self.lab.state:
            client.require(
                "scheduler_probe" not in self.lab.state,
                "scheduler original flags are missing; inspect before retry",
            )
            self.lab.state["scheduler_original_flags"] = self._saved_flags(original)
            self.lab.save()
        original_flags = self._saved_flags(self.lab.state["scheduler_original_flags"])
        now = time.time()
        marker = "adm-shc-scheduled-" + uuid.uuid4().hex
        event = json.loads(
            (self.source / "fixtures/raw-aci/stream_netflow.ndjson")
            .read_text()
            .splitlines()[0]
        )
        event.update(
            {
                "time": now,
                "index": "netflow",
                "source": marker,
                "sourcetype": "stream:netflow",
                "host": "qualification-current",
            }
        )
        event["event"].update(
            {
                "timestamp": datetime.fromtimestamp(now, timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "endtime": datetime.fromtimestamp(now + 0.1, timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "src_ip": "198.51.100.240",
                "dest_ip": "198.51.100.241",
                "src_port": 52400,
                "dest_port": 443,
                "protoid": 6,
                "bytes": 900,
                "packets": 1,
                "input_snmpidx": 436248576,
            }
        )
        if "scheduler_probe" not in self.lab.state:
            self.lab.state["scheduler_probe"] = {"state": "prepared", "event": event}
            self.lab.save()
        probe = self.lab.state["scheduler_probe"]
        client.require(
            isinstance(probe, dict)
            and probe.get("state") in ("prepared", "acknowledged")
            and isinstance(probe.get("event"), dict),
            "scheduler probe ingestion is uncertain; inspect before retry",
        )
        event = probe["event"]
        now, marker = event["time"], event["source"]
        self._record(
            "current-scheduler-fixture",
            {
                "fixture": event,
                "derived_from": "fixtures/raw-aci/stream_netflow.ndjson:first-row",
            },
        )
        # Private generated fixture lives outside source; _ingest expects a source
        # relative path for provenance, so use a direct equivalent HEC request.
        idx = client.Api("idx")
        endpoint = urllib.parse.urlsplit(idx.url)
        token = client.protected_file(self.lab.directory / "hec.secret").read_text()
        request = urllib.request.Request(
            f"https://{endpoint.hostname}:{endpoint.port - 1}/services/collector/event",
            data=client.canonical(event),
            method="POST",
            headers={"Authorization": "Splunk " + token},
        )
        if probe["state"] == "prepared":
            probe["state"] = "ingesting"
            self.lab.save()
            try:
                with idx.opener.open(request, timeout=30) as response:
                    client.require(
                        json.loads(response.read()).get("code") == 0,
                        "current fixture rejected",
                    )
            except Exception:
                raise client.Refused(
                    "verified current fixture ingestion failed"
                ) from None
            probe["state"] = "acknowledged"
            self.lab.save()
        try:
            self._set_saved_flags("sh1", ROLLUP, disabled=False, is_scheduled=True)

            def probe_indexed():
                rows, job = api.search(
                    'search index=netflow source="' + marker + '" '
                    '| eval expected=sha256("v1|".sha256(json_object("index", index, "bucket", _bkt, "event", _cd))) '
                    "| table _indextime expected",
                    str(int(now) - 1),
                    str(int(now) + 60),
                )
                return (rows, job) if len(rows) == 1 else False

            raw, raw_job = self._wait(probe_indexed, timeout=120)
            client.require(len(raw) == 1, "current probe index-time evidence missing")
            indexed = int(raw[0]["_indextime"])
            slot = (indexed // 300) * 300 + 600
            absent, absent_job = api.search(
                'search index=adm_summary source="adm:conversation" '
                '| where rollup_id="' + raw[0]["expected"] + '" | head 1',
                str(int(now) - 300),
                str(int(now) + 900),
            )
            client.require(
                not absent and time.time() < slot,
                "scheduled proof requires probe absence before its eligible slot",
            )

            def completed():
                scheduled = client.verify_scheduler(ROLLUP, slot, slot)
                rows, job = api.search(
                    'search index=adm_summary source="adm:conversation" '
                    '| where rollup_id="' + raw[0]["expected"] + '" '
                    "| stats count values(bytes_c2s) AS bytes values(records) AS records",
                    str(int(now) - 300),
                    str(int(now) + 900),
                )
                client.require(
                    len(rows) == 1 and int(rows[0]["count"]) == 1,
                    "scheduled unique summary missing or duplicated",
                )
                client.require(
                    as_list(rows[0].get("bytes")) == ["900"]
                    and as_list(rows[0].get("records")) == ["1"],
                    "scheduled unique summary counters differ",
                )
                return {"scheduler": scheduled, "summary": rows, "summary_job": job}

            outcome = self._wait(completed, timeout=max(180, slot - time.time() + 300))
            return {
                "probe_fingerprint": client.digest(event),
                "index_time": indexed,
                "eligible_slot": slot,
                "raw_job": raw_job,
                "pre_slot_absence_job": absent_job,
                **outcome,
            }
        finally:
            self._set_saved_flags("sh1", ROLLUP, **original_flags)

    def phase_settings(self):
        self.lab.opt_in_settings()
        self.lab.apply_bundle()
        self._wait(client.verify_shc_ready)
        files = self.lab.verify_candidate()
        self._record("settings-installed-files", files)
        first = client.Api("sh1").json("GET", client.SETTINGS)
        client.require(
            first.get("state") == "absent",
            "initial settings creation requires absent fixture state",
        )
        namespace = first.get("namespace")

        def payload(state):
            return {
                "schemaVersion": 1,
                "revision": uuid.uuid4().hex,
                "sources": {
                    "netflow": {
                        "state": state,
                        "cadenceSeconds": 300,
                        "staleAfterSeconds": 1200,
                    }
                },
            }

        initial = client.settings_race(
            None, [payload("active"), payload("staged")], namespace
        )
        current = client.Api("sh1").json("GET", client.SETTINGS)["settings"]["revision"]
        subsequent = client.settings_race(
            current, [payload("active"), payload("not_selected")], namespace
        )
        stale = None
        try:
            client.Api("sh3").json(
                "POST",
                client.SETTINGS,
                raw=client.canonical(
                    {
                        "settings": payload("active"),
                        "expectedRevision": current,
                        "requestId": uuid.uuid4().hex,
                        "namespace": namespace,
                    }
                ),
            )
        except client.ApiError as error:
            client.require(error.status == 409, "stale write did not return conflict")
            stale = error.status
        else:
            raise client.Refused("stale settings update unexpectedly succeeded")
        forbidden = client.assert_denied(
            client.Api("sh2", "viewer"), "POST", client.SETTINGS, raw=b"{}"
        )
        self.settings_snapshot = client.Api("sh1").json("GET", client.SETTINGS)[
            "settings"
        ]
        return {
            "files": files,
            "namespace": namespace,
            "initial": initial,
            "subsequent": subsequent,
            "stale_status": stale,
            "viewer_status": forbidden,
            "final_settings_sha256": client.digest(self.settings_snapshot),
        }

    def phase_refusal(self):
        return client.assert_standalone_only(
            self.lab.directory / "stage/splunk_adm", self.source
        )

    def phase_reapply(self):
        before = self.settings_snapshot
        before_collections = self._wait(self.collection_snapshot, timeout=120)
        self.lab.apply_bundle()
        self._wait(client.verify_shc_ready)
        files = self.lab.verify_candidate()
        for role in client.MEMBERS:
            observed = client.Api(role).json("GET", client.SETTINGS)
            client.require(
                observed.get("settings") == before and observed.get("canWrite") is True,
                "bundle reapplication changed settings or qualification override",
            )
        graphs, rows = self._graphs()
        client.require(rows == self.graph_rows, "bundle reapplication changed graph")
        topologies, topology_rows = self._topologies()
        client.require(
            topology_rows == self.topology_rows, "bundle reapplication changed topology"
        )
        v2_views, v2_rows = self._wait(self._v2_views, timeout=300)
        viewer_v2, viewer_v2_rows = self._wait(
            lambda: self._v2_views("viewer"), timeout=300
        )
        client.require(
            v2_rows == self.v2_rows and viewer_v2_rows == self.v2_rows,
            "bundle reapplication changed V2 staged reads",
        )
        client.require(
            self.public_selectors() == self.public_selector_rows,
            "bundle reapplication changed V1 public selectors",
        )
        after_collections = self._wait(self.collection_snapshot, timeout=120)
        client.require(
            before_collections == after_collections,
            "bundle reapplication changed stored collection data",
        )
        return {
            "files": files,
            "graphs": graphs,
            "topologies": topologies,
            "v2_staged_reads": v2_views,
            "viewer_v2_staged_reads": viewer_v2,
            "v1_public_selectors_preserved": True,
            "settings_preserved": True,
            "collections_preserved": after_collections,
        }

    def phase_manifest(self):
        evidence = self.lab.directory / "evidence"
        records = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(evidence.glob("*.json"))
            if not path.name.startswith("manifest-")
        }
        result = {
            "source_sha": self.source_sha,
            "archive_sha256": self.lab.state.get("archive_sha256"),
            "test_hashes": self.lab.state.get("test_hashes"),
            "records": records,
            "completed": list(self.completed),
            "cloud": "unavailable; no authorized stack",
            "boundary": "same-host synthetic functionality; no supported production topology claim",
        }
        return result

    def phase_cleanup(self):
        self.lab.cleanup()
        return self.lab.state["cleanup"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--task", required=True)
    parser.add_argument("--addon-root", action="append", default=[], type=Path)
    parser.add_argument("--reference-graph", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args(argv)
    client.require(
        args.apply and args.interactive, "explicit --apply --interactive required"
    )
    lab = Lab(args.directory, args.task)
    driver = Driver(
        lab,
        args.source,
        args.archive,
        args.source_sha,
        args.addon_root,
        args.reference_graph,
    )
    with lab.locked():
        print(
            json.dumps({"ready": True, "task": args.task, "phases": Driver.ORDER}),
            flush=True,
        )
        for line in sys.stdin:
            try:
                action = json.loads(line)
                if action.get("action") == "inspect":
                    result = driver.inspect()
                elif action.get("action") == "quit":
                    client.require(
                        "cleanup" in driver.completed or not lab.state.get("created"),
                        "cleanup task resources before releasing host lock",
                    )
                    return 0
                else:
                    result = driver.run_phase(
                        action["phase"], rerun=action.get("rerun") is True
                    )
                print(json.dumps(result), flush=True)
            except Exception as error:
                print(
                    json.dumps(
                        {
                            "outcome": "failed",
                            "error_type": type(error).__name__,
                            "http_status": getattr(error, "status", None),
                            "evidence": str(lab.directory / "evidence"),
                        }
                    ),
                    flush=True,
                )
        client.require(
            "cleanup" in driver.completed or not lab.state.get("created"),
            "controller input closed before cleanup; resources retained",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
