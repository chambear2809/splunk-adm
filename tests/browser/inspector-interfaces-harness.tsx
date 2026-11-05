import { createRoot } from "react-dom/client";
import { useState } from "react";
import { Inspector } from "../../frontend/src/Inspector";
import type { Selection } from "../../frontend/src/MapView";
import {
  indexGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "../../frontend/src/graph";
import { pathTraceObservers } from "../../frontend/src/data/pathTrace";
import { endpointGraph } from "../../frontend/src/trace/standaloneTrace";
import { traceTopology } from "../../frontend/src/trace/traceModel";
import { emptyTopology, indexTopology } from "../../frontend/src/topology";
import vdsFiVpc from "../../fixtures/path-trace-vds-fi-vpc.json";
import "../../frontend/src/styles.css";

// Live adm_path_trace shape (fixtures/path-trace-vds-fi-vpc.json): VDS IPFIX
// on two ESXi hosts and ingress-only NetFlow on a vPC leaf pair.
const rows = vdsFiVpc.rows as unknown[];
const topo = indexTopology(traceTopology(emptyTopology(), rows));
const ports = [...topo.virtualPorts.values()].flat();
const vm = (ip: string): GraphNode => {
  const p = ports.find((x) => x.ip === ip)!;
  return {
    id: p.vm,
    label: p.vm_name ?? ip,
    kind: "endpoint",
    endpoint_kind: "vm",
    addresses: [ip],
    attributes: p.mac ? { mac: p.mac } : {},
  };
};
const client = vm("192.0.2.3"),
  server = vm("198.51.100.2");
const observers = pathTraceObservers(rows);
const conv = (
  id: string,
  source: GraphNode,
  target: GraphNode,
  list: string[],
): GraphEdge => ({
  id,
  source: source.id,
  target: target.id,
  relationship: "communicates_with",
  evidence: [],
  confidence: "observed",
  count: 4,
  server_port: 47001,
  transport: "tcp",
  direction_basis: "initiator",
  observers: list,
});
const edges = [
  conv("conv-forward", client, server, observers),
  conv(
    "conv-leaf",
    client,
    server,
    observers.filter((o) => o.startsWith("netflow:192.0.2.25")),
  ),
];
const graph: Graph = {
  ...endpointGraph(rows, ["192.0.2.3", "198.51.100.2"]),
  nodes: [client, server],
  edges,
};
const index = indexGraph(graph);
const mode = new URLSearchParams(location.search).get("select") ?? "edge";
const initial: Selection =
  mode === "node"
    ? { kind: "node", id: client.id }
    : { kind: "edge", id: "conv-forward" };
const bundle =
  mode === "bundle"
    ? {
        title: "k8s-vm-01 → app-vm-02",
        edgeIds: edges.map((e) => e.id),
      }
    : undefined;

function Harness() {
  const [selection, setSelection] = useState<Selection | null>(initial);
  return (
    <div className="adm atlas">
      <aside className="inspector" style={{ width: 420 }}>
        <Inspector
          selection={selection}
          index={index}
          topo={topo}
          onSelect={setSelection}
          onClose={() => setSelection(null)}
          onShowPath={() => {}}
          summary={null}
          bundle={bundle}
        />
      </aside>
    </div>
  );
}
document.documentElement.dataset.theme = "light";
createRoot(document.getElementById("inspector-interfaces-root")!).render(
  <Harness />,
);
