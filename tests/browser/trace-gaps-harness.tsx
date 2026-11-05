import { createRoot } from "react-dom/client";
import type { SearchClient } from "../../frontend/src/data/searchClient";
import { TraceView } from "../../frontend/src/trace/TraceView";
import { usePathTrace } from "../../frontend/src/trace/usePathTrace";
import vdsFiVpc from "../../fixtures/path-trace-vds-fi-vpc.json";
import "../../frontend/src/styles.css";

// A deep-linked trace (no built map) against live-shaped adm_path_trace rows
// (fixtures/path-trace-vds-fi-vpc.json) plus the evidence of the 2026-11-04
// live scenarios: ACL-log drops for tcp/47003 at leaf102 after leaf101's vPC
// member was shut, and a Hubble policy drop between two pods.
type Row = Record<string, unknown>;
const base = vdsFiVpc.rows as Row[];
const LEAF101 = "192.0.2.252";
const services = (r: Row): Row =>
  r.row_type === "observation" && r.flow_source === "netflow"
    ? {
        ...r,
        services: ["tcp/47001", "tcp/47003"],
        client_ports: ["47110", "47111", "47112"],
      }
    : r;
const aclRows: Row[] = [
  ...base.filter((r) => !String(r.observer).includes(LEAF101)).map(services),
  {
    row_type: "observation",
    observer: "aci_acllog:pod-1/node-102",
    observer_device: "pod-1/node-102",
    flow_source: "aci_acllog",
    direction: "forward",
    records: "14",
    drops: "14",
    protocols: "tcp",
    dest_ports: "47003",
    services: "tcp/47003",
    drop_services: "tcp/47003",
  },
];
const pod = (ip: string, name: string, node: string): Row => ({
  row_type: "endpoint",
  ip,
  entity_kind: "pod",
  entity_name: name,
  cluster: "lab",
  namespace: "shop",
  node,
});
const podRows: Row[] = [
  ...base.filter(
    (r) => r.row_type !== "observation" && r.row_type !== "endpoint",
  ),
  pod("10.244.1.10", "web-1", "k8s-node-1"),
  pod("10.244.2.20", "api-1", "k8s-node-2"),
  ...[
    ["192.0.2.3", "k8s-node-1"],
    ["198.51.100.2", "k8s-node-2"],
  ].map(([ip, name]) => ({
    row_type: "endpoint",
    trace_role: "pod_node",
    ip,
    entity_kind: "k8s_node",
    entity_name: name,
    cluster: "lab",
  })),
  {
    row_type: "observation",
    observer: "hubble:k8s-node-2",
    observer_device: "k8s-node-2",
    flow_source: "hubble",
    direction: "forward",
    records: "5",
    drops: "5",
    protocols: "tcp",
    dest_ports: "8080",
    services: "tcp/8080",
    drop_services: "tcp/8080",
    drop_reasons: "POLICY_DENIED",
  },
];

const params = new URLSearchParams(location.search);
const scenario = params.get("case") === "pod" ? "pod" : "acl";
const request =
  scenario === "pod"
    ? { src: "10.244.1.10", dst: "10.244.2.20" }
    : { src: "192.0.2.3", dst: "198.51.100.2" };
const rows = scenario === "pod" ? podRows : aclRows;
const client: SearchClient = {
  search: async (r) => ({
    rows: r.search.includes("adm_path_trace(") ? rows : [],
    warnings: [],
    errors: [],
  }),
};

function Harness() {
  const result = usePathTrace({
    request,
    demo: false,
    client,
    earliest: "-15m",
  });
  return <TraceView request={request} result={result} />;
}

createRoot(document.getElementById("trace-gaps-root")!).render(<Harness />);
