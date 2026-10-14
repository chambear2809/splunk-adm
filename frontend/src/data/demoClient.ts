import nxosRows from "../../../fixtures/demo-rows.json";
import nxosTopology from "../../../fixtures/demo-topology.json";
import aciRows from "../../../fixtures/demo-rows-aci.json";
import aciTopology from "../../../fixtures/demo-topology-aci.json";
import { type Graph } from "../graph";
import { rowsToGraph, type GraphArgs } from "../rows";
import { emptyTopology, rowsToTopology, type Topology } from "../topology";
import { createStaticURL } from "@splunk/splunk-utils/url";

export type DemoScenario = "aci" | "nxos";
type Scenario = {
  label: string;
  graph: { args: GraphArgs; rows: readonly Record<string, unknown>[] };
  topology: unknown;
};
const devScenarios: Record<DemoScenario, Scenario> | undefined =
  __ADM_SPLUNK_BUILD__
    ? undefined
    : {
        aci: {
          label: "ACI pilot fabric",
          graph: aciRows,
          topology: aciTopology as unknown,
        },
        nxos: {
          label: "NX-OS fabric",
          graph: nxosRows,
          topology: nxosTopology as unknown,
        },
      };
let scenarios: Record<DemoScenario, Scenario> | undefined = devScenarios;
const requireScenarios = () => {
  if (!scenarios) throw new Error("Demo data is not prepared.");
  return scenarios;
};
export async function prepareDemo(): Promise<void> {
  if (!__ADM_SPLUNK_BUILD__ || scenarios) return;
  const load = async (name: string) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(
        createStaticURL(`app/splunk_adm/demo/${name}`),
        { signal: controller.signal },
      );
      if (!response.ok)
        throw new Error(`Demo fixture request failed (${response.status}).`);
      return await response.json();
    } finally {
      clearTimeout(timer);
    }
  };
  const [aciGraph, nxosGraph, aciTopology, nxosTopology] = await Promise.all([
    load("demo-rows-aci.json"),
    load("demo-rows.json"),
    load("demo-topology-aci.json"),
    load("demo-topology.json"),
  ]);
  scenarios = {
    aci: { label: "ACI pilot fabric", graph: aciGraph, topology: aciTopology },
    nxos: { label: "NX-OS fabric", graph: nxosGraph, topology: nxosTopology },
  };
}
export const DEMO_SCENARIOS = [
  { id: "aci" as const, label: "ACI pilot fabric" },
  { id: "nxos" as const, label: "NX-OS fabric" },
];
export const demoArgsFor = (scenario: DemoScenario): GraphArgs =>
  requireScenarios()[scenario].graph.args;
export const demoArgs: GraphArgs = {
  service: "frontend",
  environment: "demo",
  cluster: "demo-cluster",
  namespace: "shop",
};
export const demoGraph = (scenario: DemoScenario = "aci"): Graph =>
  rowsToGraph(requireScenarios()[scenario].graph.rows, demoArgsFor(scenario), {
    demo: true,
  });
export const demoTopology = (scenario: DemoScenario = "aci"): Topology => {
  const file = requireScenarios()[scenario].topology;
  if (file === undefined) return emptyTopology();
  return rowsToTopology(
    Array.isArray(file) ? file : (file as { rows?: unknown }).rows,
  );
};
