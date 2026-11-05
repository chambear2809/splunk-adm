import {
  DEMO_WINDOW,
  demoGraph,
  demoVsphereTopology,
  prepareDemo,
} from "../data/demoClient";
import { indexTopology } from "../topology";
import {
  demoImpactTopology,
  graphConversations,
  portChannelRows,
  resolveAll,
  windowHours,
  type ImpactData,
} from "./data";
import { pathContext } from "./paths";

/** Demo Impact: ACI demo graph and vSphere overlay, re-cabled through an FI pair to a vPC. */
export async function loadDemoImpact(tokens: string[]): Promise<ImpactData> {
  if (__ADM_SPLUNK_BUILD__)
    throw new Error("Demo data ships with the development server only.");
  await prepareDemo();
  const overlay = (await import("../../../fixtures/demo-impact-aci.json"))
    .default.rows;
  const topology = demoImpactTopology(demoVsphereTopology(), overlay);
  const topo = indexTopology(topology);
  const portChannels = portChannelRows(overlay, topo);
  const graph = demoGraph("aci");
  const conversations = graphConversations(graph);
  return {
    topology,
    topo,
    ctx: pathContext(topo, graph),
    elements: resolveAll(tokens, topology, topo, graph, portChannels),
    portChannels,
    conversations,
    graph,
    total: conversations.length,
    truncated: false,
    capped: false,
    hours: windowHours(DEMO_WINDOW.earliest, DEMO_WINDOW.latest),
    source: "demo",
  };
}
