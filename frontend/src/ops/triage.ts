import type { GraphEdge } from "../graph";

export interface TriageStep {
  id: string;
  title: string;
  detail: string;
}

/** Guided connectivity triage from an observed edge. Uses existing evidence only. */
export function triageSteps(edge: GraphEdge): TriageStep[] {
  const steps: TriageStep[] = [
    {
      id: "scope",
      title: "Confirm routing scope",
      detail:
        "Unmapped observers stay isolated. Map the exporter, firewall or cluster in Setup before correlating.",
    },
    {
      id: "path",
      title: "Inspect the candidate path",
      detail:
        "Path stages mark where Stream NetFlow, ACI/NX-OS inventory or Hubble observed traffic, not packet order.",
    },
  ];
  if (edge.acl_action === "drop")
    steps.push({
      id: "acl",
      title: "ACL drop is observed",
      detail: edge.acl_leaf
        ? `Dropped at ${edge.acl_leaf}. Policy intent is not inferred beyond collected ACI filters.`
        : "A collected ACL drop is present. Policy intent is not inferred beyond collected filters.",
    });
  if (edge.nat_observations?.length)
    steps.push({
      id: "nat",
      title: "NAT is same-event evidence",
      detail:
        "FTD eStreamer translations stay on this connection. They do not prove a route through other hops.",
    });
  if (edge.confidence === "inferred")
    steps.push({
      id: "inferred",
      title: "Relationship is inferred",
      detail: "Do not treat inferred edges as observed connectivity.",
    });
  steps.push({
    id: "sources",
    title: "Stay on existing collectors",
    detail:
      "Next evidence comes from Stream, SC4SNMP, SC4S/syslog TAs or the OTel Collector. Atlas does not add a collector.",
  });
  return steps;
}
