import { describe, expect, it } from "vitest";
import {
  confidenceLabel,
  endpointKindLabel,
  kindLabel,
  portLabel,
  prettyBytes,
  relationshipLabel,
} from "./glossary";
import type { GraphEdge } from "./graph";
import { truncateMiddle } from "./MapView";

describe("glossary", () => {
  it("uses plain-language names", () => {
    expect(confidenceLabel.correlated).toBe("Identified");
    expect(confidenceLabel.unresolved).toBe("Unknown IP");
    expect(endpointKindLabel.ambiguous).toBe("Multiple owners");
    expect(endpointKindLabel.external).toBe("External");
    expect(relationshipLabel.calls).toBe("Traced call");
    expect(relationshipLabel.communicates_with).toBe("Network conversation");
    expect(relationshipLabel.runs_on).toBe("Runs on");
  });
  it("names node kinds", () => {
    expect(kindLabel({ id: "a", label: "a", kind: "workload" })).toBe("Pod");
    expect(
      kindLabel({ id: "a", label: "a", kind: "endpoint", endpoint_kind: "vm" }),
    ).toBe("VM");
  });
  it("formats ports and bytes", () => {
    const e = { server_port: 5432, transport: "tcp" } as GraphEdge;
    expect(portLabel(e)).toBe("5432/tcp");
    expect(portLabel({ transport: "icmp" } as GraphEdge)).toBe("icmp");
    expect(prettyBytes(999)).toBe("999 B");
    expect(prettyBytes(20100)).toBe("20.1 KB");
    expect(prettyBytes(3.2e9)).toBe("3.2 GB");
  });
  it("truncates long names in the middle, keeping the unique suffix", () => {
    const t = truncateMiddle("ingress-nginx-controller-6b9d7c8f5-q7m2z", 24);
    expect(t).toHaveLength(24);
    expect(t.endsWith("q7m2z")).toBe(true);
    expect(truncateMiddle("short", 24)).toBe("short");
  });
});
