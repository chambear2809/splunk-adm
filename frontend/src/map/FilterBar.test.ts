import { describe, expect, it } from "vitest";
import { availablePorts } from "./FilterBar";
import type { Graph } from "../graph";

describe("FilterBar port options", () => {
  it.each([
    { source_port: 1234, destination_port: 443 },
    { source_port: 443, destination_port: 1234 },
  ])(
    "offers both ports for a lone observation $source_port → $destination_port",
    (ports) => {
      const graph = {
        edges: [{ relationship: "traffic_observation", ...ports }],
      } as unknown as Graph;
      expect(availablePorts(graph)).toEqual([443, 1234]);
    },
  );

  it("does not use a conflicting server-port fallback when only a raw source port exists", () => {
    const graph = {
      edges: [
        {
          relationship: "traffic_observation",
          source_port: 443,
          server_port: 8080,
        },
      ],
    } as unknown as Graph;
    expect(availablePorts(graph)).toEqual([443]);
  });

  it("uses server_port only for legacy observations without raw ports", () => {
    const graph = {
      edges: [
        {
          relationship: "traffic_observation",
          server_port: 8080,
        },
      ],
    } as unknown as Graph;
    expect(availablePorts(graph)).toEqual([8080]);
  });

  it("enumerates every native tuple port, including reverse and ephemeral ports", () => {
    const graph = {
      edges: [
        {
          relationship: "traffic_observation",
          traffic_observations: [
            { source_port: 49152, destination_port: 443 },
            { source_port: 443, destination_port: 49152, is_reply: true },
            { source_port: 53000, destination_port: 8443 },
          ],
        },
      ],
    } as unknown as Graph;
    expect(availablePorts(graph)).toEqual([443, 8443, 49152, 53000]);
  });
});
