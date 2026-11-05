import { describe, expect, it } from "vitest";
import type { Graph, GraphEdge, TrafficObservation } from "./graph";
import { indexGraph } from "./graph";
import {
  DEFAULT_EXPANDED_DEVICES,
  aggregateObservations,
  conversationDetail,
  deviceGroup,
  edgeConversations,
  groupDeviceRows,
  ipNames,
  observerName,
  orientObservation,
  windowByHeights,
  type DeviceRowModel,
} from "./devicesTab";
import type { Device } from "./topology";

const edge = { id: "obs-1", source: "a", target: "b" } as GraphEdge;
const entries = (observations: TrafficObservation[]) =>
  observations.map((observation) => ({ edge, observation }));
const tuple = (
  source_ip: string,
  source_port: number,
  destination_ip: string,
  destination_port: number,
  extra: Partial<TrafficObservation> = {},
): TrafficObservation => ({
  source_ip,
  source_port,
  destination_ip,
  destination_port,
  transport: "TCP",
  records: 1,
  ...extra,
});

describe("service-port detection", () => {
  it("treats a reply's source as the listener", () => {
    const o = orientObservation(
      tuple("10.0.0.1", 8080, "10.0.0.2", 60162, { is_reply: true }),
    );
    expect(o.server).toEqual({ ip: "10.0.0.1", port: 8080 });
    expect(o.client.port).toBe(60162);
    expect(o.basis).toBe("reply_flag");
  });

  it("treats a request's destination as the listener", () => {
    const o = orientObservation(
      tuple("10.0.0.2", 8443, "10.0.0.1", 8080, { is_reply: false }),
    );
    expect(o.server.port).toBe(8080);
  });

  it("prefers a well-known port, then the non-ephemeral port, then the lower", () => {
    expect(orientObservation(tuple("a", 443, "b", 5000)).server.port).toBe(443);
    expect(orientObservation(tuple("a", 60162, "b", 8080)).server.port).toBe(
      8080,
    );
    expect(orientObservation(tuple("a", 8080, "b", 60162)).server.port).toBe(
      8080,
    );
    expect(orientObservation(tuple("a", 9000, "b", 8443)).server.port).toBe(
      8443,
    );
  });

  it("honours a reported server port", () => {
    const o = orientObservation(
      tuple("a", 9000, "b", 30000, { server_port: 9000 }),
    );
    expect(o.server).toEqual({ ip: "a", port: 9000 });
  });
});

describe("conversation aggregation", () => {
  it("merges requests and replies into one row per pair and service", () => {
    const rows = aggregateObservations(
      entries([
        tuple("10.0.0.2", 60162, "10.0.0.1", 8080, {
          is_reply: false,
          bytes_in: 100,
          last_seen: 1_700_000_000,
        }),
        tuple("10.0.0.1", 8080, "10.0.0.2", 60162, {
          is_reply: true,
          bytes_out: 50,
          last_seen: 1_700_000_100,
        }),
        tuple("10.0.0.2", 60200, "10.0.0.1", 8080, { is_reply: false }),
        tuple("10.0.0.2", 60300, "10.0.0.1", 9090, { is_reply: false }),
      ]),
      new Map(),
    );
    expect(rows).toHaveLength(2);
    const [main] = rows;
    expect(main.service).toBe("8080/tcp");
    expect(main.source.ip).toBe("10.0.0.2");
    expect(main.destination.ip).toBe("10.0.0.1");
    expect(main.flows).toBe(3);
    expect(main.replies).toBe(1);
    expect(main.bytes).toBe(150);
    expect(main.lastSeen).toBe(1_700_000_100_000);
    expect(main.clientPorts).toEqual([60162, 60200]);
    expect(main.replyFlags.sort()).toEqual(["false", "true"]);
    // Client ports and reply flags live only in the drill-down text.
    expect(main.service).not.toContain("60162");
    expect(conversationDetail(main)).toContain("Client ports 60162, 60200");
    expect(conversationDetail(main)).toContain("Reply false/true");
  });

  it("flags blocked verdicts", () => {
    const [row] = aggregateObservations(
      entries([tuple("a", 50000, "b", 443, { verdict: "DROPPED" })]),
      new Map(),
    );
    expect(row.blocked).toBe(true);
  });

  it("resolves IPs to map names only when one node claims them", () => {
    const graph = {
      nodes: [
        {
          id: "p1",
          label: "frontend-pod",
          kind: "pod",
          addresses: ["10.0.0.1"],
        },
        { id: "s1", label: "svc-a", kind: "service", addresses: ["10.0.0.9"] },
        { id: "s2", label: "svc-b", kind: "service", addresses: ["10.0.0.9"] },
      ],
      edges: [],
    } as unknown as Graph;
    const names = ipNames(graph);
    const [row] = aggregateObservations(
      entries([tuple("10.0.0.9", 50000, "10.0.0.1", 8080)]),
      names,
    );
    expect(row.destination.label).toBe("frontend-pod");
    expect(row.source.label).toBe("10.0.0.9");
  });

  it("keys map conversations by node pair and service", () => {
    const graph = {
      nodes: [
        { id: "a", label: "client-a", kind: "client" },
        { id: "b", label: "server-b", kind: "service" },
      ],
      edges: [],
    } as unknown as Graph;
    const base = {
      source: "a",
      target: "b",
      relationship: "communicates_with",
      evidence: [],
      confidence: "observed",
      server_port: 443,
      transport: "tcp",
    } satisfies Omit<GraphEdge, "id" | "count">;
    const rows = edgeConversations(
      [
        { ...base, id: "e1", count: 2, bytes: 10 },
        { ...base, id: "e2", count: 3, bytes: 5, acl_action: "drop" },
      ],
      indexGraph(graph),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      flows: 5,
      bytes: 15,
      blocked: true,
      service: "443/tcp",
    });
    expect(rows[0].source.label).toBe("client-a");
  });
});

describe("device naming and grouping", () => {
  it("humanizes Hubble observation points", () => {
    expect(observerName("hubble", "appd-k8-2/TO_ENDPOINT")).toBe(
      "appd-k8-2 · Cilium (to endpoint)",
    );
    expect(observerName("hubble", "TO_STACK")).toBe("Cilium (to stack)");
    expect(observerName("stream_ipfix", "10.61.255.1")).toBe(
      "10.61.255.1 · IPFIX",
    );
    expect(
      observerName("netflow", "192.0.2.1", { name: "leaf-101" } as Device),
    ).toBe("leaf-101 · NetFlow");
  });

  it("groups devices by kind", () => {
    const d = (x: Partial<Device>) => ({ sources: [], ...x }) as Device;
    expect(deviceGroup(d({ kind: "switch", role: "leaf" }))).toBe("Leaf");
    expect(deviceGroup(d({ kind: "switch", role: "spine" }))).toBe("Spine");
    expect(deviceGroup(d({ kind: "network_device" }))).toBe("FI");
    expect(deviceGroup(d({ kind: "virtual_switch" }))).toBe("Host/VDS");
    expect(deviceGroup(undefined, "host", "node-a")).toBe("K8s node/Cilium");
    expect(deviceGroup(d({ kind: "firewall" }))).toBe("Firewall");
    expect(deviceGroup(d({ kind: "router", name: "r1" }))).toBe("Other");
  });

  it("sorts by conversations and opens only the busiest groups", () => {
    const row = (
      key: string,
      group: DeviceRowModel["group"],
      n: number,
    ): DeviceRowModel => ({
      key,
      name: key,
      details: "",
      group,
      conversations: Array.from({
        length: n,
      }) as DeviceRowModel["conversations"],
      peers: 0,
      blocked: 0,
    });
    const rows = [
      row("fw", "Firewall", 1),
      ...Array.from({ length: DEFAULT_EXPANDED_DEVICES }, (_, i) =>
        row(`leaf-${i}`, "Leaf", 10 + i),
      ),
    ];
    const groups = groupDeviceRows(rows);
    expect(groups.map((g) => g.group)).toEqual(["Leaf", "Firewall"]);
    expect(groups[0].rows[0].key).toBe(`leaf-${DEFAULT_EXPANDED_DEVICES - 1}`);
    expect(groups.map((g) => g.defaultOpen)).toEqual([true, false]);
    const filtered = groupDeviceRows(rows, "fw");
    expect(filtered).toHaveLength(1);
    expect(filtered[0].defaultOpen).toBe(true);
  });
});

describe("variable-height windowing", () => {
  it("renders only items near the viewport and pads the rest", () => {
    const heights = Array.from({ length: 1000 }, () => 50);
    const w = windowByHeights(heights, 10_000, 500, 100);
    expect(w.first).toBe(198);
    expect(w.last).toBe(212);
    expect(w.before).toBe(198 * 50);
    expect(w.before + (w.last - w.first) * 50 + w.after).toBe(50_000);
  });
});
