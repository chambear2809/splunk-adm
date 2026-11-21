import { describe, expect, it } from "vitest";
import type { SearchClient, SearchRequest } from "../data/searchClient";
import type { Row } from "../rows";
import { loadObservedImpactEvidence } from "./observedEvidence";

const scope = "validation-k3s-splunk";
const cohort = {
  schema_version: 1,
  scope,
  start: 100,
  end: 200,
  devices: [{ id: "192.0.2.11", name: "Spine1", role: "spine", domain: 1 }],
  trials: [
    {
      id: "invoice-save",
      journey: "Save invoice",
      app: "Invoice",
      actor: "browser",
      outcome: "HTTP 200",
      src: "198.51.100.16",
      dst: "203.0.113.10",
      source_port: 56606,
      destination_port: 443,
      start: 110,
      end: 150,
      captures: { forward: "receipt-forward", reverse: "receipt-reverse" },
      spines: { forward: ["192.0.2.11"], reverse: ["192.0.2.11"] },
    },
  ],
};
const envelope = (value: unknown) => ({ _raw: JSON.stringify(value) });
const receipt = (
  id: string,
  src: string,
  dst: string,
  source_port: number,
  destination_port: number,
) =>
  envelope({
    schema_version: 1,
    capture_id: id,
    scope,
    src,
    dst,
    protocol: "tcp",
    source_port,
    destination_port,
    start: 112,
    end: 130,
    collected_at: 131,
    producer: "atlas",
    segments: [
      {
        id: `${id}-segment`,
        label: "Spine1",
        source: "stream",
        reference: "ref-1",
        observed_at: 120,
        hops: [
          {
            kind: "switch",
            label: "Spine1",
            device: "192.0.2.11",
            evidence: "observed",
          },
        ],
      },
    ],
  });
const native = (
  src: string,
  dst: string,
  source_port: number,
  destination_port: number,
) => ({
  observer_device: "192.0.2.11",
  direction: src === cohort.trials[0].src ? "forward" : "reverse",
  src,
  dst,
  src_port: source_port,
  dest_port: destination_port,
  first_seen: "115.250",
  last_seen: "115.250",
  observation_domain_id: "1",
  reference: "netflow-1",
  row_type: "observation",
  flow_source: "netflow",
  protocol: "tcp",
  profile_status: "tuple-candidate",
  source_profile: "nexus_nxos_netflow",
});

class Client implements SearchClient {
  readonly requests: SearchRequest[] = [];
  constructor(
    private readonly rows: unknown[][],
    private readonly warnings: string[] = [],
  ) {}
  async search(request: SearchRequest) {
    this.requests.push(request);
    return {
      rows: (this.rows.shift() ?? []) as Row[],
      warnings: this.warnings,
      errors: [],
    };
  }
}
const options = (client: SearchClient) => ({
  client,
  earliest: "100",
  latest: "200",
  scope,
  signal: new AbortController().signal,
});

describe("loadObservedImpactEvidence", () => {
  it("normalizes a v2 leaf reference from an observed trace hop", async () => {
    const version2 = {
      schema_version: 2,
      scope,
      start: 100,
      end: 200,
      devices: [{ id: "192.0.2.14", name: "Leaf2", role: "leaf", domain: 1 }],
      trials: [
        {
          id: "invoice-form-leaf2",
          journey: "Open form",
          app: "Invoice",
          actor: "browser",
          outcome: "HTTP 200",
          src: "198.51.100.16",
          dst: "203.0.113.10",
          source_port: 61486,
          destination_port: 443,
          start: 110,
          end: 150,
          captures: { forward: "leaf2-forward" },
          exports: { forward: [] },
          trace_hops: {
            forward: [
              {
                device: "192.0.2.14",
                segment: "leaf-segment",
                hop: "Leaf2 VLAN 2301",
              },
            ],
          },
        },
      ],
    };
    const receiptRow = envelope({
      schema_version: 1,
      capture_id: "leaf2-forward",
      scope,
      src: version2.trials[0].src,
      dst: version2.trials[0].dst,
      protocol: "tcp",
      source_port: 61486,
      destination_port: 443,
      start: 112,
      end: 130,
      collected_at: 131,
      producer: "atlas",
      segments: [
        {
          id: "leaf-segment",
          label: "Leaf2",
          source: "stream",
          reference: "ref-leaf2",
          observed_at: 120,
          hops: [
            {
              kind: "switch",
              label: "Leaf2 VLAN 2301",
              device: "192.0.2.14",
              evidence: "observed",
            },
          ],
        },
      ],
    });
    const client = new Client([[envelope(version2)], [receiptRow], []]);
    const result = await loadObservedImpactEvidence(options(client));
    expect(result.devices[0].role).toBe("leaf");
    expect(result.trials[0].exports.forward).toEqual([]);
    expect(result.trials[0].observations.forward).toEqual(["192.0.2.14"]);
    expect(result.trials[0].traceHops.forward[0].segment).toBe("leaf-segment");
  });

  it("binds linked Save evidence without making it a browser-direction observation", async () => {
    const [trial] = cohort.trials;
    const ip = "192.0.2.14";
    const linked = {
      src: trial.dst,
      dst: "203.0.113.13",
      source_port: 38602,
      destination_port: 5432,
      capture: "save-db",
      device: ip,
      segment: "save-db-segment",
      hop: "Leaf2 routes toward database HAProxy",
    };
    const v2 = {
      ...cohort,
      schema_version: 2,
      devices: [
        ...cohort.devices,
        { id: ip, name: "Leaf2", role: "leaf", domain: 1 },
      ],
      trials: [{ ...trial, exports: trial.spines, linked_captures: [linked] }],
    };
    const downstream = JSON.parse(
      receipt(
        linked.capture,
        linked.src,
        linked.dst,
        linked.source_port,
        linked.destination_port,
      )._raw,
    );
    downstream.segments[0].hops = [
      { kind: "switch", label: linked.hop, evidence: "observed" },
    ];
    const rows = [
      [envelope(v2)],
      [receipt(trial.captures.forward, trial.src, trial.dst, 56606, 443)],
      [receipt(trial.captures.reverse, trial.dst, trial.src, 443, 56606)],
      [
        native(trial.src, trial.dst, 56606, 443),
        native(trial.dst, trial.src, 443, 56606),
      ],
    ];
    const result = await loadObservedImpactEvidence(
      options(new Client([...rows, [envelope(downstream)]])),
    );
    expect(result.trials[0].linkedCaptures).toEqual([linked]);
    expect(result.trials[0].observations).toEqual(trial.spines);
    expect(result.receipts.size).toBe(3);

    downstream.segments[0].hops[0].device = "192.0.2.11";
    await expect(
      loadObservedImpactEvidence(
        options(new Client([...rows, [envelope(downstream)]])),
      ),
    ).rejects.toThrow("not an exact observed device reference");
  });

  it("validates the cohort, both receipts and both directional native spine tuples", async () => {
    const client = new Client([
      [envelope(cohort)],
      [
        receipt(
          "receipt-forward",
          cohort.trials[0].src,
          cohort.trials[0].dst,
          56606,
          443,
        ),
      ],
      [
        receipt(
          "receipt-reverse",
          cohort.trials[0].dst,
          cohort.trials[0].src,
          443,
          56606,
        ),
      ],
      [
        native(cohort.trials[0].src, cohort.trials[0].dst, 56606, 443),
        native(cohort.trials[0].dst, cohort.trials[0].src, 443, 56606),
      ],
    ]);
    const result = await loadObservedImpactEvidence(options(client));
    expect(result.trials.map((t) => t.id)).toEqual(["invoice-save"]);
    expect(result.receipts.size).toBe(2);
    expect(result.native.map((r) => r.direction)).toEqual([
      "forward",
      "reverse",
    ]);
    expect(client.requests).toHaveLength(4);
  });

  it("ignores a non-cohort exporter but requires every declared spine", async () => {
    const extra = {
      ...native(cohort.trials[0].src, cohort.trials[0].dst, 56606, 443),
      scope,
      observer_device: "192.0.2.99",
      reference: "other",
    };
    const client = new Client([
      [envelope(cohort)],
      [
        receipt(
          "receipt-forward",
          cohort.trials[0].src,
          cohort.trials[0].dst,
          56606,
          443,
        ),
      ],
      [
        receipt(
          "receipt-reverse",
          cohort.trials[0].dst,
          cohort.trials[0].src,
          443,
          56606,
        ),
      ],
      [
        extra,
        native(cohort.trials[0].src, cohort.trials[0].dst, 56606, 443),
        native(cohort.trials[0].dst, cohort.trials[0].src, 443, 56606),
      ],
    ]);
    const result = await loadObservedImpactEvidence(options(client));
    expect(result.native.every((row) => row.device === "192.0.2.11")).toBe(
      true,
    );
  });

  it("rejects warnings, wrong windows and missing native coverage", async () => {
    const warned = new Client([[envelope(cohort)]], ["late data"]);
    await expect(loadObservedImpactEvidence(options(warned))).rejects.toThrow(
      "warnings",
    );
    const wrong = structuredClone(cohort);
    wrong.end = 201;
    const wrongClient = new Client([[envelope(wrong)]]);
    await expect(
      loadObservedImpactEvidence(options(wrongClient)),
    ).rejects.toThrow("window mismatch");
    const missing = new Client([
      [envelope(cohort)],
      [
        receipt(
          "receipt-forward",
          cohort.trials[0].src,
          cohort.trials[0].dst,
          56606,
          443,
        ),
      ],
      [
        receipt(
          "receipt-reverse",
          cohort.trials[0].dst,
          cohort.trials[0].src,
          443,
          56606,
        ),
      ],
      [],
    ]);
    await expect(loadObservedImpactEvidence(options(missing))).rejects.toThrow(
      "coverage",
    );
  });
});
