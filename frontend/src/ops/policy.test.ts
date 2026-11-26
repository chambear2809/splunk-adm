import { describe, expect, it } from "vitest";
import { ciliumPolicyDraft } from "./policy";

describe("Cilium policy generator", () => {
  it("emits L3/L4 YAML scoped to service egress and refuses daemon-wide audit mode", () => {
    const draft = ciliumPolicyDraft(
      {
        nodes: [
          {
            id: "payments",
            label: "payments",
            kind: "workload",
            addresses: ["10.0.0.20"],
          },
          {
            id: "other",
            label: "other",
            kind: "workload",
            addresses: ["10.0.0.99"],
          },
        ],
        edges: [
          {
            id: "e1",
            source: "frontend",
            target: "payments",
            relationship: "communicates_with",
            evidence: ["hubble"],
            confidence: "observed",
            count: 3,
            server_port: 443,
            transport: "tcp",
          },
          {
            id: "e2",
            source: "payments",
            target: "other",
            relationship: "communicates_with",
            evidence: ["hubble"],
            confidence: "observed",
            count: 1,
            server_port: 5432,
            transport: "tcp",
          },
        ],
      },
      "shop",
      "frontend",
    );
    expect(draft.yaml).toContain("kind: CiliumNetworkPolicy");
    expect(draft.yaml).toContain("10.0.0.20/32");
    expect(draft.yaml).not.toContain("10.0.0.99/32");
    expect(draft.yaml).toContain('port: "443"');
    expect(draft.yaml).not.toContain('port: "5432"');
    expect(draft.yaml).toContain("per-endpoint PolicyAuditMode");
    expect(draft.yaml).not.toContain("enable-policy-audit-mode");
  });

  it("refuses invalid namespace, invalid IPv4 octets, or empty egress", () => {
    expect(() =>
      ciliumPolicyDraft({ nodes: [], edges: [] }, "", "frontend"),
    ).toThrow(/namespace/i);
    expect(() =>
      ciliumPolicyDraft(
        {
          nodes: [
            {
              id: "bad",
              label: "bad",
              kind: "workload",
              addresses: ["999.999.999.999"],
            },
          ],
          edges: [
            {
              id: "e1",
              source: "frontend",
              target: "bad",
              relationship: "communicates_with",
              evidence: ["hubble"],
              confidence: "observed",
              count: 1,
            },
          ],
        },
        "shop",
        "frontend",
      ),
    ).toThrow(/No observed IPv4/i);
  });
});
