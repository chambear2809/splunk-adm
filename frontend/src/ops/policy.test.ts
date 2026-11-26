import { describe, expect, it } from "vitest";
import { ciliumPolicyDraft } from "./policy";

describe("Cilium policy generator", () => {
  it("emits L3/L4 YAML and refuses daemon-wide audit mode", () => {
    const draft = ciliumPolicyDraft(
      {
        nodes: [
          {
            id: "payments",
            label: "payments",
            kind: "workload",
            addresses: ["10.0.0.20"],
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
        ],
      },
      "shop",
      "frontend",
    );
    expect(draft.yaml).toContain("kind: CiliumNetworkPolicy");
    expect(draft.yaml).toContain("10.0.0.20/32");
    expect(draft.yaml).toContain('port: "443"');
    expect(draft.yaml).toContain("per-endpoint PolicyAuditMode");
    expect(draft.yaml).not.toContain("enable-policy-audit-mode");
  });
});
