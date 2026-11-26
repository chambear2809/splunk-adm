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
    expect(draft.yaml).toContain('k8s:app.kubernetes.io/name: "frontend"');
    expect(draft.yaml).toContain("10.0.0.20/32");
    expect(draft.yaml).not.toContain("10.0.0.99/32");
    expect(draft.yaml).toContain('port: "443"');
    expect(draft.yaml).not.toContain('port: "5432"');
    expect(draft.yaml).toContain("per-endpoint PolicyAuditMode");
    expect(draft.yaml).not.toContain("enable-policy-audit-mode");
  });

  it("includes all destination IPv4 addresses and ignores invalid ports/protocols", () => {
    const draft = ciliumPolicyDraft(
      {
        nodes: [
          {
            id: "db",
            label: "db",
            kind: "workload",
            addresses: ["10.0.0.30", "10.0.0.31"],
          },
        ],
        edges: [
          {
            id: "e1",
            source: "frontend",
            target: "db",
            relationship: "communicates_with",
            evidence: ["hubble"],
            confidence: "observed",
            count: 2,
            server_port: 5432,
            transport: "tcp",
          },
          {
            id: "e2",
            source: "frontend",
            target: "db",
            relationship: "communicates_with",
            evidence: ["hubble"],
            confidence: "observed",
            count: 1,
            server_port: 70000,
            transport: "icmp\ninjected: true",
          },
        ],
      },
      "shop",
      "frontend",
    );
    expect(draft.yaml).toContain("10.0.0.30/32");
    expect(draft.yaml).toContain("10.0.0.31/32");
    expect(draft.yaml).not.toContain("70000");
    expect(draft.yaml).not.toContain("injected");
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
              server_port: 443,
              transport: "tcp",
            },
          ],
        },
        "shop",
        "frontend",
      ),
    ).toThrow(/No observed L4/i);
  });

  it("uses toEndpoints for namespaced Kubernetes workloads and skips port-less edges", () => {
    const draft = ciliumPolicyDraft(
      {
        nodes: [
          {
            id: "checkout",
            label: "checkout",
            kind: "workload",
            addresses: ["10.244.0.15"],
            attributes: { namespace: "shop", service: "checkout" },
          },
          {
            id: "icmp-peer",
            label: "icmp-peer",
            kind: "endpoint",
            addresses: ["198.51.100.10"],
          },
        ],
        edges: [
          {
            id: "e1",
            source: "frontend",
            target: "checkout",
            relationship: "communicates_with",
            evidence: ["hubble"],
            confidence: "observed",
            count: 5,
            server_port: 8080,
            transport: "tcp",
          },
          {
            id: "e2",
            source: "frontend",
            target: "icmp-peer",
            relationship: "communicates_with",
            evidence: ["hubble"],
            confidence: "observed",
            count: 2,
          },
        ],
      },
      "shop",
      "frontend",
    );
    expect(draft.yaml).toContain("toEndpoints:");
    expect(draft.yaml).toContain('k8s:app.kubernetes.io/name: "checkout"');
    expect(draft.yaml).not.toContain("10.244.0.15/32");
    expect(draft.yaml).not.toContain("198.51.100.10/32");
    expect(draft.yaml).toContain("kube-dns");
  });
});
