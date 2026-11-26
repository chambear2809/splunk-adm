import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PolicyWorkbench } from "./PolicyWorkbench";
import { testGraph } from "./testGraph";

const render = (live: boolean) =>
  renderToStaticMarkup(
    <PolicyWorkbench
      graph={testGraph()}
      onClose={() => undefined}
      onShowEdge={() => undefined}
      {...(live
        ? { loadWindow: async () => Promise.reject(new Error("unused")) }
        : {})}
    />,
  );

describe("PolicyWorkbench", () => {
  it("labels itself draft-only and never claims to apply policy", () => {
    const html = render(true);
    expect(html).toContain("Draft only");
    expect(html).toContain("never");
    expect(html).toContain("pushes policy");
    expect(html).not.toMatch(/\b(apply policy|enforce now|push to)\b/i);
  });

  it("reports covered, not covered and unknown separately", () => {
    const html = render(true);
    expect(html).toContain("Covered");
    expect(html).toContain("Not covered");
    expect(html).toContain("Unknown");
    expect(html).toContain(
      "does not collect Cilium or Kubernetes policy rules",
    );
    expect(html).toContain("logged ACL drops");
  });

  it("seeds rules, replays them and lists the draft exports", () => {
    const html = render(true);
    expect(html).toContain("observed-001");
    expect(html).toContain("Not seeded");
    expect(html).toContain("Would be blocked");
    expect(html).toContain("Kubernetes NetworkPolicy (YAML)");
    expect(html).toContain("CiliumNetworkPolicy (YAML)");
    expect(html).toContain("ACI contract/subject/filter (APIC JSON)");
    expect(html).toContain("Firewall rules (CSV)");
  });

  it("offers historical windows only when a live loader exists", () => {
    expect(render(true)).toContain("Read window");
    const demo = render(false);
    expect(demo).not.toContain("Read window");
    expect(demo).toContain("demo data has one");
  });
});
