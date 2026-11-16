import { describe, expect, it } from "vitest";
import { loadDemoImpact } from "./demo";
import { dependsImpact, failsImpact } from "./model";

const fails = async (tokens: string[]) => {
  const d = await loadDemoImpact(tokens);
  return failsImpact(d.elements, d.conversations, d.ctx, { hours: d.hours });
};
const sev = (r: Awaited<ReturnType<typeof fails>>) =>
  Object.fromEntries(
    r.rows.map((c) => [`${c.conv.src.name}>${c.conv.dst.name}`, c.severity]),
  );

describe("demo impact (ACI fabric, esx-01 via FI pair to a vPC)", () => {
  it("leaf-101: vPC traffic degrades, node-a single-homed pods are out", async () => {
    const r = await fails(["leaf-101"]);
    expect(r.kpis.conversations.degraded).toBeGreaterThan(0);
    expect(r.kpis.conversations.outage).toBeGreaterThan(0);
    expect(sev(r)["checkout-5f8b9c7d6-m4n7q>orders-db-01"]).toBe("degraded");
  });
  it("one FI degrades; both FIs take orders-db-01 out", async () => {
    const one = await fails(["ucs-fi-b"]);
    expect(sev(one)["checkout-5f8b9c7d6-m4n7q>orders-db-01"]).toBe("degraded");
    const both = await fails(["ucs-fi-a", "ucs-fi-b"]);
    expect(sev(both)["checkout-5f8b9c7d6-m4n7q>orders-db-01"]).toBe("outage");
  });
  it("spine-201 is ECMP; esx-01 is a single point for orders-db-01", async () => {
    const spine = await fails(["spine-201"]);
    expect(spine.kpis.conversations.outage).toBe(0);
    expect(spine.headline).toMatch(/shifts to spine-202$/);
    const host = await fails(["esx-01"]);
    expect(sev(host)["checkout-5f8b9c7d6-m4n7q>orders-db-01"]).toBe("outage");
  });
  it("depends on: orders-db-01", async () => {
    const d = await loadDemoImpact(["orders-db-01"]);
    const r = dependsImpact(d.elements, d.conversations, d.ctx);
    expect(r.rows.find((x) => x.label === "esx-01")?.severity).toBe("outage");
    expect(r.rows.find((x) => x.label === "leaf-101")?.severity).toBe(
      "degraded",
    );
  });
});
