import { describe, expect, it } from "vitest";
import {
  breakCycles,
  buildItsiExport,
  clampBatchSize,
  itsiBrokenEdgesCsv,
  itsiEntitiesCsv,
  itsiServicesCsv,
  itsiServiceTitle,
  itsiTitleError,
  type AtlasServiceKey,
  type ObservedServiceDependency,
} from "./itsiExport";

const key = (service: string): AtlasServiceKey => ({
  service,
  environment: "prod",
  cluster: "c1",
  namespace: "shop",
});
const dep = (from: string, to: string): ObservedServiceDependency => ({
  from: key(from),
  to: key(to),
  firstSeen: 100,
  lastSeen: 200,
  conversations: 1,
});
const window = { start: 1_700_000_000, end: 1_700_086_400 };
const t = (name: string) => itsiServiceTitle(key(name));

describe("ITSI titles", () => {
  it("rejects separators, quotes, control and formula characters", () => {
    expect(itsiTitleError("checkout (prod/c1/shop)")).toBeUndefined();
    for (const bad of [
      "a,b",
      "a;b",
      "a|b",
      "a^b",
      "a\tb",
      'a"b',
      "=cmd",
      "-x",
      " a",
      "a\nb",
      "",
    ])
      expect(itsiTitleError(bad)).toBeDefined();
    expect(itsiTitleError("x".repeat(256))).toBeDefined();
  });
});

describe("cycle breaking", () => {
  it("removes every back edge deterministically and reports each cycle", () => {
    const edges = new Map([
      ["a", new Set(["b"])],
      ["b", new Set(["c"])],
      ["c", new Set(["a", "d"])],
      ["d", new Set(["d2"])],
      ["d2", new Set(["d"])],
    ]);
    const first = breakCycles(["d2", "c", "b", "a", "d"], edges);
    const second = breakCycles(["a", "b", "c", "d", "d2"], edges);
    expect(first).toEqual(second);
    expect(first.broken).toEqual([
      { from: "c", to: "a", cycle: ["a", "b", "c", "a"] },
      { from: "d2", to: "d", cycle: ["d", "d2", "d"] },
    ]);
    expect(first.kept.get("c")).toEqual(["d"]);
  });

  it("produces an acyclic export whose batches only reference earlier or same batches", () => {
    const names = Array.from(
      { length: 450 },
      (_, i) => `svc${String(i).padStart(3, "0")}`,
    );
    const dependencies = names.slice(1).map((name, i) => dep(name, names[i]));
    dependencies.push(dep(names[0], names[449]));
    const result = buildItsiExport({
      services: names.map(key),
      dependencies,
      window,
      batchSize: 200,
    });
    expect(result.batches.map((b) => b.rows.length)).toEqual([200, 200, 50]);
    expect(result.brokenEdges).toHaveLength(1);
    expect(result.dependencyCount).toBe(449);
    const batchOf = new Map<string, number>();
    for (const batch of result.batches)
      for (const row of batch.rows) batchOf.set(row.service_title, batch.index);
    for (const batch of result.batches)
      for (const row of batch.rows)
        for (const target of row.services_depends_on.split(",").filter(Boolean))
          expect(batchOf.get(target)!).toBeLessThanOrEqual(batch.index);
  });
});

describe("buildItsiExport", () => {
  it("emits ITSI service rows with comma-separated dependencies", () => {
    const result = buildItsiExport({
      services: [key("web"), key("api")],
      dependencies: [dep("web", "api"), dep("web", "db"), dep("api", "api")],
      window,
    });
    expect(result.serviceCount).toBe(3);
    const web = result.batches[0].rows.find(
      (r) => r.service_title === t("web"),
    )!;
    expect(web.services_depends_on).toBe(`${t("api")},${t("db")}`);
    expect(web.service_description).toContain("not CMDB records");
    expect(result.batches[0].rows.at(-1)!.service_title).toBe(t("web"));
    const csv = itsiServicesCsv(result.batches[0]).split("\r\n");
    expect(csv[0]).toBe(
      "service_title,service_description,services_depends_on",
    );
    expect(csv.find((line) => line.startsWith(t("web")))).toContain(
      `"${t("api")},${t("db")}"`,
    );
  });

  it("excludes unsafe or colliding titles rather than rewriting them", () => {
    const result = buildItsiExport({
      services: [key("a,b"), key("ok")],
      dependencies: [],
      businessServices: [
        {
          serviceName: t("ok"),
          serviceId: "s1",
          authority: "cmdb",
          members: [],
        },
      ],
      window,
    });
    expect(result.serviceCount).toBe(0);
    expect(result.excluded.map((e) => e.reason).join(" ")).toContain(
      "separator",
    );
    expect(result.excluded.map((e) => e.reason).join(" ")).toContain(
      "same ITSI title",
    );
  });

  it("adds business parents above their resolved members only", () => {
    const result = buildItsiExport({
      services: [key("web")],
      dependencies: [],
      businessServices: [
        {
          serviceName: "Payments",
          serviceId: "payments",
          authority: "cmdb-east",
          members: [key("web"), key("missing")],
        },
      ],
      window,
    });
    const rows = result.batches[0].rows;
    expect(rows.map((r) => r.service_title)).toEqual([t("web"), "Payments"]);
    expect(rows[1].services_depends_on).toBe(t("web"));
    expect(rows[1].service_description).toContain("not verified");
    expect(result.excluded[0].reason).toContain(
      "not an exported Atlas service",
    );
  });

  it("exports scoped entities with an IP alias and bounded size", () => {
    const result = buildItsiExport({
      services: [],
      dependencies: [],
      entities: [
        {
          scope: "east",
          ip: "10.0.0.5",
          kind: "vm",
          name: "db-01",
          firstSeen: 1,
          lastSeen: 2,
        },
        {
          scope: "east",
          ip: "10.0.0.5",
          kind: "vm",
          name: "db-01",
          firstSeen: 1,
          lastSeen: 2,
        },
        {
          scope: "west",
          ip: "10.0.0.6",
          kind: "k8s_node",
          firstSeen: 1,
          lastSeen: 2,
        },
      ],
      window,
    });
    expect(result.entities.map((e) => e.entity_title)).toEqual([
      "10.0.0.6 (west)",
      "db-01 (east)",
    ]);
    expect(itsiEntitiesCsv(result.entities).split("\r\n")[0]).toBe(
      "entity_title,entity_description,ip,atlas_scope,atlas_identity_kind",
    );
  });

  it("clamps batches to ITSI guidance and requires a window", () => {
    expect(clampBatchSize(10)).toBe(200);
    expect(clampBatchSize(1000)).toBe(300);
    expect(clampBatchSize(undefined)).toBe(250);
    expect(() =>
      buildItsiExport({
        services: [],
        dependencies: [],
        window: { start: 5, end: 5 },
      }),
    ).toThrow(/window/);
  });

  it("reports removed edges as CSV", () => {
    expect(
      itsiBrokenEdgesCsv([{ from: "a", to: "b", cycle: ["b", "a", "b"] }]),
    ).toBe("dependent_service,removed_dependency,cycle\r\na,b,b > a > b");
  });
});
