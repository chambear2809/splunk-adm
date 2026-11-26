import { describe, expect, it } from "vitest";
import source from "../../../fixtures/business-services/synthetic-v2.json";
import type { CatalogRow } from "../data/catalog";
import { previewBusinessServiceImport } from "../businessServices/import";
import {
  businessServiceParents,
  catalogServiceKeys,
  observedEntities,
  observedServiceDependencies,
} from "./itsiInputs";
import type {
  EndpointObservation,
  ObservedRelationship,
} from "./reconciliation";

const time = (value: string) => Date.parse(value) / 1000;
const window = {
  start: time("2026-01-10T00:00:00Z"),
  end: time("2026-01-20T00:00:00Z"),
};
const key = (service: string) => ({
  service,
  environment: "prod",
  cluster: "cluster-a",
  namespace: "shop",
});
const bound = (service: string): EndpointObservation => ({
  kind: "pod",
  identityState: "resolved",
  service: key(service),
  serviceState: "bound",
});
const relationship = (
  client: EndpointObservation,
  server: EndpointObservation,
  overrides: Partial<ObservedRelationship> = {},
): ObservedRelationship => ({
  scope: "cluster-east",
  clientIp: "10.0.0.1",
  serverIp: "10.0.0.2",
  serverPort: 443,
  transport: "tcp",
  firstSeen: 100,
  lastSeen: 200,
  blocked: false,
  client,
  server,
  ...overrides,
});
const catalogRow = (overrides: Partial<CatalogRow> = {}): CatalogRow => ({
  _key: "cluster-a/shop/orders/api",
  ...key("orders/api"),
  identity_contract: "qualified_v2",
  identityContext: {
    schemaVersion: 1,
    contract: "qualified_v2",
    authority: "native-producer",
    scope: "cluster-east",
    configRevision: "config-v1",
    observedWindow: window,
  },
  ...overrides,
});

describe("observed service dependencies", () => {
  it("links services only when both sides have exactly one binding", () => {
    const edges = observedServiceDependencies([
      relationship(bound("web"), bound("api")),
      relationship(bound("web"), bound("api"), {
        firstSeen: 50,
        lastSeen: 300,
      }),
      relationship(bound("web"), { ...bound("db"), serviceState: "ambiguous" }),
      relationship(bound("web"), {
        identityState: "none",
        serviceState: "unbound",
      }),
      relationship(bound("web"), bound("web")),
    ]);
    expect(edges).toEqual([
      {
        from: key("web"),
        to: key("api"),
        firstSeen: 50,
        lastSeen: 300,
        conversations: 2,
      },
    ]);
  });
});

describe("observed entities", () => {
  it("exports resolved infrastructure, not pods, and drops conflicting identities", () => {
    const vm: EndpointObservation = {
      kind: "vm",
      name: "db-01",
      identityState: "resolved",
      serviceState: "not_workload",
    };
    const entities = observedEntities([
      relationship(bound("web"), vm),
      relationship(
        bound("web"),
        { ...vm, name: "db-02" },
        { serverIp: "10.0.0.3" },
      ),
      relationship(
        bound("web"),
        { ...vm, name: "db-03" },
        { serverIp: "10.0.0.3" },
      ),
      relationship(
        bound("web"),
        { ...vm, identityState: "ambiguous" },
        { serverIp: "10.0.0.4" },
      ),
    ]);
    expect(entities).toEqual([
      {
        scope: "cluster-east",
        ip: "10.0.0.2",
        kind: "vm",
        name: "db-01",
        firstSeen: 100,
        lastSeen: 200,
      },
    ]);
  });
});

describe("catalog services", () => {
  it("skips scope fallback and scope-error rows", () => {
    expect(
      catalogServiceKeys([
        catalogRow(),
        catalogRow({ _key: "scope:east" }),
        catalogRow({ _key: "x", scopeError: "ambiguous" }),
      ]),
    ).toEqual([key("orders/api")]);
  });
});

describe("business service parents", () => {
  const preview = previewBusinessServiceImport(JSON.stringify(source));

  it("uses only bindings that resolve against qualified catalog identity", () => {
    expect(businessServiceParents([catalogRow()], preview, window)).toEqual({
      parents: [
        {
          serviceName: "Payments",
          serviceId: "business-payments",
          authority: "cmdb-east",
          members: [key("orders/api")],
        },
      ],
      excluded: [],
    });
  });

  it("excludes bindings without qualified provenance instead of guessing", () => {
    const { parents, excluded } = businessServiceParents(
      [catalogRow({ identityContext: undefined })],
      preview,
      window,
    );
    expect(parents).toEqual([]);
    expect(excluded[0].item).toBe("Binding cmdb-east/binding-1");
    expect(businessServiceParents([catalogRow()], undefined, window)).toEqual({
      parents: [],
      excluded: [],
    });
  });
});
