import { describe, expect, it } from "vitest";
import { demoGraph } from "../provider";
import type { Graph } from "../graph";
import { ownershipEvidence } from "./OwnershipEvidence";
import {
  checkedIdentityContext,
  identityContextFromRow,
} from "../data/identityContext";

const window = { start: 100, end: 400 };
const context = {
  schemaVersion: 1 as const,
  contract: "qualified_v2" as const,
  authority: "identity-producer",
  scope: "tenant-a",
  configRevision: "a".repeat(64),
  observedWindow: window,
};
const graph = (): Graph => ({
  ...demoGraph(),
  demo: false,
  window: {
    start: new Date(100000).toISOString(),
    end: new Date(400000).toISOString(),
  },
  identityContext: context,
  nodes: [
    {
      id: "opaque/service-id",
      kind: "service",
      label: "Wrong display name",
      namespace: "shop",
      cluster: "c1",
      attributes: { service: "checkout/api", environment: "prod" },
    },
    {
      id: "service:guessed",
      kind: "service",
      label: "Never use this",
      cluster: "c1",
      namespace: "shop",
    },
  ],
  edges: [],
});
describe("qualified ownership integration", () => {
  it("uses only explicit source-qualified tuples and preserves slash-permitted service names", () => {
    expect(ownershipEvidence({ graph: graph() }).nativeIdentities).toEqual([
      {
        kind: "service",
        contract: "qualified_v2",
        authority: context.authority,
        scope: context.scope,
        configRevision: context.configRevision,
        observedWindow: window,
        key: {
          service: "checkout/api",
          environment: "prod",
          cluster: "c1",
          namespace: "shop",
        },
      },
    ]);
  });
  it("clears native context on denied source, legacy observations, or demo", () => {
    for (const input of [
      { graph: graph(), unavailableReason: "Source denied" },
      { graph: { ...graph(), identityContext: undefined } },
      { graph: { ...graph(), demo: true } },
    ]) {
      const result = ownershipEvidence(input);
      expect(result.nativeIdentities).toEqual([]);
      expect(result.unavailableReason).toBeTruthy();
    }
  });
  it("rejects provenance for another window and never rebuilds it from a native-looking ID", () => {
    const value = graph();
    value.identityContext = {
      ...context,
      observedWindow: { start: 0, end: 300 },
    };
    expect(ownershipEvidence({ graph: value }).nativeIdentities).toEqual([]);
    expect(ownershipEvidence({}).nativeIdentities).toEqual([]);
  });
  it("strictly validates provenance fields, revisions, and bounds", () => {
    expect(identityContextFromRow(undefined, window)).toBeUndefined();
    expect(identityContextFromRow(JSON.stringify(context), window)).toEqual(
      context,
    );
    for (const value of [
      { ...context, extra: true },
      { ...context, contract: "v1" },
      { ...context, configRevision: "v1" },
      { ...context, scope: "" },
      { ...context, observedWindow: { ...window, start: 100.5 } },
      { ...context, observedWindow: { start: 0, end: 400 } },
    ])
      expect(() => checkedIdentityContext(value, window)).toThrow();
    expect(() => identityContextFromRow("x".repeat(4097), window)).toThrow();
  });
});

it("rejects duplicate and escaped duplicate provenance keys at every depth", () => {
  const source = JSON.stringify(context);
  expect(() =>
    identityContextFromRow(
      source.replace(
        '"authority":"identity-producer"',
        '"authority":"other","authority":"identity-producer"',
      ),
      window,
    ),
  ).toThrow("Duplicate");
  expect(() =>
    identityContextFromRow(
      source.replace('"start":100', '"start":50,"start":100'),
      window,
    ),
  ).toThrow("Duplicate");
  expect(() =>
    identityContextFromRow(
      source.replace(
        '"scope":"tenant-a"',
        '"scope":"other","sco\\u0070e":"tenant-a"',
      ),
      window,
    ),
  ).toThrow("Duplicate");
});
