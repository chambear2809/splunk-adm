import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import source from "../../../fixtures/business-services/synthetic-v2.json";
import { BusinessServiceImport } from "./BusinessServiceImport";
import { previewBusinessServiceImport } from "./import";
import {
  resolveBusinessOwnership,
  type NativeServiceIdentity,
} from "./bindings";
import { readLocalImport, saveLocalImport } from "./localImport";

const text = (value: unknown) => JSON.stringify(value);
const time = (value: string) => Date.parse(value) / 1000;
const preview = () => previewBusinessServiceImport(text(source));
const native = (): NativeServiceIdentity => ({
  ...preview().bindings[0].target,
  contract: "qualified_v2",
  observedWindow: {
    start: time("2026-01-10T00:00:00Z"),
    end: time("2026-01-20T00:00:00Z"),
  },
});
const point = { kind: "point" as const, at: time("2026-01-15T00:00:00Z") };

describe("qualified business bindings", () => {
  it("parses explicit v2 claims and separately scoped technical targets", () => {
    const value = preview();
    expect(value.errors).toEqual([]);
    expect(value.bindings[0].authority).toBe("cmdb-east");
    expect(value.bindings[0].target.authority).toBe("native-producer");
    expect(value.bindings[0].target.key.service).toBe("orders/api");
    expect(value.bindings[0].proofReference).toBe("mapping-ticket-123");
    const result = resolveBusinessOwnership(
      value.claims,
      value.bindings,
      [native()],
      point,
    );
    expect(result[0]).toMatchObject({
      status: "resolved",
      coverage: "covers",
      conflict: false,
    });
    expect(result[0]).not.toHaveProperty("edge");
  });
  it("refuses authority, scope, configuration and identity mismatches without guessing", () => {
    const v = preview();
    const context = native();
    for (const other of [
      { ...context, authority: "cmdb-east" },
      { ...context, scope: "business-east" },
      { ...context, key: { ...context.key, service: "orders" } },
      { ...context, key: { ...context.key, namespace: "other" } },
    ]) {
      expect(
        resolveBusinessOwnership(v.claims, v.bindings, [other], point)[0]
          .status,
      ).toBe("unresolved_native");
    }
    expect(
      resolveBusinessOwnership(
        v.claims,
        v.bindings,
        [{ ...context, configRevision: "new" }],
        point,
      )[0].status,
    ).toBe("stale_configuration");
    expect(
      resolveBusinessOwnership(v.claims, v.bindings, [], point)[0].status,
    ).toBe("unresolved_native");
    expect(
      resolveBusinessOwnership(
        v.claims,
        v.bindings,
        [null as unknown as NativeServiceIdentity],
        point,
      )[0].status,
    ).toBe("unresolved_native");
    // Caller removes native context when current source access is revoked.
    expect(
      resolveBusinessOwnership(v.claims, v.bindings, [context], point)[0]
        .status,
    ).toBe("resolved");
    expect(
      resolveBusinessOwnership(v.claims, v.bindings, [], point)[0].coverage,
    ).toBe("unknown");
    expect(
      resolveBusinessOwnership([], v.bindings, [context], point)[0].status,
    ).toBe("unresolved_claim");
    expect(
      resolveBusinessOwnership(
        v.claims,
        [
          {
            ...v.bindings[0],
            claim: { ...v.bindings[0].claim, authority: "other-cmdb" },
          },
        ],
        [context],
        point,
      )[0].status,
    ).toBe("unresolved_claim");
    expect(
      resolveBusinessOwnership(
        v.claims,
        v.bindings,
        [{ ...context, contract: "wrong" as "qualified_v2" }],
        point,
      )[0].status,
    ).toBe("unresolved_native");
  });
  it("limits coverage to all three independent temporal boundaries", () => {
    const v = preview();
    const interval = {
      kind: "interval" as const,
      from: time("2026-01-01T00:00:00Z"),
      to: time("2026-01-25T00:00:00Z"),
    };
    expect(
      resolveBusinessOwnership(v.claims, v.bindings, [native()], interval)[0]
        .coverage,
    ).toBe("partial");
    expect(
      resolveBusinessOwnership(v.claims, v.bindings, [native()], {
        kind: "point",
        at: time("2026-01-25T00:00:00Z"),
      })[0].coverage,
    ).toBe("unknown");
    const current = {
      ...v.bindings[0],
      validity: { basis: "snapshot_current" as const, at: point.at },
      snapshotAt: point.at,
    };
    expect(
      resolveBusinessOwnership(v.claims, [current], [native()], point)[0]
        .coverage,
    ).toBe("covers");
    expect(
      resolveBusinessOwnership(v.claims, [current], [native()], interval)[0]
        .coverage,
    ).toBe("partial");
    expect(
      resolveBusinessOwnership(v.claims, [current], [native()], {
        kind: "point",
        at: point.at + 1,
      })[0].coverage,
    ).toBe("unknown");
    const endingClaim = {
      ...v.claims[0],
      validity: {
        basis: "source_interval" as const,
        from: time("2026-01-01T00:00:00Z"),
        to: time("2026-01-12T00:00:00Z"),
      },
    };
    const laterBinding = {
      ...v.bindings[0],
      validity: {
        basis: "source_interval" as const,
        from: time("2026-01-15T00:00:00Z"),
      },
    };
    expect(
      resolveBusinessOwnership(
        [endingClaim],
        [laterBinding],
        [native()],
        interval,
      )[0].coverage,
    ).toBe("unknown");
  });
  it("preserves conflicting, duplicate, and superseded assertions", () => {
    const v = preview();
    const second = {
      ...v.bindings[0],
      recordId: "binding-2",
      target: {
        ...v.bindings[0].target,
        key: { ...v.bindings[0].target.key, service: "other" },
      },
    };
    expect(
      resolveBusinessOwnership(
        v.claims,
        [v.bindings[0], second],
        [native()],
        point,
      )[0].conflict,
    ).toBe(true);
    expect(
      resolveBusinessOwnership(
        v.claims,
        [v.bindings[0], v.bindings[0]],
        [native()],
        point,
      )[0].conflict,
    ).toBe(true);
    expect(
      resolveBusinessOwnership(
        v.claims,
        [{ ...v.bindings[0], revision: 0 }, v.bindings[0]],
        [native()],
        point,
      ),
    ).toHaveLength(1);
    expect(
      resolveBusinessOwnership(
        [{ ...v.claims[0], revision: 3 }],
        v.bindings,
        [native()],
        point,
      )[0].status,
    ).toBe("unresolved_claim");
  });
  it("fails closed on invalid binding fields and accepts version 1 without bindings", () => {
    for (const binding of [
      { ...source.bindings[0], proof_reference: "https://example.com/private" },
      {
        ...source.bindings[0],
        target: { ...source.bindings[0].target, kind: "asset" },
      },
      {
        ...source.bindings[0],
        claim: { ...source.bindings[0].claim, extra: "x" },
      },
      { ...source.bindings[0], valid_from: "bad" },
    ]) {
      const result = previewBusinessServiceImport(
        text({ ...source, bindings: [binding] }),
      );
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.claims).toEqual([]);
      expect(result.bindings).toEqual([]);
    }
    const legacy = { ...source, schema_version: 1, bindings: undefined };
    expect(previewBusinessServiceImport(text(legacy)).bindings).toEqual([]);
    expect(
      previewBusinessServiceImport(text({ ...source, bindings: undefined }))
        .errors,
    ).toEqual([]);
    expect(
      previewBusinessServiceImport(text({ ...legacy, bindings: [] })).errors
        .length,
    ).toBeGreaterThan(0);
    expect(
      previewBusinessServiceImport(
        text({ ...source, bindings: [source.bindings[0], source.bindings[0]] }),
      ).bindingConflictCount,
    ).toBe(1);
  });
  it("retains v2 on local save and exposes no invented business proof", () => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    } as unknown as Storage;
    expect(saveLocalImport(storage, text(source)).status).toBe("ready");
    const restored = readLocalImport(storage);
    expect(restored.status).toBe("ready");
    if (restored.status === "ready")
      expect(restored.preview.bindings).toHaveLength(1);
    expect(renderToStaticMarkup(<BusinessServiceImport />)).toContain(
      "does not save or verify",
    );
  });
});
