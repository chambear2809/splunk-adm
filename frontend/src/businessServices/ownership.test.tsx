import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { previewBusinessServiceImport } from "./import";
import { annotateOwnership, type ResolvedMember } from "./ownership";
import { OwnershipAnnotations } from "./OwnershipAnnotations";
import {
  readLocalImport,
  saveLocalImport,
  clearLocalImport,
} from "./localImport";

const row = {
  record_id: "one",
  revision: 1,
  service_id: "payments",
  service_name: "Payments",
  member_kind: "service",
  member_id: "cluster/shop/pay",
  scope: "east",
  team_id: "commerce",
  team_name: "Commerce",
  criticality: "critical",
  validity_basis: "source_interval",
  valid_from: "2026-01-01T00:00:00Z",
  valid_to: "2026-02-01T00:00:00Z",
};
const doc = (records: unknown[]) =>
  JSON.stringify({
    schema_version: 1,
    authority: "cmdb",
    snapshot_id: "s1",
    snapshot_at: "2026-03-01T00:00:00Z",
    records,
  });
const member: ResolvedMember = {
  authority: "cmdb",
  scope: "east",
  memberKind: "service",
  memberId: "cluster/shop/pay",
};
const claims = (records: unknown[]) =>
  previewBusinessServiceImport(doc(records)).claims;

describe("business ownership annotations", () => {
  it("requires a qualified resolved member and observes interval boundaries", () => {
    const list = claims([row]);
    expect(
      annotateOwnership(list, [{ ...member, scope: "west" }], {
        kind: "point",
        at: 1768000000,
      }),
    ).toEqual([]);
    expect(
      annotateOwnership(list, [member], { kind: "point", at: 1768000000 })[0]
        .coverage,
    ).toBe("covers");
    expect(
      annotateOwnership(list, [member], { kind: "point", at: 1769904000 })[0]
        .coverage,
    ).toBe("unknown");
    expect(
      annotateOwnership(list, [member], {
        kind: "interval",
        from: 1768000000,
        to: 1770000000,
      })[0].coverage,
    ).toBe("partial");
  });
  it("preserves conflicts and current-only limits without changing technical priority", () => {
    const current = {
      ...row,
      validity_basis: "snapshot_current",
      valid_from: undefined,
      valid_to: undefined,
    };
    const list = claims([
      current,
      { ...current, record_id: "two", team_id: "other" },
    ]);
    expect(
      annotateOwnership(list, [member], {
        kind: "point",
        at: 1772323200,
      }).every((a) => a.conflict),
    ).toBe(true);
    const html = renderToStaticMarkup(
      <OwnershipAnnotations
        claims={list}
        members={[member]}
        time={{ kind: "point", at: 1768000000 }}
      />,
    );
    expect(html).toContain("historical ownership unavailable");
    expect(html).toContain("technical priority remains separate");
    expect(html).toContain("selected time is unknown");
  });
  it("retains duplicate source revision conflicts even across different services or graph members", () => {
    const preview = previewBusinessServiceImport(
      doc([row, { ...row, service_id: "catalog", member_id: "other" }]),
    );
    expect(preview.conflictCount).toBe(1);
    const annotations = annotateOwnership(preview.claims, [member], {
      kind: "point",
      at: 1768000000,
    });
    expect(annotations).toHaveLength(1);
    expect(annotations[0].conflict).toBe(true);
    expect(
      renderToStaticMarkup(
        <OwnershipAnnotations
          claims={preview.claims}
          members={[member]}
          time={{ kind: "point", at: 1768000000 }}
        />,
      ),
    ).toContain("conflicting source records");
  });
  it("limits open intervals to their source snapshot and uses latest revisions", () => {
    const list = claims([
      { ...row, revision: 0 },
      { ...row, revision: 1, valid_to: null },
    ]);
    expect(
      annotateOwnership(list, [member], { kind: "point", at: 1772323201 }),
    ).toHaveLength(1);
    expect(
      annotateOwnership(list, [member], { kind: "point", at: 1772323201 })[0]
        .coverage,
    ).toBe("unknown");
  });
});

describe("local import", () => {
  it("validates on save and read and clears only its own local batch", () => {
    const map = new Map<string, string>();
    const storage = {
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => {
        map.set(k, v);
      },
      removeItem: (k: string) => {
        map.delete(k);
      },
    } as Storage;
    expect(saveLocalImport(storage, doc([row])).status).toBe("ready");
    expect(saveLocalImport(storage, "{}").status).toBe("uncertain");
    expect(readLocalImport(storage).status).toBe("ready");
    map.set([...map.keys()][0], "{}");
    expect(readLocalImport(storage).status).toBe("uncertain");
    expect(clearLocalImport(storage).status).toBe("empty");
    expect(readLocalImport(undefined).status).toBe("unavailable");
    expect(
      readLocalImport({
        getItem: () => {
          throw Error("denied");
        },
      } as unknown as Storage).status,
    ).toBe("unavailable");
  });
});
