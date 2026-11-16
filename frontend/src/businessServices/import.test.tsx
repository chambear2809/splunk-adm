import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { BusinessServiceImport } from "./BusinessServiceImport";
import { previewBusinessServiceImport } from "./import";

const record = {
  record_id: "claim-1",
  revision: 1,
  service_id: "payments",
  service_name: "Payments",
  member_kind: "service",
  member_id: "cluster/namespace/checkout",
  scope: "east",
  team_id: "commerce",
  team_name: "Commerce",
  criticality: "critical",
  validity_basis: "source_interval",
  valid_from: "2026-01-01T00:00:00Z",
  valid_to: null,
};
const document = (records: unknown[]) =>
  JSON.stringify({
    schema_version: 1,
    authority: "cmdb",
    snapshot_id: "snapshot-1",
    snapshot_at: "2026-02-01T00:00:00Z",
    records,
  });

describe("business service import", () => {
  it("retains stable IDs, source interval and provenance without creating traffic", () => {
    const result = previewBusinessServiceImport(document([record]));
    expect(result.errors).toEqual([]);
    expect(result.claims[0]).toMatchObject({
      serviceId: "payments",
      memberId: "cluster/namespace/checkout",
      teamId: "commerce",
      authority: "cmdb",
      validity: { basis: "source_interval", from: 1767225600 },
    });
    expect(result.claims[0]).not.toHaveProperty("edge");
  });
  it("keeps current snapshots point-in-time and refuses historical dates", () => {
    const current = {
      ...record,
      validity_basis: "snapshot_current",
      valid_from: undefined,
      valid_to: undefined,
    };
    expect(
      previewBusinessServiceImport(document([current])).claims[0].validity,
    ).toEqual({ basis: "snapshot_current", at: 1769904000 });
    expect(
      previewBusinessServiceImport(
        document([{ ...current, valid_from: "2026-01-01T00:00:00Z" }]),
      ).errors[0].row,
    ).toBe(1);
  });
  it("retains conflicting ownership claims and permits membership in two services", () => {
    const competing = { ...record, record_id: "other", team_id: "other-team" };
    const separate = { ...record, record_id: "third", service_id: "catalog" };
    const result = previewBusinessServiceImport(
      document([record, competing, separate]),
    );
    expect(result.claims).toHaveLength(3);
    expect(result.conflictCount).toBe(1);
    expect(result.conflicts[0].rows).toEqual([1, 2]);
  });
  it("retains old revisions but resolves conflict checks at latest revision", () => {
    const old = { ...record, revision: 0, team_id: "old-team" };
    const result = previewBusinessServiceImport(
      document([old, record, { ...record, record_id: "second" }]),
    );
    expect(result.claims).toHaveLength(3);
    expect(result.conflictCount).toBe(0);
  });
  it("fails the whole batch on invalid dates, missing identity, extra fields or unsafe references", () => {
    for (const invalid of [
      { ...record, valid_from: "2026-02-30T00:00:00Z" },
      { ...record, valid_from: "2026-02-01T00:00:00" },
      { ...record, valid_to: "2025-01-01T00:00:00Z" },
      { ...record, service_id: "" },
      { ...record, extra: "hidden" },
      { ...record, runbook: { label: "Guide", url: "javascript:alert(1)" } },
      {
        ...record,
        runbook: { label: "Guide", url: "https://user:pass@example.com/" },
      },
      {
        ...record,
        escalation: { label: "Help", url: "https://example.com/?token=x" },
      },
    ]) {
      const result = previewBusinessServiceImport(document([record, invalid]));
      expect(result.errors[0].row).toBe(2);
      expect(result.claims).toEqual([]);
    }
  });
  it("rejects duplicate JSON fields and repeated source revisions", () => {
    expect(
      previewBusinessServiceImport('{"schema_version":1,"schema_version":2}')
        .errors[0].message,
    ).toMatch(/Duplicate/);
    expect(
      previewBusinessServiceImport(document([record, record])).conflictCount,
    ).toBe(1);
  });
  it("presents a local preview rather than claiming persistence", () => {
    const html = renderToStaticMarkup(<BusinessServiceImport />);
    expect(html).toContain("Preview import");
    expect(html).toContain("does not save or verify");
    expect(html).not.toContain("Apply import");
  });
});
