import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import fixture from "../../../fixtures/business-services/synthetic-v2.json";
import {
  BusinessOwnershipContext,
  nativeReferenceDocument,
} from "./BusinessOwnershipContext";
import { previewBusinessServiceImport } from "./import";
import type { NativeServiceIdentity } from "./bindings";

const target = previewBusinessServiceImport(JSON.stringify(fixture)).bindings[0]
  .target;
const native: NativeServiceIdentity = {
  ...target,
  contract: "qualified_v2",
  observedWindow: { start: 1768000000, end: 1768100000 },
};
const time = { kind: "point" as const, at: 1768050000 };

describe("business ownership context", () => {
  it("makes loading explicit and shows unavailable native context without inventing an owner", () => {
    const html = renderToStaticMarkup(
      <BusinessOwnershipContext
        nativeIdentities={[]}
        time={time}
        unavailableReason="Source access unavailable"
      />,
    );
    expect(html).toContain("Load local assertions");
    expect(html).toContain("Source access unavailable");
    expect(html).toContain("not verified ownership or an access grant");
    expect(html).not.toContain("Commerce");
    expect(html).not.toContain("Download references");
  });
  it("fails closed when an unavailable reason accompanies a stale identity", () => {
    const html = renderToStaticMarkup(
      <BusinessOwnershipContext
        nativeIdentities={[native]}
        time={time}
        unavailableReason="Source access revoked"
      />,
    );
    expect(html).toContain("Source access revoked");
    expect(html).not.toContain("Download references");
  });
  it("offers only consent-gated native reference export", () => {
    const html = renderToStaticMarkup(
      <BusinessOwnershipContext
        nativeIdentities={[native]}
        time={time}
        compact
      />,
    );
    expect(html).toContain("Download references");
    expect(html).toMatch(/type="checkbox"/);
    expect(html).not.toMatch(/type="checkbox"[^>]*checked/);
    expect(html).toMatch(/disabled=""[^>]*>Download references/);
    const document = JSON.parse(
      nativeReferenceDocument([
        { ...native, privateExtra: "must-not-export" } as NativeServiceIdentity,
      ])!,
    );
    expect(document.schema_version).toBe(1);
    expect(document.references[0].key.service).toBe("orders/api");
    expect(document.references[0]).not.toHaveProperty("privateExtra");
    expect(JSON.stringify(document)).not.toContain("cmdb-east");
    expect(JSON.stringify(document)).not.toContain("mapping-ticket-123");
  });
  it("bounds and validates exported native identities", () => {
    expect(nativeReferenceDocument([])).toBeUndefined();
    expect(
      nativeReferenceDocument([null as unknown as NativeServiceIdentity]),
    ).toBeUndefined();
    expect(
      nativeReferenceDocument(Array.from({ length: 101 }, () => native)),
    ).toBeUndefined();
    expect(
      nativeReferenceDocument([
        { ...native, observedWindow: { start: 4, end: 4 } },
      ]),
    ).toBeUndefined();
    expect(
      nativeReferenceDocument([
        { ...native, contract: "unknown" as "qualified_v2" },
      ]),
    ).toBeUndefined();
  });
});
