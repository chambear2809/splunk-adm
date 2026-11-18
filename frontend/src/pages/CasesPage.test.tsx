import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { CasesPage, validCasesWindow } from "./CasesPage";

vi.mock("../investigations/caseClient", () => ({
  splunkCaseClient: () => ({
    capabilities: vi.fn(),
    list: vi.fn(),
    get: vi.fn(),
  }),
}));

describe("CasesPage", () => {
  it("accepts only absolute UTC windows", () => {
    expect(
      validCasesWindow("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"),
    ).toBe(true);
    expect(
      validCasesWindow("2026-02-30T00:00:00Z", "2026-03-01T01:00:00Z"),
    ).toBe(false);
    expect(
      validCasesWindow("0000-01-01T00:00:00Z", "0000-01-01T01:00:00Z"),
    ).toBe(false);
    expect(
      validCasesWindow("2024-02-29T00:00:00.123Z", "2024-02-29T01:00:00Z"),
    ).toBe(true);
    expect(
      validCasesWindow("2026-01-01T00:00:00", "2026-01-01T01:00:00Z"),
    ).toBe(false);
    expect(
      validCasesWindow("2026-01-01T01:00:00Z", "2026-01-01T00:00:00Z"),
    ).toBe(false);
  });

  it("renders source-independent case window controls without a search client", () => {
    const html = renderToStaticMarkup(<CasesPage />);
    expect(html).toContain("Add and share notes for a time window");
    expect(html).toContain('aria-label="Case window"');
    expect(html).toContain("Case window start (UTC)");
    expect(html).toContain("Case window end (UTC)");
    expect(html).not.toContain('aria-label="Shared investigation cases"');
    expect(html).not.toContain("Case window fixed for this session");
  });
});
