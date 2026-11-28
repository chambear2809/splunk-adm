import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { ProtocolLensLayout } from "./ProtocolLensLayout";

interface Row {
  id: string;
  name: string;
  attention: boolean;
}

describe("ProtocolLensLayout healthy row preview cap", () => {
  it("collapses > 20 healthy rows to the first 20 with a Show all (N) trigger", () => {
    const rows: Row[] = Array.from({ length: 28 }, (_, idx) => ({
      id: `r-${idx}`,
      name: `host-${idx}`,
      attention: false,
    }));

    const html = renderToStaticMarkup(
      <ProtocolLensLayout<Row>
        title="Test Lens"
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={1700000000}
        latest={1700003600}
        view="overview"
        coverageStatus="ok"
        coverageLabel="1 source"
        verdict="All 28 hosts healthy."
        verdictStatus="ok"
        kpis={[]}
        rows={rows}
        columns={[{ key: "name", header: "Host", render: (r) => r.name }]}
        onScopeChange={vi.fn()}
        onViewChange={vi.fn()}
        onInvestigate={vi.fn()}
        onBackToHub={vi.fn()}
      />,
    );

    expect(html).toContain("host-0");
    expect(html).toContain("host-19");
    expect(html).not.toContain("host-20");
    expect(html).toContain("Show all (28)");
  });

  it("caps long all-flagged tables at 20 rows initially behind Show all and folds cap-only banners into the verdict", () => {
    const rows: Row[] = Array.from({ length: 22 }, (_, idx) => ({
      id: `f-${idx}`,
      name: `flagged-${idx}`,
      attention: true,
    }));

    const html = renderToStaticMarkup(
      <ProtocolLensLayout<Row>
        title="Test Lens"
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={1700000000}
        latest={1700003600}
        view="overview"
        coverageStatus="ok"
        coverageLabel="1 source"
        verdict="22 hosts need attention."
        verdictStatus="attention"
        banner={{
          state: "partial",
          reason:
            "Sample capped at row limit — narrow the UTC window or filter.",
        }}
        kpis={[]}
        rows={rows}
        columns={[{ key: "name", header: "Host", render: (r) => r.name }]}
        onScopeChange={vi.fn()}
        onViewChange={vi.fn()}
        onInvestigate={vi.fn()}
        onBackToHub={vi.fn()}
      />,
    );

    expect(html).toContain("flagged-19");
    expect(html).not.toContain("flagged-20");
    expect(html).toContain("Show all (22)");
    expect(html).toContain('data-testid="protocol-cap-indicator"');
    expect(html).not.toContain('data-testid="protocol-state-banner"');
  });

  it("renders SPL filter bar, bidirectional toggle, window preset selector, table quick-search, and Focus flow button", () => {
    const html = renderToStaticMarkup(
      <ProtocolLensLayout<Row>
        title="TCP Health"
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={1700000000}
        latest={1700003600}
        view="overview"
        coverageStatus="ok"
        coverageLabel="1 source"
        verdict="1 flow healthy."
        verdictStatus="ok"
        kpis={[]}
        rows={[{ id: "r-1", name: "10.0.0.1 -> 10.0.0.2", attention: false }]}
        columns={[{ key: "name", header: "Flow", render: (r) => r.name }]}
        filter={{ src: "10.0.0.1", port: "443", bidirectional: true }}
        filterFields={[
          {
            key: "src",
            label: "Source IP",
            placeholder: "Source IP",
            primary: true,
          },
          {
            key: "dst",
            label: "Dest IP",
            placeholder: "Dest IP",
            primary: true,
          },
          { key: "port", label: "Port", placeholder: "Port", primary: true },
        ]}
        supportsBidirectional
        onApplyFilter={vi.fn()}
        onWindowChange={vi.fn()}
        drawerOpen
        drawerTitle="Flow Detail"
        drawerBody={<div>Detail</div>}
        onFocusFlow={vi.fn()}
        onScopeChange={vi.fn()}
        onViewChange={vi.fn()}
        onInvestigate={vi.fn()}
        onBackToHub={vi.fn()}
      />,
    );

    expect(html).toContain('data-testid="protocol-filter-bar"');
    expect(html).toContain('data-testid="protocol-filter-src"');
    expect(html).toContain('data-testid="protocol-filter-port"');
    expect(html).toContain('data-testid="protocol-filter-bidir"');
    expect(html).toContain('data-testid="protocol-window-select"');
    expect(html).toContain('data-testid="protocol-table-search"');
    expect(html).toContain('data-testid="protocol-focus-flow"');
    expect(html).toContain("10.0.0.1");
    expect(html).toContain("443");
  });
});
