import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DistributionBar } from "./DistributionBar";

describe("DistributionBar", () => {
  it("renders count mode with true totals and singular/plural unit formatting", () => {
    const html = renderToStaticMarkup(
      <DistributionBar
        title="Findings"
        mode="count"
        items={[
          {
            id: "cleartext",
            label: "Cleartext protocols",
            p50: 1,
            p95: 1,
            count: 7,
            unit: "sessions",
            status: "attention",
          },
          {
            id: "single",
            label: "Receipt Gap",
            p50: 1,
            p95: 1,
            count: 1,
            unit: "devices",
            status: "attention",
          },
        ]}
      />,
    );
    expect(html).toContain("7 sessions");
    expect(html).toContain("1 device");
    expect(html).not.toContain("1 devices");
  });

  it("renders percentile mode with p50 / p95 labels", () => {
    const html = renderToStaticMarkup(
      <DistributionBar
        title="RTT"
        items={[
          {
            id: "r1",
            label: "10.0.0.1 → 10.0.0.2",
            p50: 12,
            p95: 48,
            unit: "ms",
            status: "ok",
          },
        ]}
      />,
    );
    expect(html).toContain("p50 12 / p95 48 ms");
  });
});
