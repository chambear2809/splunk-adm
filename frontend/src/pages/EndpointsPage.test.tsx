import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { EndpointsPage, returnApplicationURL } from "./EndpointsPage";
import { csvRow } from "../csv";

describe("EndpointsPage", () => {
  it("presents bounded inputs for a live one-hop endpoint workflow", () => {
    const html = renderToStaticMarkup(
      <EndpointsPage
        live
        client={{ search: vi.fn() }}
        configurationClient={{ read: vi.fn() }}
        initial={{ address: "10.0.0.1", scope: "prod", start: 100, end: 200 }}
      />,
    );
    expect(html).toContain("Endpoint investigation");
    expect(html).toContain('aria-label="IP address"');
    expect(html).toContain('aria-label="Verified routing scope"');
    expect(html).toContain('aria-label="Start time"');
    expect(html).toContain('aria-label="End time"');
    expect(html).toContain("Inspect observed conversations");
    expect(html).toContain(":40.000");
  });
  it("returns only to a validated same-origin application map and protects CSV formulas", () => {
    const map = returnApplicationURL(
      "https://splunk.test/en-US/app/splunk_adm/map?service=frontend&environment=prod&cluster=c1&namespace=shop&mode=live",
      "https://splunk.test",
      "/en-US/app/splunk_adm/endpoints",
    );
    expect(map).toContain("/en-US/app/splunk_adm/map?");
    expect(
      returnApplicationURL(
        "https://evil.test/map",
        "https://splunk.test",
        "/app/splunk_adm/endpoints",
      ),
    ).toBeUndefined();
    expect(
      returnApplicationURL(
        "https://splunk.test/app/splunk_adm/map",
        "https://splunk.test",
        "/app/splunk_adm/endpoints",
      ),
    ).toBeUndefined();
    expect(csvRow(["=DANGEROUS()"])).toBe("'=DANGEROUS()");
  });
});
