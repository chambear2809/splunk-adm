import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { SearchClient } from "../data/searchClient";
import { CmdbSection } from "./CmdbSection";
import { CmdbWorkspace } from "./CmdbWorkspace";

const client = {} as SearchClient;

describe("CMDB workspace", () => {
  it("states read-only semantics and waits for a scope before searching", () => {
    const html = renderToStaticMarkup(
      <CmdbWorkspace
        client={client}
        catalog={[]}
        readAssetConfig={async () => undefined}
        scopeSuggestions={["east", "west"]}
      />,
    );
    expect(html).toContain("Atlas never");
    expect(html).toContain("writes to ITSI or to a CMDB");
    expect(html).toContain("your Splunk permissions");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Run reconciliation/);
    expect(html).toContain('<option value="east">');
    for (const size of [200, 250, 300])
      expect(html).toContain(`${size} services`);
    expect(html).not.toContain("Removed");
  });

  it("does not load the optional bundle until the disclosure is opened", () => {
    const html = renderToStaticMarkup(
      <CmdbSection client={client} catalog={[]} />,
    );
    expect(html).toContain("ITSI export and CMDB reconciliation");
    expect(html).not.toContain("Loading");
  });
});
