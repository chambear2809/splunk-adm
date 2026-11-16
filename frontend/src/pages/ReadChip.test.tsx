import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ReadChip } from "./MapPage";

describe("ReadChip", () => {
  it("labels exact summarized windows and partial coverage tersely", () => {
    expect(
      renderToStaticMarkup(
        <ReadChip
          read={{
            coverage: 100,
            windowSeconds: 3600,
            summarySeconds: 3300,
            rawTailSeconds: 300,
          }}
        />,
      ),
    ).toContain("Summarized · 5 min raw");
    expect(
      renderToStaticMarkup(
        <ReadChip
          read={{
            coverage: 91,
            windowSeconds: 3600,
            summarySeconds: 3300,
            pendingSeconds: 300,
          }}
        />,
      ),
    ).toContain("newest 5 min loading");
    expect(
      renderToStaticMarkup(
        <ReadChip
          read={{ coverage: 42, windowSeconds: 3600, summarySeconds: 1500 }}
        />,
      ),
    ).toContain("Summary coverage 42%");
    expect(
      renderToStaticMarkup(
        <ReadChip read={{ coverage: 3, windowSeconds: 86400 }} />,
      ),
    ).toContain("Sampled 3%");
    expect(
      renderToStaticMarkup(
        <ReadChip read={{ coverage: 100, windowSeconds: 900 }} />,
      ),
    ).toBe("");
  });
});
