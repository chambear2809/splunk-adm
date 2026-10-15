import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { createElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@splunk/react-ui/Tooltip", () => ({
  default: ({
    content,
    renderAnchor,
  }: {
    content: string;
    renderAnchor: (props: Record<string, unknown>) => ReactNode;
  }) =>
    createElement(
      "span",
      { "data-tooltip-content": content },
      renderAnchor({ "aria-describedby": "tooltip-content" }),
    ),
}));

import InfoTip from "./InfoTip";
import { terms } from "./glossary";

describe("InfoTip", () => {
  it("renders a keyboard-focusable button with the glossary explanation", () => {
    const html = renderToStaticMarkup(
      createElement(InfoTip, { term: "SNAT", children: "translation" }),
    );
    expect(html).toContain('type="button"');
    expect(html).toContain('aria-label="Explain SNAT"');
    expect(html).toContain('aria-describedby="tooltip-content"');
    expect(html).toContain(terms.SNAT);
    expect(html).not.toContain("title=");
  });

  it("has a definition for every literal InfoTip term used in the UI", () => {
    const root = fileURLToPath(new URL("./", import.meta.url));
    const walk = (directory: string): string[] =>
      readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
        entry.isDirectory()
          ? walk(join(directory, entry.name))
          : entry.name.endsWith(".tsx") && !entry.name.includes(".test.")
            ? [join(directory, entry.name)]
            : [],
      );
    const used = new Set(
      walk(root).flatMap((file) =>
        [
          ...readFileSync(file, "utf8").matchAll(/<InfoTip\s+term="([^"]+)"/g),
        ].map((match) => match[1]),
      ),
    );
    expect(used.size).toBeGreaterThan(0);
    for (const term of used) expect(terms).toHaveProperty(term);

    for (const [term, definition] of Object.entries(terms)) {
      expect(term).toMatch(/\S/);
      expect(definition.trim()).toMatch(/\S/);
    }
  });
});
