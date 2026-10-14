import type { CSSProperties, ReactNode } from "react";
import styled from "styled-components";
import useSplunkThemeExport from "@splunk/themes/useSplunkTheme";
import { toolkitDefault } from "./interop";
import { PAGES, pageURL, type Page } from "./urlState";

const useSplunkTheme = toolkitDefault(useSplunkThemeExport);
const Root = styled.div`
  background: var(--adm-page);
  color: var(--adm-ink);
  min-height: 600px;
  font-family: inherit;
  &&& :is(h1, h2, h3, h4, p, label, legend, th, td) {
    color: inherit;
  }
  &&& :is(h1, h2, h3, h4, p) {
    font-family: inherit;
  }
`;
const labels: Record<Page, string> = {
  applications: "Applications",
  map: "Map",
  data_health: "Data health",
  setup: "Setup",
  help: "Help",
};

/** Toolkit theme values also feed the existing SVG map's scoped CSS tokens. */
export function Shell({ page, children }: { page: Page; children: ReactNode }) {
  const t = useSplunkTheme();
  const tokens = {
    fontFamily: t.fontFamily,
    fontSize: t.fontSize,
    "--adm-page": t.backgroundColorPage,
    "--adm-surface": t.backgroundColorSection,
    "--adm-card": t.backgroundColorSection,
    "--adm-card-head": t.backgroundColorPage,
    "--adm-card-border": t.borderColor,
    "--adm-line": t.borderColorWeak,
    "--adm-ink": t.contentColorDefault,
    "--adm-ink-2": t.contentColorMuted,
    "--adm-muted": t.contentColorMuted,
    "--adm-link": t.contentColorLink,
    "--adm-focus": t.contentColorLink,
    "--adm-select-ring": t.contentColorDefault,
  } as CSSProperties;
  return (
    <Root className="atlas" data-atlas-theme={t.colorScheme} style={tokens}>
      <nav className="atlas-nav" aria-label="Application Atlas">
        <strong>Application Atlas</strong>
        {PAGES.map((p) => (
          <a
            key={p}
            href={pageURL(
              p,
              p === "map"
                ? new URLSearchParams(
                    typeof location === "undefined" ? "" : location.search,
                  )
                : undefined,
            )}
            aria-current={p === page ? "page" : undefined}
          >
            {labels[p]}
          </a>
        ))}
      </nav>
      {children}
    </Root>
  );
}
